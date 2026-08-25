// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package protocol_probes

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamplat "github.com/owasp-amass/open-asset-model/platform"
)

// certharvest.go performs a generic, protocol-agnostic TLS handshake
// against a host:port and, on success, stores the full peer
// certificate chain using the exact same conversion and edge
// conventions http_probes already uses for HTTPS -
// support.X509ToOAMTLSCertificate for parsing (completely unmodified,
// reused as-is), and a "certificate" edge from the Service entity to
// the leaf certificate, chained via "issuing_certificate" edges for any
// intermediates. This works identically regardless of what protocol
// runs on top of TLS - nothing here is HTTP-specific, which is the
// entire point: the hard part (parsing) was already generic, only the
// acquisition step needed generalizing.

// harvestSource identifies this plugin's own contributions distinctly
// from http_probes' - both may legitimately harvest certificates, and
// keeping the source attribution separate preserves that provenance.
var harvestSource = &et.Source{Name: "Protocol-Probes", Confidence: 80}

// HarvestCertificate is the entry point: ensure a Service entity exists
// for this host:port, skip entirely if a certificate was already
// harvested for it (the dedup guard - this is what avoids redundant
// work against ports http_probes already covers, typically 443), and
// otherwise perform the handshake and store whatever chain comes back.
func HarvestCertificate(e *et.Event, parent *dbt.Entity, addr string, port int, timeout time.Duration) error {
	svcEntity, err := findOrCreateService(e, parent, addr, port)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 5*time.Second)
	defer cancel()

	existing, err := e.Session.DB().OutgoingEdges(ctx, svcEntity, time.Time{}, "certificate")
	if err == nil && len(existing) > 0 {
		// Already harvested - by http_probes, or by a prior run of this
		// same harvester. Nothing further to do.
		return nil
	}

	certs, err := dialAndGetCertChain(addr, timeout)
	if err != nil {
		return err
	}
	if len(certs) == 0 {
		return errors.New("protocol_probes: TLS handshake succeeded but no peer certificates were presented")
	}

	storeCertChain(e, svcEntity, certs)
	return nil
}

// dialAndGetCertChain performs a plain, standard-library TLS handshake
// against addr and returns the full peer certificate chain on success.
// This is the one genuinely new piece of acquisition logic this
// project needed - everything downstream of a successful handshake
// (parsing, chain walking, edge conventions) is fully reused from what
// http_probes already does, unchanged.
//
// InsecureSkipVerify is intentional, not an oversight: the goal here is
// harvesting whatever certificate a host presents, including expired,
// self-signed, or otherwise untrusted ones - that data is still real
// and worth recording - not validating whether the connection should
// be trusted the way a normal TLS client would.
func dialAndGetCertChain(addr string, timeout time.Duration) ([]*x509.Certificate, error) {
	dialer := &net.Dialer{Timeout: timeout}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if !state.HandshakeComplete {
		return nil, errors.New("protocol_probes: TLS handshake did not complete")
	}
	return state.PeerCertificates, nil
}

// findOrCreateService builds the Service entity this harvest attaches
// to, using the same ID construction (support.ServiceWithIdentifier)
// already used elsewhere in the codebase, and links it to its parent
// (typically an IPAddress) via the standard PortRelation edge - the
// same shape http_probes produces, just via a direct, minimal path
// rather than reusing CreateServiceAsset, whose own dedup logic is
// tuned for content-bearing HTTP services (it compares OutputLen,
// which is meaningless for a cert-only harvest with no page body).
func findOrCreateService(e *et.Event, parent *dbt.Entity, addr string, port int) (*dbt.Entity, error) {
	serv := support.ServiceWithIdentifier(addr, "tcp", port)
	// Type is deliberately left as a generic marker here - real
	// protocol identification (if any, via banner classification) is
	// layered in separately, not decided by this cert-focused path.
	serv.Type = "tls"

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 15*time.Second)
	defer cancel()

	svcEntity, err := e.Session.DB().CreateAsset(ctx, serv)
	if err != nil || svcEntity == nil {
		return nil, errors.New("protocol_probes: failed to create the Service asset")
	}

	if _, err := e.Session.DB().CreateEdge(ctx, &dbt.Edge{
		Relation: &oamgen.PortRelation{
			PortNumber: port,
			Protocol:   "tcp",
		},
		FromEntity: parent,
		ToEntity:   svcEntity,
	}); err != nil {
		return nil, err
	}

	return svcEntity, nil
}

// storeCertChain walks the peer certificate chain leaf-to-root, storing
// each certificate and linking consecutive ones via "issuing_certificate"
// edges, then links the leaf back to the Service via a "certificate"
// edge - byte-for-byte the same edge shape and labels http_probes
// already produces for HTTPS, via the same shared support.Finding /
// support.ProcessAssetsWithSource mechanism, so downstream consumers
// (Horizontals' scope-expansion, any future reporting) see identical
// structure regardless of which path actually harvested a given cert.
func storeCertChain(e *et.Event, svcEntity *dbt.Entity, certs []*x509.Certificate) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), time.Duration(len(certs)*3)*time.Second)
	defer cancel()

	var findings []*support.Finding
	var prevEntity *dbt.Entity
	var firstEntity *dbt.Entity

	for _, cert := range certs {
		c := support.X509ToOAMTLSCertificate(cert)
		if c == nil {
			break
		}

		certEntity, err := e.Session.DB().CreateAsset(ctx, c)
		if err != nil || certEntity == nil {
			break
		}

		if prevEntity == nil {
			firstEntity = certEntity
		} else if prevCert, ok := prevEntity.Asset.(*oamcert.TLSCertificate); ok {
			findings = append(findings, &support.Finding{
				From:     prevEntity,
				FromName: prevCert.SerialNumber,
				To:       certEntity,
				ToName:   c.SerialNumber,
				ToMeta:   cert,
				Rel:      &oamgen.SimpleRelation{Name: "issuing_certificate"},
			})
		}
		prevEntity = certEntity
	}

	if firstEntity != nil {
		if leafCert, ok := firstEntity.Asset.(*oamcert.TLSCertificate); ok {
			svcName := "Service"
			if svc, ok := svcEntity.Asset.(*oamplat.Service); ok {
				svcName = "Service: " + svc.ID
			}
			findings = append(findings, &support.Finding{
				From:     svcEntity,
				FromName: svcName,
				To:       firstEntity,
				ToName:   leafCert.SerialNumber,
				Rel:      &oamgen.SimpleRelation{Name: "certificate"},
			})
		}
	}

	if len(findings) > 0 {
		support.ProcessAssetsWithSource(e, findings, harvestSource, "Protocol-Probes", "HarvestCertificate")
	}
}
