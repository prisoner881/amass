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
	"strconv"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amassnet "github.com/owasp-amass/amass/v5/internal/net"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
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
//
// addr is deliberately the bare IP address, not a host:port string -
// FindOrCreateService (via support.ServiceWithIdentifier) appends the
// port itself, matching the exact same unique_id convention
// http_probes already uses for its own Service entities on the same
// host:port. Passing an already-combined host:port string here was a
// real, genuine bug this function used to have: it produced a
// different, malformed ID ("addr:port:tcp:port-hash" instead of
// "addr:tcp:port-hash") that could never match http_probes' own
// entries - meaning the dedup guard above could never actually see
// that a certificate had already been harvested, since it was always
// checking a distinct, never-before-seen entity. Confirmed directly
// against a real enumeration: duplicate tls Service rows existed
// alongside http_probes' web-service rows for the identical host:port.
// The host:port string this function actually needs for dialing gets
// constructed internally, below, right before it's used.
//
// dial is the same injected amassnet.DialContext used by PeekBanner,
// for the same reason: this is active-only traffic that must be able
// to route through the operator's configured active proxy once
// feature/active-proxy-egress is merged, without requiring further
// changes to this function - see PeekBanner's own doc comment in
// banner_peek.go for the complete reasoning. A nil dial falls back to
// amassnet.NewDialContext's plain, direct dialer, the only option this
// branch has available today.
func HarvestCertificate(e *et.Event, dial amassnet.DialContext, parent *dbt.Entity, addr string, port int, timeout time.Duration) error {
	svcEntity, err := FindOrCreateService(e, parent, addr, port, "tls", "")
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

	// Deliberately not assuming anything about which port a server
	// "should" run on - a raw TLS handshake is attempted unconditionally
	// here, regardless of port number, since the whole point of active
	// probing over convention is catching services that don't run where
	// convention would predict. serverName, when one is available,
	// gives that handshake the same fair chance a normal, hostname-
	// driven client would have: many modern, virtually-hosted TLS
	// servers require a correct SNI value to select which certificate
	// to present, and can reset or refuse a bare-IP connection that
	// arrives without one - see support.PreferredSNIHostname.
	serverName := support.PreferredSNIHostname(ctx, e.Session, parent)

	target := net.JoinHostPort(addr, strconv.Itoa(port))
	certs, err := dialAndGetCertChain(e.Session.Ctx(), dial, target, serverName, timeout)
	if err != nil {
		return err
	}
	if len(certs) == 0 {
		return errors.New("protocol_probes: TLS handshake succeeded but no peer certificates were presented")
	}

	storeCertChain(e, svcEntity, certs)
	return nil
}

// dialAndGetCertChain performs a TLS handshake against addr, via the
// supplied dial function, and returns the full peer certificate chain
// on success. tls.DialWithDialer can't be used directly here since it
// requires a concrete *net.Dialer rather than an arbitrary dial
// function - instead, dial supplies the raw connection, and TLS is
// layered on top of it manually via tls.Client + HandshakeContext, the
// standard approach for TLS over an already-established connection
// from a custom dialer.
//
// serverName populates the TLS ClientHello's SNI extension when
// non-empty - see HarvestCertificate's own comment and
// support.PreferredSNIHostname for the full reasoning. An empty
// serverName omits SNI entirely, identical to this function's
// behavior before this parameter existed.
//
// InsecureSkipVerify is intentional, not an oversight: the goal here is
// harvesting whatever certificate a host presents, including expired,
// self-signed, or otherwise untrusted ones - that data is still real
// and worth recording - not validating whether the connection should
// be trusted the way a normal TLS client would.
func dialAndGetCertChain(ctx context.Context, dial amassnet.DialContext, addr, serverName string, timeout time.Duration) ([]*x509.Certificate, error) {
	if dial == nil {
		dial = amassnet.NewDialContext(timeout)
	}

	rawConn, err := dial(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer rawConn.Close()

	if err := rawConn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}

	tlsConn := tls.Client(rawConn, &tls.Config{InsecureSkipVerify: true, ServerName: serverName})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}

	state := tlsConn.ConnectionState()
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
//
// Exported and takes svcType/output as parameters rather than being
// hardcoded to the cert-harvest case, so plugin.go's banner-first path
// (service.go) can reuse this exact same construction instead of a
// second, near-duplicate implementation.
// FindOrCreateService looks up the Service at this exact host:port
// before deciding whether to set its Type/Output. ServiceWithIdentifier's
// own unique_id scheme (in support/normalization.go) is deliberately
// keyed on host:port:protocol alone, not service_type - a hash of
// "addr:tcp:port", the same host:port produces the identical,
// deterministic ID regardless of which plugin discovers it, since a
// given port can only ever be one real service in reality, whichever
// plugin gets there first.
//
// Without the existence check below, CreateAsset's upsert behavior
// meant whichever plugin ran second - http_probes or protocol_probes,
// in whatever order the pipeline happened to schedule them - silently
// overwrote the other's Type field on the exact same row. Confirmed
// directly against real enumeration data: protocol_probes' own "tls"
// classification was overwriting http_probes' genuine "web-service"
// classification on ports 80 and 443, while - for reasons not fully
// investigated, likely a field-level merge quirk in the underlying
// upsert - the real HTML response text survived intact underneath the
// wrong type label.
//
// "Find or create" now means exactly that: if a Service already
// exists here, it's returned and used as-is, Type/Output untouched;
// only a genuinely new Service gets these values set at all. The
// PortRelation edge below is still always attempted either way, since
// it's a cheap, idempotent upsert on the database side, and skipping
// it when a Service already existed risked losing a legitimate edge
// if this call's parent entity ever turned out to differ from
// whichever plugin created the Service first.
func FindOrCreateService(e *et.Event, parent *dbt.Entity, addr string, port int, svcType, output string) (*dbt.Entity, error) {
	serv := support.ServiceWithIdentifier(addr, "tcp", port)

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 15*time.Second)
	defer cancel()

	svcEntity, err := findExistingServiceByUniqueID(ctx, e, serv.ID)
	if err != nil {
		return nil, err
	}
	if svcEntity == nil {
		serv.Type = svcType
		serv.Output = output
		serv.OutputLen = len(output)

		svcEntity, err = e.Session.DB().CreateAsset(ctx, serv)
		if err != nil || svcEntity == nil {
			return nil, errors.New("protocol_probes: failed to create the Service asset")
		}
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

// findExistingServiceByUniqueID looks up a Service entity by its exact,
// deterministic unique_id, without creating or modifying anything.
// Returns (nil, nil) - not an error - when none exists yet, the
// expected, normal case for a genuinely new host:port.
func findExistingServiceByUniqueID(ctx context.Context, e *et.Event, uniqueID string) (*dbt.Entity, error) {
	found, err := e.Session.DB().FindEntitiesByContent(ctx, oam.Service, time.Time{}, 1,
		dbt.ContentFilters{"unique_id": uniqueID})
	if err != nil {
		return nil, err
	}
	if len(found) == 0 {
		return nil, nil
	}
	return found[0], nil
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
