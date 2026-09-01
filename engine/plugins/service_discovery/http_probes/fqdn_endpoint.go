// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package http_probes

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
)

type fqdnEndpoint struct {
	name   string
	plugin *httpProbing
}

func (fe *fqdnEndpoint) Name() string {
	return fe.name
}

func (fe *fqdnEndpoint) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	if !e.Session.Config().Active {
		return nil
	}
	if !support.HasDNSRecordType(e, int(dns.TypeCNAME)) &&
		!support.HasDNSRecordType(e, int(dns.TypeA)) &&
		!support.HasDNSRecordType(e, int(dns.TypeAAAA)) {
		return nil
	}
	if _, conf := e.Session.Scope().IsAssetInScope(fqdn, 0); conf == 0 {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.Service), fe.name)
	if err != nil {
		return err
	}

	src := fe.plugin.source
	var findings []*support.Finding
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, src, since) {
		findings = append(findings, fe.lookup(e, e.Entity, since)...)
	} else {
		findings = append(findings, fe.query(e, e.Entity)...)
		support.MarkAssetMonitored(e.Session, e.Entity, src)
	}

	if len(findings) > 0 {
		fe.process(e, findings)
	}
	return nil
}

func (fe *fqdnEndpoint) lookup(e *et.Event, host *dbt.Entity, since time.Time) []*support.Finding {
	var findings []*support.Finding

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	if edges, err := e.Session.DB().OutgoingEdges(ctx, host, since); err == nil && len(edges) > 0 {
		for _, edge := range edges {
			if _, err := e.Session.DB().FindEdgeTags(ctx, edge, since, fe.plugin.source.Name); err != nil {
				continue
			}
			if _, ok := edge.Relation.(*oamgen.PortRelation); ok {
				if srv, err := e.Session.DB().FindEntityById(ctx,
					edge.ToEntity.ID); err == nil && srv != nil && srv.Asset.AssetType() == oam.Service {
					findings = append(findings, &support.Finding{
						From:     host,
						FromName: host.Asset.Key(),
						To:       srv,
						ToName:   srv.Asset.Key(),
						Rel:      edge.Relation,
					})
				}
			}
		}
	}
	return findings
}

func (fe *fqdnEndpoint) query(e *et.Event, host *dbt.Entity) []*support.Finding {
	var findings []*support.Finding

	// Ports now come from support.OpenPortsForFQDN, which resolves
	// this FQDN to its own IPs (following CNAME-style intermediate
	// hops) and reads back whatever port_prefilter has already
	// discovered for each one - not the full, static Scope.Ports list
	// directly, and (as of this handler's own history) not an active
	// trigger either. A live goroutine dump during a real, large-scale
	// enumeration showed every one of this handler's own concurrency
	// slots simultaneously blocked inside a fresh scan at once,
	// entirely displacing this handler's actual work for extended
	// stretches - see support.OpenPortsForFQDN's own doc comment for
	// the full history and the accepted tradeoff this reversion makes
	// (a brand-new IP may be skipped on this specific pass if it
	// hasn't been scanned yet, recoverable on a later pass rather than
	// blocking this one). This only changes which ports get tried; the
	// actual connection target below (proto + "://" + fqdn.Name + ":"
	// + port, in probeOnePort) is untouched, so this handler's whole
	// reason for existing - connecting by hostname for correct,
	// unambiguous SNI on virtually-hosted targets, rather than by a
	// bare, possibly-shared IP - is fully preserved. A hostname
	// resolving to several, differently-configured IPs means this can
	// over-include ports only genuinely open on one of them; a
	// deliberate tradeoff toward completeness over precision, not an
	// oversight.
	ports := support.OpenPortsForFQDN(e.Session.Ctx(), e.Session, host)

	// Most-likely-to-be-open ports first (nmap's own real, published
	// frequency data) - see protocol_probes' identical use of this,
	// and ipaddr_endpoint.go's own version of this same comment, for
	// the fuller reasoning.
	support.SortByFrequencyDesc(ports)

	var count int
	fch := make(chan []*support.Finding, len(ports))
	for _, port := range ports {
		count++
		go fe.probeOnePort(e, host, port, fch)
	}

	// Only ever non-nil for an asset whose open-port count crosses
	// support.LikelyDecoyThreshold - see ipaddr_endpoint.go's own
	// identical use of this for the fuller reasoning. A nil channel
	// here preserves today's existing, deliberately unbounded behavior
	// for a normal, non-flagged asset.
	timeout := support.DecoyTimeoutChannel(len(ports))

	for range count {
		select {
		case results := <-fch:
			if len(results) > 0 {
				findings = append(findings, results...)
			}
		case <-timeout:
			return findings
		}
	}

	return findings
}

func (fe *fqdnEndpoint) probeOnePort(e *et.Event, host *dbt.Entity, port int, ch chan []*support.Finding) {
	fqdn := host.Asset.(*oamdns.FQDN)
	addr := fqdn.Name + ":" + strconv.Itoa(port)

	proto := "https"
	if port == 80 || port == 8080 {
		proto = "http"
	}

	ch <- fe.plugin.query(e, host, proto+"://"+addr, port)
}

func (fe *fqdnEndpoint) process(e *et.Event, findings []*support.Finding) {
	support.ProcessAssetsWithSource(e, findings, fe.plugin.source, fe.plugin.name, fe.name)
}
