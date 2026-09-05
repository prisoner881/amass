// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package http_probes

import (
	"context"
	"errors"
	"strconv"
	"time"

	pp "github.com/owasp-amass/amass/v5/engine/plugins/service_discovery/protocol_probes"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amassnet "github.com/owasp-amass/amass/v5/internal/net"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/open-asset-model/network"
)

type ipaddrEndpoint struct {
	name   string
	plugin *httpProbing
}

func (r *ipaddrEndpoint) Name() string {
	return r.name
}

func (r *ipaddrEndpoint) check(e *et.Event) error {
	ip, ok := e.Entity.Asset.(*network.IPAddress)
	if !ok {
		return errors.New("failed to extract the IPAddress asset")
	}

	if !e.Session.Config().Active {
		return nil
	}

	addrstr := ip.Address.String()
	if reserved, _ := amassnet.IsReservedAddress(addrstr); reserved {
		return nil
	}

	// only perform the probe if the address is in scope
	if _, conf := e.Session.Scope().IsAssetInScope(ip, 0); conf <= 0 {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.IPAddress), string(oam.Service), r.name)
	if err != nil || since.IsZero() {
		return err
	}

	src := r.plugin.source
	var findings []*support.Finding
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, src, since) {
		findings = append(findings, r.lookup(e, e.Entity, since)...)
	} else {
		f, probed := r.query(e, e.Entity)
		findings = append(findings, f...)

		// MarkAssetMonitored ONLY when there were ports to probe.
		//
		// The mark is a claim that this plugin did its work on this asset,
		// and it suppresses re-examination for the full TTL (1440 minutes by
		// default). Marking after probing nothing is therefore a lie with a
		// 24-hour lifetime, and it was a measured, recurring cost:
		//
		//   - port_prefilter and this handler sit on the same pipeline at
		//     Positions 41 and 42, but an IP can also reach this handler via
		//     the FQDN pipeline before its own IPAddress event has been
		//     through Position 41. Measured at ~13% of IPs on one target,
		//     biased toward high-fan-in CDN and WAF addresses because those
		//     are the ones many hostnames point at.
		//   - An IP whose netblock is not yet in scope is rejected by
		//     EnsureOpenPortsScanned before it ever stores a port, so this
		//     handler sees an empty list. All 50 addresses in one
		//     client-owned /24 carried a mark from this path for work that
		//     never happened.
		//
		// In both cases the port data usually arrives moments later, and
		// without the mark the asset is simply re-examined on the next pass
		// instead of being suppressed for a day.
		//
		// The distinction that matters is "had ports and found nothing"
		// versus "had no ports to try". The first is a real result and must
		// be marked, or genuinely empty hosts would be re-probed forever.
		// Only the second is suppressed, which is why query() reports
		// whether it had anything to work with rather than the caller
		// inferring it from an empty findings slice - those two states are
		// indistinguishable from the outside.
		if probed {
			support.MarkAssetMonitored(e.Session, e.Entity, src)
		}
	}

	if len(findings) > 0 {
		r.process(e, findings)
	}
	return nil
}

func (r *ipaddrEndpoint) lookup(e *et.Event, ip *dbt.Entity, since time.Time) []*support.Finding {
	var findings []*support.Finding

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	if edges, err := e.Session.DB().OutgoingEdges(ctx, ip, since); err == nil && len(edges) > 0 {
		for _, edge := range edges {
			if _, err := e.Session.DB().FindEdgeTags(ctx, edge, since, r.plugin.source.Name); err != nil {
				continue
			}
			if _, ok := edge.Relation.(*general.PortRelation); ok {
				if srv, err := e.Session.DB().FindEntityById(ctx,
					edge.ToEntity.ID); err == nil && srv != nil && srv.Asset.AssetType() == oam.Service {
					findings = append(findings, &support.Finding{
						From:     ip,
						FromName: ip.Asset.Key(),
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

// query probes the ports port_prefilter confirmed open on this address.
//
// The second return value reports whether there were any ports to probe
// at all, which the caller needs in order to decide whether marking the
// asset as monitored would be honest. It is deliberately NOT derivable
// from the findings slice: an empty slice means either "nothing was
// listening" or "there was nothing to try", and only the latter should
// leave the asset eligible for re-examination.
func (r *ipaddrEndpoint) query(e *et.Event, ipaddr *dbt.Entity) ([]*support.Finding, bool) {
	var findings []*support.Finding

	// Ports now come from port_prefilter's own, prior findings on this
	// specific IP (support.OpenPortsForIP), rather than the full,
	// static Scope.Ports list directly - see port_prefilter's own doc
	// comment for the full design reasoning behind this change.
	//
	// Scoped to the prefilter's own freshness window so that ports
	// which have since closed are not probed indefinitely on a
	// persistent database. Failing closed on an unresolvable window is
	// deliberate and costs nothing: the same error would have stopped
	// EnsureOpenPortsScanned from storing any ports in the first place,
	// so there would be nothing here to read either way.
	since, err := support.PrefilterTTLStartTime(e.Session)
	if err != nil {
		return nil, false
	}

	ports := support.OpenPortsForIP(e.Session.Ctx(), e.Session, ipaddr, since)
	if len(ports) == 0 {
		// Nothing to probe. Reported as "not probed" so the caller
		// leaves this asset eligible for re-examination rather than
		// suppressing it for the TTL over work that never happened.
		return nil, false
	}

	// Most-likely-to-be-open ports first (nmap's own real, published
	// frequency data) - see protocol_probes' own identical use of this
	// for the fuller reasoning. Every goroutine below launches
	// regardless of this order (all ports start at once, unlike
	// protocol_probes' sequential loop), but findings still arrive on
	// fch roughly in the order each port's own connection actually
	// resolves - sorting first means a flagged asset's timeout below
	// is more likely to have already captured results from its
	// highest-value ports by the time it fires.
	support.SortByFrequencyDesc(ports)

	var count int
	fch := make(chan []*support.Finding, len(ports))
	for _, port := range ports {
		count++
		go r.probeOnePort(e, ipaddr, port, fch)
	}

	// Only ever non-nil for an asset whose open-port count crosses
	// support.LikelyDecoyThreshold - see support.DecoyTimeoutChannel's
	// own doc comment. A nil channel here means this select always
	// falls through to the fch case alone, preserving today's
	// existing, deliberately unbounded behavior for a normal,
	// non-flagged asset.
	timeout := support.DecoyTimeoutChannel(len(ports))

	for range count {
		select {
		case results := <-fch:
			if len(results) > 0 {
				findings = append(findings, results...)
			}
		case <-timeout:
			return findings, true
		}
	}

	return findings, true
}

func (r *ipaddrEndpoint) probeOnePort(e *et.Event, ipaddr *dbt.Entity, port int, ch chan []*support.Finding) {
	ip := ipaddr.Asset.(*network.IPAddress)

	a := ip.Address.String()
	if ip.Type == "IPv6" {
		a = "[" + a + "]"
	}
	addr := a + ":" + strconv.Itoa(port)

	// A quick, cheap banner peek before committing to a full HTTP
	// request - this is what lets an aggregate Scope.Ports list mix
	// HTTP and non-HTTP services (SSH, SMTP, FTP, etc.) without
	// wastefully attempting an HTTP request against a port that's
	// unambiguously something else. Reuses protocol_probes' own
	// PeekBanner/ClassifyPeek/PeekTimeout directly - the same logic
	// and the same bound that plugin uses for its own classification,
	// rather than a second, potentially-drifting implementation here.
	//
	// Only an unambiguous non-HTTP classification skips the request:
	// a definite SSH banner, or a banner-first response that arrived
	// but wasn't SSH (near-certainly SMTP/FTP/POP3/etc., none of which
	// would produce a sensible HTTP response either). Silence is left
	// completely alone - that's the normal, expected signature of an
	// HTTP or HTTPS service, so those ports proceed exactly as before,
	// with zero behavior change for the common case.
	peek := pp.PeekBanner(e.Session.Ctx(), nil, addr, pp.PeekTimeout)
	if guess := pp.ClassifyPeek(peek.Data); guess == pp.GuessSSH || guess == pp.GuessAmbiguousBanner {
		ch <- nil
		return
	}

	proto := "https"
	if port == 80 || port == 8080 {
		proto = "http"
	}

	ch <- r.plugin.query(e, ipaddr, proto+"://"+addr, port)
}

func (r *ipaddrEndpoint) process(e *et.Event, findings []*support.Finding) {
	support.ProcessAssetsWithSource(e, findings, r.plugin.source, r.plugin.name, r.name)
}
