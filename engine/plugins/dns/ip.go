// Copyright (c) by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amassnet "github.com/owasp-amass/amass/v5/internal/net"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

type dnsIP struct {
	name    string
	queries []uint16
	plugin  *dnsPlugin
	source  *et.Source
}

type relIP struct {
	rtype string
	ip    *dbt.Entity
}

func (d *dnsIP) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	if support.HasDNSRecordType(e, int(dns.TypeCNAME)) {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), "FQDN", "IPAddress", d.plugin.name)
	if err != nil {
		return err
	}

	var ips []*relIP
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, d.source, since) {
		ips = append(ips, d.lookup(e, e.Entity, since)...)
	} else {
		ips = append(ips, d.query(e, e.Entity)...)
	}

	if len(ips) > 0 {
		d.process(e, fqdn.Name, ips)

		// Whether the resolving FQDN is itself in scope. Computed once
		// and reused for both provenance-based scan authorization and
		// sweep sizing below, which are otherwise independent concerns.
		fqdnInScope := false
		if _, conf := e.Session.Scope().IsAssetInScope(fqdn, 0); conf > 0 {
			fqdnInScope = true
		}

		for _, v := range ips {
			ip, ok := v.ip.Asset.(*oamnet.IPAddress)
			if !ok || ip == nil {
				continue
			}

			// Provenance-based scan authorization. An IP that an
			// in-scope FQDN resolves to is individually authorized for
			// scanning, independent of whether its enclosing netblock
			// is in scope. This is what lets target assets hosted on
			// shared cloud infrastructure (an in-scope name on an
			// AWS/Azure IP) be scanned without admitting the provider's
			// entire netblock. Scope.Add (routing to AddIPAddress)
			// matches an IP by exact
			// address, so only this one IP is authorized - never its
			// neighbors, never its CIDR. Fill and sweep key off
			// Scope().Netblocks(), never Scope().IPAddresses(), so this
			// cannot make the block eligible for fill. Always fires
			// regardless of -rigid: -rigid disables horizontal scope
			// expansion to new orgs/domains, not the scanning of an IP
			// that an already-in-scope name resolves to.
			//
			// NOTE (temporary): the log line below is for interim
			// observability while the netblock resolution-admission
			// leak still exists on this branch. Until that leak is
			// removed, that add will usually early-return false
			// (the IP is already in scope via its leaked netblock), so
			// this authorization is redundant now and only becomes
			// load-bearing once the leak is gone. Remove the log line
			// after the leak-removal change is verified.
			if fqdnInScope {
				if e.Session.Scope().Add(ip) {
					e.Session.Log().Info("provenance scan authorization: added IP to scope",
						"ip", ip.Address.String(), "resolved_from", fqdn.Name,
						slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
				}
			}

			// Sweep sizing. Deliberately driven by FQDN-based scope
			// only, not IP/Netblock-based scope. Coupling sweep
			// aggressiveness to netblock membership would mean any
			// target using shared cloud infrastructure could trigger a
			// 250-address active sweep of unrelated third-party hosts
			// sharing that same range - a real scope-boundary risk, not
			// just a performance concern. Independent of the
			// authorization above: authorization permits one resolved
			// IP; sweep expands to neighbors, which are not authorized
			// here and must earn their own provenance to be scanned.
			var size int
			if fqdnInScope {
				size = d.plugin.firstSweepSize
			}
			if size > 0 {
				support.IPAddressSweep(e, ip, d.source, size, sweepCallback)
			}
		}
	}
	return nil
}

func (d *dnsIP) lookup(e *et.Event, fqdn *dbt.Entity, since time.Time) []*relIP {
	var ips []*relIP

	if assets := d.plugin.lookupWithinTTL(e.Session, fqdn, oam.IPAddress, since, oam.BasicDNSRelation, 1, 28); len(assets) > 0 {
		for _, a := range assets {
			ips = append(ips, &relIP{rtype: "dns_record", ip: a})
		}
	}

	return ips
}

func (d *dnsIP) query(e *et.Event, name *dbt.Entity) []*relIP {
	var ips []*relIP

	fqdn, valid := name.Asset.(*oamdns.FQDN)
	if !valid {
		return ips
	}

	for _, qtype := range d.queries {
		if rr, err := support.PerformQuery(e.Session.Ctx(), fqdn.Name, qtype); err == nil {
			if records := d.store(e, name, rr); len(records) > 0 {
				ips = append(ips, records...)
				support.MarkAssetMonitored(e.Session, name, d.source)
			}
		} else if err == support.ErrFailedMaxDNSAttempts {
			e.Session.Log().Warn(err.Error(), "fqdn", fqdn.Name,
				slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
		}
	}

	return ips
}

func (d *dnsIP) store(e *et.Event, fqdn *dbt.Entity, rr []dns.RR) []*relIP {
	var ips []*relIP

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	for _, record := range rr {
		var ip net.IP
		var ipType string

		switch record.Header().Rrtype {
		case dns.TypeA:
			ipType = "IPv4"
			ip = (record.(*dns.A)).A
		case dns.TypeAAAA:
			ipType = "IPv6"
			ip = (record.(*dns.AAAA)).AAAA
		default:
			continue
		}

		addr, valid := amassnet.IPToAddr(ip)
		if !valid {
			continue
		}

		ipaddr, err := e.Session.DB().CreateAsset(ctx, &oamnet.IPAddress{
			Address: addr,
			Type:    ipType,
		})
		if err != nil || ipaddr == nil {
			e.Session.Log().Error(err.Error(), slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
			continue
		}

		if edge, err := e.Session.DB().CreateEdge(ctx, &dbt.Edge{
			Relation: &oamdns.BasicDNSRelation{
				Name: "dns_record",
				Header: oamdns.RRHeader{
					RRType: int(record.Header().Rrtype),
					Class:  int(record.Header().Class),
					TTL:    int(record.Header().Ttl),
				},
			},
			FromEntity: fqdn,
			ToEntity:   ipaddr,
		}); err == nil && edge != nil {
			ips = append(ips, &relIP{rtype: "dns_record", ip: ipaddr})
			_, _ = e.Session.DB().CreateEdgeProperty(ctx, edge, &general.SourceProperty{
				Source:     d.source.Name,
				Confidence: d.source.Confidence,
			})
		}
	}

	return ips
}

func (d *dnsIP) process(e *et.Event, name string, addrs []*relIP) {
	for _, a := range addrs {
		ip, valid := a.ip.Asset.(*oamnet.IPAddress)
		if !valid {
			continue
		}

		switch ip.Type {
		case "IPv4":
			support.AddDNSRecordType(e, int(dns.TypeA))
		case "IPv6":
			support.AddDNSRecordType(e, int(dns.TypeAAAA))
		}

		_ = e.Dispatcher.DispatchEvent(&et.Event{
			Name:    ip.Address.String(),
			Entity:  a.ip,
			Session: e.Session,
		})

		e.Session.Log().Info("relationship discovered", "from", name, "relation", a.rtype,
			"to", ip.Address.String(), slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
	}
}
