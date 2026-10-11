// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"strconv"
	"strings"
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
	"github.com/owasp-amass/resolve/utils"
)

type dnsReverse struct {
	name   string
	plugin *dnsPlugin
}

type relRev struct {
	ipFQDN *dbt.Entity
	target *dbt.Entity
}

func NewReverse(p *dnsPlugin) *dnsReverse {
	return &dnsReverse{
		name:   p.name + "-Reverse",
		plugin: p,
	}
}

func (d *dnsReverse) check(e *et.Event) error {
	ip, ok := e.Entity.Asset.(*oamnet.IPAddress)
	if !ok {
		return errors.New("failed to extract the IPAddress asset")
	}

	addrstr := ip.Address.String()
	if reserved, _ := amassnet.IsReservedAddress(addrstr); reserved {
		return nil
	}

	reverse, err := dns.ReverseAddr(ip.Address.String())
	if err != nil {
		return nil
	}
	reverse = utils.RemoveLastDot(reverse)

	since, err := support.TTLStartTime(e.Session.Config(), "IPAddress", "FQDN", d.plugin.name)
	if err != nil {
		return err
	}

	var ptr *dbt.Entity
	src := d.plugin.source
	monitored := support.AssetMonitoredWithinTTL(e.Session, e.Entity, src, since)
	if monitored {
		ptr = d.lookupPTRAlias(e, reverse, since)
	} else {
		ptr = d.createPTRAlias(e, reverse, e.Entity)
	}
	if ptr == nil {
		return nil
	}

	var rev []*relRev
	if monitored {
		rev = append(rev, d.lookup(e, ptr, since)...)
	} else {
		rev = append(rev, d.query(e, addrstr, ptr)...)
		support.MarkAssetMonitored(e.Session, ptr, src)
	}

	if len(rev) > 0 {
		support.AddDNSRecordType(e, int(dns.TypePTR))
		d.attributeOwned(e, ip, rev, !monitored)
		d.process(e, rev)

		// PTR-triggered sweeping was removed here, not fixed to use
		// the (now-corrected, see ip_netblock.go/bgptools/netblock.go)
		// IP-based scope check. That check has never once succeeded
		// throughout this project's history, and this path had no
		// fallback the way dns/ip.go does - meaning this sweep has
		// never actually fired, ever. The PTR-resolved hostname here
		// is a discovered *output* of an arbitrary reverse lookup,
		// not a trusted, already-validated input the way dns/ip.go's
		// originating FQDN is, so checking scope against it wouldn't
		// be a faithful equivalent - it would be new, different
		// behavior, not a preserved one. Removing this dead code is
		// the accurate way to keep today's real behavior (no sweep
		// from this path) while still letting the scope fix benefit
		// every other consumer of IsAssetInScope correctly.
	}
	return nil
}

func (d *dnsReverse) lookup(e *et.Event, fqdn *dbt.Entity, since time.Time) []*relRev {
	var rev []*relRev

	if _, ok := fqdn.Asset.(*oamdns.FQDN); !ok {
		return rev
	}

	if assets := d.plugin.lookupWithinTTL(e.Session, fqdn, oam.FQDN, since, oam.BasicDNSRelation, 12); len(assets) > 0 {
		for _, a := range assets {
			rev = append(rev, &relRev{ipFQDN: fqdn, target: a})
		}
	}

	return rev
}

func (d *dnsReverse) query(e *et.Event, ipstr string, ptr *dbt.Entity) []*relRev {
	var rev []*relRev

	if rr, err := support.PerformQuery(e.Session.Ctx(), ipstr, dns.TypePTR); err == nil {
		if records := d.store(e, ptr, rr); len(records) > 0 {
			rev = append(rev, records...)
		}
	} else if err == support.ErrFailedMaxDNSAttempts {
		if name, derr := dns.ReverseAddr(ipstr); derr == nil {
			e.Session.Log().Warn(err.Error(), "fqdn", name,
				slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
		}
	}
	return rev
}

func (d *dnsReverse) store(e *et.Event, ptr *dbt.Entity, rr []dns.RR) []*relRev {
	var rev []*relRev

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 10*time.Second)
	defer cancel()

	// additional validation of the PTR record
	for _, record := range rr {
		if record.Header().Rrtype != dns.TypePTR {
			continue
		}

		data := strings.ToLower(strings.TrimSpace((record.(*dns.PTR)).Ptr))
		name := support.ScrapeSubdomainNames(data)
		if len(name) != 1 {
			continue
		}

		if t, err := e.Session.DB().CreateAsset(ctx, &oamdns.FQDN{Name: name[0]}); err == nil && t != nil {
			if edge, err := e.Session.DB().CreateEdge(ctx, &dbt.Edge{
				Relation: &oamdns.BasicDNSRelation{
					Name: "dns_record",
					Header: oamdns.RRHeader{
						RRType: int(record.Header().Rrtype),
						Class:  int(record.Header().Class),
						TTL:    int(record.Header().Ttl),
					},
				},
				FromEntity: ptr,
				ToEntity:   t,
			}); err == nil && edge != nil {
				rev = append(rev, &relRev{ipFQDN: ptr, target: t})
				_, _ = e.Session.DB().CreateEdgeProperty(ctx, edge, &general.SourceProperty{
					Source:     d.plugin.source.Name,
					Confidence: d.plugin.source.Confidence,
				})
			}
		} else {
			e.Session.Log().Error(err.Error(), slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
		}
	}

	return rev
}

func (d *dnsReverse) lookupPTRAlias(e *et.Event, name string, since time.Time) *dbt.Entity {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 3*time.Second)
	defer cancel()

	if ents, err := e.Session.DB().FindEntitiesByContent(ctx, oam.FQDN, since, 1, dbt.ContentFilters{
		"name": name,
	}); err == nil && len(ents) == 1 {
		return ents[0]
	}

	return nil
}

func (d *dnsReverse) createPTRAlias(e *et.Event, name string, ip *dbt.Entity) *dbt.Entity {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 5*time.Second)
	defer cancel()

	ptr, err := e.Session.DB().CreateAsset(ctx, &oamdns.FQDN{Name: name})
	if err != nil || ptr == nil {
		return nil
	}
	if edge, err := e.Session.DB().CreateEdge(ctx, &dbt.Edge{
		Relation:   &general.SimpleRelation{Name: "ptr_record"},
		FromEntity: ip,
		ToEntity:   ptr,
	}); err == nil && edge != nil {
		_, _ = e.Session.DB().CreateEdgeProperty(ctx, edge, &general.SourceProperty{
			Source:     d.plugin.source.Name,
			Confidence: d.plugin.source.Confidence,
		})
	}

	_ = e.Dispatcher.DispatchEvent(&et.Event{
		Name:    ptr.Asset.Key(),
		Entity:  ptr,
		Session: e.Session,
	})

	e.Session.Log().Info("relationship discovered", "from", ip.Asset.Key(), "relation", "ptr_record",
		"to", ptr.Asset.Key(), slog.Group("plugin", "name", d.plugin.name, "handler", d.name))

	return ptr
}

func (d *dnsReverse) process(e *et.Event, rev []*relRev) {
	for _, r := range rev {
		ip, valid := r.ipFQDN.Asset.(*oamdns.FQDN)
		if !valid {
			continue
		}

		target, valid := r.target.Asset.(*oamdns.FQDN)
		if !valid {
			continue
		}

		_ = e.Dispatcher.DispatchEvent(&et.Event{
			Name:    target.Name,
			Entity:  r.target,
			Session: e.Session,
		})

		e.Session.Log().Info("relationship discovered", "from", ip.Name, "relation", "dns_record",
			"to", target.Name, slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
	}
}

// attributeOwned links the in-scope PTR names of an IP in a seed-owned
// netblock directly to that IP, so the name is attributed to the address
// without walking the in-addr.arpa chain:
//
//   - IP -ptr_record-> host, alongside the existing chain
//     IP -ptr_record-> <ip>.in-addr.arpa -dns_record(PTR)-> host.
//   - apex -node-> host, so domain queries list the name even when it has
//     no forward DNS record. The apex handler creates this edge only for
//     names that resolved. Generic names that spell out the address
//     (10-1-2-3.dhcp.example.com) get no node edge: every address in a
//     block usually has one, and they would flood the subdomain list.
//
// Both checks must pass (the owned block and the in-scope name), so names
// in other address space are untouched. With refresh false (the PTR data
// came from the database, not a query), existing edges are left as they
// are and only missing ones are created, so their last-seen times still
// reflect the last real lookup.
func (d *dnsReverse) attributeOwned(e *et.Event, ip *oamnet.IPAddress, rev []*relRev, refresh bool) {
	var names []*dbt.Entity
	for _, r := range rev {
		if fqdn, ok := r.target.Asset.(*oamdns.FQDN); ok {
			if _, conf := e.Session.Scope().IsAssetInScope(fqdn, 0); conf > 0 {
				names = append(names, r.target)
			}
		}
	}
	if len(names) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 15*time.Second)
	defer cancel()

	if !support.IPInOwnedNetblock(ctx, e.Session, e.Entity) {
		return
	}

	linked := make(map[string]bool)
	if !refresh {
		if edges, err := e.Session.DB().OutgoingEdges(ctx, e.Entity, time.Time{}, "ptr_record"); err == nil {
			for _, edge := range edges {
				if edge.ToEntity != nil {
					linked[edge.ToEntity.ID] = true
				}
			}
		}
	}

	for _, t := range names {
		name := t.Asset.Key()

		if !linked[t.ID] {
			if edge, err := e.Session.DB().CreateEdge(ctx, &dbt.Edge{
				Relation:   &general.SimpleRelation{Name: "ptr_record"},
				FromEntity: e.Entity,
				ToEntity:   t,
			}); err == nil && edge != nil {
				_, _ = e.Session.DB().CreateEdgeProperty(ctx, edge, &general.SourceProperty{
					Source:     d.plugin.source.Name,
					Confidence: d.plugin.source.Confidence,
				})
				e.Session.Log().Info("owned-block PTR name linked to its address", "from", ip.Address.String(),
					"relation", "ptr_record", "to", name, slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
			}
		}

		if ptrNameEmbedsAddress(name, ip.Address) {
			continue
		}
		apex := d.plugin.apexOf(name)
		if apex == nil {
			continue
		}
		if !refresh {
			if edges, err := e.Session.DB().IncomingEdges(ctx, t, time.Time{}, "node"); err == nil && len(edges) > 0 {
				continue
			}
		}
		if _, err := e.Session.DB().CreateEdge(ctx, &dbt.Edge{
			Relation:   &general.SimpleRelation{Name: "node"},
			FromEntity: apex,
			ToEntity:   t,
		}); err == nil {
			e.Session.Log().Info("relationship discovered", "from", apex.Asset.Key(), "relation",
				"node", "to", name, slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
		}
	}
}

// ptrNameEmbedsAddress reports whether an IPv4 address appears in the name
// as four consecutive numbers, in either order: 10-1-2-3.example.com,
// host-3-2-1-10.example.com, ip10.1.2.3.example.com.
func ptrNameEmbedsAddress(name string, addr netip.Addr) bool {
	if !addr.Is4() {
		return false
	}
	a4 := addr.As4()

	var nums []int
	for _, f := range strings.FieldsFunc(name, func(r rune) bool { return r < '0' || r > '9' }) {
		if len(f) > 3 {
			nums = append(nums, -1)
			continue
		}
		n, _ := strconv.Atoi(f)
		nums = append(nums, n)
	}

	for i := 0; i+4 <= len(nums); i++ {
		fwd, rev := true, true
		for j := 0; j < 4; j++ {
			fwd = fwd && nums[i+j] == int(a4[j])
			rev = rev && nums[i+j] == int(a4[3-j])
		}
		if fwd || rev {
			return true
		}
	}
	return false
}
