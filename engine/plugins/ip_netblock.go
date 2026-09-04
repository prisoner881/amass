// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	"github.com/owasp-amass/amass/v5/engine/sessions"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amassnet "github.com/owasp-amass/amass/v5/internal/net"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

// maxAdmittedNetblockBits caps how much address space one registration
// record may admit, expressed as host bits: 11 permits a /21 (2,048
// addresses) for IPv4 and rejects anything larger.
//
// Sized from measurement. The largest client-owned block observed with a
// matching registration contact was a /21, which at the pre-filter's
// sustained ~4 IPs/sec costs roughly nine minutes. A /16 would cost over
// four hours, and registry assignments are occasionally far larger than
// that. Oversized blocks are still recorded in the database; they are
// simply not scanned wholesale.
const maxAdmittedNetblockBits = 11

type ipNetblock struct {
	name   string
	log    *slog.Logger
	source *et.Source
	// owned caches the registration-ownership decision per netblock CIDR.
	//
	// This handler fires on EVERY IPAddress the pipeline touches - 7,192
	// in one observed run - while the ownership question is per netblock,
	// of which there were 455. Without the cache, every IP that fails the
	// cheap HasInScopeFQDN test would repeat a multi-hop graph walk, and
	// the IPs that fail that test are the majority. Bounded by the number
	// of distinct netblocks, so it cannot grow without limit.
	owned sync.Map
}

func NewIPNetblock() et.Plugin {
	return &ipNetblock{
		name: "IP-Netblock",
		source: &et.Source{
			Name:       "IP-Netblock",
			Confidence: 100,
		},
	}
}

func (d *ipNetblock) Name() string {
	return d.name
}

func (d *ipNetblock) Start(r et.Registry) error {
	d.log = r.Log().WithGroup("plugin").With("name", d.name)

	name := d.name + "-Handler"
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       d,
		Name:         name,
		Position:     4,
		MaxInstances: support.MaxHandlerInstances,
		Transforms:   []string{string(oam.Netblock)},
		EventType:    oam.IPAddress,
		Callback:     d.lookup,
	}); err != nil {
		d.log.Error(fmt.Sprintf("Failed to register a handler: %v", err), "handler", name)
		return err
	}

	d.log.Info("Plugin started")
	return nil
}

func (d *ipNetblock) Stop() {
	d.log.Info("Plugin stopped")
}

func (d *ipNetblock) lookup(e *et.Event) error {
	ip, ok := e.Entity.Asset.(*oamnet.IPAddress)
	if !ok {
		return errors.New("failed to extract the IPAddress asset")
	}

	if reserved, cidr := amassnet.IsReservedAddress(ip.Address.String()); reserved {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil
		}

		netblock := &oamnet.Netblock{
			Type: "IPv4",
			CIDR: prefix,
		}
		if prefix.Addr().Is6() {
			netblock.Type = "IPv6"
		}

		d.reservedAS(e, netblock)
		return nil
	}

	var entry *sessions.CIDRangerEntry
	for range 120 {
		entry = support.IPNetblock(e.Session, ip.Address.String())
		if entry != nil {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if entry == nil {
		return nil
	}

	nb, as := d.store(e, entry)
	if nb == nil || as == nil {
		return nil
	}

	d.process(e, e.Entity, nb, as)
	return nil
}

// netblockOwnedByTarget answers, once per netblock, whether the RDAP
// registration contacts prove this block is assigned to a domain already
// in scope - and whether it is small enough to admit.
//
// Failing to admit is always safe: the block stays unscanned, exactly as
// it does today. Admitting wrongly points active scan traffic at somebody
// else's network, so every branch bails rather than guesses.
func (d *ipNetblock) netblockOwnedByTarget(ctx context.Context, e *et.Event,
	nb *dbt.Entity, netblock *oamnet.Netblock) bool {
	key := netblock.CIDR.String()
	if v, ok := d.owned.Load(key); ok {
		return v.(bool)
	}

	admit := support.NetblockRegisteredToScopedDomain(ctx, e.Session, nb)
	if admit {
		if ones, bits := netblock.CIDR.Bits(), netblock.CIDR.Addr().BitLen(); bits-ones > maxAdmittedNetblockBits {
			d.log.Info("netblock ownership confirmed but too large to admit",
				"netblock", key, "host_bits", bits-ones, "limit", maxAdmittedNetblockBits)
			admit = false
		} else {
			d.log.Info("netblock admitted to scope by registration contact", "netblock", key)
		}
	}

	d.owned.Store(key, admit)
	return admit
}

func (d *ipNetblock) store(e *et.Event, entry *sessions.CIDRangerEntry) (*dbt.Entity, *dbt.Entity) {
	netblock := &oamnet.Netblock{
		Type: "IPv4",
		CIDR: netip.MustParsePrefix(entry.Net.String()),
	}
	if netblock.CIDR.Addr().Is6() {
		netblock.Type = "IPv6"
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 10*time.Second)
	defer cancel()

	nb, err := e.Session.DB().CreateAsset(ctx, netblock)
	if err != nil || nb == nil {
		return nil, nil
	}

	// Registers the discovered netblock with the session's live scope
	// tracker (e.Session.Scope()), not just the database - but only
	// when the IP that triggered this discovery genuinely traces back
	// to something already in scope. This plugin fires unconditionally
	// on every IPAddress the pipeline ever touches, including IPs
	// resolved from completely out-of-scope, incidentally-discovered
	// FQDNs (a shared CDN or third-party service some unrelated domain
	// happens to use). Without this gate, that unconditional firing -
	// harmless before Scope.Add() actually worked, since nothing read
	// its result - now means any netblock touched by any IP resolution
	// anywhere gets permanently registered as in-scope, and every other
	// IP sharing that (often huge, shared) range becomes in-scope too
	// via the normal, correct containment check. Confirmed directly
	// against a real enumeration: this was the complete, actual
	// mechanism behind Cloudflare/AWS/Azure/Google/GitHub ranges, and
	// entirely unrelated third-party infrastructure, all ending up
	// marked in-scope. See support.HasInScopeFQDN for the actual check,
	// shared with whois/bgptools/netblock.go's identical situation.
	// Two independent routes into scope.
	//
	// HasInScopeFQDN is the original, cheap test: some hostname that
	// resolves to this IP is already in scope. It covers the ordinary
	// case and short-circuits before the second test runs.
	//
	// The registration check covers what that test structurally cannot.
	// An IP discovered by neighbourhood sweep (support.IPAddressSweep)
	// has no hostname of its own, so HasInScopeFQDN always rejects it and
	// the pre-filter never scans it - measured at 3,563 discovered but
	// entirely unassessed IP-only assets in a single enumeration, sitting
	// inside blocks the target demonstrably owns. Those forgotten hosts
	// are exactly what this tool exists to surface, and an attacker
	// enumerating a netblock needs no hostname to reach them.
	//
	// The registration test is deliberately the second operand so the
	// cheap path wins whenever it can.
	if support.HasInScopeFQDN(ctx, e.Session, e.Entity) {
		e.Session.Scope().Add(netblock)
	} else if d.netblockOwnedByTarget(ctx, e, nb, netblock) {
		e.Session.Scope().Add(netblock)
	}

	_, _ = e.Session.DB().CreateEntityProperty(ctx, nb, &general.SourceProperty{
		Source:     entry.Src.Name,
		Confidence: entry.Src.Confidence,
	})

	edge, err := e.Session.DB().CreateEdge(ctx, &dbt.Edge{
		Relation:   &general.SimpleRelation{Name: "contains"},
		FromEntity: nb,
		ToEntity:   e.Entity,
	})
	if err != nil || edge == nil {
		return nil, nil
	}

	_, _ = e.Session.DB().CreateEdgeProperty(ctx, edge, &general.SourceProperty{
		Source:     entry.Src.Name,
		Confidence: entry.Src.Confidence,
	})

	as, err := e.Session.DB().CreateAsset(ctx, &oamnet.AutonomousSystem{Number: entry.ASN})
	if err != nil || as == nil {
		return nil, nil
	}

	_, _ = e.Session.DB().CreateEntityProperty(ctx, as, &general.SourceProperty{
		Source:     entry.Src.Name,
		Confidence: entry.Src.Confidence,
	})

	edge, err = e.Session.DB().CreateEdge(ctx, &dbt.Edge{
		Relation:   &general.SimpleRelation{Name: "announces"},
		FromEntity: as,
		ToEntity:   nb,
	})
	if err != nil || edge == nil {
		return nil, nil
	}

	_, _ = e.Session.DB().CreateEdgeProperty(ctx, edge, &general.SourceProperty{
		Source:     entry.Src.Name,
		Confidence: entry.Src.Confidence,
	})

	return nb, as
}

func (d *ipNetblock) process(e *et.Event, ip, nb, as *dbt.Entity) {
	ipstr := ip.Asset.Key()
	nbname := nb.Asset.Key()

	_ = e.Dispatcher.DispatchEvent(&et.Event{
		Name:    nb.Asset.Key(),
		Entity:  nb,
		Session: e.Session,
	})

	e.Session.Log().Info("relationship discovered", "from", nbname, "relation", "contains",
		"to", ipstr, slog.Group("plugin", "name", d.name, "handler", d.name+"-Handler"))

	asname := "AS" + as.Asset.Key()
	_ = e.Dispatcher.DispatchEvent(&et.Event{
		Name:    asname,
		Entity:  as,
		Session: e.Session,
	})

	e.Session.Log().Info("relationship discovered", "from", asname, "relation", "announces",
		"to", nbname, slog.Group("plugin", "name", d.name, "handler", d.name+"-Handler"))
}

func (d *ipNetblock) reservedAS(e *et.Event, netblock *oamnet.Netblock) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 10*time.Second)
	defer cancel()

	nb, err := e.Session.DB().CreateAsset(ctx, netblock)
	if err != nil || nb == nil {
		return
	}

	_, _ = e.Session.DB().CreateEntityProperty(ctx, nb, &general.SourceProperty{
		Source:     d.source.Name,
		Confidence: d.source.Confidence,
	})

	asn, err := e.Session.DB().CreateAsset(ctx, &oamnet.AutonomousSystem{Number: 0})
	if err != nil || asn == nil {
		return
	}

	_, _ = e.Session.DB().CreateEntityProperty(ctx, nb, &general.SourceProperty{
		Source:     d.source.Name,
		Confidence: d.source.Confidence,
	})

	edge, err := e.Session.DB().CreateEdge(ctx, &dbt.Edge{
		Relation:   &general.SimpleRelation{Name: "announces"},
		FromEntity: asn,
		ToEntity:   nb,
	})
	if err != nil || edge == nil {
		return
	}

	_, _ = e.Session.DB().CreateEdgeProperty(ctx, edge, &general.SourceProperty{
		Source:     d.source.Name,
		Confidence: d.source.Confidence,
	})
}
