// Copyright (c) by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
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

type ipNetblock struct {
	name   string
	log    *slog.Logger
	source *et.Source
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
	// tracker (e.Session.Scope()) on the conservative "ambiguous" path:
	// admit it only if it is small enough (IPv4, mask /20 or longer)
	// that scanning the whole block on a weak signal is acceptable.
	//
	// This plugin fires on every IPAddress the pipeline touches,
	// including IPs resolved from out-of-scope, incidentally-discovered
	// FQDNs (shared CDN or third-party infrastructure). The previous
	// gate here admitted a netblock of ANY size whenever a single
	// in-scope name merely resolved into it (support.HasInScopeFQDN);
	// because scope containment then marks every address in the range
	// in scope, that admitted entire cloud-provider /10s and /11s and
	// unrelated third-party ranges - confirmed directly against a real
	// enumeration as the mechanism behind AWS/Azure/Google/Cloudflare
	// ranges being scanned. The size gate stops that: a large block is
	// never admitted on this weak, incidental signal.
	//
	// Two things preserve the assets we do want. First, a netblock the
	// target genuinely owns still reaches scope at any size via the
	// ownership path (AdmitOwnedNetblock below, and the session-end
	// FinishOwnedNetblockFills re-walk), which is gated on RDAP contact
	// attribution, not size. Second, an individual IP that an in-scope
	// FQDN resolves to is authorized for scanning directly and
	// independently of its enclosing netblock (see the provenance
	// authorization in dns/ip.go), so declining to scope a large
	// ambiguous block here does not lose target hosts inside it.
	if support.PrefixEligibleForAmbientAdmit(netblock.CIDR) {
		e.Session.Scope().Add(netblock)
	}
	support.AdmitOwnedNetblock(e, nb)

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
