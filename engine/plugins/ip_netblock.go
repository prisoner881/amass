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
	"os"
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

	// TEMPORARY DIAGNOSTIC - remove once the missing-netblock-scope
	// investigation is resolved. Writes directly to stderr, bypassing
	// the same log-visibility gap confirmed multiple times already.
	// Checks support.ResolvingFQDNs and IsAssetInScope individually, in
	// addition to the actual HasInScopeFQDN call below, so we can see
	// exactly where a real dns_record edge (independently confirmed via
	// direct SQL query to exist) stops producing an in-scope result -
	// rather than only seeing HasInScopeFQDN's final true/false.
	{
		fqdns := support.ResolvingFQDNs(ctx, e.Session, e.Entity)
		fmt.Fprintf(os.Stderr, "DEBUG ip_netblock store() ip=%v netblock=%v resolvingFQDNs=%d\n",
			e.Entity.Asset.Key(), netblock.CIDR.String(), len(fqdns))
		for _, fqdn := range fqdns {
			_, conf := e.Session.Scope().IsAssetInScope(fqdn, 0)
			fmt.Fprintf(os.Stderr, "DEBUG ip_netblock store()   fqdn=%v inScopeConf=%d\n", fqdn.Name, conf)
		}
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
	if support.HasInScopeFQDN(ctx, e.Session, e.Entity) {
		e.Session.Scope().Add(netblock)
		fmt.Fprintf(os.Stderr, "DEBUG ip_netblock store() ADDED netblock=%v to scope\n", netblock.CIDR.String())
	} else {
		fmt.Fprintf(os.Stderr, "DEBUG ip_netblock store() SKIPPED netblock=%v (not in scope)\n", netblock.CIDR.String())
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
