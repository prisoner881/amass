// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package rdap

import (
	"context"
	"errors"
	"time"

	"github.com/openrdap/rdap"
	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/open-asset-model/network"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
	"github.com/owasp-amass/open-asset-model/url"
)

// maxAdmittedNetblockBits caps the size of a netblock admitted to scope
// by registration contact, expressed as host bits: 11 permits a /21
// (2,048 addresses) for IPv4 and rejects anything larger.
//
// Sized from measurement rather than taste. The largest client-owned
// block observed carrying a matching registration contact was a /21, and
// at the prefilter's sustained ~4 IPs/sec a /21 costs roughly nine
// minutes - acceptable for one block. A /16 would cost over four hours.
// The cap bounds the pathological case; a per-run budget would be the
// next refinement if many qualifying blocks ever appear at once.
const maxAdmittedNetblockBits = 11

type ipnet struct {
	name       string
	plugin     *rdapPlugin
	transforms []string
}

func (r *ipnet) Name() string {
	return r.name
}

func (r *ipnet) check(e *et.Event) error {
	_, ok := e.Entity.Asset.(*oamreg.IPNetRecord)
	if !ok {
		return errors.New("failed to cast the IPNetRecord asset")
	}

	matches, err := e.Session.Config().CheckTransformations(
		string(oam.IPNetRecord), append(r.transforms, r.plugin.name)...)
	if err != nil || matches.Len() == 0 {
		return nil
	}

	var findings []*support.Finding
	if record, ok := e.Meta.(*rdap.IPNetwork); ok && record != nil {
		r.store(e, record, e.Entity, matches)
	} else {
		findings = append(findings, r.lookup(e, e.Entity, matches)...)
	}

	if len(findings) > 0 {
		r.process(e, findings)
	}

	r.admitOwnedNetblock(e)
	return nil
}

// admitOwnedNetblock registers this record's netblock with the session's
// live scope tracker when its RDAP registration contacts prove the block
// is assigned to a domain already in scope.
//
// This is the ONLY path by which a netblock containing no in-scope FQDN
// can become in-scope, and it is deliberately narrow. ip_netblock.go
// gates on support.HasInScopeFQDN, which requires an IP to have a
// hostname that resolves to it. IPs found by neighbourhood sweep have no
// hostname at all, so they are discovered and then never scanned - the
// forgotten-subnet case this tool most needs to catch.
//
// Placed here rather than in ip_netblock.go because of ordering.
// ip_netblock.go runs at Position 4 on the IPAddress pipeline and creates
// the Netblock entity; the RDAP record and its contacts do not exist
// until the resulting Netblock event reaches rdap's own handler and, in
// turn, dispatches this IPNetRecord event. This handler is the first
// point at which the ownership evidence is complete.
//
// Failing to admit is always safe - the block simply stays unscanned, as
// it does today. Admitting wrongly directs active scan traffic at a third
// party, so every branch below bails rather than guesses.
func (r *ipnet) admitOwnedNetblock(e *et.Event) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 20*time.Second)
	defer cancel()

	if !support.NetblockRegisteredToScopedDomain(ctx, e.Session, e.Entity) {
		return
	}

	// The netblock is on the FROM side: Netblock -registration-> IPNetRecord.
	edges, err := e.Session.DB().IncomingEdges(ctx, e.Entity, time.Time{}, "registration")
	if err != nil {
		return
	}

	for _, edge := range edges {
		nbent, err := e.Session.DB().FindEntityById(ctx, edge.FromEntity.ID)
		if err != nil || nbent == nil {
			continue
		}

		nb, ok := nbent.Asset.(*network.Netblock)
		if !ok {
			continue
		}

		// A ceiling on how much address space one registration record can
		// admit. Registry assignments are occasionally enormous, and a
		// single /8 would add 16 million addresses to the scan queue -
		// enough to make an enumeration never finish, whatever the
		// ownership evidence says. Blocks larger than this are still
		// recorded in the database; they are simply not scanned wholesale.
		if ones, bits := nb.CIDR.Bits(), nb.CIDR.Addr().BitLen(); bits-ones > maxAdmittedNetblockBits {
			e.Session.Log().Info("netblock ownership confirmed but too large to admit",
				"netblock", nb.CIDR.String(), "plugin", r.plugin.name, "handler", r.name)
			continue
		}

		e.Session.Scope().Add(nb)
		e.Session.Log().Info("netblock admitted to scope by registration contact",
			"netblock", nb.CIDR.String(), "plugin", r.plugin.name, "handler", r.name)
	}
}

func (r *ipnet) lookup(e *et.Event, asset *dbt.Entity, m *config.Matches) []*support.Finding {
	var rtypes []string
	var findings []*support.Finding
	sinces := make(map[string]time.Time)

	for _, atype := range r.transforms {
		if !m.IsMatch(atype) {
			continue
		}

		since, err := support.TTLStartTime(e.Session.Config(), string(oam.IPNetRecord), atype, r.plugin.name)
		if err != nil {
			continue
		}
		sinces[atype] = since

		switch atype {
		case string(oam.URL):
			rtypes = append(rtypes, "rdap_url")
		case string(oam.FQDN):
			rtypes = append(rtypes, "whois_server")
		case string(oam.ContactRecord):
			rtypes = append(rtypes, "registrant", "admin_contact", "abuse_contact", "technical_contact")
		}
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	if edges, err := e.Session.DB().OutgoingEdges(ctx, asset, time.Time{}, rtypes...); err == nil && len(edges) > 0 {
		for _, edge := range edges {
			a, err := e.Session.DB().FindEntityById(ctx, edge.ToEntity.ID)
			if err != nil {
				continue
			}
			totype := string(a.Asset.AssetType())

			since, ok := sinces[totype]
			if !ok || (ok && a.LastSeen.Before(since)) {
				continue
			}

			if !r.oneOfSources(e, edge, r.plugin.source, since) {
				continue
			}

			var name string
			switch v := a.Asset.(type) {
			case *oamdns.FQDN:
				name = v.Name
			case *contact.ContactRecord:
				name = "ContactRecord: " + v.DiscoveredAt
			case *url.URL:
				name = v.Raw
			default:
				continue
			}

			iprec := asset.Asset.(*oamreg.IPNetRecord)
			findings = append(findings, &support.Finding{
				From:     asset,
				FromName: "IPNetRecord: " + iprec.Handle,
				To:       a,
				ToName:   name,
				Rel:      edge.Relation,
			})
		}
	}

	return findings
}

func (r *ipnet) oneOfSources(e *et.Event, edge *dbt.Edge, src *et.Source, since time.Time) bool {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 10*time.Second)
	defer cancel()

	if tags, err := e.Session.DB().FindEdgeTags(ctx, edge, since, src.Name); err == nil && len(tags) > 0 {
		for _, tag := range tags {
			if _, ok := tag.Property.(*general.SourceProperty); ok {
				return true
			}
		}
	}
	return false
}

func (r *ipnet) store(e *et.Event, resp *rdap.IPNetwork, entity *dbt.Entity, m *config.Matches) {
	var findings []*support.Finding
	iprec := entity.Asset.(*oamreg.IPNetRecord)

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	if u := r.plugin.getJSONLink(resp.Links); u != nil && m.IsMatch(string(oam.URL)) {
		if a, err := e.Session.DB().CreateAsset(ctx, u); err == nil && a != nil {
			findings = append(findings, &support.Finding{
				From:     entity,
				FromName: "IPNetRecord: " + iprec.Handle,
				To:       a,
				ToName:   u.Raw,
				Rel:      &general.SimpleRelation{Name: "rdap_url"},
			})
		}
	}

	if name := iprec.WhoisServer; name != "" && m.IsMatch(string(oam.FQDN)) {
		fqdn := &oamdns.FQDN{Name: name}

		if _, conf := e.Session.Scope().IsAssetInScope(fqdn, 0); conf > 0 {
			if a, err := e.Session.DB().CreateAsset(ctx, fqdn); err == nil && a != nil {
				findings = append(findings, &support.Finding{
					From:     entity,
					FromName: "IPNetRecord: " + iprec.Handle,
					To:       a,
					ToName:   name,
					Rel:      &general.SimpleRelation{Name: "whois_server"},
				})
			}
		}
	}

	// process the relations built above
	support.ProcessAssetsWithSource(e, findings, r.plugin.source, r.plugin.name, r.name)

	if m.IsMatch(string(oam.ContactRecord)) {
		for _, v := range resp.Entities {
			r.plugin.storeEntity(e, 1, &v, entity, r.plugin.source, m)
		}
	}
}

func (r *ipnet) process(e *et.Event, findings []*support.Finding) {
	support.ProcessAssetsWithSource(e, findings, r.plugin.source, r.plugin.name, r.name)
}
