// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"errors"
	"time"

	"github.com/caffix/stringset"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamcon "github.com/owasp-amass/open-asset-model/contact"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

// Unlabeled IncomingEdges over 10 hops on a shared multi-tenant graph
// walks contains/dns_record/port and OOMs. Restrict to org/contact
// edges, cap nodes and wall time, and fail open (no match → create).
const (
	ancestorMaxHops  = 10
	ancestorMaxNodes = 256
	ancestorMaxOrgs  = 32
	ancestorTimeout  = 2 * time.Second
)

var ancestorEdgeLabels = []string{
	"organization",
	"id",
	"subsidiary",
	"registration",
	"registrant",
	"admin_contact",
	"abuse_contact",
	"technical_contact",
}

func dedupChecks(sess et.Session, obj *dbt.Entity, o *oamorg.Organization) *dbt.Entity {
	var names []string

	for _, name := range []string{o.Name, o.LegalName} {
		if name != "" {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return nil
	}

	switch obj.Asset.(type) {
	case *oamcon.ContactRecord:
		if org, found := nameExistsInContactRecord(sess, obj, names); found {
			return org
		}
		if org, err := existsAndSharesLocEntity(sess, obj, o); err == nil {
			return org
		}
		if org, err := existsAndSharesAncestorEntity(sess, obj, o); err == nil {
			return org
		}
		if org, err := existsAndHasAncestorInSession(sess, o); err == nil {
			return org
		}
	case *oamorg.Organization:
		if org, found := nameRelatedToOrganization(sess, obj, names); found {
			return org
		}
		if org, err := existsAndSharesLocEntity(sess, obj, o); err == nil {
			return org
		}
		if org, err := existsAndSharesAncestorEntity(sess, obj, o); err == nil {
			return org
		}
		if org, err := existsAndHasAncestorInSession(sess, o); err == nil {
			return org
		}
	}

	if org, found := nameExistsInSessionScope(sess, o); found {
		return org
	}

	return nil
}

func nameExistsInContactRecord(sess et.Session, cr *dbt.Entity, names []string) (*dbt.Entity, bool) {
	if cr == nil {
		return nil, false
	}

	ctx, cancel := context.WithTimeout(sess.Ctx(), 30*time.Second)
	defer cancel()

	if edges, err := sess.DB().OutgoingEdges(ctx, cr, time.Time{}, "organization"); err == nil && len(edges) > 0 {
		for _, edge := range edges {
			if a, err := sess.DB().FindEntityById(ctx, edge.ToEntity.ID); err == nil && a != nil {
				if _, ok := a.Asset.(*oamorg.Organization); ok {
					if _, _, found := NameMatch(sess, a, names); found {
						return a, true
					}
				}
			}
		}
	}
	return nil, false
}

func nameExistsInSessionScope(sess et.Session, o *oamorg.Organization) (*dbt.Entity, bool) {
	ctx, cancel := context.WithTimeout(sess.Ctx(), 10*time.Second)
	defer cancel()

	ents, err := sess.DB().FindEntitiesByContent(ctx, oam.Organization, time.Time{}, 0, dbt.ContentFilters{
		"name": o.Name,
	})
	if err != nil || len(ents) == 0 {
		return nil, false
	}

	for _, ent := range ents {
		if _, err := sess.Scope().IsAssociated(&et.Association{Submission: ent}); err == nil {
			return ent, true
		}
	}

	return nil, false
}

func nameRelatedToOrganization(sess et.Session, orgent *dbt.Entity, names []string) (*dbt.Entity, bool) {
	if orgent == nil {
		return nil, false
	}

	ctx, cancel := context.WithTimeout(sess.Ctx(), 30*time.Second)
	defer cancel()

	if edges, err := sess.DB().IncomingEdges(ctx, orgent, time.Time{}, "subsidiary"); err == nil && len(edges) > 0 {
		for _, edge := range edges {
			if a, err := sess.DB().FindEntityById(ctx, edge.FromEntity.ID); err == nil && a != nil {
				if _, ok := a.Asset.(*oamorg.Organization); ok {
					if _, _, found := NameMatch(sess, a, names); found {
						return a, true
					}
				}
			}
		}
	}
	if edges, err := sess.DB().OutgoingEdges(ctx, orgent, time.Time{}, "subsidiary"); err == nil && len(edges) > 0 {
		for _, edge := range edges {
			if a, err := sess.DB().FindEntityById(ctx, edge.ToEntity.ID); err == nil && a != nil {
				if _, ok := a.Asset.(*oamorg.Organization); ok {
					if _, _, found := NameMatch(sess, a, names); found {
						return a, true
					}
				}
			}
		}
	}
	return nil, false
}

func existsAndSharesLocEntity(sess et.Session, obj *dbt.Entity, o *oamorg.Organization) (*dbt.Entity, error) {
	var names []string
	var locs []*dbt.Entity

	if o.Name != "" {
		names = append(names, o.Name)
	}
	if o.LegalName != "" {
		names = append(names, o.LegalName)
	}
	if len(names) == 0 {
		return nil, errors.New("zero names provided in the Organization")
	}

	ctx, cancel := context.WithTimeout(sess.Ctx(), 30*time.Second)
	defer cancel()

	if edges, err := sess.DB().OutgoingEdges(ctx, obj, time.Time{}, "legal_address", "hq_address", "location"); err == nil {
		for _, edge := range edges {
			if a, err := sess.DB().FindEntityById(ctx, edge.ToEntity.ID); err == nil && a != nil {
				if _, ok := a.Asset.(*oamcon.Location); ok {
					locs = append(locs, a)
				}
			}
		}
	}

	locs = append(locs, matchingLocations(sess, locs)...)

	var orgents, crecords []*dbt.Entity
	for _, loc := range locs {
		if edges, err := sess.DB().IncomingEdges(ctx, loc, time.Time{}, "legal_address", "hq_address", "location"); err == nil {
			for _, edge := range edges {
				if a, err := sess.DB().FindEntityById(ctx, edge.FromEntity.ID); err == nil && a != nil {
					if _, ok := a.Asset.(*oamcon.ContactRecord); ok && a.ID != obj.ID {
						crecords = append(crecords, a)
					} else if _, ok := a.Asset.(*oamorg.Organization); ok && a.ID != obj.ID {
						orgents = append(orgents, a)
					}
				}
			}
		}
	}

	for _, cr := range crecords {
		if edges, err := sess.DB().OutgoingEdges(ctx, cr, time.Time{}, "organization"); err == nil {
			for _, edge := range edges {
				if a, err := sess.DB().FindEntityById(ctx, edge.ToEntity.ID); err == nil && a != nil {
					if _, ok := a.Asset.(*oamorg.Organization); ok {
						orgents = append(orgents, a)
					}
				}
			}
		}
	}

	for _, orgent := range orgents {
		if _, _, found := NameMatch(sess, orgent, names); found {
			return orgent, nil
		}
	}

	return nil, errors.New("no matching org found")
}

func matchingLocations(sess et.Session, locs []*dbt.Entity) []*dbt.Entity {
	var newlocs []*dbt.Entity

	set := stringset.New()
	defer set.Close()

	for _, loc := range locs {
		set.Insert(loc.ID)
	}

	for _, loc := range locs {
		lasset, valid := loc.Asset.(*oamcon.Location)
		if !valid {
			continue
		}

		cf := make(dbt.ContentFilters)
		if lasset.BuildingNumber != "" {
			cf["building_number"] = lasset.BuildingNumber
		}
		if lasset.StreetName != "" {
			cf["street_name"] = lasset.StreetName
		}
		if lasset.City != "" {
			cf["city"] = lasset.City
		}
		if lasset.Province != "" {
			cf["province"] = lasset.Province
		}
		if lasset.Country != "" {
			cf["country"] = lasset.Country
		}

		ctx, cancel := context.WithTimeout(sess.Ctx(), 10*time.Second)
		defer cancel()

		ents, err := sess.DB().FindEntitiesByContent(ctx, oam.Location, time.Time{}, 0, cf)
		if err != nil || len(ents) == 0 {
			continue
		}

		for _, ent := range ents {
			if !set.Has(ent.ID) {
				set.Insert(ent.ID)
				newlocs = append(newlocs, ent)
			}
		}
	}

	return newlocs
}

func existsAndSharesAncestorEntity(sess et.Session, obj *dbt.Entity, o *oamorg.Organization) (*dbt.Entity, error) {
	orgents, err := orgsWithSameNames(sess, []string{o.Name, o.LegalName})
	if err != nil {
		return nil, err
	}
	if len(orgents) == 0 {
		return nil, errors.New("no matching org found")
	}
	if len(orgents) > ancestorMaxOrgs {
		sess.Log().Info("org ancestor walk skipped",
			"reason", "too many same-name orgs",
			"n", len(orgents), "name", o.Name)
		return nil, errors.New("too many same-name orgs")
	}

	ctx, cancel := context.WithTimeout(sess.Ctx(), ancestorTimeout)
	defer cancel()

	ancestors := make(map[string]struct{}, 32)
	ancestors[obj.ID] = struct{}{}
	nodes := 1
	if !walkIncoming(ctx, sess, []*dbt.Entity{obj}, ancestors, &nodes, nil) {
		logAncestorAbort(sess, o.Name, ctx, nodes)
		return nil, errors.New("no matching org found")
	}

	visited := make(map[string]struct{}, 32)
	for _, orgent := range orgents {
		if _, ok := ancestors[orgent.ID]; ok {
			return orgent, nil
		}
		hit := false
		ok := walkIncoming(ctx, sess, []*dbt.Entity{orgent}, visited, &nodes, func(id string) bool {
			if _, found := ancestors[id]; found {
				hit = true
				return true
			}
			return false
		})
		if hit {
			return orgent, nil
		}
		if !ok {
			logAncestorAbort(sess, o.Name, ctx, nodes)
			return nil, errors.New("no matching org found")
		}
	}

	return nil, errors.New("no matching org found")
}

func existsAndHasAncestorInSession(sess et.Session, o *oamorg.Organization) (*dbt.Entity, error) {
	orgents, err := orgsWithSameNames(sess, []string{o.Name, o.LegalName})
	if err != nil {
		return nil, err
	}
	if len(orgents) == 0 {
		return nil, errors.New("no matching org found")
	}
	if len(orgents) > ancestorMaxOrgs {
		sess.Log().Info("org ancestor walk skipped",
			"reason", "too many same-name orgs",
			"n", len(orgents), "name", o.Name)
		return nil, errors.New("too many same-name orgs")
	}

	ctx, cancel := context.WithTimeout(sess.Ctx(), ancestorTimeout)
	defer cancel()

	visited := make(map[string]struct{}, 32)
	nodes := 0
	for _, orgent := range orgents {
		if sess.Backlog().Has(orgent) {
			return orgent, nil
		}
		found, aborted := walkIncomingSession(ctx, sess, orgent, visited, &nodes)
		if found != nil {
			return found, nil
		}
		if aborted {
			logAncestorAbort(sess, o.Name, ctx, nodes)
			return nil, errors.New("no matching org found")
		}
	}

	return nil, errors.New("no matching org found")
}

func logAncestorAbort(sess et.Session, name string, ctx context.Context, nodes int) {
	reason := "node cap"
	if ctx.Err() != nil {
		reason = "timeout"
	}
	sess.Log().Info("org ancestor walk aborted",
		"reason", reason, "nodes", nodes, "name", name)
}

// walkIncoming BFS over labeled IncomingEdges. onHit(id) true stops
// with success. Returns false if the budget or ctx is exhausted
// before the frontier empties (caller treats as no match).
func walkIncoming(ctx context.Context, sess et.Session, start []*dbt.Entity, seen map[string]struct{}, nodes *int, onHit func(id string) bool) bool {
	frontier := start
	for hop := 0; hop < ancestorMaxHops && len(frontier) > 0; hop++ {
		if ctx.Err() != nil {
			return false
		}
		var next []*dbt.Entity
		for _, r := range frontier {
			if ctx.Err() != nil {
				return false
			}
			edges, err := sess.DB().IncomingEdges(ctx, r, time.Time{}, ancestorEdgeLabels...)
			if err != nil {
				continue
			}
			for _, edge := range edges {
				if edge.FromEntity == nil {
					continue
				}
				id := edge.FromEntity.ID
				if _, found := seen[id]; found {
					continue
				}
				seen[id] = struct{}{}
				*nodes++
				if *nodes > ancestorMaxNodes {
					return false
				}
				if onHit != nil && onHit(id) {
					return true
				}
				a, err := sess.DB().FindEntityById(ctx, id)
				if err != nil || a == nil {
					continue
				}
				next = append(next, a)
			}
		}
		frontier = next
	}
	return true
}

func walkIncomingSession(ctx context.Context, sess et.Session, start *dbt.Entity, seen map[string]struct{}, nodes *int) (*dbt.Entity, bool) {
	frontier := []*dbt.Entity{start}
	for hop := 0; hop < ancestorMaxHops && len(frontier) > 0; hop++ {
		if ctx.Err() != nil {
			return nil, true
		}
		var next []*dbt.Entity
		for _, r := range frontier {
			if ctx.Err() != nil {
				return nil, true
			}
			edges, err := sess.DB().IncomingEdges(ctx, r, time.Time{}, ancestorEdgeLabels...)
			if err != nil {
				continue
			}
			for _, edge := range edges {
				if edge.FromEntity == nil {
					continue
				}
				id := edge.FromEntity.ID
				if _, found := seen[id]; found {
					continue
				}
				seen[id] = struct{}{}
				*nodes++
				if *nodes > ancestorMaxNodes {
					return nil, true
				}
				if sess.Backlog().Has(edge.FromEntity) {
					return start, false
				}
				a, err := sess.DB().FindEntityById(ctx, id)
				if err != nil || a == nil {
					continue
				}
				if sess.Backlog().Has(a) {
					return start, false
				}
				next = append(next, a)
			}
		}
		frontier = next
	}
	return nil, false
}