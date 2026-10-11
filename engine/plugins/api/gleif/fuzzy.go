// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package gleif

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"strings"
	"time"

	"github.com/adrg/strutil"
	"github.com/adrg/strutil/metrics"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	"github.com/owasp-amass/amass/v5/engine/plugins/support/org"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

type fuzzyCompletions struct {
	name   string
	plugin *gleif
}

func (fc *fuzzyCompletions) check(e *et.Event) error {
	_, ok := e.Entity.Asset.(*oamorg.Organization)
	if !ok {
		return errors.New("failed to extract the Organization asset")
	}

	since, err := support.TTLStartTime(e.Session.Config(),
		string(oam.Organization), string(oam.Identifier), fc.plugin.name)
	if err != nil {
		return err
	}

	var id *dbt.Entity
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, fc.plugin.source, since) {
		id = fc.lookup(e, e.Entity, since)
	} else {
		var completed bool
		id, completed = fc.query(e, e.Entity)
		if completed {
			support.MarkAssetMonitored(e.Session, e.Entity, fc.plugin.source)
		}
	}

	if id != nil {
		fc.process(e, e.Entity, id)
	}
	return nil
}

func (fc *fuzzyCompletions) lookup(e *et.Event, orgent *dbt.Entity, since time.Time) *dbt.Entity {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	if edges, err := e.Session.DB().OutgoingEdges(ctx, orgent, since, "id"); err == nil {
		for _, edge := range edges {
			if tags, err := e.Session.DB().FindEdgeTags(ctx, edge, since, fc.plugin.source.Name); err != nil || len(tags) == 0 {
				continue
			}
			if a, err := e.Session.DB().FindEntityById(ctx, edge.ToEntity.ID); err == nil && a != nil {
				if id, ok := a.Asset.(*oamgen.Identifier); ok && id != nil && id.Type == oamgen.LEICode {
					return a
				}
			}
		}
	}
	return nil
}

// query also reports whether GLEIF answered every request it needed;
// check() marks the organization monitored only then. "No match" is an
// answer (ErrGLEIFNotFound); a failed request is not.
func (fc *fuzzyCompletions) query(e *et.Event, orgent *dbt.Entity) (*dbt.Entity, bool) {
	var conf int
	var rec *LEIRecord
	var failures []string

	if leient := fc.plugin.orgEntityToLEI(e, orgent); leient != nil {
		lei := leient.Asset.(*oamgen.Identifier)

		r, err := GLEIFGetLEIRecord(e.Session.Ctx(), lei.ID)
		if err == nil {
			rec = r
			conf = 100
		} else if !errors.Is(err, ErrGLEIFNotFound) {
			failures = append(failures, err.Error())
		}
	}

	if rec == nil {
		o := orgent.Asset.(*oamorg.Organization)

		result, err := GLEIFSearchFuzzyCompletions(e.Session.Ctx(), o.Name)
		if err != nil {
			if !errors.Is(err, ErrGLEIFNotFound) {
				e.Session.Log().Error(err.Error(), slog.Group("plugin", "name", fc.plugin.name, "handler", fc.name))
				failures = append(failures, err.Error())
			}
		} else {
			m := make(map[string]string)
			for _, d := range result.Data {
				if d.Type == "fuzzycompletions" && d.Relationships.LEIRecords.Data.Type == "lei-records" {
					key := strings.ToLower(d.Attributes.Value)
					m[key] = d.Relationships.LEIRecords.Data.ID
				}
			}

			var ffail []string
			rec, ffail = filterFuzzyCompletions(e, orgent, o.Name, m)
			failures = append(failures, ffail...)
		}
	}

	if rec == nil {
		if len(failures) > 0 {
			if e.Session.Ctx().Err() == nil {
				support.LogLookupFailure(fc.plugin.log, fc.plugin.name, "organization "+orgent.ID, strings.Join(failures, "; "))
			}
			return nil, false
		}
		e.Session.Log().Info("no LEI record found for organization",
			"org", orgent.ID, slog.Group("plugin", "name", fc.plugin.name, "handler", fc.name))
		return nil, true
	}

	ident := fc.store(e, orgent, rec, conf)
	return ident, ident != nil
}

// filterFuzzyCompletions picks the best-scoring LEI record among the
// candidates, and returns the errors of the record requests that failed
// (a candidate GLEIF no longer has is not a failure).
func filterFuzzyCompletions(e *et.Event, orgent *dbt.Entity, brand string, m map[string]string) (*LEIRecord, []string) {
	var rec *LEIRecord
	var failures []string
	o := orgent.Asset.(*oamorg.Organization)

	var names []string
	for k := range m {
		names = append(names, k)
	}
	if len(names) == 0 {
		return nil, nil
	}

	if exact, partial, found := org.NameMatch(e.Session, orgent, names); found {
		var conf int

		for _, match := range exact {
			score := 30

			if len(exact) == 1 {
				score += 30
			}

			lei := m[match]
			r, err := GLEIFGetLEIRecord(e.Session.Ctx(), lei)
			if err != nil && !errors.Is(err, ErrGLEIFNotFound) {
				failures = append(failures, err.Error())
			}
			if err == nil {
				if LocMatch(e, orgent, r) {
					score += 40
				}
				if score > conf {
					rec = r
					conf = score
				}
			}
		}

		swg := metrics.NewSmithWatermanGotoh()
		swg.CaseSensitive = false
		swg.GapPenalty = -0.1
		swg.Substitution = metrics.MatchMismatch{
			Match:    1,
			Mismatch: -0.5,
		}

		for _, match := range partial {
			if !strings.Contains(strings.ToLower(match), strings.ToLower(brand)) {
				continue
			}

			sim := strutil.Similarity(o.Name, match, swg)
			score := int(math.Round(sim * 30))

			if len(partial) == 1 {
				score += 30
			}

			lei := m[match]
			r, err := GLEIFGetLEIRecord(e.Session.Ctx(), lei)
			if err != nil && !errors.Is(err, ErrGLEIFNotFound) {
				failures = append(failures, err.Error())
			}
			if err == nil {
				if LocMatch(e, orgent, r) {
					score += 40
				}
				if score > conf {
					rec = r
					conf = score
				}
			}
		}
	}

	return rec, failures
}

func (fc *fuzzyCompletions) store(e *et.Event, orgent *dbt.Entity, rec *LEIRecord, conf int) *dbt.Entity {
	fc.plugin.updateOrgFromLEIRecord(e, orgent, rec, conf)

	ident, err := fc.plugin.createLEIFromRecord(e, orgent, rec, conf)
	if err != nil {
		e.Session.Log().Error(err.Error(), slog.Group("plugin", "name", fc.plugin.name, "handler", fc.name))
		return nil
	}

	return ident
}

func (fc *fuzzyCompletions) process(e *et.Event, orgent, ident *dbt.Entity) {
	id := ident.Asset.(*oamgen.Identifier)

	_ = e.Dispatcher.DispatchEvent(&et.Event{
		Name:    id.UniqueID,
		Entity:  ident,
		Session: e.Session,
	})

	o := orgent.Asset.(*oamorg.Organization)
	e.Session.Log().Info("relationship discovered", "from", o.Name, "relation", "id",
		"to", id.UniqueID, slog.Group("plugin", "name", fc.plugin.name, "handler", fc.name))
}
