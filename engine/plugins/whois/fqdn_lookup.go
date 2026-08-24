// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package whois

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	whoisclient "github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
	"golang.org/x/net/publicsuffix"
)

type fqdnLookup struct {
	name   string
	plugin *whois
}

func (r *fqdnLookup) Name() string {
	return r.name
}

func (r *fqdnLookup) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to cast the FQDN asset")
	}

	name := strings.ToLower(fqdn.Name)
	if dom, err := publicsuffix.EffectiveTLDPlusOne(name); err != nil || dom != name {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.DomainRecord), r.name)
	if err != nil {
		return err
	}

	var asset *dbt.Entity
	src := r.plugin.source
	var record *whoisparser.WhoisInfo
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, src, since) {
		asset = r.lookup(e, fqdn.Name, since)
	} else {
		asset, record = r.query(e, fqdn.Name, e.Entity, src)
		support.MarkAssetMonitored(e.Session, e.Entity, src)
	}

	if asset != nil {
		r.process(e, record, e.Entity, asset)
	}
	return nil
}

func (r *fqdnLookup) lookup(e *et.Event, name string, since time.Time) *dbt.Entity {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	ents, err := e.Session.DB().FindEntitiesByContent(ctx, oam.DomainRecord, since, 1, dbt.ContentFilters{
		"domain": name,
	})
	if err != nil || len(ents) != 1 {
		return nil
	}
	dr := ents[0]

	if tags, err := e.Session.DB().FindEntityTags(ctx, dr,
		since, r.plugin.source.Name, r.plugin.rdapSource.Name); err == nil && len(tags) > 0 {
		for _, tag := range tags {
			if tag.Property.PropertyType() == oam.SourceProperty {
				return dr
			}
		}
	}
	return nil
}

// query tries RDAP first, falling back to the legacy WHOIS protocol
// lookup only if RDAP has no bootstrap entry for the domain's TLD, or
// the RDAP call itself fails. Both paths converge on the same
// storeRecord() below, so downstream consumers - the DomainRecord
// created here, and domain_record.go's contact extraction - see
// identical structure and shape regardless of which source actually
// answered.
func (r *fqdnLookup) query(e *et.Event, name string, fent *dbt.Entity, src *et.Source) (*dbt.Entity, *whoisparser.WhoisInfo) {
	if info, raw, err := r.plugin.queryRDAP(e, name); err == nil && info != nil {
		return r.storeRecord(e, info, raw, fent, r.plugin.rdapSource)
	}

	info, raw, err := r.queryWHOIS(e, name)
	if err != nil || info == nil {
		return nil, nil
	}
	return r.storeRecord(e, info, raw, fent, src)
}

// queryWHOIS respects WHOIS-server-friendly pacing via a bounded wait,
// not an unconditional one - same fix, same reasoning as the CertSpotter
// fix applied earlier: r.plugin.rlimit is a single limiter shared across
// every concurrent apex-domain lookup. A plain limiter.Wait(ctx) blocks
// the calling goroutine - and the pipeline execution slot it's
// holding - for however long its turn takes. The configured rate here
// (1 per 5 seconds) is reasonable on its own, but with many distinct
// apex domains discovered in a single run, concurrent callers queuing
// up behind one shared limiter reproduces the same effective stall,
// observed directly in production: waits up to 30+ minutes, starving
// the pipeline's FQDN token pool for everything else. Reserve()+Delay()
// lets the wait be seen upfront and skipped, cleanly, past a reasonable
// bound, rather than blocking indefinitely while holding that slot.
//
// The bound needs real headroom for normal concurrent queuing, not just
// a short cutoff - an earlier 10-second threshold was too tight: with
// support.MidHandlerInstances (16) concurrent handler slots all
// potentially needing a WHOIS lookup at once, and a 5-second interval,
// the worst-case *normal* queue depth is 16 * 5s = 80s. A threshold
// anywhere near 10s would skip most of a legitimate concurrent burst,
// not just the pathological cases this was meant to catch.
const maxAcceptableWHOISWait = 90 * time.Second

func (r *fqdnLookup) queryWHOIS(e *et.Event, name string) (*whoisparser.WhoisInfo, string, error) {
	reservation := r.plugin.rlimit.Reserve()
	if !reservation.OK() {
		return nil, "", errors.New("WHOIS: rate limiter cannot grant a reservation")
	}
	delay := reservation.Delay()
	if delay > maxAcceptableWHOISWait {
		reservation.Cancel()
		r.plugin.log.Warn("skipping WHOIS lookup, rate limit wait too long",
			"name", name, "wait", delay.String())
		return nil, "", errors.New("WHOIS: rate limit wait exceeded acceptable bound")
	}

	select {
	case <-e.Session.Ctx().Done():
		reservation.Cancel()
		return nil, "", e.Session.Ctx().Err()
	case <-time.After(delay):
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 10*time.Second)
	defer cancel()

	var resp string
	ch := make(chan string, 1)
	go r.whoisRoutine(e.Session, name, ch)

	select {
	case <-ctx.Done():
		return nil, "", ctx.Err()
	case resp = <-ch:
	}
	if resp == "" {
		return nil, "", errors.New("WHOIS: empty response")
	}

	info, err := whoisparser.Parse(resp)
	if err != nil {
		msg := fmt.Sprintf("failed to parse the WHOIS record for %s", name)
		e.Session.Log().Error(msg, slog.Group("plugin", "name", r.plugin.name, "handler", r.name))
		return nil, "", err
	}
	if !strings.EqualFold(info.Domain.Domain, name) {
		return nil, "", fmt.Errorf("WHOIS: parsed domain %q does not match %q", info.Domain.Domain, name)
	}

	return &info, resp, nil
}

func (r *fqdnLookup) whoisRoutine(sess et.Session, name string, ch chan string) {
	resp, err := whoisclient.Whois(name)
	if err != nil {
		resp = ""
		msg := fmt.Sprintf("failed to acquire the WHOIS record for %s", name)
		sess.Log().Error(msg, slog.Group("plugin", "name", r.plugin.name, "handler", r.name))
	}
	ch <- resp
}

// storeRecord is the single, shared path both RDAP and WHOIS results
// flow through - identical DomainRecord construction, identical edge
// creation, identical downstream event shape, regardless of which
// source actually answered. info is expected fully populated per the
// whoisparser.WhoisInfo shape either way: WHOIS via whoisparser.Parse,
// RDAP via rdapToWhoisInfo in rdap.go.
func (r *fqdnLookup) storeRecord(e *et.Event, info *whoisparser.WhoisInfo, raw string, fent *dbt.Entity, src *et.Source) (*dbt.Entity, *whoisparser.WhoisInfo) {
	fqdn := fent.Asset.(*oamdns.FQDN)

	dr := &oamreg.DomainRecord{
		Raw:            raw,
		ID:             info.Domain.ID,
		Domain:         strings.ToLower(info.Domain.Domain),
		Punycode:       info.Domain.Punycode,
		Name:           info.Domain.Name,
		Extension:      info.Domain.Extension,
		WhoisServer:    strings.ToLower(info.Domain.WhoisServer),
		CreatedDate:    info.Domain.CreatedDate,
		UpdatedDate:    info.Domain.UpdatedDate,
		ExpirationDate: info.Domain.ExpirationDate,
		DNSSEC:         info.Domain.DNSSec,
	}

	dr.Status = append(dr.Status, info.Domain.Status...)
	if tstr := support.TimeToJSONString(info.Domain.CreatedDateInTime); tstr != "" {
		dr.CreatedDate = tstr
	}
	if tstr := support.TimeToJSONString(info.Domain.UpdatedDateInTime); tstr != "" {
		dr.UpdatedDate = tstr
	}
	if tstr := support.TimeToJSONString(info.Domain.ExpirationDateInTime); tstr != "" {
		dr.ExpirationDate = tstr
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	autasset, err := e.Session.DB().CreateAsset(ctx, dr)
	if err == nil && autasset != nil {
		// Tag the DomainRecord entity itself with its real source, in
		// addition to the edge below - this is what lets
		// domain_record.go's handler determine dynamically whether a
		// given record came from RDAP or WHOIS, rather than assuming
		// one unconditionally for every downstream Person/Organization/
		// ContactRecord entity it derives from it.
		_, _ = e.Session.DB().CreateEntityProperty(ctx, autasset, &general.SourceProperty{
			Source:     src.Name,
			Confidence: src.Confidence,
		})

		if edge, err := e.Session.DB().CreateEdge(ctx, &dbt.Edge{
			Relation:   &general.SimpleRelation{Name: "registration"},
			FromEntity: fent,
			ToEntity:   autasset,
		}); err == nil && edge != nil {
			_, _ = e.Session.DB().CreateEdgeProperty(ctx, edge, &general.SourceProperty{
				Source:     src.Name,
				Confidence: src.Confidence,
			})
			msg := fmt.Sprintf("successfully acquired the %s record for %s", src.Name, fqdn.Name)
			e.Session.Log().Info(msg, slog.Group("plugin", "name", r.plugin.name, "handler", r.name))
		}
	}

	return autasset, info
}

func (r *fqdnLookup) process(e *et.Event, record *whoisparser.WhoisInfo, fqdn, dr *dbt.Entity) {
	d := dr.Asset.(*oamreg.DomainRecord)

	name := d.Domain + " WHOIS domain record"
	_ = e.Dispatcher.DispatchEvent((&et.Event{
		Name:    name,
		Meta:    record,
		Entity:  dr,
		Session: e.Session,
	}))

	fname := fqdn.Asset.(*oamdns.FQDN)
	e.Session.Log().Info("relationship discovered", "from", fname.Name, "relation",
		"registration", "to", name, slog.Group("plugin", "name", r.plugin.name, "handler", r.name))
}
