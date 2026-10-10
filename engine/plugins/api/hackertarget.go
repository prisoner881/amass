// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/csv"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"golang.org/x/time/rate"
)

type hackerTarget struct {
	name   string
	url    string
	log    *slog.Logger
	rlimit *rate.Limiter
	source *et.Source
}

func NewHackerTarget() et.Plugin {
	limit := rate.Every(2 * time.Second)

	return &hackerTarget{
		name:   "HackerTarget",
		url:    "https://api.hackertarget.com/hostsearch/?q=",
		rlimit: rate.NewLimiter(limit, 1),
		source: &et.Source{
			Name:       "HackerTarget",
			Confidence: 80,
		},
	}
}

func (ht *hackerTarget) Name() string {
	return ht.name
}

func (ht *hackerTarget) Start(r et.Registry) error {
	ht.log = r.Log().WithGroup("plugin").With("name", ht.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       ht,
		Name:         ht.name + "-Handler",
		Position:     25,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   []string{string(oam.FQDN)},
		EventType:    oam.FQDN,
		Callback:     ht.check,
	}); err != nil {
		return err
	}

	ht.log.Info("Plugin started")
	return nil
}

func (ht *hackerTarget) Stop() {
	ht.log.Info("Plugin stopped")
}

func (ht *hackerTarget) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	if !support.HasSLDInScope(e) {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.FQDN), ht.name)
	if err != nil {
		return err
	}

	var names []*dbt.Entity
	if !support.AssetMonitoredWithinTTL(e.Session, e.Entity, ht.source, since) {
		var completed bool
		names, completed = ht.query(e, fqdn.Name)
		if completed {
			support.MarkAssetMonitored(e.Session, e.Entity, ht.source)
		}
	}

	if len(names) > 0 {
		ht.process(e, names)
	}
	return nil
}

// hackerTargetFailure reports why a 200 response body is not an answer.
// HackerTarget returns its daily quota notice ("API count exceeded -
// Increase Quota with Membership") as plain text with status 200, which
// parses as an empty result. Its other plain-text replies ("error ...")
// are still taken as the answer for the name: one of them may mean that
// nothing was found, and retrying those every session would spend the
// daily quota.
func hackerTargetFailure(body string) string {
	if strings.Contains(strings.ToLower(body), "api count exceeded") {
		return "daily API quota exceeded"
	}
	return ""
}

// query reports whether HackerTarget answered; check() marks the name
// monitored only then.
func (ht *hackerTarget) query(e *et.Event, name string) ([]*dbt.Entity, bool) {
	_ = ht.rlimit.Wait(e.Session.Ctx())
	e.Session.NetSem().Acquire()

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	resp, err := amasshttp.RequestWebPage(ctx,
		e.Session.Clients().General, &amasshttp.Request{URL: ht.url + name})
	e.Session.NetSem().Release()
	reason := support.HTTPLookupFailure(resp, err)
	if reason == "" {
		reason = hackerTargetFailure(resp.Body)
	}
	if reason != "" {
		support.LogLookupFailure(ht.log, ht.name, name, reason)
		return nil, false
	}

	var names []string
	if records, err := csv.NewReader(strings.NewReader(resp.Body)).ReadAll(); err == nil {
		for _, record := range records {
			if len(record) < 2 {
				continue
			}
			// if the subdomain is not in scope, skip it
			n := strings.ToLower(strings.TrimSpace(record[0]))
			if _, conf := e.Session.Scope().IsAssetInScope(&oamdns.FQDN{Name: n}, 0); conf > 0 {
				names = append(names, n)
			}
		}
	}

	return ht.store(e, names), true
}

func (ht *hackerTarget) store(e *et.Event, names []string) []*dbt.Entity {
	return support.StoreFQDNsWithSource(e.Session, names, ht.source, ht.name, ht.name+"-Handler")
}

func (ht *hackerTarget) process(e *et.Event, assets []*dbt.Entity) {
	support.ProcessFQDNsWithSource(e, assets, ht.source)
}
