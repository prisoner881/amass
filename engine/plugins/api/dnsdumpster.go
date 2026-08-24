// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
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

// dnsDumpster queries the current dnsdumpster.com/hackertarget.com REST API
// (api.dnsdumpster.com), which replaced the older, unauthenticated
// form-scrape technique v4.x's plugin used. The current API requires a
// registered X-API-Key on every request - there is no unauthenticated
// fallback, unlike CertSpotter, so this plugin declines to run at all
// when no key is configured rather than degrading gracefully.
type dnsDumpster struct {
	name   string
	log    *slog.Logger
	rlimit *rate.Limiter
	source *et.Source
}

func NewDNSDumpster() et.Plugin {
	return &dnsDumpster{
		name: "DNSDumpster",
		// Documented limit: 1 request per 2 seconds. Same cadence crt.sh
		// and HackerTarget already use elsewhere in this codebase -
		// DNSDumpster and HackerTarget share a parent company, so it's
		// unsurprising the rate posture matches.
		rlimit: rate.NewLimiter(rate.Every(2*time.Second), 1),
		source: &et.Source{
			Name:       "DNSDumpster",
			Confidence: 80,
		},
	}
}

func (dd *dnsDumpster) Name() string {
	return dd.name
}

func (dd *dnsDumpster) Start(r et.Registry) error {
	dd.log = r.Log().WithGroup("plugin").With("name", dd.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       dd,
		Name:         dd.name + "-Handler",
		Position:     25,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   []string{string(oam.FQDN)},
		EventType:    oam.FQDN,
		Callback:     dd.check,
	}); err != nil {
		return err
	}

	dd.log.Info("Plugin started")
	return nil
}

func (dd *dnsDumpster) Stop() {
	dd.log.Info("Plugin stopped")
}

func (dd *dnsDumpster) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	if !support.HasSLDInScope(e) {
		return nil
	}

	key := dd.apiKey(e)
	if key == "" {
		// Unlike CertSpotter, there is no unauthenticated path for this
		// API - nothing useful to do without a configured key.
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.FQDN), dd.name)
	if err != nil {
		return err
	}

	var names []*dbt.Entity
	if !support.AssetMonitoredWithinTTL(e.Session, e.Entity, dd.source, since) {
		names = append(names, dd.query(e, fqdn.Name, key)...)
		support.MarkAssetMonitored(e.Session, e.Entity, dd.source)
	}

	if len(names) > 0 {
		dd.process(e, names)
	}
	return nil
}

// apiKey requires a configured DNSDumpster entry in datasources.yaml -
// there is no free/unauthenticated tier for this API, so an absent key
// means the plugin has nothing to do (see check(), above).
func (dd *dnsDumpster) apiKey(e *et.Event) string {
	ds := e.Session.Config().GetDataSourceConfig(dd.name)
	if ds == nil {
		return ""
	}
	for _, cr := range ds.Creds {
		if cr != nil && cr.Apikey != "" {
			return cr.Apikey
		}
	}
	return ""
}

// dnsDumpsterHostRecord matches the shape shared by the "a", "cname",
// "ns", and "mx" arrays in the API response - each is a list of records
// with at least a "host" field.
type dnsDumpsterHostRecord struct {
	Host string `json:"host"`
}

type dnsDumpsterResponse struct {
	A        []dnsDumpsterHostRecord `json:"a"`
	CNAME    []dnsDumpsterHostRecord `json:"cname"`
	NS       []dnsDumpsterHostRecord `json:"ns"`
	MX       []dnsDumpsterHostRecord `json:"mx"`
	APIError string                  `json:"error"`
}

// maxAcceptableDNSDumpsterWait mirrors the reasoning already applied to
// CertSpotter and WHOIS: support.MidHandlerInstances (16) concurrent
// callers against this limiter's 2-second interval gives a worst-case
// normal queue of 16 * 2s = 32s - the bound needs real headroom above
// that, not a short cutoff meant for a much slower limiter.
const maxAcceptableDNSDumpsterWait = 45 * time.Second

func (dd *dnsDumpster) query(e *et.Event, name, key string) []*dbt.Entity {
	reservation := dd.rlimit.Reserve()
	if !reservation.OK() {
		return nil
	}
	delay := reservation.Delay()
	if delay > maxAcceptableDNSDumpsterWait {
		reservation.Cancel()
		dd.log.Warn("skipping DNSDumpster call, rate limit wait too long",
			"name", name, "wait", delay.String())
		return nil
	}
	select {
	case <-e.Session.Ctx().Done():
		reservation.Cancel()
		return nil
	case <-time.After(delay):
	}
	e.Session.NetSem().Acquire()

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	// NOTE: this fetches a single page. The free tier is capped at 50
	// records with no further pages available; Plus accounts can retrieve
	// up to 200 on this same request and access ?page=2+ beyond that, but
	// paging isn't implemented here since it's not usable on the tier
	// this was written against. Straightforward to add later via the
	// documented ?page= parameter if that changes.
	resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, &amasshttp.Request{
		URL:    "https://api.dnsdumpster.com/domain/" + name,
		Header: amasshttp.Header{"X-API-Key": []string{key}},
	})
	e.Session.NetSem().Release()
	if err != nil {
		return nil
	}

	if resp.StatusCode == 429 {
		dd.log.Warn("rate limited by the DNSDumpster API")
		return nil
	}
	if resp.StatusCode != 200 || resp.Body == "" {
		return nil
	}

	var d dnsDumpsterResponse
	if err := json.Unmarshal([]byte(resp.Body), &d); err != nil {
		return nil
	}
	if d.APIError != "" {
		dd.log.Warn("DNSDumpster API error: " + d.APIError)
		return nil
	}

	var hosts []string
	for _, group := range [][]dnsDumpsterHostRecord{d.A, d.CNAME, d.NS, d.MX} {
		for _, rec := range group {
			h := strings.ToLower(strings.TrimSpace(rec.Host))
			if h == "" {
				continue
			}
			if _, conf := e.Session.Scope().IsAssetInScope(&oamdns.FQDN{Name: h}, 0); conf > 0 {
				hosts = append(hosts, h)
			}
		}
	}

	return dd.store(e, hosts)
}

func (dd *dnsDumpster) store(e *et.Event, names []string) []*dbt.Entity {
	return support.StoreFQDNsWithSource(e.Session, names, dd.source, dd.name, dd.name+"-Handler")
}

func (dd *dnsDumpster) process(e *et.Event, assets []*dbt.Entity) {
	support.ProcessFQDNsWithSource(e, assets, dd.source)
}
