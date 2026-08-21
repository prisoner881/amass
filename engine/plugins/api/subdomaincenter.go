// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/url"
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

// subdomainCenter queries the free api.subdomain.center service (A.R.P.
// Syndicate). No key is required - a free query returns up to 500 results
// in random order. A key is optional and, per the vendor's docs, removes
// that 500-result cap and returns the full, sorted result set. This was
// present in Amass 4.x (api/subdomaincenter.ads) but was not carried over
// to the v5 rewrite.
//
// Response shape (confirmed against a live query, not assumed): a flat
// JSON array of subdomain strings, e.g. ["www.example.com","api.example.com"].
// No wrapping object, no per-entry metadata.
type subdomainCenter struct {
	name   string
	log    *slog.Logger
	rlimit *rate.Limiter
	source *et.Source
}

func NewSubdomainCenter() et.Plugin {
	return &subdomainCenter{
		name: "SubdomainCenter",
		// No rate limit is published by the vendor. Using the same
		// conservative 2-second cadence already applied elsewhere in this
		// codebase to other lightly-documented free sources (crt.sh,
		// HackerTarget, DNSDumpster) rather than assuming a more
		// permissive limit that isn't actually confirmed anywhere.
		rlimit: rate.NewLimiter(rate.Every(2*time.Second), 1),
		source: &et.Source{
			Name:       "SubdomainCenter",
			Confidence: 70,
		},
	}
}

func (sc *subdomainCenter) Name() string {
	return sc.name
}

func (sc *subdomainCenter) Start(r et.Registry) error {
	sc.log = r.Log().WithGroup("plugin").With("name", sc.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       sc,
		Name:         sc.name + "-Handler",
		Position:     25,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   []string{string(oam.FQDN)},
		EventType:    oam.FQDN,
		Callback:     sc.check,
	}); err != nil {
		return err
	}

	sc.log.Info("Plugin started")
	return nil
}

func (sc *subdomainCenter) Stop() {
	sc.log.Info("Plugin stopped")
}

func (sc *subdomainCenter) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	if !support.HasSLDInScope(e) {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.FQDN), sc.name)
	if err != nil {
		return err
	}

	var names []*dbt.Entity
	if !support.AssetMonitoredWithinTTL(e.Session, e.Entity, sc.source, since) {
		names = append(names, sc.query(e, fqdn.Name, sc.apiKey(e))...)
		support.MarkAssetMonitored(e.Session, e.Entity, sc.source)
	}

	if len(names) > 0 {
		sc.process(e, names)
	}
	return nil
}

// apiKey looks up an optional SubdomainCenter key from datasources.yaml.
// An empty return is expected and fully supported - the service works
// unauthenticated, just capped at 500 unsorted results per query.
func (sc *subdomainCenter) apiKey(e *et.Event) string {
	ds := e.Session.Config().GetDataSourceConfig(sc.name)
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

func (sc *subdomainCenter) query(e *et.Event, name, key string) []*dbt.Entity {
	if err := sc.rlimit.Wait(e.Session.Ctx()); err != nil {
		return nil
	}
	e.Session.NetSem().Acquire()

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	params := url.Values{}
	params.Set("domain", name)

	req := &amasshttp.Request{
		URL: "https://api.subdomain.center/?" + params.Encode(),
	}
	if key != "" {
		req.Header = amasshttp.Header{"X-API-Key": []string{key}}
	}

	resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, req)
	e.Session.NetSem().Release()
	if err != nil {
		return nil
	}
	if resp.StatusCode != 200 || resp.Body == "" {
		return nil
	}

	var results []string
	if err := json.Unmarshal([]byte(resp.Body), &results); err != nil {
		sc.log.Warn("failed to decode the JSON response")
		return nil
	}

	var names []string
	for _, s := range results {
		h := strings.ToLower(strings.TrimSpace(s))
		if h == "" {
			continue
		}
		if _, conf := e.Session.Scope().IsAssetInScope(&oamdns.FQDN{Name: h}, 0); conf > 0 {
			names = append(names, h)
		}
	}

	return sc.store(e, names)
}

func (sc *subdomainCenter) store(e *et.Event, names []string) []*dbt.Entity {
	return support.StoreFQDNsWithSource(e.Session, names, sc.source, sc.name, sc.name+"-Handler")
}

func (sc *subdomainCenter) process(e *et.Event, assets []*dbt.Entity) {
	support.ProcessFQDNsWithSource(e, assets, sc.source)
}
