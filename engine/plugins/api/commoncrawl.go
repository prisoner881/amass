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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"golang.org/x/time/rate"
)

// commonCrawl queries the free, unauthenticated Common Crawl CDX index API
// for URLs captured under a domain, extracting hostnames from them. This
// was present in Amass 4.x (crawl/commoncrawl.ads) but was not carried
// over to the v5 rewrite.
//
// Two live queries were used to confirm this design against real data
// (not assumed) before writing it:
//   - GET https://index.commoncrawl.org/collinfo.json lists the current
//     crawl collections, newest first, each with an "id" and a "cdx-api"
//     endpoint URL.
//   - GET {cdx-api}?url=*.<domain>&output=json&fl=url returns
//     newline-delimited JSON (NOT a JSON array - one {"url": "..."}
//     object per line), where each url is a full URL with scheme, path,
//     and query string, not a bare hostname.
//
// Per v4's own approach, at most 6 of the most recent collections are
// queried per domain. Server-side "&limit=" is used to bound each
// individual collection's response size, rather than a client-side cap
// applied after the fact - RequestWebPage buffers the entire response
// body into memory before a plugin ever sees it, so a cap that only
// discards excess lines after decoding would do nothing to bound the
// actual network/memory cost of a very large response.
type commonCrawl struct {
	name   string
	log    *slog.Logger
	rlimit *rate.Limiter
	source *et.Source

	mu        sync.Mutex
	endpoints []string // cached cdx-api URLs, populated once per session
}

const (
	commonCrawlMaxCollections  = 6
	commonCrawlPerRequestLimit = 10000
)

func NewCommonCrawl() et.Plugin {
	return &commonCrawl{
		name: "CommonCrawl",
		// No published rate limit for the CDX API. Using the same
		// conservative 2-second cadence applied to other lightly
		// documented free sources elsewhere in this codebase.
		rlimit: rate.NewLimiter(rate.Every(2*time.Second), 1),
		source: &et.Source{
			Name:       "CommonCrawl",
			Confidence: 60,
		},
	}
}

func (cc *commonCrawl) Name() string {
	return cc.name
}

func (cc *commonCrawl) Start(r et.Registry) error {
	cc.log = r.Log().WithGroup("plugin").With("name", cc.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       cc,
		Name:         cc.name + "-Handler",
		Position:     25,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   []string{string(oam.FQDN)},
		EventType:    oam.FQDN,
		Callback:     cc.check,
	}); err != nil {
		return err
	}

	cc.log.Info("Plugin started")
	return nil
}

func (cc *commonCrawl) Stop() {
	cc.log.Info("Plugin stopped")
}

func (cc *commonCrawl) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	if !support.HasSLDInScope(e) {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.FQDN), cc.name)
	if err != nil {
		return err
	}

	var names []*dbt.Entity
	if !support.AssetMonitoredWithinTTL(e.Session, e.Entity, cc.source, since) {
		names = append(names, cc.query(e, fqdn.Name)...)
		support.MarkAssetMonitored(e.Session, e.Entity, cc.source)
	}

	if len(names) > 0 {
		cc.process(e, names)
	}
	return nil
}

type commonCrawlCollection struct {
	ID     string `json:"id"`
	CDXAPI string `json:"cdx-api"`
}

// endpointList lazily fetches and caches, once per session, the cdx-api
// URLs for the commonCrawlMaxCollections most recent crawl collections.
// Collections rotate roughly every two weeks, so caching for the life of
// a run (rather than per-query) avoids redundant lookups without risking
// meaningfully stale data within a single Amass execution.
func (cc *commonCrawl) endpointList(e *et.Event) []string {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	if len(cc.endpoints) > 0 {
		return cc.endpoints
	}

	if err := cc.rlimit.Wait(e.Session.Ctx()); err != nil {
		return nil
	}
	e.Session.NetSem().Acquire()

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, &amasshttp.Request{
		URL: "https://index.commoncrawl.org/collinfo.json",
	})
	e.Session.NetSem().Release()
	if err != nil || resp.StatusCode != 200 || resp.Body == "" {
		return nil
	}

	var collections []commonCrawlCollection
	if err := json.Unmarshal([]byte(resp.Body), &collections); err != nil {
		cc.log.Warn("failed to decode the collinfo.json response")
		return nil
	}

	for i, c := range collections {
		if i >= commonCrawlMaxCollections {
			break
		}
		if c.CDXAPI != "" {
			cc.endpoints = append(cc.endpoints, c.CDXAPI)
		}
	}

	return cc.endpoints
}

type commonCrawlRecord struct {
	URL string `json:"url"`
}

func (cc *commonCrawl) query(e *et.Event, name string) []*dbt.Entity {
	endpoints := cc.endpointList(e)
	if len(endpoints) == 0 {
		return nil
	}

	found := make(map[string]struct{})
	for _, endpoint := range endpoints {
		for h := range cc.queryCollection(e, endpoint, name) {
			found[h] = struct{}{}
		}
	}

	var names []string
	for h := range found {
		if _, conf := e.Session.Scope().IsAssetInScope(&oamdns.FQDN{Name: h}, 0); conf > 0 {
			names = append(names, h)
		}
	}

	return cc.store(e, names)
}

// queryCollection fetches a single collection's CDX results for the
// domain and returns the distinct, lowercased hostnames extracted from
// the captured URLs. The server-side "limit" parameter bounds the
// response size at the source.
func (cc *commonCrawl) queryCollection(e *et.Event, endpoint, name string) map[string]struct{} {
	hosts := make(map[string]struct{})

	if err := cc.rlimit.Wait(e.Session.Ctx()); err != nil {
		return hosts
	}
	e.Session.NetSem().Acquire()

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 60*time.Second)
	defer cancel()

	params := url.Values{}
	params.Set("url", "*."+name)
	params.Set("output", "json")
	params.Set("fl", "url")
	params.Set("limit", strconv.Itoa(commonCrawlPerRequestLimit))

	resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, &amasshttp.Request{
		URL: endpoint + "?" + params.Encode(),
	})
	e.Session.NetSem().Release()
	if err != nil {
		return hosts
	}
	// A 404 from the CDX API means no captures were found for this query
	// in this collection - not an error, just an empty result.
	if resp.StatusCode == 404 || resp.Body == "" {
		return hosts
	}
	if resp.StatusCode != 200 {
		cc.log.Warn("unexpected response status from a Common Crawl collection")
		return hosts
	}

	// Newline-delimited JSON: one {"url": "..."} object per line, not a
	// single JSON array. Confirmed against a live response before this
	// was written, not assumed.
	for _, line := range strings.Split(resp.Body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var rec commonCrawlRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}

		u, err := url.Parse(rec.URL)
		if err != nil {
			continue
		}
		h := strings.ToLower(strings.TrimSpace(u.Hostname()))
		if h != "" {
			hosts[h] = struct{}{}
		}
	}

	return hosts
}

func (cc *commonCrawl) store(e *et.Event, names []string) []*dbt.Entity {
	return support.StoreFQDNsWithSource(e.Session, names, cc.source, cc.name, cc.name+"-Handler")
}

func (cc *commonCrawl) process(e *et.Event, assets []*dbt.Entity) {
	support.ProcessFQDNsWithSource(e, assets, cc.source)
}
