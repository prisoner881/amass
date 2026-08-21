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
	amassdns "github.com/owasp-amass/amass/v5/internal/net/dns"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"golang.org/x/time/rate"
)

// certSpotter queries SSLMate's CT Search API (api.certspotter.com) for
// certificate issuances covering a domain and its subdomains. Unauthenticated
// calls are supported but subject to a materially stricter free-tier quota
// than authenticated ones; see unauthLimiter/authLimiter below.
type certSpotter struct {
	name   string
	log    *slog.Logger
	source *et.Source

	// Two independent limiters because the unauthenticated and
	// authenticated free-tier quotas are not remotely the same shape.
	// unauthLimiter assumes a conservative daily ceiling (verify the
	// current SSLMate figure before deploying; the value below is a
	// placeholder floor, not a number to trust blindly).
	unauthLimiter *rate.Limiter
	authLimiter   *rate.Limiter

	// retryNotBefore honors the API's Retry-After header, which is
	// documented as the authoritative backoff signal for this endpoint.
	// It takes precedence over the static limiters above whenever set.
	mu             sync.Mutex
	retryNotBefore time.Time
}

func NewCertSpotter() et.Plugin {
	return &certSpotter{
		name: "CertSpotter",
		// Placeholder floor: ~10 subdomain-inclusive queries/day, spread
		// evenly. CONFIRM against SSLMate's current published (or observed)
		// free-tier limit before relying on this in production - the
		// figure used here comes from a third-party integration doc, not
		// SSLMate's own current docs, which do not publish an exact number.
		unauthLimiter: rate.NewLimiter(rate.Every(24*time.Hour/10), 1),
		// Authenticated free-tier keys are reported to have a materially
		// higher quota. Starting at the same cadence crt.sh uses is a
		// conservative default; tune upward once real usage confirms headroom.
		authLimiter: rate.NewLimiter(rate.Every(2*time.Second), 1),
		source: &et.Source{
			Name:       "CertSpotter",
			Confidence: 100,
		},
	}
}

func (cs *certSpotter) Name() string {
	return cs.name
}

func (cs *certSpotter) Start(r et.Registry) error {
	cs.log = r.Log().WithGroup("plugin").With("name", cs.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       cs,
		Name:         cs.name + "-Handler",
		Position:     22,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   []string{string(oam.FQDN)},
		EventType:    oam.FQDN,
		Callback:     cs.check,
	}); err != nil {
		return err
	}

	cs.log.Info("Plugin started")
	return nil
}

func (cs *certSpotter) Stop() {
	cs.log.Info("Plugin stopped")
}

func (cs *certSpotter) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	if !support.HasSLDInScope(e) {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.FQDN), cs.name)
	if err != nil {
		return err
	}

	var names []*dbt.Entity
	if !support.AssetMonitoredWithinTTL(e.Session, e.Entity, cs.source, since) {
		names = append(names, cs.query(e, fqdn.Name, cs.apiKey(e))...)
		support.MarkAssetMonitored(e.Session, e.Entity, cs.source)
	}

	if len(names) > 0 {
		cs.process(e, names)
	}
	return nil
}

// apiKey looks up an optional CertSpotter key from datasources.yaml. An
// empty return is expected and fully supported - CertSpotter allows
// unauthenticated queries, just at a much lower rate.
func (cs *certSpotter) apiKey(e *et.Event) string {
	ds := e.Session.Config().GetDataSourceConfig(cs.name)
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

func (cs *certSpotter) query(e *et.Event, name, key string) []*dbt.Entity {
	var names []string

	after := ""
	for {
		issuances, retryAfter, err := cs.page(e, name, key, after)
		if err != nil {
			break
		}
		if len(issuances) == 0 {
			// Empty page: nothing further to fetch right now. Respect
			// whatever backoff the server told us for the *next* call,
			// but don't treat this as an error for the current one.
			if retryAfter > 0 {
				cs.setRetryNotBefore(retryAfter)
			}
			break
		}

		last := ""
		for _, iss := range issuances {
			for _, n := range iss.DNSNames {
				nstr := strings.ToLower(strings.TrimSpace(amassdns.RemoveAsteriskLabel(n)))
				if _, conf := e.Session.Scope().IsAssetInScope(&oamdns.FQDN{Name: nstr}, 0); conf > 0 {
					names = append(names, nstr)
				}
			}
			last = iss.ID
		}
		if last == "" {
			break
		}
		after = last
	}

	return cs.store(e, names)
}

type certSpotterIssuance struct {
	ID       string   `json:"id"`
	DNSNames []string `json:"dns_names"`
}

// page performs a single page of the CT Search API "List Issuances for a
// Domain" call and returns the decoded issuances plus any Retry-After value
// (seconds) the server attached to the response.
func (cs *certSpotter) page(e *et.Event, name, key, after string) ([]certSpotterIssuance, int, error) {
	if !cs.readyToCall() {
		return nil, 0, errors.New("CertSpotter: waiting out a server-directed backoff")
	}

	limiter := cs.unauthLimiter
	if key != "" {
		limiter = cs.authLimiter
	}
	_ = limiter.Wait(e.Session.Ctx())

	params := url.Values{}
	params.Set("domain", name)
	params.Set("include_subdomains", "true")
	params.Set("match_wildcards", "true")
	params.Set("expand", "dns_names")
	if after != "" {
		params.Set("after", after)
	}

	req := &amasshttp.Request{
		URL: "https://api.certspotter.com/v1/issuances?" + params.Encode(),
	}
	if key != "" {
		req.Header = amasshttp.Header{"Authorization": []string{"Bearer " + key}}
	}

	e.Session.NetSem().Acquire()
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()
	resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, req)
	e.Session.NetSem().Release()
	if err != nil {
		return nil, 0, err
	}

	retryAfter := parseRetryAfter(resp.Header)
	if resp.StatusCode == 429 || resp.StatusCode == 403 {
		cs.setRetryNotBefore(retryAfter)
		return nil, retryAfter, errors.New("CertSpotter: rate limited")
	}
	if resp.StatusCode != 200 || resp.Body == "" {
		return nil, retryAfter, errors.New("CertSpotter: unexpected response")
	}

	var issuances []certSpotterIssuance
	if err := json.Unmarshal([]byte(resp.Body), &issuances); err != nil {
		return nil, retryAfter, err
	}

	return issuances, retryAfter, nil
}

func parseRetryAfter(h amasshttp.Header) int {
	if h == nil {
		return 0
	}
	vals, ok := h["Retry-After"]
	if !ok || len(vals) == 0 {
		return 0
	}
	secs, err := strconv.Atoi(strings.TrimSpace(vals[0]))
	if err != nil || secs < 0 {
		return 0
	}
	return secs
}

func (cs *certSpotter) readyToCall() bool {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return time.Now().After(cs.retryNotBefore)
}

func (cs *certSpotter) setRetryNotBefore(seconds int) {
	if seconds <= 0 {
		return
	}
	cs.mu.Lock()
	defer cs.mu.Unlock()
	t := time.Now().Add(time.Duration(seconds) * time.Second)
	if t.After(cs.retryNotBefore) {
		cs.retryNotBefore = t
	}
}

func (cs *certSpotter) store(e *et.Event, names []string) []*dbt.Entity {
	return support.StoreFQDNsWithSource(e.Session, names, cs.source, cs.name, cs.name+"-Handler")
}

func (cs *certSpotter) process(e *et.Event, assets []*dbt.Entity) {
	support.ProcessFQDNsWithSource(e, assets, cs.source)
}
