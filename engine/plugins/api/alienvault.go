// Copyright (c) by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/url"
	"strings"
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

// AlienVault queries OTX DirectConnect passive DNS for in-scope apexes.
// Plugin name is "AlienVault" so it matches datasources.yaml.
//
//	GET https://otx.alienvault.com/api/v1/indicators/domain/{apex}/passive_dns
//	Header: X-OTX-API-KEY
//
// Hostnames from passive_dns[].hostname (and CNAME targets in .address)
// are stored only when IsAssetInScope > 0. IPs are ignored. 429/5xx
// do not mark the asset monitored so TTL can retry.
type alienVault struct {
	name   string
	log    *slog.Logger
	rlimit *rate.Limiter
	source *et.Source
}

const (
	otxPassiveDNSURL = "https://otx.alienvault.com/api/v1/indicators/domain/"
	otxHTTPTimeout   = 30 * time.Second
)

func NewAlienVault() et.Plugin {
	return &alienVault{
		name:   "AlienVault",
		rlimit: rate.NewLimiter(rate.Every(time.Second), 1),
		source: &et.Source{
			Name:       "AlienVault",
			Confidence: 70,
		},
	}
}

func (a *alienVault) Name() string { return a.name }

func (a *alienVault) Start(r et.Registry) error {
	a.log = r.Log().WithGroup("plugin").With("name", a.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       a,
		Name:         a.name + "-Handler",
		Position:     22,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   []string{string(oam.FQDN)},
		EventType:    oam.FQDN,
		Callback:     a.check,
	}); err != nil {
		return err
	}

	a.log.Info("Plugin started")
	return nil
}

func (a *alienVault) Stop() {
	a.log.Info("Plugin stopped")
}

func (a *alienVault) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}
	if !support.HasSLDInScope(e) {
		return nil
	}

	keys := a.apiKeys(e)
	if len(keys) == 0 {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.FQDN), a.name)
	if err != nil {
		return err
	}
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, a.source, since) {
		return nil
	}

	names, retry := a.query(e, fqdn.Name, keys)
	if !retry {
		support.MarkAssetMonitored(e.Session, e.Entity, a.source)
	}
	if len(names) > 0 {
		a.process(e, names)
	}
	return nil
}

func (a *alienVault) apiKeys(e *et.Event) []string {
	ds := e.Session.Config().GetDataSourceConfig(a.name)
	if ds == nil {
		return nil
	}
	var keys []string
	for _, cr := range ds.Creds {
		if cr != nil && cr.Apikey != "" {
			keys = append(keys, cr.Apikey)
		}
	}
	return keys
}

type otxPassiveDNS struct {
	PassiveDNS []otxPDNSRecord `json:"passive_dns"`
	Count      int             `json:"count"`
}

type otxPDNSRecord struct {
	Hostname   string `json:"hostname"`
	Address    string `json:"address"`
	RecordType string `json:"record_type"`
}

func (a *alienVault) query(e *et.Event, apex string, keys []string) ([]*dbt.Entity, bool) {
	var lastRetry bool
	for _, key := range keys {
		names, retry, err := a.fetch(e, apex, key)
		if retry {
			lastRetry = true
			continue
		}
		if err != nil {
			a.log.Warn("OTX query failed", "apex", apex, "error", err.Error())
			continue
		}
		a.log.Info("OTX passive_dns", "apex", apex, "rows", len(names))
		return a.store(e, names), false
	}
	return nil, lastRetry
}

func (a *alienVault) fetch(e *et.Event, apex, key string) ([]string, bool, error) {
	_ = a.rlimit.Wait(e.Session.Ctx())
	e.Session.NetSem().Acquire()

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), otxHTTPTimeout)
	defer cancel()

	u := otxPassiveDNSURL + url.PathEscape(apex) + "/passive_dns"
	resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, &amasshttp.Request{
		URL:    u,
		Header: amasshttp.Header{"X-OTX-API-KEY": []string{key}},
	})
	e.Session.NetSem().Release()
	if err != nil {
		return nil, true, err
	}
	if resp.StatusCode == 429 || resp.StatusCode >= 500 {
		return nil, true, nil
	}
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		a.log.Warn("OTX rejected API key", "status", resp.StatusCode)
		return nil, false, nil
	}
	if resp.StatusCode != 200 || resp.Body == "" {
		return nil, false, nil
	}

	var result otxPassiveDNS
	if err := json.Unmarshal([]byte(resp.Body), &result); err != nil {
		return nil, false, err
	}
	return collectOTXHostnames(e, result.PassiveDNS), false, nil
}

func collectOTXHostnames(e *et.Event, recs []otxPDNSRecord) []string {
	seen := make(map[string]struct{}, len(recs))
	var out []string
	for _, rec := range recs {
		for _, raw := range []string{rec.Hostname, rec.Address} {
			n := normalizeOTXName(raw)
			if n == "" {
				continue
			}
			if _, dup := seen[n]; dup {
				continue
			}
			seen[n] = struct{}{}
			if _, conf := e.Session.Scope().IsAssetInScope(&oamdns.FQDN{Name: n}, 0); conf > 0 {
				out = append(out, n)
			}
		}
	}
	return out
}

func normalizeOTXName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return ""
	}
	if net.ParseIP(s) != nil {
		return ""
	}
	s = amassdns.RemoveAsteriskLabel(s)
	if s == "" || strings.Contains(s, "*") || !strings.Contains(s, ".") {
		return ""
	}
	return s
}

func (a *alienVault) store(e *et.Event, names []string) []*dbt.Entity {
	return support.StoreFQDNsWithSource(e.Session, names, a.source, a.name, a.name+"-Handler")
}

func (a *alienVault) process(e *et.Event, assets []*dbt.Entity) {
	support.ProcessFQDNsWithSource(e, assets, a.source)
}