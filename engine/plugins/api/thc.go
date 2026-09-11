// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amassnet "github.com/owasp-amass/amass/v5/internal/net"
	amassdns "github.com/owasp-amass/amass/v5/internal/net/dns"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"golang.org/x/time/rate"
)

// ipTHC queries ip.thc.org (The Hacker's Choice) — a free, unauthenticated
// index of ~6B passive DNS names. Three lookups, all CSV (50k cap/request):
//
//   - FQDN / HasSLDInScope: subdomains of the apex, plus reverse CNAMEs
//     (names that point at the apex).
//   - IPAddress: reverse DNS for the covering IPv4 /24, but only when that
//     address sits in a netblock attributed to a seed (NetblockOwnedBySeed).
//     Unattributed cloud/CDN space is never queried. IPv6 is skipped (the
//     API's CIDR vocabulary is v4 /8 /16 /24).
//
// JSON is capped at 200 rows; CSV is what we use. Rate limit is 0.5 req/s
// after a 250-token burst; CSV costs 3 tokens. We pace at 2s/request and
// back off on HTTP 429 without marking the asset monitored, so TTL can retry.
//
// Names are stored only when IsAssetInScope > 0, same as HackerTarget.
// Out-of-scope reverse-CNAME hits are counted in the log and dropped so
// this plugin does not become a horizontal expander.
type ipTHC struct {
	name     string
	log      *slog.Logger
	rlimit   *rate.Limiter
	source   *et.Source
	rdnsDone sync.Map // "a.b.c.0/24" -> struct{}  (process-lifetime /24 dedup)
}

const (
	thcCSVLimit                  = 50000
	thcSubdomainsURL             = "https://ip.thc.org/api/v1/subdomains/download"
	thcCnamesURL                 = "https://ip.thc.org/api/v1/cnames/download"
	thcRDNSURL                   = "https://ip.thc.org/api/v1/download"
	maxAcceptableTHCWait         = 45 * time.Second
	thcHTTPTimeout               = 90 * time.Second
	thcOwnedLookupTimeout        = 10 * time.Second
)

func NewIPTHC() et.Plugin {
	return &ipTHC{
		name:   "IP-THC",
		rlimit: rate.NewLimiter(rate.Every(2*time.Second), 1),
		source: &et.Source{
			Name:       "IP-THC",
			Confidence: 70,
		},
	}
}

func (t *ipTHC) Name() string { return t.name }

func (t *ipTHC) Start(r et.Registry) error {
	t.log = r.Log().WithGroup("plugin").With("name", t.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       t,
		Name:         t.name + "-FQDN-Handler",
		Position:     25,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   []string{string(oam.FQDN)},
		EventType:    oam.FQDN,
		Callback:     t.checkFQDN,
	}); err != nil {
		return err
	}

	// After IP-Netblock (position 4) so a contains edge may already exist.
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       t,
		Name:         t.name + "-IP-Handler",
		Position:     22,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   []string{string(oam.FQDN)},
		EventType:    oam.IPAddress,
		Callback:     t.checkIP,
	}); err != nil {
		return err
	}

	t.log.Info("Plugin started")
	return nil
}

func (t *ipTHC) Stop() {
	t.log.Info("Plugin stopped")
}

func (t *ipTHC) checkFQDN(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}
	if !support.HasSLDInScope(e) {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.FQDN), t.name)
	if err != nil {
		return err
	}
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, t.source, since) {
		return nil
	}

	names, retry := t.queryFQDN(e, fqdn.Name)
	if !retry {
		support.MarkAssetMonitored(e.Session, e.Entity, t.source)
	}
	if len(names) > 0 {
		t.process(e, names)
	}
	return nil
}

func (t *ipTHC) queryFQDN(e *et.Event, apex string) ([]*dbt.Entity, bool) {
	subq := thcSubdomainsURL + "?" + url.Values{
		"domain": {apex},
		"limit":  {fmt.Sprintf("%d", thcCSVLimit)},
	}.Encode()
	cnq := thcCnamesURL + "?" + url.Values{
		"target_domain": {apex},
		"limit":         {fmt.Sprintf("%d", thcCSVLimit)},
	}.Encode()

	subs, subRetry := t.fetchCSV(e, subq, "subdomains", apex)
	cnames, cnRetry := t.fetchCSV(e, cnq, "cnames", apex)

	seen := make(map[string]struct{}, len(subs)+len(cnames))
	var inScope []string
	var dropped int
	for _, n := range append(subs, cnames...) {
		n = normalizeTHCName(n)
		if n == "" {
			continue
		}
		if _, dup := seen[n]; dup {
			continue
		}
		seen[n] = struct{}{}
		if _, conf := e.Session.Scope().IsAssetInScope(&oamdns.FQDN{Name: n}, 0); conf > 0 {
			inScope = append(inScope, n)
		} else {
			dropped++
		}
	}
	if dropped > 0 {
		t.log.Info("dropped out-of-scope names",
			"apex", apex, "kept", len(inScope), "dropped", dropped)
	}
	return t.store(e, inScope), subRetry || cnRetry
}

func (t *ipTHC) checkIP(e *et.Event) error {
	ip, ok := e.Entity.Asset.(*oamnet.IPAddress)
	if !ok {
		return errors.New("failed to extract the IPAddress asset")
	}
	addrstr := ip.Address.String()
	if reserved, _ := amassnet.IsReservedAddress(addrstr); reserved {
		return nil
	}

	addr, err := netip.ParseAddr(addrstr)
	if err != nil {
		return nil
	}
	if !addr.Is4() {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.IPAddress), string(oam.FQDN), t.name)
	if err != nil {
		return err
	}
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, t.source, since) {
		return nil
	}

	if !t.ipOnOwnedBlock(e) {
		// Fail closed: do not mark. A later event after RDAP/owned-fill
		// may attach a contains edge this check needs.
		return nil
	}

	cidr, ok := v4slash24(addr)
	if !ok {
		return nil
	}
	if _, loaded := t.rdnsDone.LoadOrStore(cidr, struct{}{}); loaded {
		support.MarkAssetMonitored(e.Session, e.Entity, t.source)
		return nil
	}

	q := thcRDNSURL + "?" + url.Values{
		"ip_address": {cidr},
		"limit":      {fmt.Sprintf("%d", thcCSVLimit)},
	}.Encode()
	raw, retry := t.fetchCSV(e, q, "rdns", cidr)
	if !retry {
		support.MarkAssetMonitored(e.Session, e.Entity, t.source)
	} else {
		t.rdnsDone.Delete(cidr)
	}

	seen := make(map[string]struct{}, len(raw))
	var inScope []string
	for _, n := range raw {
		n = normalizeTHCName(n)
		if n == "" {
			continue
		}
		if _, dup := seen[n]; dup {
			continue
		}
		seen[n] = struct{}{}
		if _, conf := e.Session.Scope().IsAssetInScope(&oamdns.FQDN{Name: n}, 0); conf > 0 {
			inScope = append(inScope, n)
		}
	}
	t.log.Info("owned-block rDNS",
		"cidr", cidr, "returned", len(raw), "in_scope", len(inScope))
	if len(inScope) > 0 {
		t.process(e, t.store(e, inScope))
	}
	return nil
}

func (t *ipTHC) ipOnOwnedBlock(e *et.Event) bool {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), thcOwnedLookupTimeout)
	defer cancel()

	edges, err := e.Session.DB().IncomingEdges(ctx, e.Entity, time.Time{}, "contains")
	if err != nil {
		return false
	}
	for _, edge := range edges {
		if edge.FromEntity == nil {
			continue
		}
		ent, err := e.Session.DB().FindEntityById(ctx, edge.FromEntity.ID)
		if err != nil || ent == nil {
			continue
		}
		if _, ok := ent.Asset.(*oamnet.Netblock); !ok {
			continue
		}
		if yes, _ := support.NetblockOwnedBySeed(ctx, e.Session, ent); yes {
			return true
		}
	}
	return false
}

func v4slash24(addr netip.Addr) (string, bool) {
	if !addr.Is4() {
		return "", false
	}
	p, err := addr.Prefix(24)
	if err != nil {
		return "", false
	}
	return p.Masked().String(), true
}

func (t *ipTHC) fetchCSV(e *et.Event, rawURL, kind, key string) ([]string, bool) {
	reservation := t.rlimit.Reserve()
	if !reservation.OK() {
		return nil, true
	}
	delay := reservation.Delay()
	if delay > maxAcceptableTHCWait {
		reservation.Cancel()
		t.log.Warn("skipping IP-THC call, rate limit wait too long",
			"kind", kind, "key", key, "wait", delay.String())
		return nil, true
	}
	select {
	case <-e.Session.Ctx().Done():
		reservation.Cancel()
		return nil, true
	case <-time.After(delay):
	}

	e.Session.NetSem().Acquire()
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), thcHTTPTimeout)
	defer cancel()

	resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, &amasshttp.Request{
		URL: rawURL,
		Header: amasshttp.Header{
			"Accept": []string{"text/csv, text/plain;q=0.9, */*;q=0.1"},
		},
	})
	e.Session.NetSem().Release()
	if err != nil {
		t.log.Warn("IP-THC request failed", "kind", kind, "key", key, "error", err.Error())
		return nil, true
	}
	if resp == nil {
		return nil, true
	}
	if resp.StatusCode == 429 {
		t.log.Warn("IP-THC rate limited", "kind", kind, "key", key)
		return nil, true
	}
	if resp.StatusCode != 200 || resp.Body == "" {
		t.log.Warn("IP-THC unexpected status",
			"kind", kind, "key", key, "status", resp.StatusCode)
		return nil, resp.StatusCode >= 500
	}

	names := parseTHCDomainCSV(resp.Body)
	if len(names) >= thcCSVLimit {
		t.log.Warn("IP-THC CSV truncated at 50k", "kind", kind, "key", key)
	}
	t.log.Info("IP-THC CSV", "kind", kind, "key", key, "rows", len(names))
	return names, false
}

func (t *ipTHC) store(e *et.Event, names []string) []*dbt.Entity {
	return support.StoreFQDNsWithSource(e.Session, names, t.source, t.name, t.name+"-Handler")
}

func (t *ipTHC) process(e *et.Event, assets []*dbt.Entity) {
	support.ProcessFQDNsWithSource(e, assets, t.source)
}

// parseTHCDomainCSV pulls hostname fields out of a THC CSV body. The
// documented schemas use a "domain" column; we also accept subdomain /
// hostname / name, and fall back to column 0 when the first row already
// looks like a hostname (headerless dump).
func parseTHCDomainCSV(body string) []string {
	r := csv.NewReader(strings.NewReader(body))
	r.ReuseRecord = false
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	records, err := r.ReadAll()
	if err != nil || len(records) == 0 {
		return nil
	}

	col, headered := thcDomainColumn(records[0])
	start := 0
	if headered {
		start = 1
	}

	out := make([]string, 0, len(records)-start)
	seen := make(map[string]struct{}, len(records))
	for _, rec := range records[start:] {
		if col >= len(rec) {
			continue
		}
		n := normalizeTHCName(rec[col])
		if n == "" || !strings.Contains(n, ".") {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	return out
}

func thcDomainColumn(header []string) (int, bool) {
	for i, h := range header {
		switch strings.ToLower(strings.TrimSpace(h)) {
		case "domain", "subdomain", "hostname", "name", "host":
			return i, true
		}
	}
	if len(header) > 0 && strings.Contains(header[0], ".") {
		return 0, false
	}
	return 0, true
}

// normalizeTHCName matches CertSpotter/crt.sh: strip wildcard labels
// (*.apps.example.com → apps.example.com) so we never persist a literal '*'.
func normalizeTHCName(n string) string {
	n = strings.ToLower(strings.TrimSpace(n))
	n = strings.TrimSuffix(n, ".")
	n = strings.ToLower(strings.TrimSpace(amassdns.RemoveAsteriskLabel(n)))
	return n
}
