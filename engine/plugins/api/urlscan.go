// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	general "github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"golang.org/x/time/rate"
)

// urlscan queries the urlscan.io Search API for previously submitted/
// observed page scans matching a domain or an ASN. This existed in
// Amass v4.x and had a partial v5 port that was deleted in commit
// ac15a444 ("no linter errors") - the deleted version mixed a
// nonexistent v4 Cache API with a nonexistent v5 DB.Create signature
// and had its own TODO admitting it was unfinished. This is a fresh
// build against the current v5 plugin interfaces, using the deleted
// version only as a spec for the endpoint, query syntax, and response
// shape - all three confirmed against a live, authenticated response
// captured for luxoft.com before this was written, not assumed.
//
// A free API key is required - urlscan.io's current docs state search
// requires an account and key, with no confirmed unauthenticated
// fallback (unlike CertSpotter). check() declines to run without one.
//
// Only the first page of results is fetched. The free tier's `total`
// field can report more matches than are actually returned, and
// `has_more` was observed false even when total exceeded the page size
// - by agreement, this is treated as "100 results is better than zero"
// rather than chased with pagination logic against an unreliable signal.
//
// Beyond FQDNs, each result's `page.ip`, `page.asn`, and `page.ptr`
// carry real information worth keeping in the graph. These are written
// as genuine dns_record / ptr_record edges (the same relation types the
// dns/reverse.go and dns/ip.go plugins use for live lookups) rather than
// a separately-named relation - by agreement, "URLScan observed this at
// scan time" is still legitimate resolution history for the asset-db to
// retain, same as any other historically-true-but-possibly-stale
// resolution. RRType and Class are honestly derivable from the IP's own
// address family; TTL has no source in URLScan's response and is set to
// 0 - confirmed by grepping the codebase that nothing anywhere reads
// RRHeader.TTL back out of a stored edge, so this is inert, not
// misleading. TLS certificate summary fields in the response
// (tlsIssuer, tlsValidDays, etc.) are NOT used - confirmed insufficient
// to build a real TLSCertificate entity, which requires a full
// *x509.Certificate from a live handshake, not four summary strings.
// ASN entities are intentionally NOT associated with their containing
// Netblock here - the existing IP-Netblock plugin already does that
// authoritatively for any new IPAddress entity that enters the graph.
//
// Discovered FQDNs (including the domain results themselves) are stored
// regardless of scope, matching the Page-Links plugin's reasoning: a
// urlscan.io result's page.domain is what a scan actually observed,
// including post-redirect destinations - closer in kind to a link found
// on a page than to a CT-log SAN entry, so an out-of-scope result is
// still a useful data point rather than noise to discard.
type urlscan struct {
	name   string
	log    *slog.Logger
	rlimit *rate.Limiter
	source *et.Source
}

func NewURLScan() et.Plugin {
	return &urlscan{
		name: "URLScan",
		// No published rate limit found; same conservative default
		// applied to other lightly-documented sources in this codebase.
		rlimit: rate.NewLimiter(rate.Every(2*time.Second), 1),
		source: &et.Source{
			Name:       "URLScan",
			Confidence: 70,
		},
	}
}

func (u *urlscan) Name() string {
	return u.name
}

func (u *urlscan) Start(r et.Registry) error {
	u.log = r.Log().WithGroup("plugin").With("name", u.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       u,
		Name:         u.name + "-FQDN-Handler",
		Position:     25,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   []string{string(oam.FQDN), string(oam.IPAddress)},
		EventType:    oam.FQDN,
		Callback:     u.checkFQDN,
	}); err != nil {
		return err
	}

	// The ASN-triggered handler (checkASN, "asn:AS<N>" queries) was
	// deliberately removed after real-world testing against
	// fortifydata.com. Querying by ASN only produces meaningful results
	// for organizations that own and announce dedicated IP space
	// themselves - for the far more common case of a target hosted on
	// shared cloud infrastructure (AWS, Azure, GCP, etc.), the ASN
	// belongs to the cloud provider, not the target, and the query
	// returns essentially every unrelated domain anyone has ever hosted
	// on that provider. In production this produced 58,000+ globally
	// unrelated FQDNs from a single run against one real domain. There
	// is no reliable way to distinguish a dedicated ASN from a shared
	// cloud-provider ASN in advance, so this handler is not re-added
	// conditionally - it is removed outright.

	u.log.Info("Plugin started")
	return nil
}

func (u *urlscan) Stop() {
	u.log.Info("Plugin stopped")
}

func (u *urlscan) apiKey(e *et.Event) string {
	ds := e.Session.Config().GetDataSourceConfig(u.name)
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

func (u *urlscan) checkFQDN(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}
	if !support.HasSLDInScope(e) {
		return nil
	}

	key := u.apiKey(e)
	if key == "" {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.FQDN), u.name)
	if err != nil {
		return err
	}

	if !support.AssetMonitoredWithinTTL(e.Session, e.Entity, u.source, since) {
		u.query(e, "domain:"+fqdn.Name, key)
		support.MarkAssetMonitored(e.Session, e.Entity, u.source)
	}
	return nil
}

// checkASN and its "asn:AS<N>" query type were removed - see the note in
// Start() for why.

type urlscanPage struct {
	Domain     string `json:"domain"`
	ApexDomain string `json:"apexDomain"`
	IP         string `json:"ip"`
	PTR        string `json:"ptr"`
}

type urlscanResult struct {
	Page urlscanPage `json:"page"`
}

type urlscanResponse struct {
	Results []urlscanResult `json:"results"`
	Total   int             `json:"total"`
	HasMore bool            `json:"has_more"`
}

// query performs a single-page search and stores everything found: the
// observed FQDNs, IPAddress entities with proper dns_record edges back
// to the FQDN that resolved to them, and PTR-derived FQDN entities with
// proper ptr_record edges back to their IPAddress - see the type-level
// comment for why each of these choices was made.
// maxAcceptableURLScanWait mirrors the reasoning already applied to
// CertSpotter and WHOIS: support.MidHandlerInstances (16) concurrent
// callers against this limiter's 2-second interval gives a worst-case
// normal queue of 16 * 2s = 32s - the bound needs real headroom above
// that, not a short cutoff meant for a much slower limiter.
const maxAcceptableURLScanWait = 45 * time.Second

func (u *urlscan) query(e *et.Event, q, key string) {
	reservation := u.rlimit.Reserve()
	if !reservation.OK() {
		return
	}
	delay := reservation.Delay()
	if delay > maxAcceptableURLScanWait {
		reservation.Cancel()
		u.log.Warn("skipping URLScan call, rate limit wait too long",
			"query", q, "wait", delay.String())
		return
	}
	select {
	case <-e.Session.Ctx().Done():
		reservation.Cancel()
		return
	case <-time.After(delay):
	}
	e.Session.NetSem().Acquire()

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	params := url.Values{}
	params.Set("q", q)

	resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, &amasshttp.Request{
		URL:    "https://urlscan.io/api/v1/search/?" + params.Encode(),
		Header: amasshttp.Header{"API-Key": []string{key}},
	})
	e.Session.NetSem().Release()
	if err != nil || resp.StatusCode != 200 || resp.Body == "" {
		return
	}

	var parsed urlscanResponse
	if err := json.Unmarshal([]byte(resp.Body), &parsed); err != nil {
		u.log.Warn("failed to decode the URLScan response")
		return
	}

	var fqdnNames []string
	seenFQDN := make(map[string]struct{})
	addFQDN := func(name string) {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			return
		}
		if _, dup := seenFQDN[name]; dup {
			return
		}
		seenFQDN[name] = struct{}{}
		fqdnNames = append(fqdnNames, name)
	}

	for _, r := range parsed.Results {
		addFQDN(r.Page.Domain)
		addFQDN(r.Page.ApexDomain)
	}

	stored := support.StoreFQDNsWithSource(e.Session, fqdnNames, u.source, u.name, u.name+"-FQDN-Handler")
	byName := make(map[string]*dbt.Entity, len(stored))
	for _, ent := range stored {
		if f, ok := ent.Asset.(*oamdns.FQDN); ok {
			byName[f.Name] = ent
		}
	}
	support.ProcessFQDNsWithSource(e, stored, u.source)

	// IP and PTR data ride along per-result, since each result's page.ip
	// is specifically the IP that page.domain resolved to - a per-name
	// linkage that a flat, deduplicated FQDN list alone can't carry.
	for _, r := range parsed.Results {
		fqdnEntity := byName[strings.ToLower(strings.TrimSpace(r.Page.Domain))]
		if fqdnEntity == nil {
			continue
		}
		ipEntity := u.storeIP(e, fqdnEntity, r.Page.IP)
		if ipEntity != nil && r.Page.PTR != "" {
			u.storePTR(e, ipEntity, r.Page.PTR)
		}
	}
}

func (u *urlscan) storeIP(e *et.Event, fqdnEntity *dbt.Entity, ipStr string) *dbt.Entity {
	if ipStr == "" {
		return nil
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(ipStr))
	if err != nil {
		return nil
	}

	ipType := "IPv4"
	rrtype := dns.TypeA
	if addr.Is6() {
		ipType = "IPv6"
		rrtype = dns.TypeAAAA
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 10*time.Second)
	defer cancel()

	ipEntity, err := e.Session.DB().CreateAsset(ctx, &oamnet.IPAddress{Address: addr, Type: ipType})
	if err != nil || ipEntity == nil {
		return nil
	}

	edge, err := e.Session.DB().CreateEdge(ctx, &dbt.Edge{
		Relation: &oamdns.BasicDNSRelation{
			Name: "dns_record",
			Header: oamdns.RRHeader{
				RRType: int(rrtype),
				Class:  int(dns.ClassINET),
				TTL:    0, // not reported by URLScan; confirmed unread anywhere downstream
			},
		},
		FromEntity: fqdnEntity,
		ToEntity:   ipEntity,
	})
	if err != nil || edge == nil {
		return nil
	}
	_, _ = e.Session.DB().CreateEntityProperty(ctx, ipEntity, &general.SourceProperty{
		Source:     u.source.Name,
		Confidence: u.source.Confidence,
	})
	_, _ = e.Session.DB().CreateEdgeProperty(ctx, edge, &general.SourceProperty{
		Source:     u.source.Name,
		Confidence: u.source.Confidence,
	})

	_ = e.Dispatcher.DispatchEvent(&et.Event{
		Name:    ipEntity.Asset.Key(),
		Entity:  ipEntity,
		Session: e.Session,
	})

	return ipEntity
}

// isValidPTRHostname rejects the two malformed value shapes actually
// observed in real production data from urlscan.io's page.ptr field: a
// bare IP address, and a raw reverse-DNS zone name (in-addr.arpa /
// ip6.arpa) - the PTR query name itself, not a resolved hostname. Both
// were found being stored directly as FQDN entities before this check
// existed.
func isValidPTRHostname(name string) bool {
	if name == "" {
		return false
	}
	if strings.HasSuffix(name, ".in-addr.arpa") || strings.HasSuffix(name, ".ip6.arpa") {
		return false
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return false
	}
	return true
}

func (u *urlscan) storePTR(e *et.Event, ipEntity *dbt.Entity, ptrName string) {
	name := strings.ToLower(strings.TrimSpace(ptrName))
	if !isValidPTRHostname(name) {
		return
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 10*time.Second)
	defer cancel()

	ptrEntity, err := e.Session.DB().CreateAsset(ctx, &oamdns.FQDN{Name: name})
	if err != nil || ptrEntity == nil {
		return
	}

	edge, err := e.Session.DB().CreateEdge(ctx, &dbt.Edge{
		Relation:   &general.SimpleRelation{Name: "ptr_record"},
		FromEntity: ipEntity,
		ToEntity:   ptrEntity,
	})
	if err != nil || edge == nil {
		return
	}
	_, _ = e.Session.DB().CreateEntityProperty(ctx, ptrEntity, &general.SourceProperty{
		Source:     u.source.Name,
		Confidence: u.source.Confidence,
	})
	_, _ = e.Session.DB().CreateEdgeProperty(ctx, edge, &general.SourceProperty{
		Source:     u.source.Name,
		Confidence: u.source.Confidence,
	})

	_ = e.Dispatcher.DispatchEvent(&et.Event{
		Name:    ptrEntity.Asset.Key(),
		Entity:  ptrEntity,
		Session: e.Session,
	})
}
