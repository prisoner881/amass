// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package whois

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	whoisparser "github.com/likexian/whois-parser"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
)

// rdap.go adds RDAP as the primary domain-registration data source, with
// the existing WHOIS protocol lookup (fqdn_lookup.go) kept as a fallback
// for TLDs RDAP doesn't cover. RDAP and WHOIS both query the domain
// registry's own infrastructure, not the target's - the same category
// as every other OSINT source in this codebase (CertSpotter, URLScan,
// etc.), correctly outside the active-proxy-egress path.
//
// RDAP is plain HTTPS with structured JSON, unlike WHOIS's free-text
// format that varies by registry - but coverage isn't universal. IANA's
// bootstrap registry (https://data.iana.org/rdap/dns.json) lists which
// registries have RDAP; confirmed directly against the live file that
// .edu is not among them (Educause runs .edu independently of ICANN's
// RDAP mandate). For any TLD not in this list, or if the RDAP query
// itself fails, the caller falls back to the existing WHOIS path.
//
// The bootstrap file is fetched once per engine process (sync.Once),
// not per session - it's a static, non-target-specific public resource,
// the same reasoning CommonCrawl already applies to its own one-time
// collection-list fetch.

var (
	bootstrapOnce sync.Once
	bootstrapMap  map[string][]string // lowercase TLD -> candidate RDAP base URLs
	bootstrapErr  error
)

// rdapBootstrapFile mirrors the real shape of data.iana.org/rdap/dns.json:
// "services": [ [ [tld, tld, ...], [url, url, ...] ], ... ]
type rdapBootstrapFile struct {
	Services [][2][]string `json:"services"`
}

func loadRDAPBootstrap() (map[string][]string, error) {
	bootstrapOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		resp, err := amasshttp.RequestWebPage(ctx, amasshttp.DefaultClient, &amasshttp.Request{
			URL: "https://data.iana.org/rdap/dns.json",
		})
		if err != nil || resp == nil || resp.Body == "" {
			bootstrapErr = fmt.Errorf("failed to fetch the IANA RDAP bootstrap file: %v", err)
			return
		}

		var file rdapBootstrapFile
		if err := json.Unmarshal([]byte(resp.Body), &file); err != nil {
			bootstrapErr = fmt.Errorf("failed to parse the IANA RDAP bootstrap file: %w", err)
			return
		}

		m := make(map[string][]string)
		for _, entry := range file.Services {
			tlds, urls := entry[0], entry[1]
			for _, tld := range tlds {
				m[strings.ToLower(tld)] = urls
			}
		}
		bootstrapMap = m
	})
	return bootstrapMap, bootstrapErr
}

// rdapBaseURL returns the first candidate RDAP base URL for the domain's
// root-zone TLD, or ("", false) if RDAP isn't available for it. This
// uses the literal last DNS label (e.g. "uk" for "example.co.uk"), not
// a public-suffix-derived one - RDAP bootstrapping is about which
// registry operates a root-zone TLD, a different question from where a
// public suffix boundary falls.
func rdapBaseURL(domain string) (string, bool) {
	m, err := loadRDAPBootstrap()
	if err != nil || m == nil {
		return "", false
	}
	idx := strings.LastIndex(domain, ".")
	if idx == -1 {
		return "", false
	}
	tld := strings.ToLower(domain[idx+1:])
	urls, ok := m[tld]
	if !ok || len(urls) == 0 {
		return "", false
	}
	return urls[0], true
}

type rdapNameserver struct {
	LDHName string `json:"ldhName"`
}

type rdapEvent struct {
	EventAction string `json:"eventAction"`
	EventDate   string `json:"eventDate"`
}

type rdapEntity struct {
	Roles      []string        `json:"roles"`
	VcardArray json.RawMessage `json:"vcardArray"`
}

type rdapDomainResponse struct {
	LDHName     string           `json:"ldhName"`
	Status      []string         `json:"status"`
	Nameservers []rdapNameserver `json:"nameservers"`
	Events      []rdapEvent      `json:"events"`
	Entities    []rdapEntity     `json:"entities"`
}

// queryRDAP performs a single RDAP domain lookup and converts the result
// into the same *whoisparser.WhoisInfo shape the WHOIS path produces, so
// downstream consumers (store(), and domain_record.go's contact
// extraction) work unchanged regardless of which source answered.
//
// Rate limiting mirrors the same bounded Reserve()+Delay() pattern
// already applied to CertSpotter and the WHOIS fallback in this same
// package - a plain limiter.Wait(ctx) would hold a pipeline execution
// slot for however long the wait takes, the exact bug fixed earlier
// today. RDAP additionally honors HTTP 429 + Retry-After (RFC 7480
// §5.5), the protocol's own documented backoff signal - this takes
// precedence over the static limiter the same way CertSpotter's
// server-directed backoff does.
//
// The bound needs the same real headroom as the WHOIS fix, not a short
// cutoff: support.MidHandlerInstances (16) concurrent callers against
// this limiter's 2-second interval gives a worst-case *normal* queue of
// 16 * 2s = 32s.
const maxAcceptableRDAPWait = 45 * time.Second

func (w *whois) queryRDAP(e *et.Event, domain string) (*whoisparser.WhoisInfo, string, error) {
	if !w.readyToCallRDAP() {
		return nil, "", errors.New("RDAP: waiting out a server-directed backoff")
	}

	base, ok := rdapBaseURL(domain)
	if !ok {
		return nil, "", errors.New("RDAP: no bootstrap entry for this TLD")
	}
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}

	reservation := w.rdapLimiter.Reserve()
	if !reservation.OK() {
		return nil, "", errors.New("RDAP: rate limiter cannot grant a reservation")
	}
	delay := reservation.Delay()
	if delay > maxAcceptableRDAPWait {
		reservation.Cancel()
		w.log.Warn("skipping RDAP call, rate limit wait too long",
			"domain", domain, "wait", delay.String())
		return nil, "", errors.New("RDAP: rate limit wait exceeded acceptable bound")
	}
	select {
	case <-e.Session.Ctx().Done():
		reservation.Cancel()
		return nil, "", e.Session.Ctx().Err()
	case <-time.After(delay):
	}

	// Session-scoped client and the shared network semaphore, the same
	// pattern every other live network call in this codebase uses
	// (e.g. CertSpotter's own page() call) - not a bare package-level
	// client. RDAP still doesn't touch the target's own infrastructure
	// (a registry server, not the target), so this stays outside the
	// active-proxy-egress path, same as every other OSINT source.
	e.Session.NetSem().Acquire()
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()
	resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, &amasshttp.Request{
		URL: base + "domain/" + domain,
	})
	e.Session.NetSem().Release()
	if err != nil || resp == nil {
		return nil, "", fmt.Errorf("RDAP: request failed: %v", err)
	}
	if resp.StatusCode == 429 {
		w.setRDAPRetryNotBefore(parseRDAPRetryAfter(resp.Header))
		return nil, "", errors.New("RDAP: server responded 429, backing off")
	}
	if resp.StatusCode != 200 {
		return nil, "", fmt.Errorf("RDAP: server returned status %d", resp.StatusCode)
	}
	if resp.Body == "" {
		return nil, "", errors.New("RDAP: empty response body")
	}

	var parsed rdapDomainResponse
	if err := json.Unmarshal([]byte(resp.Body), &parsed); err != nil {
		return nil, "", fmt.Errorf("RDAP: failed to decode response: %w", err)
	}

	return rdapToWhoisInfo(&parsed, domain), resp.Body, nil
}

func (w *whois) readyToCallRDAP() bool {
	w.rdapMu.Lock()
	defer w.rdapMu.Unlock()
	return time.Now().After(w.rdapRetryNotBefore)
}

func (w *whois) setRDAPRetryNotBefore(seconds int) {
	if seconds <= 0 {
		return
	}
	w.rdapMu.Lock()
	defer w.rdapMu.Unlock()
	t := time.Now().Add(time.Duration(seconds) * time.Second)
	if t.After(w.rdapRetryNotBefore) {
		w.rdapRetryNotBefore = t
	}
}

func parseRDAPRetryAfter(h amasshttp.Header) int {
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

func rdapToWhoisInfo(resp *rdapDomainResponse, domain string) *whoisparser.WhoisInfo {
	name := strings.ToLower(resp.LDHName)
	if name == "" {
		name = strings.ToLower(domain)
	}

	dom := &whoisparser.Domain{
		Domain: name,
		Status: resp.Status,
	}
	for _, ns := range resp.Nameservers {
		if ns.LDHName != "" {
			dom.NameServers = append(dom.NameServers, strings.ToLower(ns.LDHName))
		}
	}
	for _, ev := range resp.Events {
		switch strings.ToLower(ev.EventAction) {
		case "registration":
			dom.CreatedDate = ev.EventDate
		case "expiration":
			dom.ExpirationDate = ev.EventDate
		case "last changed":
			dom.UpdatedDate = ev.EventDate
		}
	}

	info := &whoisparser.WhoisInfo{Domain: dom}

	for _, ent := range resp.Entities {
		contact := &whoisparser.Contact{
			Name:         extractVCardField(ent.VcardArray, "fn"),
			Organization: extractVCardField(ent.VcardArray, "org"),
			Email:        extractVCardField(ent.VcardArray, "email"),
		}
		if contact.Name == "" && contact.Organization == "" && contact.Email == "" {
			// Nothing usable extracted - common for registrant/admin/tech
			// roles on modern records, redacted for privacy under most
			// current registry policies. Not an RDAP-specific gap; the
			// same redaction affects the WHOIS fallback path equally.
			continue
		}
		for _, role := range ent.Roles {
			switch strings.ToLower(role) {
			case "registrar":
				info.Registrar = contact
			case "registrant":
				info.Registrant = contact
			case "administrative":
				info.Administrative = contact
			case "technical":
				info.Technical = contact
			case "billing":
				info.Billing = contact
			}
		}
	}

	return info
}

// extractVCardField pulls a single simple text field (e.g. "fn", "org",
// "email") out of an RDAP entity's jCard vcardArray. jCard's shape is
// ["vcard", [ [propName, {params}, valueType, value], ... ]] - this
// only handles the simple-string-value case, which covers name,
// organization, and email; structured fields like "adr" (address,
// itself an array of components) are intentionally not handled here.
func extractVCardField(vcardArray json.RawMessage, field string) string {
	if len(vcardArray) == 0 {
		return ""
	}

	var outer []json.RawMessage
	if err := json.Unmarshal(vcardArray, &outer); err != nil || len(outer) < 2 {
		return ""
	}

	var props [][]json.RawMessage
	if err := json.Unmarshal(outer[1], &props); err != nil {
		return ""
	}

	for _, p := range props {
		if len(p) < 4 {
			continue
		}
		var propName string
		if err := json.Unmarshal(p[0], &propName); err != nil || !strings.EqualFold(propName, field) {
			continue
		}
		var val string
		if err := json.Unmarshal(p[3], &val); err == nil && val != "" {
			return val
		}
	}
	return ""
}
