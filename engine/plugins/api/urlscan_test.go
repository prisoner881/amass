// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// As with every plugin built in this batch, this codebase has no harness
// for constructing a full et.Session in a unit test, so check()/query()
// themselves are exercised only by manual runs. This covers response
// decoding and the IP address-family classification logic, using a
// trimmed excerpt of an actual live, authenticated response captured
// for luxoft.com (both an IPv6 and an IPv4-with-PTR result, since the
// full sample was confirmed to genuinely contain both address families,
// not assumed IPv4-only).

const realURLScanResponseExcerpt = `{
  "results": [
    {"page": {"domain": "www.luxoft.com", "apexDomain": "luxoft.com", "ip": "2620:1ec:48:1::38", "ptr": ""}},
    {"page": {"domain": "www.luxoft.com", "apexDomain": "luxoft.com", "ip": "54.154.175.213", "ptr": "www.luxoft.com"}},
    {"page": {"domain": "vpn-bmw-onsite.luxoft.com", "apexDomain": "luxoft.com", "ip": "", "ptr": ""}},
    {"page": {"domain": "login.microsoftonline.com", "apexDomain": "microsoftonline.com", "ip": "20.190.151.68", "ptr": ""}}
  ],
  "total": 267,
  "has_more": false
}`

func TestURLScanResponseDecoding(t *testing.T) {
	var parsed urlscanResponse
	if err := json.Unmarshal([]byte(realURLScanResponseExcerpt), &parsed); err != nil {
		t.Fatalf("unexpected decode error: %v", err)
	}

	if parsed.Total != 267 {
		t.Errorf("expected total=267, got %d", parsed.Total)
	}
	if parsed.HasMore {
		t.Errorf("expected has_more=false, got true")
	}
	if len(parsed.Results) != 4 {
		t.Fatalf("expected 4 results, got %d", len(parsed.Results))
	}

	// Confirms the out-of-scope result (a different apex domain entirely)
	// decodes identically to an in-scope one - by design, this plugin
	// does not filter on decode; scope handling happens at storage time.
	last := parsed.Results[3].Page
	if last.Domain != "login.microsoftonline.com" || last.ApexDomain != "microsoftonline.com" {
		t.Errorf("unexpected out-of-scope result: %+v", last)
	}
}

func TestURLScanDedupAcrossResults(t *testing.T) {
	var parsed urlscanResponse
	if err := json.Unmarshal([]byte(realURLScanResponseExcerpt), &parsed); err != nil {
		t.Fatalf("unexpected decode error: %v", err)
	}

	seen := make(map[string]struct{})
	var names []string
	for _, r := range parsed.Results {
		for _, n := range []string{r.Page.Domain, r.Page.ApexDomain} {
			n = strings.ToLower(strings.TrimSpace(n))
			if n == "" {
				continue
			}
			if _, dup := seen[n]; dup {
				continue
			}
			seen[n] = struct{}{}
			names = append(names, n)
		}
	}

	// www.luxoft.com and luxoft.com each appear twice across the first
	// two results (identical page, two different IPs observed) and must
	// collapse to one entry each.
	want := map[string]bool{
		"www.luxoft.com": true, "luxoft.com": true,
		"vpn-bmw-onsite.luxoft.com": true,
		"login.microsoftonline.com": true, "microsoftonline.com": true,
	}
	if len(names) != len(want) {
		t.Fatalf("expected %d distinct names, got %d: %v", len(want), len(names), names)
	}
	for _, n := range names {
		if !want[n] {
			t.Errorf("unexpected name in dedup result: %q", n)
		}
	}
}

// classifyIP mirrors the address-family logic in storeIP() - factored
// out here so it's testable without a *dbt.Entity/*et.Event.
func classifyIP(ipStr string) (ipType string, rrtype uint16, ok bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(ipStr))
	if err != nil {
		return "", 0, false
	}
	if addr.Is6() {
		return "IPv6", dns.TypeAAAA, true
	}
	return "IPv4", dns.TypeA, true
}

func TestClassifyIPRealValues(t *testing.T) {
	cases := []struct {
		ip       string
		wantType string
		wantOK   bool
	}{
		{"2620:1ec:48:1::38", "IPv6", true}, // real value from the live sample
		{"54.154.175.213", "IPv4", true},    // real value from the live sample
		{"", "", false},                     // no IP reported for this result
		{"not-an-ip", "", false},
	}

	for _, c := range cases {
		gotType, _, gotOK := classifyIP(c.ip)
		if gotOK != c.wantOK {
			t.Errorf("classifyIP(%q) ok = %v, want %v", c.ip, gotOK, c.wantOK)
			continue
		}
		if gotOK && gotType != c.wantType {
			t.Errorf("classifyIP(%q) type = %q, want %q", c.ip, gotType, c.wantType)
		}
	}
}

func TestClassifyIPRRTypeMatchesFamily(t *testing.T) {
	_, rrtype, ok := classifyIP("2620:1ec:48:1::38")
	if !ok || rrtype != dns.TypeAAAA {
		t.Errorf("expected TypeAAAA for an IPv6 address, got %v (ok=%v)", rrtype, ok)
	}
	_, rrtype, ok = classifyIP("54.154.175.213")
	if !ok || rrtype != dns.TypeA {
		t.Errorf("expected TypeA for an IPv4 address, got %v (ok=%v)", rrtype, ok)
	}
}

// TestIsValidPTRHostname covers the two malformed shapes actually found
// in real production data - a bare IP address and a raw reverse-DNS
// zone name - alongside real, valid hostnames to confirm neither
// direction is over-corrected.
func TestIsValidPTRHostname(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"www.luxoft.com", true},                                     // real value from earlier verification
		{"ec2-54-217-223-222.eu-west-1.compute.amazonaws.com", true}, // real value from earlier verification
		{"", false},
		{"213.149.1.171", false},              // real malformed value found in production
		{"36.116.165.18.in-addr.arpa", false}, // real malformed value found in production
		{"2001:db8::1", false},                // IPv6 address, same category of error
		{"1.2.3.4.ip6.arpa", false},
	}
	for _, c := range cases {
		if got := isValidPTRHostname(c.name); got != c.want {
			t.Errorf("isValidPTRHostname(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}
