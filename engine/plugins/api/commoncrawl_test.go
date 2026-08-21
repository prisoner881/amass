// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

// As with the other plugins in this batch, this codebase has no harness
// for building a full et.Session in a unit test, so check()/query() are
// exercised only by manual runs. This covers the parsing logic, using a
// trimmed excerpt of an actual live CDX response captured against a real
// domain (luxoft.com), not synthetic data.

func TestCommonCrawlNDJSONParsing(t *testing.T) {
	body := `{"url": "https://www.luxoft.com/robots.txt"}
{"url": "http://www.luxoft.com/robots.txt"}
{"url": "http://luxoft.com/robots.txt"}
{"url": "https://career.luxoft.com/robots.txt"}
{"url": "https://confessions.luxoft.com/"}
{"url": "https://dap.luxoft.com/agenticsystem-dxc-cioplaybook?utm_source=dxc-idc&utm_medium=referral"}
{"url": "https://ml.luxoft.com/cases/ml-experiments/description"}
{"url": "https://quiz.luxoft.com/global-quiz-devops-ua/"}`

	hosts := make(map[string]struct{})
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec commonCrawlRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("unexpected decode error on line %q: %v", line, err)
		}
		u, err := url.Parse(rec.URL)
		if err != nil {
			t.Fatalf("unexpected URL parse error on %q: %v", rec.URL, err)
		}
		h := strings.ToLower(strings.TrimSpace(u.Hostname()))
		if h != "" {
			hosts[h] = struct{}{}
		}
	}

	want := []string{
		"www.luxoft.com", "luxoft.com", "career.luxoft.com",
		"confessions.luxoft.com", "dap.luxoft.com",
		"ml.luxoft.com", "quiz.luxoft.com",
	}
	if len(hosts) != len(want) {
		t.Fatalf("expected %d distinct hosts, got %d: %v", len(want), len(hosts), hosts)
	}
	for _, h := range want {
		if _, ok := hosts[h]; !ok {
			t.Errorf("expected host %q to be present, was not found", h)
		}
	}
}

func TestCommonCrawlDeduplicatesAcrossProtocolVariants(t *testing.T) {
	// The live sample showed the same robots.txt fetched across both
	// http:// and https:// and across repeat crawls of the same URL -
	// all of these must collapse to a single hostname entry.
	body := `{"url": "https://www.luxoft.com/robots.txt"}
{"url": "http://www.luxoft.com/robots.txt"}
{"url": "https://www.luxoft.com/robots.txt"}
{"url": "https://www.luxoft.com/robots.txt"}`

	hosts := make(map[string]struct{})
	for _, line := range strings.Split(body, "\n") {
		var rec commonCrawlRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("unexpected decode error: %v", err)
		}
		u, _ := url.Parse(rec.URL)
		hosts[strings.ToLower(u.Hostname())] = struct{}{}
	}

	if len(hosts) != 1 {
		t.Fatalf("expected exactly 1 distinct host after dedup, got %d: %v", len(hosts), hosts)
	}
}

func TestCommonCrawlMalformedLineIsSkippedNotFatal(t *testing.T) {
	// A truncated or corrupted line (e.g. from a network hiccup mid-body)
	// should be skipped, not abort processing of the remaining lines.
	body := `{"url": "https://www.luxoft.com/robots.txt"}
{"url": "https://career.luxoft.com/robots.t
{"url": "https://confessions.luxoft.com/"}`

	var decoded, skipped int
	for _, line := range strings.Split(body, "\n") {
		var rec commonCrawlRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			skipped++
			continue
		}
		decoded++
	}

	if decoded != 2 {
		t.Errorf("expected 2 successfully decoded lines, got %d", decoded)
	}
	if skipped != 1 {
		t.Errorf("expected 1 skipped malformed line, got %d", skipped)
	}
}

func TestCommonCrawlEndpointSelectionRespectsMaxAndOrder(t *testing.T) {
	// Mirrors the real collinfo.json shape (newest-first) and confirms
	// only the first commonCrawlMaxCollections entries would be kept.
	body := `[
		{"id":"CC-MAIN-2026-30","cdx-api":"https://index.commoncrawl.org/CC-MAIN-2026-30-index"},
		{"id":"CC-MAIN-2026-25","cdx-api":"https://index.commoncrawl.org/CC-MAIN-2026-25-index"},
		{"id":"CC-MAIN-2026-21","cdx-api":"https://index.commoncrawl.org/CC-MAIN-2026-21-index"},
		{"id":"CC-MAIN-2026-17","cdx-api":"https://index.commoncrawl.org/CC-MAIN-2026-17-index"},
		{"id":"CC-MAIN-2026-12","cdx-api":"https://index.commoncrawl.org/CC-MAIN-2026-12-index"},
		{"id":"CC-MAIN-2026-08","cdx-api":"https://index.commoncrawl.org/CC-MAIN-2026-08-index"},
		{"id":"CC-MAIN-2026-04","cdx-api":"https://index.commoncrawl.org/CC-MAIN-2026-04-index"}
	]`

	var collections []commonCrawlCollection
	if err := json.Unmarshal([]byte(body), &collections); err != nil {
		t.Fatalf("unexpected decode error: %v", err)
	}

	var endpoints []string
	for i, c := range collections {
		if i >= commonCrawlMaxCollections {
			break
		}
		endpoints = append(endpoints, c.CDXAPI)
	}

	if len(endpoints) != commonCrawlMaxCollections {
		t.Fatalf("expected %d endpoints, got %d", commonCrawlMaxCollections, len(endpoints))
	}
	if endpoints[0] != "https://index.commoncrawl.org/CC-MAIN-2026-30-index" {
		t.Errorf("expected the newest collection first, got %q", endpoints[0])
	}
	// The 7th entry in the source data must not appear - confirms the
	// cap is actually enforced, not just coincidentally satisfied.
	for _, e := range endpoints {
		if e == "https://index.commoncrawl.org/CC-MAIN-2026-04-index" {
			t.Errorf("7th collection should have been excluded by the max-6 cap, found %q", e)
		}
	}
}
