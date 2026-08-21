// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"testing"
)

// As with certspotter_test.go, this codebase has no harness for building a
// full et.Session in a unit test, so this covers only the pure decoding
// logic - check()/query() themselves remain exercised by manual runs only.

func TestDNSDumpsterResponseDecoding(t *testing.T) {
	body := `{
		"a": [{"host": "www.example.com", "ips": []}],
		"cname": [{"host": "cdn.example.com", "ips": []}],
		"ns": [{"host": "dns1.registrar-servers.com", "ips": []}],
		"mx": [{"host": "mail.example.com", "ips": []}],
		"total_a_recs": 1,
		"txt": ["v=spf1 -all"]
	}`

	var d dnsDumpsterResponse
	if err := json.Unmarshal([]byte(body), &d); err != nil {
		t.Fatalf("unexpected decode error: %v", err)
	}

	if len(d.A) != 1 || d.A[0].Host != "www.example.com" {
		t.Errorf("unexpected A records: %+v", d.A)
	}
	if len(d.CNAME) != 1 || d.CNAME[0].Host != "cdn.example.com" {
		t.Errorf("unexpected CNAME records: %+v", d.CNAME)
	}
	if len(d.NS) != 1 || d.NS[0].Host != "dns1.registrar-servers.com" {
		t.Errorf("unexpected NS records: %+v", d.NS)
	}
	if len(d.MX) != 1 || d.MX[0].Host != "mail.example.com" {
		t.Errorf("unexpected MX records: %+v", d.MX)
	}
	if d.APIError != "" {
		t.Errorf("expected no API error, got %q", d.APIError)
	}
}

func TestDNSDumpsterRateLimitErrorDecoding(t *testing.T) {
	body := `{"error":"Rate limit exceeded"}`

	var d dnsDumpsterResponse
	if err := json.Unmarshal([]byte(body), &d); err != nil {
		t.Fatalf("unexpected decode error: %v", err)
	}
	if d.APIError != "Rate limit exceeded" {
		t.Errorf("expected APIError to be populated, got %q", d.APIError)
	}
	if len(d.A) != 0 {
		t.Errorf("expected no A records on an error response, got %+v", d.A)
	}
}
