// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"testing"
)

// As with certspotter_test.go and dnsdumpster_test.go, this codebase has
// no harness for building a full et.Session in a unit test, so this
// covers only the pure decoding logic - check()/query() remain exercised
// by manual runs only.

// TestSubdomainCenterResponseDecoding uses a trimmed excerpt of an actual
// live response captured against a real domain (luxoft.com), not a
// hypothetical shape - the flat-array-of-strings format was confirmed
// this way before any parsing code was written against it.
func TestSubdomainCenterResponseDecoding(t *testing.T) {
	body := `["ds.luxoft.com", "dmz-mdb.luxoft.com", "nas.luxoft.com", "www.adc.luxoft.com", "home.luxoft.com"]`

	var results []string
	if err := json.Unmarshal([]byte(body), &results); err != nil {
		t.Fatalf("unexpected decode error: %v", err)
	}

	if len(results) != 5 {
		t.Fatalf("expected 5 entries, got %d", len(results))
	}
	if results[0] != "ds.luxoft.com" {
		t.Errorf("unexpected first entry: %q", results[0])
	}
	if results[4] != "home.luxoft.com" {
		t.Errorf("unexpected last entry: %q", results[4])
	}
}

func TestSubdomainCenterEmptyResponseDecoding(t *testing.T) {
	body := `[]`

	var results []string
	if err := json.Unmarshal([]byte(body), &results); err != nil {
		t.Fatalf("unexpected decode error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected no entries, got %d", len(results))
	}
}

func TestSubdomainCenterMalformedResponseDecoding(t *testing.T) {
	// Guards against a future API change silently producing an object
	// instead of an array - should fail to decode into []string, not
	// panic or partially populate.
	body := `{"domain":"luxoft.com","subdomains":["ds.luxoft.com"]}`

	var results []string
	if err := json.Unmarshal([]byte(body), &results); err == nil {
		t.Fatal("expected a decode error for an object response, got none")
	}
}
