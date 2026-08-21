// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"testing"
	"time"

	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
)

// NOTE: this codebase has no existing harness for constructing a full
// et.Session in a unit test (no mock Session/DB/Scope exists anywhere in
// the tree today), so this file intentionally does not attempt an
// end-to-end test of check()/query()/page() against a live or faked
// HTTP server the way internal/net/active_egress_test.go does for the
// lower-level active-egress primitive. It covers the two pieces of new,
// non-trivial logic that don't require a Session at all: Retry-After
// header parsing, and the backoff-gate state machine.

func TestParseRetryAfter(t *testing.T) {
	cases := []struct {
		name string
		hdr  amasshttp.Header
		want int
	}{
		{"nil header", nil, 0},
		{"absent header", amasshttp.Header{"Content-Type": {"application/json"}}, 0},
		{"valid value", amasshttp.Header{"Retry-After": {"300"}}, 300},
		{"whitespace padded", amasshttp.Header{"Retry-After": {"  120 "}}, 120},
		{"non-numeric value ignored", amasshttp.Header{"Retry-After": {"Wed, 21 Oct 2026 07:28:00 GMT"}}, 0},
		{"negative value ignored", amasshttp.Header{"Retry-After": {"-5"}}, 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseRetryAfter(tc.hdr); got != tc.want {
				t.Errorf("parseRetryAfter(%v) = %d, want %d", tc.hdr, got, tc.want)
			}
		})
	}
}

func TestRetryBackoffGate(t *testing.T) {
	cs := &certSpotter{}

	if !cs.readyToCall() {
		t.Fatal("expected a freshly constructed plugin to be ready to call")
	}

	cs.setRetryNotBefore(1) // 1 second
	if cs.readyToCall() {
		t.Fatal("expected readyToCall to be false immediately after setRetryNotBefore")
	}

	time.Sleep(1100 * time.Millisecond)
	if !cs.readyToCall() {
		t.Fatal("expected readyToCall to be true after the backoff window elapsed")
	}
}

func TestRetryBackoffGateNeverShrinksWindow(t *testing.T) {
	cs := &certSpotter{}

	cs.setRetryNotBefore(10)
	first := cs.retryNotBefore

	// A shorter subsequent backoff must not pull the deadline earlier.
	cs.setRetryNotBefore(1)
	if cs.retryNotBefore.Before(first) {
		t.Fatal("setRetryNotBefore must not shorten an existing backoff window")
	}

	// setRetryNotBefore(0) and negative values must be no-ops.
	cs.setRetryNotBefore(0)
	if cs.retryNotBefore != first {
		t.Fatal("setRetryNotBefore(0) should be a no-op")
	}
}
