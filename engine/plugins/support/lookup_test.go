// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
)

func TestHTTPLookupFailure(t *testing.T) {
	cases := []struct {
		name string
		resp *amasshttp.Response
		err  error
		want string
	}{
		{"ok", &amasshttp.Response{StatusCode: 200, Body: "[]"}, nil, ""},
		{"transport", nil, errors.New("dial tcp: timeout"), "dial tcp: timeout"},
		{"nil response", nil, nil, "no response"},
		{"rate limited", &amasshttp.Response{StatusCode: 429, Body: "slow down"}, nil, "HTTP 429"},
		{"empty body", &amasshttp.Response{StatusCode: 200}, nil, "empty response body"},
	}
	for _, c := range cases {
		if got := HTTPLookupFailure(c.resp, c.err); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestLogLookupFailureThrottlesPerPlugin(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	plugin := "throttle-test-" + t.Name()

	LogLookupFailure(log, plugin, "a.example.com", "HTTP 500")
	LogLookupFailure(log, plugin, "b.example.com", "HTTP 500")
	LogLookupFailure(log, plugin, "c.example.com", "HTTP 500")
	if n := strings.Count(buf.String(), "lookup failed"); n != 1 {
		t.Fatalf("logged %d lines within the interval, want 1:\n%s", n, buf.String())
	}

	// Another plugin is throttled separately.
	LogLookupFailure(log, plugin+"-other", "a.example.com", "HTTP 500")
	if n := strings.Count(buf.String(), "lookup failed"); n != 2 {
		t.Fatalf("a second plugin was throttled by the first: %d lines", n)
	}

	// After the interval, the next line reports the folded failures.
	lookupFailureMu.Lock()
	lookupFailureByName[plugin].last = time.Now().Add(-2 * lookupFailureInterval)
	lookupFailureMu.Unlock()
	buf.Reset()
	LogLookupFailure(log, plugin, "d.example.com", "HTTP 500")
	if !strings.Contains(buf.String(), "failures_since_last_log=2") {
		t.Errorf("next line does not report the 2 folded failures:\n%s", buf.String())
	}
}
