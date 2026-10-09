// Copyright (c) by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"testing"

	"github.com/caffix/pipeline"
	"github.com/caffix/queue"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
)

// TestNameIsExactScopeDomain covers the exact-domain membership test the
// OSINT bypass uses to decide whether a name takes the normal OSINT path
// (configured domains) or is routed around it (everything else). The
// overlapping-domain case (www.example.com configured alongside
// example.com) is the one Known-FQDN gets wrong and the gate must get
// right.
func TestNameIsExactScopeDomain(t *testing.T) {
	cases := []struct {
		name    string
		domains []string
		want    bool
	}{
		{"example.com", []string{"example.com"}, true},
		{"Example.COM", []string{"example.com"}, true},                        // case-insensitive
		{"example.com", []string{"EXAMPLE.COM"}, true},                        // case-insensitive both sides
		{"  example.com  ", []string{"example.com"}, true},                    // trimmed
		{"www.example.com", []string{"example.com"}, false},                   // subdomain, not configured
		{"www.example.com", []string{"example.com", "www.example.com"}, true}, // overlapping-domain fix
		{"notexample.com", []string{"example.com"}, false},                    // suffix trap
		{"*.apps.example.com", []string{"example.com"}, false},                // wildcard label
		{"", []string{"example.com"}, false},                                  // empty name
		{"example.com", nil, false},                                           // no configured domains
		{"example.com", []string{}, false},                                    // empty domain list
	}

	for _, c := range cases {
		if got := nameIsExactScopeDomain(c.name, c.domains); got != c.want {
			t.Errorf("nameIsExactScopeDomain(%q, %v) = %v, want %v",
				c.name, c.domains, got, c.want)
		}
	}
}

// TestOSINTBypassSkippableListMatchesRange is a guard on the guard: it
// documents that the allow-list is the single source of truth for which
// FQDN handlers may live in the bypass range, and fails if it is emptied
// or obviously corrupted. The live invariant (every handler actually
// registered in [fqdnOSINTFirst, fqdnOSINTLast] is on this list) is
// enforced at pipeline-build time by assertOSINTBypassInvariant; that
// path needs a fully constructed registry, so it is exercised by the
// engine's own startup rather than duplicated here.
func TestOSINTBypassSkippableListMatchesRange(t *testing.T) {
	if len(osintBypassSkippable) == 0 {
		t.Fatal("osintBypassSkippable is empty; the bypass invariant guard " +
			"would reject every OSINT handler and no FQDN pipeline could build")
	}
	// The two multi-pipeline plugins disambiguate their FQDN handler with
	// a -FQDN-Handler suffix; a regression to -Handler would make the
	// build-time guard panic on a legitimate handler.
	for _, required := range []string{"IP-THC-FQDN-Handler", "URLScan-FQDN-Handler", "crt.sh-Handler"} {
		if !osintBypassSkippable[required] {
			t.Errorf("osintBypassSkippable missing %q; build-time guard would "+
				"panic on this legitimate handler", required)
		}
	}
}

// TestFQDNOSINTRangeSane keeps the position constants coherent: OSINT must
// start above the DNS/scope stages and end below HTTP probing.
func TestFQDNOSINTRangeSane(t *testing.T) {
	if fqdnOSINTFirst <= 14 {
		t.Errorf("fqdnOSINTFirst=%d must be above the DNS/Known-FQDN/WHOIS "+
			"stages (<=14)", fqdnOSINTFirst)
	}
	if fqdnOSINTLast >= 41 {
		t.Errorf("fqdnOSINTLast=%d must be below HTTP probing (41)", fqdnOSINTLast)
	}
	if fqdnOSINTFirst > fqdnOSINTLast {
		t.Errorf("fqdnOSINTFirst=%d > fqdnOSINTLast=%d", fqdnOSINTFirst, fqdnOSINTLast)
	}
}

type bypassTestParams struct {
	reg pipeline.StageRegistry
}

func (p *bypassTestParams) Pipeline() *pipeline.Pipeline     { return nil }
func (p *bypassTestParams) Registry() pipeline.StageRegistry { return p.reg }

// TestOSINTBypassRouting checks the gate's routing decision. A name that
// Known-FQDN flagged with HasSLDInScope (a scope domain added at runtime,
// so absent from Config().Domains()) must continue into OSINT. An
// unflagged discovered name must be handed to the resume stage instead.
func TestOSINTBypassRouting(t *testing.T) {
	const resumeID = "FQDN - Priority: 41"

	cases := []struct {
		name       string
		sldInScope bool
		wantOSINT  bool
	}{
		{"horizontal.net", true, true},    // runtime scope domain flagged by Known-FQDN
		{"www.example.com", false, false}, // discovered name, no flag
	}

	for _, c := range cases {
		ev := &et.Event{
			Name:   c.name,
			Entity: &dbt.Entity{Asset: &oamdns.FQDN{Name: c.name}},
		}
		if c.sldInScope {
			support.AddSLDInScope(ev)
		}

		q := queue.NewQueue()
		tp := &bypassTestParams{reg: pipeline.StageRegistry{resumeID: q}}

		out, err := osintBypassTask(resumeID).Process(context.Background(), et.NewEventDataElement(ev), tp)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", c.name, err)
		}
		if gotOSINT := out != nil; gotOSINT != c.wantOSINT {
			t.Errorf("%s: continued into OSINT = %v, want %v", c.name, gotOSINT, c.wantOSINT)
		}
		wantQueued := 0
		if !c.wantOSINT {
			wantQueued = 1
		}
		if q.Len() != wantQueued {
			t.Errorf("%s: resume queue length = %d, want %d", c.name, q.Len(), wantQueued)
		}
	}
}
