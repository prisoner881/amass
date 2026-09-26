// Copyright (c) by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"strings"

	"github.com/caffix/pipeline"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
)

const (
	// First and last FQDN pipeline positions that are subdomain OSINT.
	// DNS, horizontals, Known-FQDN, DNS-SD, alterations, and WHOIS are
	// all strictly below fqdnOSINTFirst. HTTP probing is strictly above
	// fqdnOSINTLast. Every FQDN handler registered in [fqdnOSINTFirst,
	// fqdnOSINTLast] must return immediately for a name that is not an
	// in-scope SLD (i.e. it gates on support.HasSLDInScope), because the
	// OSINT bypass routes discovered names around this whole range. That
	// invariant is enforced at build time by assertOSINTBypassInvariant
	// (see osint_bypass_invariant in pipelines.go). Do not place a
	// non-OSINT FQDN handler in this range, and keep HTTP probing above
	// fqdnOSINTLast.
	fqdnOSINTFirst = 20
	fqdnOSINTLast  = 40
)

// newOSINTBypass builds the FIFO gate that lets discovered (non-seed)
// FQDNs skip the subdomain-OSINT positions (fqdnOSINTFirst..fqdnOSINTLast)
// and resume at the given stage id (HTTP probing). Scope domains keep the
// existing path through OSINT unchanged.
//
// The gate exists because those OSINT positions include one-name-wide
// pipeline.Parallel stages (positions 22 and 25). A scope domain held
// inside crt.sh/AlienVault for tens of seconds blocks the single lane,
// and discovered names - which every OSINT plugin refuses anyway, since
// they lack HasSLDInScope - pile up behind it. Routing them around the
// range removes that head-of-line blocking without changing what any
// plugin collects.
func newOSINTBypass(resumeID string) pipeline.Stage {
	return pipeline.FIFO("FQDN - OSINT bypass", pipeline.TaskFunc(
		func(ctx context.Context, data pipeline.Data, tp pipeline.TaskParams) (pipeline.Data, error) {
			ede, ok := data.(*et.EventDataElement)
			if !ok || ede == nil || ede.Event == nil {
				return nil, nil
			}

			// Session already ending: acknowledge and stop, matching
			// handlerTask's own done-handling so the backlog row is not
			// left leased forever.
			if ede.Event.Session != nil && ede.Event.Session.Done() {
				sendElementOnExit(ede)
				return nil, nil
			}

			// A domain the operator explicitly configured takes the
			// normal path through OSINT. Set HasSLDInScope if it is not
			// already set: this also fixes the overlapping-domain case
			// where Known-FQDN refuses to set the flag on a configured
			// domain that is a subdomain of another configured domain.
			if exactScopeDomain(ede.Event) {
				if !support.HasSLDInScope(ede.Event) {
					support.AddSLDInScope(ede.Event)
				}
				return data, nil
			}

			// Discovered name: append the SAME event pointer to the
			// resume stage's data queue and do not forward it into OSINT.
			// EventDataElement.Clone returns the same pointer, and HTTP
			// probing reads DNS-record flags stored on this event by the
			// earlier DNS stages; a copy would make the probe see no
			// addresses, so pass data unchanged.
			if q, found := tp.Registry()[resumeID]; found && q != nil {
				pipeline.SendData(ctx, resumeID, data, tp)
				return nil, nil
			}

			// The resume stage is not registered (no FQDN handler after
			// fqdnOSINTLast). Walking OSINT is slow but dropping the name
			// would leave its backlog row leased forever, so forward it.
			return data, nil
		},
	))
}

// exactScopeDomain reports whether the event's FQDN is one of the domains
// passed to the enumeration, not merely a name under one of them. It is a
// thin Event-reading wrapper over nameIsExactScopeDomain so the matching
// logic can be tested without stubbing the full Session interface.
//
// WhichDomain is the wrong test here: given both example.com and
// www.example.com configured, it can return the parent, which is exactly
// the overlapping-domain case the gate must handle correctly.
func exactScopeDomain(e *et.Event) bool {
	if e == nil || e.Session == nil || e.Session.Config() == nil || e.Entity == nil {
		return false
	}
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok || fqdn == nil {
		return false
	}
	// Config.Domains returns the slice under the config lock; the caller
	// must not mutate it. Comparing it is fine.
	return nameIsExactScopeDomain(fqdn.Name, e.Session.Config().Domains())
}

// nameIsExactScopeDomain reports whether name equals (case-insensitively,
// trimmed) one of the configured domains. Pure function: no Session, no
// Event, so it is directly unit-testable.
func nameIsExactScopeDomain(name string, domains []string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return false
	}
	for _, d := range domains {
		if strings.ToLower(strings.TrimSpace(d)) == n {
			return true
		}
	}
	return false
}
