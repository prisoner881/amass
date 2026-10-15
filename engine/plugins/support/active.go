// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"net/http"
	"time"

	et "github.com/owasp-amass/amass/v5/engine/types"
	amassnet "github.com/owasp-amass/amass/v5/internal/net"
)

// This file is the single decision point for every -active connection's
// egress. An active operation touches a target asset (a port connect scan, an
// HTTP probe, a raw TLS/JARM dial), so when an active proxy is configured all
// of it MUST go through the proxy.
//
// The rule, in one place:
//
//   - active_proxy set   → the proxy dialer / client. A proxy that is down
//     makes active operations fail; they never fall back to a direct
//     connection. The engine checks the proxy once at session start-up and
//     does not watch it mid-run: an external monitor stops the engines if
//     the proxy fails.
//   - no proxy, strict   → ErrNoActiveEgress. (Session creation already
//     refused this, so it is a defensive guard.)
//   - no proxy, not strict → a direct dialer / the Probe client. The operator
//     opted out of the proxy for this run.
//
// There is no nil-means-direct path: a caller that cannot obtain a dialer or
// client here must skip the active operation, never fall back to a direct
// connection on its own.

// ActiveDialer returns the dialer every -active raw connection (port scan,
// banner peek, TLS/JARM handshake) must use. timeout applies only to the
// direct (opted-out) dialer; the proxy dialer carries its own timeouts.
func ActiveDialer(sess et.Session, timeout time.Duration) (amassnet.DialContext, error) {
	if ae := sess.ActiveEgress(); ae != nil {
		return ae.DialContext, nil
	}
	if sess.Config().ActiveStrict {
		return nil, amassnet.ErrNoActiveEgress
	}
	return amassnet.NewDialContext(timeout), nil
}

// ActiveHTTPClient returns the client every -active HTTP probe must use.
func ActiveHTTPClient(sess et.Session) (*http.Client, error) {
	if c := sess.Clients().Active; c != nil {
		return c, nil
	}
	if sess.Config().ActiveStrict {
		return nil, amassnet.ErrNoActiveEgress
	}
	return sess.Clients().Probe, nil
}
