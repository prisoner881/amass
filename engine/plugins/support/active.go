// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	et "github.com/owasp-amass/amass/v5/engine/types"
	amassnet "github.com/owasp-amass/amass/v5/internal/net"
)

// This file is the single decision point for every -active connection's
// egress. An active operation touches a target asset (a port connect scan, an
// HTTP probe, a raw TLS/JARM dial), so when an active proxy is configured all
// of it MUST go through the proxy, and a proxy failure stops the whole run.
//
// The rule, in one place:
//
//   - active_proxy set   → the proxy dialer / client. Every proxy-side
//     failure fails the session (FailActiveProxy), so the enumeration stops
//     on the first one; a target answer relayed through a working proxy is an
//     ordinary result.
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
		return wrapActiveDial(sess, ae.DialContext), nil
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

// wrapActiveDial wraps the proxy dialer so that any proxy-side failure fails
// the session immediately. Callers that swallow dial errors (scanPorts treats
// a failed dial as a closed port) therefore cannot hide a dead proxy: the
// session is already being killed by the time the error returns.
func wrapActiveDial(sess et.Session, base amassnet.DialContext) amassnet.DialContext {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := base(ctx, network, addr)
		if err != nil && amassnet.IsProxyError(err) {
			FailActiveProxy(sess, "dial", addr, err)
		}
		return conn, err
	}
}

// FailActiveProxy records a fatal active-proxy failure and stops the whole
// enumeration. It is called the moment any active operation finds the proxy
// unusable. The error is logged (so it reaches the engine log and, via the
// log stream, the enum console) and the session is killed, which cancels
// every in-flight active operation and makes the enum CLI exit non-zero.
func FailActiveProxy(sess et.Session, op, target string, err error) {
	if sess == nil {
		return
	}
	sess.Log().Error("active proxy failure; stopping the enumeration",
		"operation", op, "target", target,
		"active_proxy", sess.Config().ActiveProxy, "error", err.Error())
	sess.FailActive(fmt.Sprintf("active proxy failure during %s of %s: %v", op, target, err))
}

// CheckActiveHTTPError inspects the error from an -active HTTP request made
// through ActiveHTTPClient. When it is a proxy-side failure, it fails the
// session. Returns true when the run was failed, so the caller can stop.
func CheckActiveHTTPError(sess et.Session, target string, err error) bool {
	if err == nil || !amassnet.IsProxyError(err) {
		return false
	}
	FailActiveProxy(sess, "http probe", target, err)
	return true
}
