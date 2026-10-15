// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// This file implements the Active egress profile. The Amass engine has two
// distinct egress profiles:
//
//   - Default egress: used by passive OSINT, data sources, crawler/general
//     HTTP clients, and all DNS. This is the existing behaviour.
//
//   - Active egress: used ONLY by traffic generated as a side effect of the
//     -active flag (HTTP service probes, raw TLS/JARM dials, port connect
//     scans). This traffic MUST be sent through an operator-specified runtime
//     proxy (config.Config.ActiveProxy). When no active proxy is configured
//     the engine is fail-closed (unless the operator opted out with
//     -active-strict=false). DNS is never routed through the active proxy.
package net

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

func basicAuth(user, pw string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + pw))
}

// ErrNoActiveEgress is returned by helpers when an active-only operation is
// attempted but no active egress profile is available. Callers MUST treat
// this as a hard failure for that operation — never fall back to direct
// dialing.
var ErrNoActiveEgress = errors.New("active egress is not configured: refusing to send active traffic over the default network")

// ProxyError marks a failure that is the active proxy's fault — the proxy
// could not be reached, rejected our credentials, or refused to relay — as
// opposed to the target's own answer (connection refused, host unreachable)
// relayed back through a working proxy. HealthCheck uses the distinction to
// refuse a session only when the proxy itself is unusable. IsProxyError
// reports whether an error chain contains one.
type ProxyError struct{ err error }

func (e *ProxyError) Error() string { return e.err.Error() }
func (e *ProxyError) Unwrap() error { return e.err }

func proxyErrorf(format string, a ...any) *ProxyError {
	return &ProxyError{err: fmt.Errorf(format, a...)}
}

// IsProxyError reports whether err is, or wraps, a *ProxyError.
func IsProxyError(err error) bool {
	var pe *ProxyError
	return errors.As(err, &pe)
}

// ActiveEgress encapsulates the network primitives used by every -active
// code path. It is intentionally narrow so that auditing the set of active
// egress users is just a matter of grepping for the field names.
//
// All fields are constructed once at session startup from the
// config.Config.ActiveProxy URL and reused for the lifetime of the session.
type ActiveEgress struct {
	// Proxy is the raw URL the operator configured. Kept verbatim for
	// logging and for components that want to construct their own
	// transports.
	Proxy string

	// DialContext dials through the active proxy. It is used by raw TLS /
	// JARM fingerprinting, the port connect scan, and as the dialer
	// underneath the active HTTP client.
	//
	// Unlike NewDialContext, this dialer never falls through to a direct
	// connection: if the proxy is unreachable it fails, and a proxy-side
	// failure is wrapped in *ProxyError so callers can tell it apart from
	// the target's own answer.
	DialContext DialContext

	// Client is the http.Client active service probes MUST use.
	Client *http.Client

	proxyURL  *url.URL
	transport *http.Transport
}

// CloseIdleConnections releases keep-alive sockets held by the active client.
// Safe to call on a nil receiver.
func (a *ActiveEgress) CloseIdleConnections() {
	if a == nil || a.transport == nil {
		return
	}
	a.transport.CloseIdleConnections()
}

// HealthCheck opens and immediately closes a tunnelled connection to probe,
// confirming the proxy is reachable and willing to relay.
// It returns a *ProxyError only when the proxy itself is the problem
// (unreachable, bad auth, refuses to relay). A connection that the proxy
// relays — whether it succeeds, or the probe host refuses it — means the
// proxy works, so HealthCheck returns nil. The engine calls this once before
// dispatching any work, so a dead proxy fails the session at startup.
func (a *ActiveEgress) HealthCheck(ctx context.Context, probe string) error {
	if a == nil {
		return ErrNoActiveEgress
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	conn, err := a.DialContext(ctx, "tcp", probe)
	if err != nil {
		if IsProxyError(err) {
			return err
		}
		// A relayed target answer (refused/unreachable/timeout) proves the
		// proxy is usable, which is all the health check needs to confirm.
		return nil
	}
	_ = conn.Close()
	return nil
}

// NewActiveEgress builds an ActiveEgress from the operator-supplied proxy
// URL. Returns (nil, nil) when proxyURL is empty — callers treat that as
// "active egress not configured" and either fail closed or (when
// ActiveStrict is false) send active traffic over the default egress.
//
// The supplied probeTimeout is applied to active HTTP probes.
func NewActiveEgress(proxyURL string, probeTimeout time.Duration) (*ActiveEgress, error) {
	if strings.TrimSpace(proxyURL) == "" {
		return nil, nil
	}

	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid active proxy URL %q: %w", proxyURL, err)
	}

	// Per-dial timeout for reaching the proxy and tunnelling to a target.
	// 6s is 3x the direct connect-scan timeout (PortPrefilterScanTimeout,
	// 2s), enough headroom for a Tor circuit without hanging the pipeline.
	dial, err := buildProxyDialContext(u, 6*time.Second)
	if err != nil {
		return nil, err
	}

	// The transport's own DialContext already tunnels through the proxy, so
	// the request's destination host is what gets dialled. Do NOT also set
	// Proxy here: that made the client CONNECT to the proxy's own address
	// first (proxy-to-proxy), which real proxies such as Tor refuse.
	tr := &http.Transport{
		DialContext:           dial,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          64,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   8 * time.Second,
		ExpectContinueTimeout: 0,
		ResponseHeaderTimeout: 15 * time.Second,
		// Service probes already accepted self-signed certs in the legacy
		// probe transport — preserve that so the swap is purely a routing
		// change.
		TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
		DisableCompression: true,
	}

	if probeTimeout <= 0 {
		probeTimeout = 30 * time.Second
	}

	return &ActiveEgress{
		Proxy:       proxyURL,
		DialContext: dial,
		Client: &http.Client{
			Transport: tr,
			Timeout:   probeTimeout,
		},
		proxyURL:  u,
		transport: tr,
	}, nil
}

// buildProxyDialContext returns a DialContext that opens every connection
// through the supplied proxy URL. http/https proxies use HTTP CONNECT.
// socks5 and socks5h both use golang.org/x/net/proxy.SOCKS5, which sends
// hostnames verbatim using the SOCKS5 DOMAINNAME address type (proxy-side
// resolution). Active-mode callers pass hostnames or discovered IPs and
// never pre-resolve, so both schemes resolve correctly at the proxy.
func buildProxyDialContext(u *url.URL, perDialTimeout time.Duration) (DialContext, error) {
	switch strings.ToLower(u.Scheme) {
	case "socks5", "socks5h":
		var auth *proxy.Auth
		if u.User != nil {
			pw, _ := u.User.Password()
			auth = &proxy.Auth{User: u.User.Username(), Password: pw}
		}
		base := &net.Dialer{Timeout: perDialTimeout, KeepAlive: 30 * time.Second}
		d, err := proxy.SOCKS5("tcp", u.Host, auth, base)
		if err != nil {
			return nil, fmt.Errorf("failed to construct SOCKS5 dialer: %w", err)
		}
		ctxDialer, ok := d.(proxy.ContextDialer)
		if !ok {
			return nil, errors.New("SOCKS5 dialer does not support context")
		}
		return func(ctx context.Context, network, addr string) (net.Conn, error) {
			if !strings.HasPrefix(network, "tcp") {
				return nil, fmt.Errorf("active egress does not support network %q over SOCKS5", network)
			}
			conn, err := ctxDialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, classifySOCKSDialError(u.Host, addr, err)
			}
			return conn, nil
		}, nil
	case "http", "https":
		return httpConnectDialer(u, perDialTimeout), nil
	default:
		return nil, fmt.Errorf("unsupported active proxy scheme %q", u.Scheme)
	}
}

// classifySOCKSDialError decides whether a SOCKS5 dial failure is the proxy's
// fault or the target's answer relayed back. golang.org/x/net/proxy wraps a
// failure to reach the proxy as a "socks connect" *net.OpError that nests a
// "dial" *net.OpError to the proxy host; a relayed target answer is a SOCKS
// reply status with no nested dial error. So:
//
//   - a nested "dial" OpError, or a SOCKS reply about the proxy's own state
//     (general failure, not allowed by ruleset, command or address type not
//     supported) → proxy failure, wrapped in a *ProxyError;
//   - a relayed "connection refused" / "unreachable" / "TTL expired" from the
//     target → an ordinary scan result, passed through unwrapped so the port
//     scanner records it as a closed/unreachable/filtered port.
func classifySOCKSDialError(proxyHost, addr string, err error) error {
	// Could not reach the proxy at all: the chain contains a dial OpError.
	for e := err; e != nil; e = errors.Unwrap(e) {
		if op, ok := e.(*net.OpError); ok && op.Op == "dial" {
			return proxyErrorf("active proxy %s is unreachable (dialing %s): %w", proxyHost, addr, err)
		}
	}

	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "general socks server failure"),
		strings.Contains(msg, "not allowed by ruleset"),
		strings.Contains(msg, "command not supported"),
		strings.Contains(msg, "address type not supported"):
		return proxyErrorf("active proxy %s refused to relay to %s: %w", proxyHost, addr, err)
	case strings.Contains(msg, "connection refused"),
		strings.Contains(msg, "host unreachable"),
		strings.Contains(msg, "network unreachable"),
		strings.Contains(msg, "ttl expired"):
		// Relayed target answer: an ordinary scan result, not a proxy fault.
		// "TTL expired" (reply 0x06) is how Tor and Dante report a target that
		// never answered, i.e. a filtered port; treating it as a proxy failure
		// would end a run on the first filtered port.
		return err
	default:
		// Anything else talking to the proxy (auth, protocol) is a proxy fault.
		return proxyErrorf("active proxy %s is unusable (dialing %s): %w", proxyHost, addr, err)
	}
}

// httpConnectDialer returns a DialContext that uses HTTP CONNECT against the
// given proxy. Used for the HTTP active client and for raw TLS / JARM dials
// when the active proxy is an http(s) proxy. The returned conn is the
// tunnelled TCP connection. A non-2xx CONNECT response, or a failure to
// reach the proxy, is wrapped in *ProxyError.
func httpConnectDialer(proxyURL *url.URL, perDialTimeout time.Duration) DialContext {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if !strings.HasPrefix(network, "tcp") {
			return nil, fmt.Errorf("active egress does not support network %q over HTTP proxy", network)
		}

		dialer := &net.Dialer{Timeout: perDialTimeout, KeepAlive: 30 * time.Second}
		proxyHost := proxyURL.Host
		var rawConn net.Conn
		var err error
		if proxyURL.Scheme == "https" {
			// tls.DialWithDialer ignores ctx; dial the TCP connection with
			// the context first, then do the TLS handshake under the context
			// deadline, so cancellation and timeouts are honoured.
			var tcp net.Conn
			tcp, err = dialer.DialContext(ctx, "tcp", proxyHost)
			if err == nil {
				tconn := tls.Client(tcp, &tls.Config{ServerName: hostOnly(proxyHost)})
				if dl, ok := ctx.Deadline(); ok {
					_ = tcp.SetDeadline(dl)
				}
				if herr := tconn.HandshakeContext(ctx); herr != nil {
					_ = tcp.Close()
					err = herr
				} else {
					_ = tcp.SetDeadline(time.Time{})
					rawConn = tconn
				}
			}
		} else {
			rawConn, err = dialer.DialContext(ctx, "tcp", proxyHost)
		}
		if err != nil {
			return nil, proxyErrorf("failed to reach active proxy %s: %w", proxyHost, err)
		}

		req := &http.Request{
			Method: http.MethodConnect,
			URL:    &url.URL{Host: addr},
			Host:   addr,
			Header: make(http.Header),
		}
		if proxyURL.User != nil {
			pw, _ := proxyURL.User.Password()
			req.Header.Set("Proxy-Authorization",
				"Basic "+basicAuth(proxyURL.User.Username(), pw))
		}

		if deadline, ok := ctx.Deadline(); ok {
			_ = rawConn.SetDeadline(deadline)
		} else {
			_ = rawConn.SetDeadline(time.Now().Add(perDialTimeout))
		}

		if werr := req.Write(rawConn); werr != nil {
			_ = rawConn.Close()
			return nil, proxyErrorf("CONNECT write to %s failed: %w", proxyHost, werr)
		}

		br := bufio.NewReader(rawConn)
		resp, rerr := http.ReadResponse(br, req)
		if rerr != nil {
			_ = rawConn.Close()
			return nil, proxyErrorf("CONNECT response from %s failed: %w", proxyHost, rerr)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			_ = rawConn.Close()
			return nil, classifyConnectStatus(proxyHost, addr, resp.StatusCode, resp.Status)
		}

		_ = rawConn.SetDeadline(time.Time{})
		if n := br.Buffered(); n > 0 {
			peeked, _ := br.Peek(n)
			return &bufferedConn{Conn: rawConn, buf: peeked}, nil
		}
		return rawConn, nil
	}
}

// classifyConnectStatus turns a non-200 CONNECT status into a proxy failure
// or a relayed target answer. 502/504 with an upstream-refused meaning is the
// target's answer; everything else (auth, forbidden, proxy errors) is a proxy
// failure. HTTP CONNECT cannot always distinguish "target refused" from
// "proxy refused", so only the clearly-upstream 5xx codes pass through.
func classifyConnectStatus(proxyHost, addr string, code int, status string) error {
	switch code {
	case http.StatusBadGateway, http.StatusGatewayTimeout:
		// Upstream (target) did not accept the connection: a scan result.
		return fmt.Errorf("target %s not reachable via proxy: %s", addr, status)
	default:
		return proxyErrorf("active proxy %s CONNECT to %s rejected: %s", proxyHost, addr, status)
	}
}

// bufferedConn is a net.Conn that prepends a pre-read byte slice before
// reading from the underlying connection. It surfaces any bytes the CONNECT
// response reader buffered past the response.
type bufferedConn struct {
	net.Conn
	mu  sync.Mutex
	buf []byte
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	b.mu.Lock()
	if len(b.buf) > 0 {
		n := copy(p, b.buf)
		b.buf = b.buf[n:]
		b.mu.Unlock()
		return n, nil
	}
	b.mu.Unlock()
	return b.Conn.Read(p)
}

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}
