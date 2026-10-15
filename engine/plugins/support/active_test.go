// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/config"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amassnet "github.com/owasp-amass/amass/v5/internal/net"
)

// activeTestSession is a minimal et.Session for the active-egress helpers.
type activeTestSession struct {
	et.Session
	cfg      *config.Config
	egress   *amassnet.ActiveEgress
	clients  *et.SessionHTTPClients
	failed   bool
	failWhy  string
	failOnce sync.Once
}

func (s *activeTestSession) Ctx() context.Context                 { return context.Background() }
func (s *activeTestSession) Log() *slog.Logger                    { return slog.New(slog.NewTextHandler(io.Discard, nil)) }
func (s *activeTestSession) Config() *config.Config               { return s.cfg }
func (s *activeTestSession) Clients() *et.SessionHTTPClients      { return s.clients }
func (s *activeTestSession) ActiveEgress() *amassnet.ActiveEgress { return s.egress }
func (s *activeTestSession) FailActive(reason string) {
	s.failOnce.Do(func() { s.failed, s.failWhy = true, reason })
}

func newActiveSession(strict bool, egress *amassnet.ActiveEgress) *activeTestSession {
	cfg := config.NewConfig()
	cfg.Active = true
	cfg.ActiveStrict = strict
	clients := &et.SessionHTTPClients{Probe: &http.Client{Timeout: time.Second}}
	if egress != nil {
		clients.Active = egress.Client
	}
	return &activeTestSession{cfg: cfg, egress: egress, clients: clients}
}

// tinySOCKS5 is a no-auth SOCKS5 CONNECT proxy that records destinations.
// refuse != 0 answers every CONNECT with that reply code instead of relaying.
type tinySOCKS5 struct {
	ln     net.Listener
	mu     sync.Mutex
	dests  []string
	refuse byte
}

func startTinySOCKS5(t *testing.T, refuse byte) *tinySOCKS5 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &tinySOCKS5{ln: ln, refuse: refuse}
	go p.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return p
}

func (p *tinySOCKS5) addr() string { return p.ln.Addr().String() }
func (p *tinySOCKS5) seen() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.dests...)
}

func (p *tinySOCKS5) serve() {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		go p.handle(c)
	}
}

func (p *tinySOCKS5) handle(c net.Conn) {
	defer c.Close()
	b := make([]byte, 262)
	if _, err := io.ReadFull(c, b[:2]); err != nil {
		return
	}
	io.ReadFull(c, b[:int(b[1])])
	c.Write([]byte{5, 0})
	if _, err := io.ReadFull(c, b[:4]); err != nil {
		return
	}
	var host string
	switch b[3] {
	case 1:
		io.ReadFull(c, b[:4])
		host = net.IP(b[:4]).String()
	case 3:
		io.ReadFull(c, b[:1])
		n := int(b[0])
		io.ReadFull(c, b[:n])
		host = string(b[:n])
	}
	io.ReadFull(c, b[:2])
	dst := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(b[:2]))))
	p.mu.Lock()
	p.dests = append(p.dests, dst)
	p.mu.Unlock()

	if p.refuse != 0 {
		c.Write([]byte{5, p.refuse, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	up, err := net.DialTimeout("tcp", dst, 2*time.Second)
	if err != nil {
		c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer up.Close()
	c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	go io.Copy(up, c)
	io.Copy(c, up)
}

func deadAddr(t *testing.T) string {
	t.Helper()
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	a := ln.Addr().String()
	_ = ln.Close()
	return a
}

// With a proxy configured, the active dialer reaches the target THROUGH the
// proxy: the proxy records the destination, and no direct connection is made.
func TestActiveDialerRoutesThroughProxy(t *testing.T) {
	backend, _ := net.Listen("tcp", "127.0.0.1:0")
	defer backend.Close()
	go func() {
		if c, err := backend.Accept(); err == nil {
			c.Write([]byte("x"))
			c.Close()
		}
	}()

	proxy := startTinySOCKS5(t, 0)
	ae, err := amassnet.NewActiveEgress("socks5://"+proxy.addr(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	sess := newActiveSession(true, ae)

	dial, err := ActiveDialer(sess, 2*time.Second)
	if err != nil {
		t.Fatalf("ActiveDialer: %v", err)
	}
	conn, err := dial(context.Background(), "tcp", backend.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()

	if seen := proxy.seen(); len(seen) != 1 || seen[0] != backend.Addr().String() {
		t.Errorf("proxy saw %v, want the target reached through it", seen)
	}
	if sess.failed {
		t.Errorf("session failed unexpectedly: %s", sess.failWhy)
	}
}

// A proxy failure during an active dial fails the whole session.
func TestActiveDialerFailsSessionOnProxyError(t *testing.T) {
	ae, err := amassnet.NewActiveEgress("socks5://"+deadAddr(t), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	sess := newActiveSession(true, ae)

	dial, err := ActiveDialer(sess, 2*time.Second)
	if err != nil {
		t.Fatalf("ActiveDialer: %v", err)
	}
	if _, derr := dial(context.Background(), "tcp", "192.0.2.10:443"); derr == nil {
		t.Fatal("expected the dial to fail against a dead proxy")
	}
	if !sess.failed {
		t.Fatal("a proxy failure did not fail the session")
	}
}

// A target refused THROUGH a working proxy is an ordinary scan result, not a
// session failure.
func TestActiveDialerTargetRefusalIsNotProxyFailure(t *testing.T) {
	proxy := startTinySOCKS5(t, 0)
	ae, _ := amassnet.NewActiveEgress("socks5://"+proxy.addr(), 2*time.Second)
	sess := newActiveSession(true, ae)

	dial, _ := ActiveDialer(sess, 2*time.Second)
	// Point at a closed local port; the proxy relays the refusal.
	if _, err := dial(context.Background(), "tcp", deadAddr(t)); err == nil {
		t.Fatal("expected a refusal")
	}
	if sess.failed {
		t.Errorf("a relayed target refusal must not fail the session: %s", sess.failWhy)
	}
}

func TestActiveDialerStrictWithoutProxy(t *testing.T) {
	sess := newActiveSession(true, nil)
	if _, err := ActiveDialer(sess, time.Second); err != amassnet.ErrNoActiveEgress {
		t.Errorf("strict + no proxy: got %v, want ErrNoActiveEgress", err)
	}

	relaxed := newActiveSession(false, nil)
	if d, err := ActiveDialer(relaxed, time.Second); err != nil || d == nil {
		t.Errorf("non-strict + no proxy: got (%v, %v), want a direct dialer", d, err)
	}
}

func TestActiveHTTPClientSelection(t *testing.T) {
	ae, _ := amassnet.NewActiveEgress("socks5://"+deadAddr(t), time.Second)
	sess := newActiveSession(true, ae)
	if c, err := ActiveHTTPClient(sess); err != nil || c != ae.Client {
		t.Errorf("with proxy: got (%v, %v), want the active client", c, err)
	}

	strictNo := newActiveSession(true, nil)
	if _, err := ActiveHTTPClient(strictNo); err != amassnet.ErrNoActiveEgress {
		t.Errorf("strict + no proxy: got %v, want ErrNoActiveEgress", err)
	}

	relaxed := newActiveSession(false, nil)
	if c, err := ActiveHTTPClient(relaxed); err != nil || c != relaxed.clients.Probe {
		t.Errorf("non-strict + no proxy: got (%v, %v), want the Probe client", c, err)
	}
}

func TestCheckActiveHTTPError(t *testing.T) {
	sess := newActiveSession(true, nil)
	// A plain error is not a proxy failure.
	if CheckActiveHTTPError(sess, "t", context.DeadlineExceeded) {
		t.Error("deadline exceeded wrongly treated as a proxy failure")
	}
	if sess.failed {
		t.Error("session failed on a non-proxy error")
	}

	// Produce a genuine proxy error by dialing a dead proxy, then feed it to
	// the HTTP error check exactly as an active probe would.
	ae, _ := amassnet.NewActiveEgress("socks5://"+deadAddr(t), time.Second)
	_, proxyErr := ae.DialContext(context.Background(), "tcp", "192.0.2.10:443")
	if proxyErr == nil || !amassnet.IsProxyError(proxyErr) {
		t.Fatalf("expected a proxy error from a dead proxy, got %v", proxyErr)
	}
	if !CheckActiveHTTPError(sess, "t", proxyErr) {
		t.Error("a proxy error was not detected")
	}
	if !sess.failed {
		t.Error("a proxy error did not fail the session")
	}
}

// countingListener accepts connections and counts them, so a test can compare
// how many connections the target saw with how many the proxy relayed.
type countingListener struct {
	ln net.Listener
	mu sync.Mutex
	n  int
}

func newCountingListener(t *testing.T) *countingListener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cl := &countingListener{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			cl.mu.Lock()
			cl.n++
			cl.mu.Unlock()
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return cl
}

func (c *countingListener) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

func (c *countingListener) port() int {
	return c.ln.Addr().(*net.TCPAddr).Port
}

// No leakage: scan a set of ports (some open, some closed) through the proxy.
// Every connection attempt must arrive at the proxy, and every connection the
// target accepted must have been relayed by it, so the target saw exactly the
// connections the proxy made on its behalf and nothing came in directly.
func TestScanPortsLeaksNothingAroundTheProxy(t *testing.T) {
	var open []*countingListener
	var ports []int
	for i := 0; i < 5; i++ {
		l := newCountingListener(t)
		open = append(open, l)
		ports = append(ports, l.port())
	}
	for i := 0; i < 15; i++ { // closed ports
		_, p, _ := net.SplitHostPort(deadAddr(t))
		n, _ := strconv.Atoi(p)
		ports = append(ports, n)
	}

	proxy := startTinySOCKS5(t, 0)
	ae, err := amassnet.NewActiveEgress("socks5://"+proxy.addr(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	sess := newActiveSession(true, ae)
	dial, err := ActiveDialer(sess, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	got := scanPorts(context.Background(), dial, "127.0.0.1", ports, nil)
	time.Sleep(100 * time.Millisecond) // let the listeners finish counting

	if len(got) != len(open) {
		t.Errorf("found %d open ports, want %d", len(got), len(open))
	}
	if seen := len(proxy.seen()); seen != len(ports) {
		t.Errorf("proxy relayed %d connection attempts, want all %d scanned ports", seen, len(ports))
	}
	var targetSaw int
	for _, l := range open {
		targetSaw += l.count()
	}
	if targetSaw != len(open) {
		t.Errorf("target saw %d connections, want %d (one per open port, all via the proxy)", targetSaw, len(open))
	}
	if sess.failed {
		t.Errorf("session failed during a healthy scan: %s", sess.failWhy)
	}
}

// A nil dialer must scan nothing: it never falls back to a direct connection.
func TestScanPortsNilDialerScansNothing(t *testing.T) {
	l := newCountingListener(t)
	if got := scanPorts(context.Background(), nil, "127.0.0.1", []int{l.port()}, nil); len(got) != 0 {
		t.Errorf("nil dialer returned open ports %v", got)
	}
	time.Sleep(100 * time.Millisecond)
	if l.count() != 0 {
		t.Errorf("a nil dialer connected directly (%d connections)", l.count())
	}
}

// -active-strict=false only matters when there is no proxy. With a proxy
// configured, active traffic goes through it whatever the flag says.
func TestProxyWinsEvenWhenStrictIsOff(t *testing.T) {
	backend := newCountingListener(t)
	proxy := startTinySOCKS5(t, 0)
	ae, _ := amassnet.NewActiveEgress("socks5://"+proxy.addr(), 3*time.Second)
	sess := newActiveSession(false, ae) // strict OFF, proxy set

	dial, err := ActiveDialer(sess, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dial(context.Background(), "tcp", "127.0.0.1:"+strconv.Itoa(backend.port()))
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	time.Sleep(50 * time.Millisecond)

	if len(proxy.seen()) != 1 {
		t.Errorf("with strict off and a proxy set, the dial did not go through the proxy (proxy saw %v)", proxy.seen())
	}
	if c, err := ActiveHTTPClient(sess); err != nil || c != ae.Client {
		t.Errorf("with strict off and a proxy set, the HTTP client is not the proxied one")
	}
}
