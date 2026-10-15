// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package net

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeSOCKS5 is a minimal no-auth SOCKS5 CONNECT proxy for tests. It records
// every destination it was asked to reach. When refuse is set it answers every
// CONNECT with the given SOCKS reply code instead of dialing.
type fakeSOCKS5 struct {
	ln     net.Listener
	mu     sync.Mutex
	dests  []string
	refuse byte // 0 = relay; non-zero = reply code
}

func newFakeSOCKS5(t *testing.T, refuse byte) *fakeSOCKS5 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSOCKS5{ln: ln, refuse: refuse}
	go f.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return f
}

func (f *fakeSOCKS5) addr() string { return f.ln.Addr().String() }

func (f *fakeSOCKS5) seen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.dests...)
}

func (f *fakeSOCKS5) serve() {
	for {
		c, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.handle(c)
	}
}

func (f *fakeSOCKS5) handle(c net.Conn) {
	defer c.Close()
	b := make([]byte, 262)
	if _, err := io.ReadFull(c, b[:2]); err != nil {
		return
	}
	n := int(b[1])
	if _, err := io.ReadFull(c, b[:n]); err != nil {
		return
	}
	c.Write([]byte{5, 0}) // no auth

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
		l := int(b[0])
		io.ReadFull(c, b[:l])
		host = string(b[:l])
	}
	io.ReadFull(c, b[:2])
	port := binary.BigEndian.Uint16(b[:2])
	dst := net.JoinHostPort(host, itoa(port))

	f.mu.Lock()
	f.dests = append(f.dests, dst)
	f.mu.Unlock()

	if f.refuse != 0 {
		c.Write([]byte{5, f.refuse, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	up, err := net.DialTimeout("tcp", dst, 2*time.Second)
	if err != nil {
		c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0}) // connection refused
		return
	}
	defer up.Close()
	c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	go io.Copy(up, c)
	io.Copy(c, up)
}

func itoa(u uint16) string {
	return strings.TrimLeft(string([]byte{
		byte('0' + u/10000%10),
		byte('0' + u/1000%10),
		byte('0' + u/100%10),
		byte('0' + u/10%10),
		byte('0' + u%10),
	}), "0")
}

// The active HTTP client reaches the target through the SOCKS proxy, and the
// proxy is asked to connect to the TARGET, not to itself. A regression here
// (setting Transport.Proxy as well as DialContext) made the client ask the
// proxy to connect to the proxy's own address, which real proxies refuse.
func TestActiveHTTPClientTunnelsToTargetNotProxy(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()
	targetAddr := target.Listener.Addr().String()

	f := newFakeSOCKS5(t, 0)
	ae, err := NewActiveEgress("socks5://"+f.addr(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := ae.Client.Get(target.URL)
	if err != nil {
		t.Fatalf("GET through proxy failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "ok" {
		t.Errorf("body = %q, want ok", string(body))
	}
	for _, d := range f.seen() {
		if d == f.addr() {
			t.Fatalf("proxy was asked to connect to itself (%s)", d)
		}
	}
	if seen := f.seen(); len(seen) != 1 || seen[0] != targetAddr {
		t.Errorf("proxy destinations = %v, want [%s]", seen, targetAddr)
	}
}

// DialContext routes a raw TCP connection (JARM, banner peek) through the proxy.
func TestActiveDialContextUsesProxy(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go func() {
		c, err := backend.Accept()
		if err == nil {
			c.Write([]byte("hello"))
			c.Close()
		}
	}()

	f := newFakeSOCKS5(t, 0)
	ae, _ := NewActiveEgress("socks5://"+f.addr(), 5*time.Second)
	conn, err := ae.DialContext(context.Background(), "tcp", backend.Addr().String())
	if err != nil {
		t.Fatalf("dial through proxy: %v", err)
	}
	buf := make([]byte, 5)
	io.ReadFull(conn, buf)
	conn.Close()
	if string(buf) != "hello" {
		t.Errorf("read %q, want hello", string(buf))
	}
	if seen := f.seen(); len(seen) != 1 || seen[0] != backend.Addr().String() {
		t.Errorf("proxy destinations = %v, want [%s]", seen, backend.Addr().String())
	}
}

// A SOCKS reply about the proxy's own state (general failure) is a ProxyError;
// a relayed "connection refused" from the target is not.
func TestDialErrorClassification(t *testing.T) {
	// Proxy answers every CONNECT with "general SOCKS server failure" (1).
	f := newFakeSOCKS5(t, 1)
	ae, _ := NewActiveEgress("socks5://"+f.addr(), 5*time.Second)
	_, err := ae.DialContext(context.Background(), "tcp", "192.0.2.10:443")
	if !IsProxyError(err) {
		t.Errorf("general SOCKS failure: IsProxyError=false, want true (err=%v)", err)
	}

	// Target refuses: the proxy relays "connection refused". Point the proxy
	// at a closed local port so the upstream dial genuinely fails.
	f2 := newFakeSOCKS5(t, 0)
	ae2, _ := NewActiveEgress("socks5://"+f2.addr(), 5*time.Second)
	closed := closedLocalAddr(t)
	_, err = ae2.DialContext(context.Background(), "tcp", closed)
	if err == nil {
		t.Fatal("expected a dial error to a closed port")
	}
	if IsProxyError(err) {
		t.Errorf("relayed target refusal was misclassified as a proxy error: %v", err)
	}
}

// An unreachable proxy fails, and the failure is a ProxyError. HealthCheck
// surfaces it.
func TestHealthCheckFailsOnDeadProxy(t *testing.T) {
	dead := closedLocalAddr(t)
	ae, err := NewActiveEgress("socks5://"+dead, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	err = ae.HealthCheck(context.Background(), "192.0.2.10:443")
	if err == nil || !IsProxyError(err) {
		t.Errorf("HealthCheck on a dead proxy: want ProxyError, got %v", err)
	}
}

func TestNewActiveEgressEmptyIsNil(t *testing.T) {
	ae, err := NewActiveEgress("  ", 0)
	if err != nil || ae != nil {
		t.Errorf("empty proxy: got (%v, %v), want (nil, nil)", ae, err)
	}
	if _, err := NewActiveEgress("ftp://x:1", 0); err == nil {
		t.Error("unsupported scheme should error")
	}
}

func TestProxyErrorUnwrap(t *testing.T) {
	base := errors.New("boom")
	pe := &ProxyError{err: base}
	if !errors.Is(pe, base) {
		t.Error("ProxyError should unwrap to its cause")
	}
}

// closedLocalAddr returns a host:port that nothing is listening on.
func closedLocalAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}
