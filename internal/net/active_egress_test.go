// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package net

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestNewActiveEgress_EmptyReturnsNil(t *testing.T) {
	ae, err := NewActiveEgress("", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ae != nil {
		t.Fatalf("expected nil ActiveEgress for empty URL, got %+v", ae)
	}
}

func TestNewActiveEgress_InvalidScheme(t *testing.T) {
	if _, err := NewActiveEgress("ftp://example:21", 0); err == nil {
		t.Fatalf("expected error for unsupported scheme")
	}
}

func TestActiveDNSExchange_ErrNoActiveEgress(t *testing.T) {
	_, err := ActiveDNSExchange(context.Background(), nil, "1.1.1.1:53", new(dns.Msg))
	if !errors.Is(err, ErrNoActiveEgress) {
		t.Fatalf("expected ErrNoActiveEgress, got %v", err)
	}
}

// fakeHTTPConnectProxy is a minimal HTTP CONNECT proxy that pipes the tunnel
// to a goroutine-controlled target. It exists purely so that the active
// egress dialer test does not need real network access.
type fakeHTTPConnectProxy struct {
	ln       net.Listener
	targetLn net.Listener
	wg       sync.WaitGroup
	hits     int32
}

func newFakeProxy(t *testing.T) *fakeHTTPConnectProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	p := &fakeHTTPConnectProxy{ln: ln, targetLn: target}
	p.wg.Add(1)
	go p.serve()
	return p
}

func (p *fakeHTTPConnectProxy) serve() {
	defer p.wg.Done()
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		go p.handle(c)
	}
}

func (p *fakeHTTPConnectProxy) handle(c net.Conn) {
	defer func() { _ = c.Close() }()
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if req.Method != http.MethodConnect {
		_, _ = io.WriteString(c, "HTTP/1.1 405 Method Not Allowed\r\n\r\n")
		return
	}
	atomic.AddInt32(&p.hits, 1)
	upstream, err := net.Dial("tcp", p.targetLn.Addr().String())
	if err != nil {
		_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer func() { _ = upstream.Close() }()
	_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\n\r\n")
	// Splice the two connections.
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, c); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, upstream); done <- struct{}{} }()
	<-done
}

func (p *fakeHTTPConnectProxy) Close() {
	_ = p.ln.Close()
	_ = p.targetLn.Close()
}

func (p *fakeHTTPConnectProxy) acceptTarget() (net.Conn, error) {
	return p.targetLn.Accept()
}

func TestActiveEgress_HTTPConnect_TunnelsTCP(t *testing.T) {
	p := newFakeProxy(t)
	defer p.Close()

	ae, err := NewActiveEgress("http://"+p.ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("NewActiveEgress: %v", err)
	}
	if ae == nil || ae.DialContext == nil {
		t.Fatalf("expected dialer")
	}

	// Server side: accept on the proxy's target socket and echo a marker.
	srvDone := make(chan struct{})
	go func() {
		defer close(srvDone)
		c, err := p.acceptTarget()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_, _ = io.WriteString(c, "HELLO\n")
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn, err := ae.DialContext(ctx, "tcp", "example.invalid:9999")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := string(buf[:n]); !strings.Contains(got, "HELLO") {
		t.Fatalf("unexpected tunneled payload: %q", got)
	}
	<-srvDone

	if atomic.LoadInt32(&p.hits) != 1 {
		t.Fatalf("expected exactly one CONNECT hit, got %d", p.hits)
	}
}

func TestActiveEgress_HTTPClient_RoutesThroughProxy(t *testing.T) {
	// Origin server records the host header.
	gotHost := make(chan string, 1)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost <- r.Host
		_, _ = w.Write([]byte("ok"))
	}))
	defer origin.Close()
	originURL, _ := url.Parse(origin.URL)

	// Proxy: forwards plain HTTP (no CONNECT) to the origin so we can test
	// that Transport.Proxy was honored.
	proxySeen := make(chan string, 1)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxySeen <- r.URL.String()
		// Forward the request to the origin without preserving original
		// behaviour — this is enough to prove the request went through us.
		r.URL = originURL
		r.RequestURI = ""
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.Copy(w, resp.Body)
	}))
	defer proxy.Close()

	ae, err := NewActiveEgress(proxy.URL, time.Second)
	if err != nil {
		t.Fatalf("NewActiveEgress: %v", err)
	}
	if ae == nil || ae.Client == nil {
		t.Fatalf("expected active client")
	}

	// Use a plain http:// URL so the Transport sends it through the proxy
	// (CONNECT would only be triggered for https).
	resp, err := ae.Client.Get("http://example.invalid/probe")
	if err != nil {
		t.Fatalf("client.Get: %v", err)
	}
	_ = resp.Body.Close()

	select {
	case <-proxySeen:
	case <-time.After(2 * time.Second):
		t.Fatalf("active proxy was not used")
	}
	// gotHost should have been hit by the proxy forwarding to origin.
	select {
	case <-gotHost:
	case <-time.After(2 * time.Second):
		t.Fatalf("origin was not reached via proxy")
	}
}
