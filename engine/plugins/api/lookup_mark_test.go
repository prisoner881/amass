// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	"github.com/owasp-amass/amass/v5/engine/sessions/scope"
	et "github.com/owasp-amass/amass/v5/engine/types"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
)

// These tests run each plugin's real check() against canned HTTP responses
// and a SQLite asset database, and assert the rule the plugins share: the
// queried name is marked monitored only when the source answered.

type fakeResp struct {
	status int
	body   string
}

// fakeTransport answers requests from a queue; the last entry repeats.
type fakeTransport struct {
	mu    sync.Mutex
	resps []fakeResp
	calls int
}

func (f *fakeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.resps[min(f.calls, len(f.resps)-1)]
	f.calls++
	return &http.Response{
		StatusCode: r.status,
		Status:     http.StatusText(r.status),
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader(r.body)),
		Request:    req,
	}, nil
}

type noopSem struct{}

func (noopSem) Acquire()   {}
func (noopSem) Release()   {}
func (noopSem) InUse() int { return 0 }
func (noopSem) Cap() int   { return 1 }

type markTestSession struct {
	et.Session
	db      repository.Repository
	cfg     *config.Config
	scope   et.Scope
	clients *et.SessionHTTPClients
}

func (s *markTestSession) Ctx() context.Context            { return context.Background() }
func (s *markTestSession) Log() *slog.Logger               { return discardLog() }
func (s *markTestSession) NetSem() et.SessionSemaphone     { return noopSem{} }
func (s *markTestSession) Config() *config.Config          { return s.cfg }
func (s *markTestSession) Scope() et.Scope                 { return s.scope }
func (s *markTestSession) DB() repository.Repository       { return s.db }
func (s *markTestSession) Clients() *et.SessionHTTPClients { return s.clients }
func (s *markTestSession) Done() bool                      { return false }

type nopDispatcher struct{ et.Dispatcher }

func (nopDispatcher) DispatchEvent(*et.Event) error { return nil }

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// newMarkTestEvent returns an FQDN event for example.com whose HTTP
// requests are answered by resps. Every source gets an API key.
func newMarkTestEvent(t *testing.T, resps ...fakeResp) (*et.Event, *fakeTransport) {
	t.Helper()
	db, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "assets.db"))
	if err != nil {
		t.Fatalf("failed to open the test asset database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	cfg := config.NewConfig()
	cfg.AddDomains("example.com")
	cfg.Transformations = map[string]*config.Transformation{
		"FQDN->ALL": {From: "fqdn", To: "all", TTL: 1440},
	}
	for _, name := range []string{"URLScan", "DNSDumpster", "CertSpotter", "AlienVault"} {
		cfg.DataSrcConfigs.Datasources = append(cfg.DataSrcConfigs.Datasources, &config.DataSource{
			Name:  name,
			Creds: map[string]*config.Credentials{"account": {Apikey: "test-key"}},
		})
	}

	ft := &fakeTransport{resps: resps}
	s := &markTestSession{
		db:      db,
		cfg:     cfg,
		clients: &et.SessionHTTPClients{General: &http.Client{Transport: ft}},
	}
	s.scope = scope.CreateFromConfigScope(s)

	ent, err := db.CreateAsset(context.Background(), &oamdns.FQDN{Name: "example.com"})
	if err != nil {
		t.Fatalf("failed to create the FQDN entity: %v", err)
	}
	return &et.Event{
		Name:       "example.com",
		Entity:     ent,
		Meta:       &support.FQDNMeta{SLDInScope: true},
		Session:    s,
		Dispatcher: nopDispatcher{},
	}, ft
}

func marked(e *et.Event, src *et.Source) bool {
	return support.AssetMonitoredWithinTTL(e.Session, e.Entity, src, time.Now().Add(-time.Hour))
}

func storedFQDN(t *testing.T, e *et.Event, name string) bool {
	t.Helper()
	found, err := e.Session.DB().FindEntitiesByContent(context.Background(), oam.FQDN, time.Time{}, 1,
		dbt.ContentFilters{"name": name})
	return err == nil && len(found) > 0
}

type markCase struct {
	name       string
	resps      []fakeResp
	wantMarked bool
}

type markPlugin struct {
	plugin string
	// setup builds the plugin and returns its check callback and source.
	setup func() (func(*et.Event) error, *et.Source)
	cases []markCase
}

var (
	ok200 = func(body string) fakeResp { return fakeResp{200, body} }
	fail  = func(status int) fakeResp { return fakeResp{status, "error"} }
)

func markPlugins() []markPlugin {
	return []markPlugin{
		{"crt.sh", func() (func(*et.Event) error, *et.Source) {
			p := NewCrtsh().(*crtsh)
			p.log = discardLog()
			return p.check, p.source
		}, []markCase{
			{"answer", []fakeResp{ok200(`[{"name_value":"www.example.com"}]`)}, true},
			{"no certificates", []fakeResp{ok200(`[]`)}, true},
			{"server error", []fakeResp{fail(502)}, false},
			{"not JSON", []fakeResp{ok200(`<html>busy</html>`)}, false},
		}},
		{"HackerTarget", func() (func(*et.Event) error, *et.Source) {
			p := NewHackerTarget().(*hackerTarget)
			p.log = discardLog()
			return p.check, p.source
		}, []markCase{
			{"answer", []fakeResp{ok200("www.example.com,192.0.2.1\n")}, true},
			{"quota exceeded", []fakeResp{ok200("API count exceeded - Increase Quota with Membership")}, false},
			// Unchanged: other plain-text replies are taken as the answer.
			{"plain-text error", []fakeResp{ok200("error check your search parameter")}, true},
			{"server error", []fakeResp{fail(500)}, false},
		}},
		{"URLScan", func() (func(*et.Event) error, *et.Source) {
			p := NewURLScan().(*urlscan)
			p.log = discardLog()
			return p.checkFQDN, p.source
		}, []markCase{
			{"answer", []fakeResp{ok200(`{"results":[{"page":{"domain":"www.example.com"}}],"total":1}`)}, true},
			{"no results", []fakeResp{ok200(`{"results":[],"total":0}`)}, true},
			{"key rejected", []fakeResp{fail(401)}, false},
			{"quota", []fakeResp{fail(429)}, false},
		}},
		{"SubdomainCenter", func() (func(*et.Event) error, *et.Source) {
			p := NewSubdomainCenter().(*subdomainCenter)
			p.log = discardLog()
			return p.check, p.source
		}, []markCase{
			{"answer", []fakeResp{ok200(`["www.example.com"]`)}, true},
			{"server error", []fakeResp{fail(503)}, false},
			{"not JSON", []fakeResp{ok200(`oops`)}, false},
		}},
		{"DNSDumpster", func() (func(*et.Event) error, *et.Source) {
			p := NewDNSDumpster().(*dnsDumpster)
			p.log = discardLog()
			return p.check, p.source
		}, []markCase{
			{"answer", []fakeResp{ok200(`{"a":[{"host":"www.example.com"}]}`)}, true},
			{"rate limited", []fakeResp{fail(429)}, false},
			{"API error", []fakeResp{ok200(`{"error":"too many requests"}`)}, false},
		}},
		{"CertSpotter", func() (func(*et.Event) error, *et.Source) {
			p := NewCertSpotter().(*certSpotter)
			p.log = discardLog()
			return p.check, p.source
		}, []markCase{
			{"all pages", []fakeResp{ok200(`[{"id":"1","dns_names":["www.example.com"]}]`), ok200(`[]`)}, true},
			{"rate limited", []fakeResp{fail(429)}, false},
			{"second page fails", []fakeResp{ok200(`[{"id":"1","dns_names":["www.example.com"]}]`), fail(500)}, false},
		}},
		{"AlienVault", func() (func(*et.Event) error, *et.Source) {
			p := NewAlienVault().(*alienVault)
			p.log = discardLog()
			return p.check, p.source
		}, []markCase{
			{"answer", []fakeResp{ok200(`{"passive_dns":[{"hostname":"www.example.com"}]}`)}, true},
			{"key rejected", []fakeResp{fail(403)}, false},
			{"server error", []fakeResp{fail(500)}, false},
		}},
		{"DNSRepo", func() (func(*et.Event) error, *et.Source) {
			p := NewDNSRepo().(*dnsrepo)
			p.log = discardLog()
			return p.check, p.source
		}, []markCase{
			{"public page", []fakeResp{ok200(`<td>www.example.com.</td>`)}, true},
			{"server error", []fakeResp{fail(500)}, false},
		}},
		{"IP-THC", func() (func(*et.Event) error, *et.Source) {
			p := NewIPTHC().(*ipTHC)
			p.log = discardLog()
			return p.checkFQDN, p.source
		}, []markCase{
			{"answer", []fakeResp{ok200("domain\nwww.example.com\n")}, true},
			{"blocked", []fakeResp{fail(403)}, false},
			// Unchanged: any other status is THC's answer for the key.
			{"not found", []fakeResp{fail(404)}, true},
		}},
	}
}

func TestLookupMarkedOnlyWhenSourceAnswered(t *testing.T) {
	for _, mp := range markPlugins() {
		for _, c := range mp.cases {
			t.Run(mp.plugin+"/"+c.name, func(t *testing.T) {
				t.Parallel()
				check, src := mp.setup()
				e, ft := newMarkTestEvent(t, c.resps...)
				if err := check(e); err != nil {
					t.Fatalf("check returned an error: %v", err)
				}
				if ft.calls == 0 {
					t.Fatal("the plugin made no request")
				}
				if got := marked(e, src); got != c.wantMarked {
					t.Errorf("marked = %v, want %v", got, c.wantMarked)
				}
			})
		}
	}
}

// Names from the pages fetched before a failure are kept even though the
// name is left unmarked.
func TestCertSpotterKeepsPagesBeforeFailure(t *testing.T) {
	p := NewCertSpotter().(*certSpotter)
	p.log = discardLog()
	e, _ := newMarkTestEvent(t, ok200(`[{"id":"1","dns_names":["www.example.com"]}]`), fail(500))
	if err := p.check(e); err != nil {
		t.Fatalf("check returned an error: %v", err)
	}
	if marked(e, p.source) {
		t.Error("marked after a failed page")
	}
	if !storedFQDN(t, e, "www.example.com") {
		t.Error("the name from the first page was not stored")
	}
}

// A name already marked within the TTL is not queried again.
func TestMarkedNameIsNotQueriedAgain(t *testing.T) {
	p := NewCrtsh().(*crtsh)
	p.log = discardLog()
	e, ft := newMarkTestEvent(t, ok200(`[]`))
	_ = p.check(e)
	_ = p.check(e)
	if ft.calls != 1 {
		t.Errorf("made %d requests, want 1", ft.calls)
	}
}

// After a failure the next check queries again.
func TestFailedLookupIsRetried(t *testing.T) {
	p := NewCrtsh().(*crtsh)
	p.log = discardLog()
	e, ft := newMarkTestEvent(t, fail(502), ok200(`[]`))
	_ = p.check(e)
	_ = p.check(e)
	if ft.calls != 2 || !marked(e, p.source) {
		t.Errorf("calls = %d, marked = %v; want 2 calls and marked after the retry", ft.calls, marked(e, p.source))
	}
}
