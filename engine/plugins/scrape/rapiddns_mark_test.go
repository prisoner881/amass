// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scrape

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
	oamdns "github.com/owasp-amass/open-asset-model/dns"
)

// RapidDNS marks a name monitored only when the page was served. The
// harness matches engine/plugins/api/lookup_mark_test.go.

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
// requests are answered by resps.
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

func TestRapidDNSMarkedOnlyWhenPageServed(t *testing.T) {
	cases := []struct {
		name       string
		resp       fakeResp
		wantMarked bool
	}{
		{"page", fakeResp{200, `<td>www.example.com</td>`}, true},
		{"page without names", fakeResp{200, `<html>none</html>`}, true},
		{"server error", fakeResp{503, "busy"}, false},
		{"blocked", fakeResp{403, "denied"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := NewRapidDNS().(*rapidDNS)
			p.log = discardLog()
			e, ft := newMarkTestEvent(t, c.resp)
			if err := p.check(e); err != nil {
				t.Fatalf("check returned an error: %v", err)
			}
			if ft.calls == 0 {
				t.Fatal("the plugin made no request")
			}
			if got := marked(e, p.source); got != c.wantMarked {
				t.Errorf("marked = %v, want %v", got, c.wantMarked)
			}
		})
	}
}
