// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package gleif

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	"golang.org/x/time/rate"
)

type reply struct {
	status int
	body   string
}

// fakeGLEIF answers by the last element of the request path.
type fakeGLEIF struct {
	mu      sync.Mutex
	replies map[string]reply // "fuzzycompletions", "direct-parent", "direct-children", "lei-records"
	calls   map[string]int
}

func (f *fakeGLEIF) RoundTrip(req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	key := "lei-records"
	for _, k := range []string{"fuzzycompletions", "direct-parent", "direct-children"} {
		if strings.HasSuffix(req.URL.Path, k) {
			key = k
		}
	}
	if f.calls == nil {
		f.calls = make(map[string]int)
	}
	f.calls[key]++
	r, ok := f.replies[key]
	if !ok {
		r = reply{404, ""}
	}
	return &http.Response{
		StatusCode: r.status,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader(r.body)),
		Request:    req,
	}, nil
}

// TestMain points the GLEIF helpers at the fake server and lifts the
// 3-second request pacing, which would only slow the tests down.
func TestMain(m *testing.M) {
	gleifBaseURL = "https://gleif.test/api/v1"
	gleifLimit = rate.NewLimiter(rate.Inf, 1)
	os.Exit(m.Run())
}

func useFake(t *testing.T, replies map[string]reply) *fakeGLEIF {
	t.Helper()
	f := &fakeGLEIF{replies: replies}
	gleifClient = &http.Client{Transport: f}
	t.Cleanup(func() { gleifClient = nil })
	return f
}

const (
	leiID      = "5493001KJTIIGC8Y1R12"
	leiRecord  = `{"data":{"type":"lei-records","id":"5493001KJTIIGC8Y1R12","attributes":{"lei":"5493001KJTIIGC8Y1R12"}}}`
	noChildren = `{"meta":{"pagination":{"currentPage":1,"lastPage":1}},"links":{"next":""},"data":[]}`
	noMatches  = `{"data":[]}`
)

func TestGLEIFHelperOutcomes(t *testing.T) {
	ctx := context.Background()

	useFake(t, map[string]reply{"lei-records": {404, ""}})
	if _, err := GLEIFGetLEIRecord(ctx, leiID); !errors.Is(err, ErrGLEIFNotFound) {
		t.Errorf("404: got %v, want ErrGLEIFNotFound", err)
	}

	useFake(t, map[string]reply{"lei-records": {503, "busy"}})
	if _, err := GLEIFGetLEIRecord(ctx, leiID); err == nil || errors.Is(err, ErrGLEIFNotFound) {
		t.Errorf("503: got %v, want a failure that is not ErrGLEIFNotFound", err)
	}

	useFake(t, map[string]reply{"lei-records": {200, `{"data":{"type":"lei-records","id":"OTHER"}}`}})
	if _, err := GLEIFGetLEIRecord(ctx, leiID); !errors.Is(err, ErrGLEIFNotFound) {
		t.Errorf("another record: got %v, want ErrGLEIFNotFound", err)
	}

	useFake(t, map[string]reply{"lei-records": {200, leiRecord}})
	if rec, err := GLEIFGetLEIRecord(ctx, leiID); err != nil || rec == nil || rec.ID != leiID {
		t.Errorf("record: got %v, %v", rec, err)
	}

	useFake(t, map[string]reply{"fuzzycompletions": {200, noMatches}})
	if _, err := GLEIFSearchFuzzyCompletions(ctx, "Example Corp"); !errors.Is(err, ErrGLEIFNotFound) {
		t.Errorf("search without results: got %v, want ErrGLEIFNotFound", err)
	}

	useFake(t, map[string]reply{"fuzzycompletions": {429, `{"errors":[{"status":"429"}]}`}})
	if _, err := GLEIFSearchFuzzyCompletions(ctx, "Example Corp"); err == nil || errors.Is(err, ErrGLEIFNotFound) {
		t.Errorf("rate limited search: got %v, want a failure that is not ErrGLEIFNotFound", err)
	}

	useFake(t, map[string]reply{"direct-children": {200, noChildren}})
	if kids, err := GLEIFGetDirectChildrenRecords(ctx, leiID); err != nil || len(kids) != 0 {
		t.Errorf("no children: got %v, %v", kids, err)
	}
}

type gleifTestSession struct {
	et.Session
	db  repository.Repository
	cfg *config.Config
}

func (s *gleifTestSession) Ctx() context.Context      { return context.Background() }
func (s *gleifTestSession) Log() *slog.Logger         { return slog.New(slog.NewTextHandler(io.Discard, nil)) }
func (s *gleifTestSession) Config() *config.Config    { return s.cfg }
func (s *gleifTestSession) DB() repository.Repository { return s.db }
func (s *gleifTestSession) Done() bool                { return false }

type nopDispatcher struct{ et.Dispatcher }

func (nopDispatcher) DispatchEvent(*et.Event) error { return nil }

func newGLEIFTest(t *testing.T) (*gleif, *gleifTestSession) {
	t.Helper()
	db, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "assets.db"))
	if err != nil {
		t.Fatalf("failed to open the test asset database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	cfg := config.NewConfig()
	cfg.Transformations = map[string]*config.Transformation{
		"Organization->ALL": {From: "organization", To: "all", TTL: 43200},
		"Identifier->ALL":   {From: "identifier", To: "all", TTL: 43200},
	}

	g := NewGLEIF().(*gleif)
	g.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	g.fuzzy = &fuzzyCompletions{name: g.name + "-Fuzzy-Handler", plugin: g}
	g.related = &relatedOrgs{name: g.name + "-Related-Handler", plugin: g}
	return g, &gleifTestSession{db: db, cfg: cfg}
}

func marked(e *et.Event, src *et.Source) bool {
	return support.AssetMonitoredWithinTTL(e.Session, e.Entity, src, time.Now().Add(-time.Hour))
}

func TestGLEIFFuzzyMarkedOnlyWhenAnswered(t *testing.T) {
	for _, c := range []struct {
		name       string
		search     reply
		wantMarked bool
	}{
		{"no matching organization", reply{200, noMatches}, true},
		{"server error", reply{503, "busy"}, false},
		{"rate limited", reply{429, "slow down"}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := useFake(t, map[string]reply{"fuzzycompletions": c.search})
			g, s := newGLEIFTest(t)
			ent, err := s.db.CreateAsset(context.Background(), &oamorg.Organization{ID: "example-corp", Name: "Example Corp"})
			if err != nil {
				t.Fatal(err)
			}
			e := &et.Event{Entity: ent, Session: s, Dispatcher: nopDispatcher{}}
			if err := g.fuzzy.check(e); err != nil {
				t.Fatalf("check returned an error: %v", err)
			}
			if f.calls["fuzzycompletions"] != 1 {
				t.Fatalf("made %d searches, want 1", f.calls["fuzzycompletions"])
			}
			if got := marked(e, g.source); got != c.wantMarked {
				t.Errorf("marked = %v, want %v", got, c.wantMarked)
			}
		})
	}
}

func TestGLEIFRelatedMarkedOnlyWhenAnswered(t *testing.T) {
	for _, c := range []struct {
		name       string
		parent     reply
		children   reply
		wantMarked bool
	}{
		{"no parent, no children", reply{404, ""}, reply{200, noChildren}, true},
		{"parent request failed", reply{503, "busy"}, reply{200, noChildren}, false},
		{"children request failed", reply{404, ""}, reply{500, "error"}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := useFake(t, map[string]reply{"direct-parent": c.parent, "direct-children": c.children})
			g, s := newGLEIFTest(t)
			ent, err := s.db.CreateAsset(context.Background(), &oamgen.Identifier{
				UniqueID: oamgen.LEICode + ":" + leiID, ID: leiID, Type: oamgen.LEICode,
			})
			if err != nil {
				t.Fatal(err)
			}
			e := &et.Event{Entity: ent, Session: s, Dispatcher: nopDispatcher{}}
			if err := g.related.check(e); err != nil {
				t.Fatalf("check returned an error: %v", err)
			}
			if f.calls["direct-parent"] != 1 || f.calls["direct-children"] != 1 {
				t.Fatalf("calls = %v, want one parent and one children request", f.calls)
			}
			if got := marked(e, g.source); got != c.wantMarked {
				t.Errorf("marked = %v, want %v", got, c.wantMarked)
			}
		})
	}
}
