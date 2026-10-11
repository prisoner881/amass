// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package whois

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	whoisparser "github.com/likexian/whois-parser"
	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
)

// These tests run fqdnLookup.check() against a fake RDAP server and a fake
// port-43 WHOIS, and assert that the domain is marked monitored only when
// the lookup completed.

const (
	whoisNoMatch = "No match for \"EXAMPLE.COM\".\n>>> Last update of whois database: 2026-10-11T00:00:00Z <<<\n"
	whoisLimit   = "WHOIS LIMIT EXCEEDED - SEE WWW.PIR.ORG/WHOIS FOR DETAILS\n"
	rdapDomain   = `{"objectClassName":"domain","ldhName":"EXAMPLE.COM","status":["active"],
		"events":[{"eventAction":"registration","eventDate":"2000-01-01T00:00:00Z"},
		{"eventAction":"last changed","eventDate":"2026-01-01T00:00:00Z"}]}`
)

type rdapReply struct {
	status int
	body   string
}

type fakeRDAP struct {
	reply rdapReply
	calls int
}

func (f *fakeRDAP) RoundTrip(req *http.Request) (*http.Response, error) {
	f.calls++
	return &http.Response{
		StatusCode: f.reply.status,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader(f.reply.body)),
		Request:    req,
	}, nil
}

type noopSem struct{}

func (noopSem) Acquire()   {}
func (noopSem) Release()   {}
func (noopSem) InUse() int { return 0 }
func (noopSem) Cap() int   { return 1 }

type whoisTestSession struct {
	et.Session
	db      repository.Repository
	cfg     *config.Config
	clients *et.SessionHTTPClients
}

func (s *whoisTestSession) Ctx() context.Context            { return context.Background() }
func (s *whoisTestSession) Log() *slog.Logger               { return discardLog() }
func (s *whoisTestSession) NetSem() et.SessionSemaphone     { return noopSem{} }
func (s *whoisTestSession) Config() *config.Config          { return s.cfg }
func (s *whoisTestSession) DB() repository.Repository       { return s.db }
func (s *whoisTestSession) Clients() *et.SessionHTTPClients { return s.clients }
func (s *whoisTestSession) Done() bool                      { return false }

type nopDispatcher struct{ et.Dispatcher }

func (nopDispatcher) DispatchEvent(*et.Event) error { return nil }

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// The IANA bootstrap is fetched once per process; seed it so no test goes
// to the network. Only "com" has an RDAP server here.
func seedRDAPBootstrap() {
	bootstrapOnce.Do(func() {
		bootstrapMap = map[string][]string{"com": {"https://rdap.test/"}}
	})
}

// newWhoisTest returns the handler and an event for example.com whose RDAP
// request gets rdap and whose port-43 query returns whoisReply / whoisErr.
func newWhoisTest(t *testing.T, rdap rdapReply, whoisReply string, whoisErr error) (*fqdnLookup, *et.Event, *fakeRDAP) {
	t.Helper()
	seedRDAPBootstrap()

	orig := whoisQuery
	whoisQuery = func(string) (string, error) { return whoisReply, whoisErr }
	t.Cleanup(func() { whoisQuery = orig })

	db, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "assets.db"))
	if err != nil {
		t.Fatalf("failed to open the test asset database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	cfg := config.NewConfig()
	cfg.Transformations = map[string]*config.Transformation{
		"FQDN->ALL": {From: "fqdn", To: "all", TTL: 1440},
	}
	ft := &fakeRDAP{reply: rdap}
	s := &whoisTestSession{db: db, cfg: cfg, clients: &et.SessionHTTPClients{General: &http.Client{Transport: ft}}}

	ent, err := db.CreateAsset(context.Background(), &oamdns.FQDN{Name: "example.com"})
	if err != nil {
		t.Fatal(err)
	}

	w := NewWHOIS().(*whois)
	w.log = discardLog()
	r := &fqdnLookup{name: w.name + "-Handler", plugin: w}
	return r, &et.Event{Name: "example.com", Entity: ent, Session: s, Dispatcher: nopDispatcher{}}, ft
}

func marked(e *et.Event, src *et.Source) bool {
	return support.AssetMonitoredWithinTTL(e.Session, e.Entity, src, time.Now().Add(-time.Hour))
}

func storedDomainRecord(e *et.Event) bool {
	ents, err := e.Session.DB().FindEntitiesByContent(context.Background(), oam.DomainRecord, time.Time{}, 1,
		dbt.ContentFilters{"domain": "example.com"})
	return err == nil && len(ents) > 0
}

func TestWHOISTestRepliesParseAsExpected(t *testing.T) {
	if _, err := whoisparser.Parse(whoisNoMatch); !errors.Is(err, whoisparser.ErrNotFoundDomain) {
		t.Errorf("no-match reply parsed with %v, want ErrNotFoundDomain", err)
	}
	if _, err := whoisparser.Parse(whoisLimit); !errors.Is(err, whoisparser.ErrDomainLimitExceed) {
		t.Errorf("limit reply parsed with %v, want ErrDomainLimitExceed", err)
	}
}

func TestWHOISMarkedOnlyWhenAnswered(t *testing.T) {
	cases := []struct {
		name       string
		rdap       rdapReply
		whois      string
		whoisErr   error
		wantMarked bool
		wantRecord bool
	}{
		{"RDAP record", rdapReply{200, rdapDomain}, "", errors.New("unused"), true, true},
		{"RDAP 404, WHOIS unreachable", rdapReply{404, `{"errorCode":404}`}, "", errors.New("connection refused"), true, false},
		{"RDAP 404, WHOIS no match", rdapReply{404, `{"errorCode":404}`}, whoisNoMatch, nil, true, false},
		{"RDAP down, WHOIS no match", rdapReply{503, "busy"}, whoisNoMatch, nil, true, false},
		{"RDAP down, WHOIS unreachable", rdapReply{503, "busy"}, "", errors.New("connection refused"), false, false},
		{"RDAP rate limited, WHOIS limit", rdapReply{429, "slow down"}, whoisLimit, nil, false, false},
		{"RDAP undecodable, WHOIS unreachable", rdapReply{200, "<html>"}, "", errors.New("timeout"), false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, e, ft := newWhoisTest(t, c.rdap, c.whois, c.whoisErr)
			if err := r.check(e); err != nil {
				t.Fatalf("check returned an error: %v", err)
			}
			if ft.calls != 1 {
				t.Fatalf("made %d RDAP requests, want 1", ft.calls)
			}
			if got := marked(e, r.plugin.source); got != c.wantMarked {
				t.Errorf("marked = %v, want %v", got, c.wantMarked)
			}
			if got := storedDomainRecord(e); got != c.wantRecord {
				t.Errorf("DomainRecord stored = %v, want %v", got, c.wantRecord)
			}
		})
	}
}

func TestWHOISAnswered(t *testing.T) {
	for _, c := range []struct {
		err  error
		want bool
	}{
		{nil, false},
		{whoisparser.ErrNotFoundDomain, true},
		{whoisparser.ErrReservedDomain, true},
		{whoisparser.ErrPremiumDomain, true},
		{whoisparser.ErrBlockedDomain, true},
		{errWHOISDomainMismatch, true},
		{whoisparser.ErrDomainLimitExceed, false},
		{whoisparser.ErrDomainDataInvalid, false},
		{errors.New("WHOIS: empty response"), false},
		{context.DeadlineExceeded, false},
	} {
		if got := whoisAnswered(c.err); got != c.want {
			t.Errorf("whoisAnswered(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}
