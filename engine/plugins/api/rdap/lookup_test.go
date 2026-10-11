// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package rdap

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openrdap/rdap"
	"github.com/openrdap/rdap/bootstrap"
	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/network"
)

func TestRDAPLookupFailureClassification(t *testing.T) {
	answered := []error{
		nil,
		&rdap.ClientError{Type: rdap.ObjectDoesNotExist},
		&rdap.ClientError{Type: rdap.BootstrapNoMatch},
		&rdap.ClientError{Type: rdap.BootstrapNotSupported},
		&rdap.ClientError{Type: rdap.InputError},
	}
	for _, err := range answered {
		if reason := rdapLookupFailure(err); reason != "" {
			t.Errorf("%v: got failure %q, want an answer", err, reason)
		}
	}
	failed := []error{
		&rdap.ClientError{Type: rdap.NoWorkingServers, Text: "no servers"},
		&rdap.ClientError{Type: rdap.RDAPServerError, Text: "server error"},
		context.DeadlineExceeded,
		errors.New("bootstrap download failed"),
	}
	for _, err := range failed {
		if rdapLookupFailure(err) == "" {
			t.Errorf("%v: got an answer, want a failure", err)
		}
	}
}

const (
	ipv4Bootstrap = `{"version":"1.0","publication":"2026-01-01T00:00:00Z",
		"services":[[["192.0.2.0/24"],["https://rdap.test/"]]]}`
	asnBootstrap = `{"version":"1.0","publication":"2026-01-01T00:00:00Z",
		"services":[[["64496-64511"],["https://rdap.test/"]]]}`
	ipNetworkBody = `{"objectClassName":"ip network","handle":"NET-192-0-2-0-1",
		"startAddress":"192.0.2.0","endAddress":"192.0.2.255","ipVersion":"v4","name":"TEST-NET",
		"type":"ASSIGNMENT","events":[{"eventAction":"registration","eventDate":"2000-01-01T00:00:00Z"},
		{"eventAction":"last changed","eventDate":"2026-01-01T00:00:00Z"}]}`
	autnumBody = `{"objectClassName":"autnum","handle":"AS64500","startAutnum":64500,"endAutnum":64500,
		"name":"TEST-AS","events":[{"eventAction":"registration","eventDate":"2000-01-01T00:00:00Z"},
		{"eventAction":"last changed","eventDate":"2026-01-01T00:00:00Z"}]}`
)

type reply struct {
	status int
	body   string
}

// fakeRegistry serves the IANA bootstrap files from iana.test and answers
// every RDAP query on rdap.test with one reply.
type fakeRegistry struct {
	mu        sync.Mutex
	bootstrap reply // overrides the bootstrap files when status is set
	rdap      reply
	queries   int
}

func (f *fakeRegistry) RoundTrip(req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	r := f.rdap
	switch {
	case req.URL.Host == "iana.test" && f.bootstrap.status != 0:
		r = f.bootstrap
	case req.URL.Host == "iana.test" && strings.HasSuffix(req.URL.Path, "ipv4.json"):
		r = reply{200, ipv4Bootstrap}
	case req.URL.Host == "iana.test" && strings.HasSuffix(req.URL.Path, "asn.json"):
		r = reply{200, asnBootstrap}
	case req.URL.Host == "iana.test":
		r = reply{404, ""}
	default:
		f.queries++
	}
	return &http.Response{
		StatusCode: r.status,
		Header:     http.Header{"Content-Type": []string{"application/rdap+json"}},
		Body:       io.NopCloser(strings.NewReader(r.body)),
		Request:    req,
	}, nil
}

type rdapTestSession struct {
	et.Session
	db  repository.Repository
	cfg *config.Config
}

func (s *rdapTestSession) Ctx() context.Context      { return context.Background() }
func (s *rdapTestSession) Log() *slog.Logger         { return discardLog() }
func (s *rdapTestSession) Config() *config.Config    { return s.cfg }
func (s *rdapTestSession) DB() repository.Repository { return s.db }
func (s *rdapTestSession) Done() bool                { return false }

type nopDispatcher struct{ et.Dispatcher }

func (nopDispatcher) DispatchEvent(*et.Event) error { return nil }

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// newRDAPTest returns a plugin whose RDAP client talks to reg, and an event
// for the given asset.
func newRDAPTest(t *testing.T, reg *fakeRegistry, asset oam.Asset) (*rdapPlugin, *et.Event) {
	t.Helper()
	db, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "assets.db"))
	if err != nil {
		t.Fatalf("failed to open the test asset database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	cfg := config.NewConfig()
	cfg.Transformations = map[string]*config.Transformation{
		"Netblock->ALL":         {From: "netblock", To: "all", TTL: 43200},
		"AutonomousSystem->ALL": {From: "autonomoussystem", To: "all", TTL: 43200},
	}

	ent, err := db.CreateAsset(context.Background(), asset)
	if err != nil {
		t.Fatal(err)
	}

	hc := &http.Client{Transport: reg}
	base, _ := url.Parse("https://iana.test/")
	p := NewRDAP().(*rdapPlugin)
	p.log = discardLog()
	p.client = &rdap.Client{HTTP: hc, Bootstrap: &bootstrap.Client{HTTP: hc, BaseURL: base}}
	p.netblock = &netblock{name: p.name + "-Netblock-Handler", plugin: p}
	p.autsys = &autsys{name: p.name + "-Autsys-Handler", plugin: p}

	return p, &et.Event{Entity: ent, Session: &rdapTestSession{db: db, cfg: cfg}, Dispatcher: nopDispatcher{}}
}

func marked(e *et.Event, src *et.Source) bool {
	return support.AssetMonitoredWithinTTL(e.Session, e.Entity, src, time.Now().Add(-time.Hour))
}

func stored(e *et.Event, atype oam.AssetType, filters dbt.ContentFilters) bool {
	ents, err := e.Session.DB().FindEntitiesByContent(context.Background(), atype, time.Time{}, 1, filters)
	return err == nil && len(ents) > 0
}

func TestRDAPNetblockMarkedOnlyWhenAnswered(t *testing.T) {
	cases := []struct {
		name       string
		cidr       string
		bootstrap  reply
		rdap       reply
		wantMarked bool
		wantRecord bool
	}{
		{"record", "192.0.2.0/24", reply{}, reply{200, ipNetworkBody}, true, true},
		{"object does not exist", "192.0.2.0/24", reply{}, reply{404, ""}, true, false},
		{"no RDAP server covers it", "198.51.100.0/24", reply{}, reply{200, ipNetworkBody}, true, false},
		{"server error", "192.0.2.0/24", reply{}, reply{503, "busy"}, false, false},
		{"rate limited", "192.0.2.0/24", reply{}, reply{429, "slow down"}, false, false},
		{"bootstrap unavailable", "192.0.2.0/24", reply{500, "down"}, reply{200, ipNetworkBody}, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reg := &fakeRegistry{bootstrap: c.bootstrap, rdap: c.rdap}
			p, e := newRDAPTest(t, reg, &network.Netblock{CIDR: netip.MustParsePrefix(c.cidr), Type: "IPv4"})
			if err := p.netblock.check(e); err != nil {
				t.Fatalf("check returned an error: %v", err)
			}
			if got := marked(e, p.source); got != c.wantMarked {
				t.Errorf("marked = %v, want %v", got, c.wantMarked)
			}
			if got := stored(e, oam.IPNetRecord, dbt.ContentFilters{"cidr": c.cidr}); got != c.wantRecord {
				t.Errorf("IPNetRecord stored = %v, want %v", got, c.wantRecord)
			}
		})
	}
}

func TestRDAPAutsysMarkedOnlyWhenAnswered(t *testing.T) {
	cases := []struct {
		name       string
		rdap       reply
		wantMarked bool
	}{
		{"record", reply{200, autnumBody}, true},
		{"object does not exist", reply{404, ""}, true},
		{"server error", reply{502, "bad gateway"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reg := &fakeRegistry{rdap: c.rdap}
			p, e := newRDAPTest(t, reg, &network.AutonomousSystem{Number: 64500})
			if err := p.autsys.check(e); err != nil {
				t.Fatalf("check returned an error: %v", err)
			}
			if reg.queries != 1 {
				t.Fatalf("made %d RDAP queries, want 1", reg.queries)
			}
			if got := marked(e, p.source); got != c.wantMarked {
				t.Errorf("marked = %v, want %v", got, c.wantMarked)
			}
		})
	}
}
