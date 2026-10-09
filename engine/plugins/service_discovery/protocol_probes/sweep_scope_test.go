// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package protocol_probes

import (
	"context"
	"net/netip"
	"path/filepath"
	"slices"
	"testing"

	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/engine/sessions/scope"
	et "github.com/owasp-amass/amass/v5/engine/types"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	dbt "github.com/owasp-amass/asset-db/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

// sweepTestSession satisfies et.Session for seedScopedIP and
// sweepSeedDomains, which only call Ctx, DB, Config and Scope.
type sweepTestSession struct {
	et.Session
	db    repository.Repository
	cfg   *config.Config
	scope et.Scope
}

func (s *sweepTestSession) Ctx() context.Context      { return context.Background() }
func (s *sweepTestSession) DB() repository.Repository { return s.db }
func (s *sweepTestSession) Config() *config.Config    { return s.cfg }
func (s *sweepTestSession) Scope() et.Scope           { return s.scope }

// newSweepTestSession configures example.com and dev.corp.example.org, then
// adds horizontal.net to the session scope the way horizontal expansion
// does at runtime (it never reaches the config's domain list).
func newSweepTestSession(t *testing.T) *sweepTestSession {
	t.Helper()
	db, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "assets.db"))
	if err != nil {
		t.Fatalf("failed to open the test asset database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	cfg := config.NewConfig()
	cfg.AddDomains("example.com", "dev.corp.example.org")

	s := &sweepTestSession{db: db, cfg: cfg}
	s.scope = scope.CreateFromConfigScope(s)
	s.scope.AddDomain("horizontal.net")
	return s
}

// resolvedIP stores name -dns_record-> addr and returns the IP entity.
func resolvedIP(t *testing.T, s *sweepTestSession, name, addr string) *dbt.Entity {
	t.Helper()
	ctx := context.Background()
	fqdn, err := s.db.CreateAsset(ctx, &oamdns.FQDN{Name: name})
	if err != nil {
		t.Fatalf("failed to create FQDN %s: %v", name, err)
	}
	ip, err := s.db.CreateAsset(ctx, &oamnet.IPAddress{Address: netip.MustParseAddr(addr), Type: "IPv4"})
	if err != nil {
		t.Fatalf("failed to create IP %s: %v", addr, err)
	}
	if _, err := s.db.CreateEdge(ctx, &dbt.Edge{
		Relation:   &oamdns.BasicDNSRelation{Name: "dns_record", Header: oamdns.RRHeader{RRType: 1, Class: 1}},
		FromEntity: fqdn,
		ToEntity:   ip,
	}); err != nil {
		t.Fatalf("failed to link %s to %s: %v", name, addr, err)
	}
	return ip
}

func TestSeedScopedIPIncludesRuntimeScopeDomains(t *testing.T) {
	s := newSweepTestSession(t)

	cases := []struct {
		name, addr string
		want       bool
	}{
		{"www.example.com", "203.0.113.10", true},          // configured domain
		{"api.dev.corp.example.org", "203.0.113.11", true}, // configured subdomain (not in scope's domain list)
		{"mail.horizontal.net", "203.0.113.12", true},      // domain added to scope at runtime
		{"cdn.unrelated.io", "203.0.113.13", false},        // not in scope
	}
	for _, c := range cases {
		if got := seedScopedIP(s, resolvedIP(t, s, c.name, c.addr)); got != c.want {
			t.Errorf("seedScopedIP(%s via %s) = %v, want %v", c.addr, c.name, got, c.want)
		}
	}
}

func TestSweepSeedDomainsUnionsConfigAndScope(t *testing.T) {
	s := newSweepTestSession(t)

	got := sweepSeedDomains(s)
	slices.Sort(got)
	want := []string{"dev.corp.example.org", "example.com", "horizontal.net"}
	if !slices.Equal(got, want) {
		t.Errorf("sweepSeedDomains = %v, want %v", got, want)
	}
}
