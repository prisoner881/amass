// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	et "github.com/owasp-amass/amass/v5/engine/types"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

// exampleScope treats names under example.com as in scope.
type exampleScope struct{ et.Scope }

func (exampleScope) IsAssetInScope(a oam.Asset, _ int) (oam.Asset, int) {
	if f, ok := a.(*oamdns.FQDN); ok && (f.Name == "example.com" || strings.HasSuffix(f.Name, ".example.com")) {
		return a, 100
	}
	return nil, 0
}

type admitTestSession struct {
	et.Session
	db repository.Repository
}

func (s *admitTestSession) Ctx() context.Context      { return context.Background() }
func (s *admitTestSession) DB() repository.Repository { return s.db }
func (s *admitTestSession) Scope() et.Scope           { return exampleScope{} }

// HasInScopeFQDN gates ambient netblock admission: only an A/AAAA answer
// from an in-scope name counts. An IP that only out-of-scope names resolve
// to (a CDN behind a third-party link) must not admit its block.
func TestHasInScopeFQDN(t *testing.T) {
	db, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "assets.db"))
	if err != nil {
		t.Fatalf("failed to open the test asset database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sess := &admitTestSession{db: db}
	ctx := context.Background()

	mk := func(a oam.Asset) *dbt.Entity {
		ent, err := db.CreateAsset(ctx, a)
		if err != nil {
			t.Fatal(err)
		}
		return ent
	}
	ip := func(s string) *dbt.Entity {
		return mk(&oamnet.IPAddress{Address: netip.MustParseAddr(s), Type: "IPv4"})
	}
	aRecord := func(name string, to *dbt.Entity) {
		if _, err := db.CreateEdge(ctx, &dbt.Edge{
			Relation:   &oamdns.BasicDNSRelation{Name: "dns_record", Header: oamdns.RRHeader{RRType: 1, Class: 1}},
			FromEntity: mk(&oamdns.FQDN{Name: name}),
			ToEntity:   to,
		}); err != nil {
			t.Fatal(err)
		}
	}

	target := ip("192.0.2.10")
	aRecord("www.example.com", target)
	aRecord("cdn.other.net", target)

	cdn := ip("198.51.100.20")
	aRecord("bit.ly", cdn)
	aRecord("cdn.other.net", cdn)

	ptrOnly := ip("203.0.113.30")
	if _, err := db.CreateEdge(ctx, &dbt.Edge{
		Relation:   &general.SimpleRelation{Name: "ptr_record"},
		FromEntity: ptrOnly,
		ToEntity:   mk(&oamdns.FQDN{Name: "host.example.com"}),
	}); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name string
		ip   *dbt.Entity
		want bool
	}{
		{"an in-scope name resolves to it", target, true},
		{"only out-of-scope names resolve to it", cdn, false},
		{"only a PTR record names it", ptrOnly, false},
		{"nothing resolves to it", ip("203.0.113.40"), false},
	} {
		if got := HasInScopeFQDN(ctx, sess, c.ip); got != c.want {
			t.Errorf("%s: HasInScopeFQDN = %v, want %v", c.name, got, c.want)
		}
	}
}
