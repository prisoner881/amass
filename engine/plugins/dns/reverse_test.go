// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/config"
	et "github.com/owasp-amass/amass/v5/engine/types"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
)

func TestPTRNameEmbedsAddress(t *testing.T) {
	addr := netip.MustParseAddr("10.1.2.3")
	for name, want := range map[string]bool{
		"10-1-2-3.dhcp.example.com":    true,
		"host-3-2-1-10.example.com":    true,
		"ip10.1.2.3.example.com":       true,
		"x010-001-002-003.example.com": true,
		"mail.example.com":             false,
		"10-1-2-4.example.com":         false,
		"vpn2.example.com":             false,
		"1-2-3.example.com":            false,
		"10-1-2-3333.example.com":      false,
	} {
		if got := ptrNameEmbedsAddress(name, addr); got != want {
			t.Errorf("ptrNameEmbedsAddress(%q) = %v, want %v", name, got, want)
		}
	}
	if ptrNameEmbedsAddress("2001-db8--1.example.com", netip.MustParseAddr("2001:db8::1")) {
		t.Error("IPv6 addresses are not checked")
	}
}

// scopeOf treats every name under example.com as in scope.
type scopeOf struct{ et.Scope }

func (scopeOf) IsAssetInScope(a oam.Asset, _ int) (oam.Asset, int) {
	if f, ok := a.(*oamdns.FQDN); ok && (f.Name == "example.com" || strings.HasSuffix(f.Name, ".example.com")) {
		return a, 100
	}
	return nil, 0
}

type reverseTestSession struct {
	et.Session
	db  repository.Repository
	cfg *config.Config
}

func (s *reverseTestSession) Ctx() context.Context { return context.Background() }
func (s *reverseTestSession) Log() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
func (s *reverseTestSession) Config() *config.Config    { return s.cfg }
func (s *reverseTestSession) DB() repository.Repository { return s.db }
func (s *reverseTestSession) Scope() et.Scope           { return scopeOf{} }

type reverseTest struct {
	t    *testing.T
	sess *reverseTestSession
	rev  *dnsReverse
	apex *dbt.Entity
}

func newReverseTest(t *testing.T) *reverseTest {
	t.Helper()
	db, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "assets.db"))
	if err != nil {
		t.Fatalf("failed to open the test asset database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	cfg := config.NewConfig()
	cfg.AddDomains("example.com")

	rt := &reverseTest{t: t, sess: &reverseTestSession{db: db, cfg: cfg}}
	p := NewDNS().(*dnsPlugin)
	rt.apex = rt.asset(&oamdns.FQDN{Name: "example.com"})
	p.addApex("example.com", rt.apex)
	rt.rev = NewReverse(p)
	return rt
}

func (rt *reverseTest) asset(a oam.Asset) *dbt.Entity {
	rt.t.Helper()
	ent, err := rt.sess.db.CreateAsset(context.Background(), a)
	if err != nil {
		rt.t.Fatal(err)
	}
	return ent
}

func (rt *reverseTest) link(from *dbt.Entity, label string, to *dbt.Entity) {
	rt.t.Helper()
	if _, err := rt.sess.db.CreateEdge(context.Background(), &dbt.Edge{
		Relation:   &general.SimpleRelation{Name: label},
		FromEntity: from,
		ToEntity:   to,
	}); err != nil {
		rt.t.Fatalf("%s edge: %v", label, err)
	}
}

// ip creates 192.0.2.x inside 192.0.2.0/24. With owned, the block's RDAP
// registrant has an example.com email address, which makes it seed-owned.
func (rt *reverseTest) ip(addr string, owned bool) (*dbt.Entity, *oamnet.IPAddress) {
	rt.t.Helper()
	a := &oamnet.IPAddress{Address: netip.MustParseAddr(addr), Type: "IPv4"}
	ipEnt := rt.asset(a)
	nb := rt.asset(&oamnet.Netblock{CIDR: netip.MustParsePrefix("192.0.2.0/24"), Type: "IPv4"})
	rt.link(nb, "contains", ipEnt)
	if owned {
		rec := rt.asset(&oamreg.IPNetRecord{CIDR: netip.MustParsePrefix("192.0.2.0/24"), Handle: "NET-192-0-2-0-1", Name: "TEST-NET",
			StartAddress: netip.MustParseAddr("192.0.2.0"), EndAddress: netip.MustParseAddr("192.0.2.255"), Type: "IPv4"})
		cr := rt.asset(&contact.ContactRecord{DiscoveredAt: "rdap"})
		email := rt.asset(&general.Identifier{UniqueID: general.EmailAddress + ":noc@example.com",
			ID: "noc@example.com", Type: general.EmailAddress})
		rt.link(nb, "registration", rec)
		rt.link(rec, "registrant", cr)
		rt.link(cr, "id", email)
	}
	return ipEnt, a
}

func (rt *reverseTest) attribute(ipEnt *dbt.Entity, ip *oamnet.IPAddress, refresh bool, names ...string) []*dbt.Entity {
	rt.t.Helper()
	arpa := rt.asset(&oamdns.FQDN{Name: "x.2.0.192.in-addr.arpa"})
	var rev []*relRev
	var targets []*dbt.Entity
	for _, n := range names {
		tgt := rt.asset(&oamdns.FQDN{Name: n})
		targets = append(targets, tgt)
		rev = append(rev, &relRev{ipFQDN: arpa, target: tgt})
	}
	e := &et.Event{Entity: ipEnt, Session: rt.sess}
	rt.rev.attributeOwned(e, ip, rev, refresh)
	return targets
}

func (rt *reverseTest) ptrTargets(ipEnt *dbt.Entity) map[string]int {
	rt.t.Helper()
	got := make(map[string]int)
	edges, _ := rt.sess.db.OutgoingEdges(context.Background(), ipEnt, time.Time{}, "ptr_record")
	for _, edge := range edges {
		if to, err := rt.sess.db.FindEntityById(context.Background(), edge.ToEntity.ID); err == nil {
			got[to.Asset.Key()]++
		}
	}
	return got
}

func (rt *reverseTest) hasNode(fqdn *dbt.Entity) bool {
	rt.t.Helper()
	edges, err := rt.sess.db.IncomingEdges(context.Background(), fqdn, time.Time{}, "node")
	return err == nil && len(edges) > 0
}

func TestAttributeOwnedLinksInScopePTRNames(t *testing.T) {
	rt := newReverseTest(t)
	ipEnt, ip := rt.ip("192.0.2.10", true)
	names := rt.attribute(ipEnt, ip, true, "mail.example.com", "192-0-2-10.dhcp.example.com", "host.other.net")

	got := rt.ptrTargets(ipEnt)
	if got["mail.example.com"] != 1 || got["192-0-2-10.dhcp.example.com"] != 1 {
		t.Errorf("direct ptr_record edges = %v, want both example.com names", got)
	}
	if got["host.other.net"] != 0 {
		t.Error("an out-of-scope PTR name was linked")
	}

	if !rt.hasNode(names[0]) {
		t.Error("mail.example.com has no node edge from its apex")
	}
	if rt.hasNode(names[1]) {
		t.Error("a generic name that spells out the address got a node edge")
	}
	if rt.hasNode(names[2]) {
		t.Error("an out-of-scope name got a node edge")
	}
}

func TestAttributeOwnedIgnoresIPsOutsideOwnedBlocks(t *testing.T) {
	rt := newReverseTest(t)
	ipEnt, ip := rt.ip("192.0.2.20", false)
	names := rt.attribute(ipEnt, ip, true, "mail.example.com")

	if got := rt.ptrTargets(ipEnt); len(got) != 0 {
		t.Errorf("direct ptr_record edges = %v, want none", got)
	}
	if rt.hasNode(names[0]) {
		t.Error("a PTR name on an IP outside owned blocks got a node edge")
	}
}

func TestAttributeOwnedFromDatabaseKeepsExistingEdges(t *testing.T) {
	rt := newReverseTest(t)
	ipEnt, ip := rt.ip("192.0.2.30", true)
	rt.attribute(ipEnt, ip, true, "mail.example.com")

	edges, _ := rt.sess.db.OutgoingEdges(context.Background(), ipEnt, time.Time{}, "ptr_record")
	if len(edges) != 1 {
		t.Fatalf("got %d ptr_record edges, want 1", len(edges))
	}
	before := edges[0].LastSeen

	time.Sleep(1100 * time.Millisecond)
	rt.attribute(ipEnt, ip, false, "mail.example.com", "vpn.example.com")

	got := rt.ptrTargets(ipEnt)
	if got["mail.example.com"] != 1 || got["vpn.example.com"] != 1 {
		t.Errorf("direct ptr_record edges = %v, want one each", got)
	}
	edges, _ = rt.sess.db.OutgoingEdges(context.Background(), ipEnt, time.Time{}, "ptr_record")
	for _, edge := range edges {
		to, _ := rt.sess.db.FindEntityById(context.Background(), edge.ToEntity.ID)
		if to != nil && to.Asset.Key() == "mail.example.com" && !edge.LastSeen.Equal(before) {
			t.Errorf("the existing edge was refreshed from cached data: last seen %v, was %v", edge.LastSeen, before)
		}
	}
}
