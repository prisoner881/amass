// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package horizontals

import (
	"context"
	"fmt"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/owasp-amass/amass/v5/config"
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

type horTestSession struct {
	et.Session
	db  repository.Repository
	cfg *config.Config
}

func (s *horTestSession) Ctx() context.Context      { return context.Background() }
func (s *horTestSession) Config() *config.Config    { return s.cfg }
func (s *horTestSession) DB() repository.Repository { return s.db }

// An IP can have a ptr_record edge straight to a host name as well as the
// one to its in-addr.arpa name. The PTR data hangs off the arpa name, so
// that is the edge to follow, whichever was created first.
func TestLookupPTRRecordNameFollowsArpaEdge(t *testing.T) {
	db, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "assets.db"))
	if err != nil {
		t.Fatalf("failed to open the test asset database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	cfg := config.NewConfig()
	cfg.Transformations = map[string]*config.Transformation{
		"IPAddress->ALL": {From: "ipaddress", To: "all", TTL: 1440},
	}
	sess := &horTestSession{db: db, cfg: cfg}

	ctx := context.Background()
	mustAsset := func(a oam.Asset) *dbt.Entity {
		ent, err := db.CreateAsset(ctx, a)
		if err != nil {
			t.Fatal(err)
		}
		return ent
	}
	h := &horaddr{name: "Horizontals-IPAddress-Handler", plugin: NewHorizontals().(*horizPlugin)}

	for i, hostFirst := range []bool{true, false} {
		ip := mustAsset(&oamnet.IPAddress{Address: netip.AddrFrom4([4]byte{192, 0, 2, byte(10 + i)}), Type: "IPv4"})
		host := mustAsset(&oamdns.FQDN{Name: fmt.Sprintf("host%d.example.com", i)})
		arpa := mustAsset(&oamdns.FQDN{Name: fmt.Sprintf("%d.2.0.192.in-addr.arpa", 10+i)})
		order := []*dbt.Entity{arpa, host}
		if hostFirst {
			order = []*dbt.Entity{host, arpa}
		}
		for _, to := range order {
			if _, err := db.CreateEdge(ctx, &dbt.Edge{
				Relation:   &general.SimpleRelation{Name: "ptr_record"},
				FromEntity: ip,
				ToEntity:   to,
			}); err != nil {
				t.Fatal(err)
			}
		}

		ptr, err := h.lookupPTRRecordName(sess, ip)
		if err != nil {
			t.Fatalf("hostFirst=%v: lookupPTRRecordName: %v", hostFirst, err)
		}
		if got := ptr.Asset.Key(); got != arpa.Asset.Key() {
			t.Errorf("hostFirst=%v: followed the ptr_record edge to %s, want %s", hostFirst, got, arpa.Asset.Key())
		}
	}
}
