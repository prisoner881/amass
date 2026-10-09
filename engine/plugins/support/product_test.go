// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	et "github.com/owasp-amass/amass/v5/engine/types"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	oam "github.com/owasp-amass/open-asset-model"
	oamplat "github.com/owasp-amass/open-asset-model/platform"
)

// productTestSession satisfies et.Session for the helpers under test,
// which only call DB().
type productTestSession struct {
	et.Session
	db repository.Repository
}

func (s *productTestSession) DB() repository.Repository { return s.db }

func newProductTestSession(t *testing.T) *productTestSession {
	t.Helper()
	db, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "assets.db"))
	if err != nil {
		t.Fatalf("failed to open the test asset database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return &productTestSession{db: db}
}

func TestProductIDIsCaseInsensitive(t *testing.T) {
	if ProductID("Nginx") != ProductID("nginx") {
		t.Errorf("ProductID(Nginx) = %q, ProductID(nginx) = %q; want equal", ProductID("Nginx"), ProductID("nginx"))
	}
	if ProductReleaseName("Nginx", "1.18.0") != "nginx 1.18.0" {
		t.Errorf("ProductReleaseName = %q, want %q", ProductReleaseName("Nginx", "1.18.0"), "nginx 1.18.0")
	}
	// The hash is unchanged from the legacy scheme, so an already
	// lowercase name keeps its existing ID.
	if ProductID("nginx") != legacyProductID("nginx") {
		t.Errorf("lowercase name changed ID: %q vs legacy %q", ProductID("nginx"), legacyProductID("nginx"))
	}
}

func TestCreateProductAssetMergesSpellings(t *testing.T) {
	ctx := context.Background()
	sess := newProductTestSession(t)

	a, err := CreateProductAsset(ctx, sess, "Nginx", &oamplat.Product{ID: ProductID("Nginx"), Name: "Nginx", Type: "software"})
	if err != nil || a == nil {
		t.Fatalf("first create failed: %v", err)
	}
	b, err := CreateProductAsset(ctx, sess, "nginx", &oamplat.Product{ID: ProductID("nginx"), Name: "nginx", Type: "software"})
	if err != nil || b == nil {
		t.Fatalf("second create failed: %v", err)
	}
	if a.ID != b.ID {
		t.Errorf("Nginx and nginx produced different entities: %s vs %s", a.ID, b.ID)
	}
}

func TestCreateProductAssetReusesLegacyID(t *testing.T) {
	ctx := context.Background()
	sess := newProductTestSession(t)

	// A row written by the old scheme: mixed-case prefix.
	legacy, err := sess.DB().CreateAsset(ctx, &oamplat.Product{ID: legacyProductID("Nginx"), Name: "Nginx", Type: "software"})
	if err != nil || legacy == nil {
		t.Fatalf("failed to seed the legacy product: %v", err)
	}

	got, err := CreateProductAsset(ctx, sess, "Nginx", &oamplat.Product{ID: ProductID("Nginx"), Name: "Nginx", Type: "software"})
	if err != nil || got == nil {
		t.Fatalf("create failed: %v", err)
	}
	if got.ID != legacy.ID {
		t.Errorf("legacy product not reused: got entity %s, want %s", got.ID, legacy.ID)
	}

	all, err := sess.DB().FindEntitiesByType(ctx, oam.Product, time.Unix(1, 0), 0)
	if err != nil {
		t.Fatalf("FindEntitiesByType failed: %v", err)
	}
	if len(all) != 1 {
		t.Errorf("found %d Product entities, want 1", len(all))
	}
}

func TestCreateProductReleaseAssetReusesLegacyName(t *testing.T) {
	ctx := context.Background()
	sess := newProductTestSession(t)

	legacy, err := sess.DB().CreateAsset(ctx, &oamplat.ProductRelease{Name: "Nginx 1.18.0"})
	if err != nil || legacy == nil {
		t.Fatalf("failed to seed the legacy release: %v", err)
	}

	got, err := CreateProductReleaseAsset(ctx, sess, "Nginx", "1.18.0")
	if err != nil || got == nil {
		t.Fatalf("create failed: %v", err)
	}
	if got.ID != legacy.ID {
		t.Errorf("legacy release not reused: got entity %s, want %s", got.ID, legacy.ID)
	}

	fresh, err := CreateProductReleaseAsset(ctx, sess, "Apache", "2.4.58")
	if err != nil || fresh == nil {
		t.Fatalf("create failed: %v", err)
	}
	if r, ok := fresh.Asset.(*oamplat.ProductRelease); !ok || r.Name != "apache 2.4.58" {
		t.Errorf("new release name = %v, want %q", fresh.Asset, "apache 2.4.58")
	}
}
