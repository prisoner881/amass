// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"strings"
	"time"

	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamplat "github.com/owasp-amass/open-asset-model/platform"
)

// ProductID returns the canonical Product unique_id for a technology name.
// The whole ID is lowercased so the same technology reported with
// different capitalization by different sources ("Nginx" from Wappalyzer,
// "nginx" from Recog) maps to one entity. A mixed-case ID splits the graph
// on SQLite, and on Postgres the second spelling fails outright: the
// product table's unique_id is case-sensitive, but entity.natural_key is a
// lowercased citext UNIQUE column, so the insert violates it.
func ProductID(name string) string {
	lower := strings.ToLower(name)
	return lower + "-" + Hash64Hex(lower)
}

// legacyProductID is the ID scheme used before ProductID: the original
// spelling of the name as the prefix, with the lowercased name hashed.
func legacyProductID(name string) string {
	return name + "-" + Hash64Hex(strings.ToLower(name))
}

// ProductReleaseName returns the canonical ProductRelease name (the
// release's unique key) for a technology name and version. The name part
// is lowercased for the same reason as ProductID; the version is kept as
// reported.
func ProductReleaseName(name, version string) string {
	return strings.ToLower(name) + " " + version
}

// CreateProductAsset upserts the Product for techName, which must already
// carry ProductID(techName) as its ID. If no Product with that ID exists
// but one exists under the legacy mixed-case ID (written before IDs were
// canonicalized), the legacy row is updated instead, so an existing
// database keeps one entity per product rather than gaining a duplicate
// (SQLite) or failing every write (Postgres).
func CreateProductAsset(ctx context.Context, sess et.Session, techName string, p *oamplat.Product) (*dbt.Entity, error) {
	if legacy := legacyProductID(techName); legacy != p.ID &&
		!productExists(ctx, sess, oam.Product, dbt.ContentFilters{"unique_id": p.ID}) &&
		productExists(ctx, sess, oam.Product, dbt.ContentFilters{"unique_id": legacy}) {
		cp := *p
		cp.ID = legacy
		p = &cp
	}
	return sess.DB().CreateAsset(ctx, p)
}

// CreateProductReleaseAsset upserts the ProductRelease for techName and
// version under ProductReleaseName, falling back to an existing release
// stored under the legacy name (original capitalization), as
// CreateProductAsset does for products.
func CreateProductReleaseAsset(ctx context.Context, sess et.Session, techName, version string) (*dbt.Entity, error) {
	name := ProductReleaseName(techName, version)
	if legacy := techName + " " + version; legacy != name &&
		!productExists(ctx, sess, oam.ProductRelease, dbt.ContentFilters{"name": name}) &&
		productExists(ctx, sess, oam.ProductRelease, dbt.ContentFilters{"name": legacy}) {
		name = legacy
	}
	return sess.DB().CreateAsset(ctx, &oamplat.ProductRelease{Name: name})
}

func productExists(ctx context.Context, sess et.Session, atype oam.AssetType, filters dbt.ContentFilters) bool {
	found, err := sess.DB().FindEntitiesByContent(ctx, atype, time.Time{}, 1, filters)
	return err == nil && len(found) > 0
}
