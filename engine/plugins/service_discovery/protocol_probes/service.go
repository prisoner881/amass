// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package protocol_probes

import (
	"context"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	general "github.com/owasp-amass/open-asset-model/general"
	oamplat "github.com/owasp-amass/open-asset-model/platform"
)

// service.go converts a successful Recog match into Product/
// ProductRelease entities, deliberately matching the exact conventions
// already established in engine/plugins/enrich/techstack.go: Product
// entities stay coarse (one canonical entity per technology name,
// shared across every Service that uses it, keyed by
// support.Hash64Hex on the lowercased name - the same construction
// already used there), and ProductRelease names embed the product name
// rather than a bare version string, since ProductRelease dedups
// globally by name with no parent-product scoping - a bare version
// would risk colliding across unrelated products that happen to share
// a version number.

// storeRecogMatch creates (or reuses) the Product entity for a
// matched technology and, when Recog reported a version, the
// corresponding ProductRelease - identical shape and edges
// ("product_used", "release") to what Tech-Stack already produces for
// HTTP-sourced identifications, so both paths are indistinguishable to
// anything querying the resulting graph.
func storeRecogMatch(e *et.Event, svcEntity *dbt.Entity, src *et.Source, match RecogMatch) {
	if match.Product != "" {
		storeOneProduct(e, svcEntity, src, match.Vendor, match.Product, match.Version)
	}
	// A Recog fingerprint can identify the OS alongside the service
	// itself (e.g. an SSH build string revealing the host is FreeBSD) -
	// stored as its own, separate Product entity when present, exactly
	// as distinct a fact as the service identification itself.
	if match.OSProduct != "" {
		storeOneProduct(e, svcEntity, src, match.OSVendor, match.OSProduct, match.OSVersion)
	}
}

func storeOneProduct(e *et.Event, svcEntity *dbt.Entity, src *et.Source, vendor, techName, version string) {
	productEntity := storeProduct(e, svcEntity, src, vendor, techName)
	if productEntity == nil {
		return
	}
	if version != "" {
		storeRelease(e, svcEntity, src, productEntity, techName, version)
	}
}

func storeProduct(e *et.Event, svcEntity *dbt.Entity, src *et.Source, vendor, techName string) *dbt.Entity {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 10*time.Second)
	defer cancel()

	id := techName + "-" + support.Hash64Hex(strings.ToLower(techName))

	productEntity, err := e.Session.DB().CreateAsset(ctx, &oamplat.Product{
		ID:          id,
		Name:        techName,
		Type:        "software",
		Category:    vendor,
		Description: "",
	})
	if err != nil || productEntity == nil {
		return nil
	}

	edge, err := e.Session.DB().CreateEdge(ctx, &dbt.Edge{
		Relation:   &general.SimpleRelation{Name: "product_used"},
		FromEntity: svcEntity,
		ToEntity:   productEntity,
	})
	if err != nil || edge == nil {
		return productEntity
	}

	srcProp := &general.SourceProperty{Source: src.Name, Confidence: src.Confidence}
	_, _ = e.Session.DB().CreateEntityProperty(ctx, productEntity, srcProp)
	_, _ = e.Session.DB().CreateEdgeProperty(ctx, edge, srcProp)

	return productEntity
}

func storeRelease(e *et.Event, svcEntity *dbt.Entity, src *et.Source, productEntity *dbt.Entity, techName, version string) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 10*time.Second)
	defer cancel()

	releaseEntity, err := e.Session.DB().CreateAsset(ctx, &oamplat.ProductRelease{
		Name: techName + " " + version,
	})
	if err != nil || releaseEntity == nil {
		return
	}

	edge, err := e.Session.DB().CreateEdge(ctx, &dbt.Edge{
		Relation:   &general.SimpleRelation{Name: "release"},
		FromEntity: productEntity,
		ToEntity:   releaseEntity,
	})
	if err != nil || edge == nil {
		return
	}

	srcProp := &general.SourceProperty{Source: src.Name, Confidence: src.Confidence}
	_, _ = e.Session.DB().CreateEntityProperty(ctx, releaseEntity, srcProp)
	_, _ = e.Session.DB().CreateEdgeProperty(ctx, edge, srcProp)

	// Second, direct edge from the Service to the ProductRelease.
	//
	// The "release" edge above originates at the Product, and Product
	// entities are globally deduplicated by name (their Key() is the
	// name-derived ID), so every version of a given product discovered
	// anywhere in the enumeration accumulates on that single shared
	// node. That makes the Product->ProductRelease edge useless for
	// answering "which version is THIS host running" - a host running
	// nginx 1.18.0 is indistinguishable from one running 1.30.4 once
	// both versions exist in the estate. Confirmed against real data:
	// two UB hosts verified by nmap as nginx 1.18.0 each resolved to
	// six candidate releases through the Product node.
	//
	// ProductRelease is deduplicated by name too, so the release entity
	// stays shared; only the edge is per-Service, which is exactly the
	// missing fact. The Product-originating edge is deliberately left
	// in place rather than replaced, so nothing already consuming it
	// changes behavior.
	svcEdge, err := e.Session.DB().CreateEdge(ctx, &dbt.Edge{
		Relation:   &general.SimpleRelation{Name: "release_used"},
		FromEntity: svcEntity,
		ToEntity:   releaseEntity,
	})
	if err != nil || svcEdge == nil {
		return
	}
	_, _ = e.Session.DB().CreateEdgeProperty(ctx, svcEdge, srcProp)
}
