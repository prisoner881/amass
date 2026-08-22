// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package enrich

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	general "github.com/owasp-amass/open-asset-model/general"
	oamplat "github.com/owasp-amass/open-asset-model/platform"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

// techStack identifies the technology stack (CMS, CDN, analytics, hosting,
// etc.) of a probed Service, using the already-captured response headers
// and page body - no new network traffic, same reuse principle already
// applied by JARM and Page-Links.
//
// Detection itself is delegated to wappalyzergo (MIT), a Go port of the
// Wappalyzer detection engine that sources its signature data from
// enthec/webappanalyzer (GPLv3), an actively maintained community
// continuation of the technology fingerprint database after the original
// Wappalyzer project went closed-source in August 2023. This plugin
// treats wappalyzergo strictly as a library dependency; it does not
// bundle, redistribute, or modify enthec's data itself.
//
// Product entities are intentionally coarse, by design: one canonical
// entity per detected technology name (e.g. "WordPress"), shared across
// every Service that uses it, not one per (service, technology) pair.
// ProductRelease entities carry the product name as part of their own
// name (e.g. "WordPress 6.4") because ProductRelease dedups globally on
// name alone with no parent-product scoping - a bare version string
// would risk colliding across unrelated products that happen to share
// a version number.
type techStack struct {
	name   string
	log    *slog.Logger
	client *wappalyzer.Wappalyze
	source *et.Source
}

func NewTechStack() et.Plugin {
	return &techStack{
		name: "Tech-Stack",
		source: &et.Source{
			Name:       "Tech-Stack",
			Confidence: 70,
		},
	}
}

func (ts *techStack) Name() string {
	return ts.name
}

func (ts *techStack) Start(r et.Registry) error {
	ts.log = r.Log().WithGroup("plugin").With("name", ts.name)

	// The detection client compiles every fingerprint's regex patterns
	// once at construction - built here, at plugin startup, not per
	// Service processed. Recreating it per-event would recompile the
	// entire signature set on every single probed service.
	client, err := wappalyzer.New()
	if err != nil {
		return err
	}
	ts.client = client

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       ts,
		Name:         ts.name + "-Handler",
		Position:     44,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   []string{string(oam.Product)},
		EventType:    oam.Service,
		Callback:     ts.check,
	}); err != nil {
		return err
	}

	ts.log.Info("Plugin started")
	return nil
}

func (ts *techStack) Stop() {
	ts.log.Info("Plugin stopped")
}

func (ts *techStack) check(e *et.Event) error {
	serv, ok := e.Entity.Asset.(*oamplat.Service)
	if !ok {
		return errors.New("failed to extract the Service asset")
	}

	if serv.Output == "" {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.Service), string(oam.Product), ts.name)
	if err != nil {
		return err
	}

	if !support.AssetMonitoredWithinTTL(e.Session, e.Entity, ts.source, since) {
		ts.detect(e, serv)
		support.MarkAssetMonitored(e.Session, e.Entity, ts.source)
	}
	return nil
}

func (ts *techStack) detect(e *et.Event, serv *oamplat.Service) {
	info := ts.client.FingerprintWithInfo(serv.Attributes, []byte(serv.Output))

	for key, appInfo := range info {
		techName, version := splitVersion(key)
		if techName == "" {
			continue
		}

		productEntity := ts.storeProduct(e, serv, techName, version, appInfo)
		if productEntity == nil {
			continue
		}

		if version != "" {
			ts.storeRelease(e, serv, productEntity, techName, version)
		}
	}
}

// splitVersion separates wappalyzergo's "AppName" or "AppName:1.2.3"
// key format (confirmed against the library's own FormatAppVersion)
// into the bare technology name and an optional version string.
func splitVersion(key string) (name, version string) {
	if idx := strings.Index(key, ":"); idx != -1 {
		return key[:idx], key[idx+1:]
	}
	return key, ""
}

func (ts *techStack) storeProduct(e *et.Event, serv *oamplat.Service, techName, version string, appInfo wappalyzer.AppInfo) *dbt.Entity {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 10*time.Second)
	defer cancel()

	id := techName + "-" + support.Hash64Hex(strings.ToLower(techName))
	category := strings.Join(appInfo.Categories, ", ")

	productEntity, err := e.Session.DB().CreateAsset(ctx, &oamplat.Product{
		ID:          id,
		Name:        techName,
		Type:        "software",
		Category:    category,
		Description: appInfo.Description,
	})
	if err != nil || productEntity == nil {
		ts.log.Error("failed to create Product entity",
			"product", techName, "version", version, "asset", serv.ID, "error", errString(err))
		return nil
	}

	edge, err := e.Session.DB().CreateEdge(ctx, &dbt.Edge{
		Relation:   &general.SimpleRelation{Name: "product_used"},
		FromEntity: e.Entity,
		ToEntity:   productEntity,
	})
	if err != nil || edge == nil {
		ts.log.Error("failed to create product_used edge",
			"product", techName, "version", version, "asset", serv.ID, "error", errString(err))
		return productEntity
	}

	src := &general.SourceProperty{Source: ts.source.Name, Confidence: ts.source.Confidence}
	_, _ = e.Session.DB().CreateEntityProperty(ctx, productEntity, src)
	_, _ = e.Session.DB().CreateEdgeProperty(ctx, edge, src)

	// Raw filename only (e.g. "WordPress.svg") - not a resolvable link.
	// A separate, external process is expected to resolve this to a
	// real local asset and update this property in place later.
	if appInfo.Icon != "" {
		if _, err := e.Session.DB().CreateEntityProperty(ctx, productEntity, &general.SimpleProperty{
			PropertyName:  "icon",
			PropertyValue: appInfo.Icon,
		}); err != nil {
			ts.log.Warn("failed to store icon property",
				"product", techName, "icon", appInfo.Icon, "asset", serv.ID, "error", err.Error())
		}
	}

	_ = e.Dispatcher.DispatchEvent(&et.Event{
		Name:    productEntity.Asset.Key(),
		Entity:  productEntity,
		Session: e.Session,
	})

	ts.log.Info("product detected",
		"product", techName, "version", version, "category", category, "asset", serv.ID)

	return productEntity
}

// errString safely stringifies an error that may be nil, since a failed
// CreateAsset/CreateEdge call can return (nil, nil) as well as a real
// error - both are logged as failures here, so this avoids a nil
// dereference when err itself is nil but the returned entity/edge was.
func errString(err error) string {
	if err == nil {
		return "no entity/edge returned"
	}
	return err.Error()
}

func (ts *techStack) storeRelease(e *et.Event, serv *oamplat.Service, productEntity *dbt.Entity, techName, version string) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 10*time.Second)
	defer cancel()

	releaseName := techName + " " + version
	releaseEntity, err := e.Session.DB().CreateAsset(ctx, &oamplat.ProductRelease{
		Name: releaseName,
	})
	if err != nil || releaseEntity == nil {
		ts.log.Error("failed to create ProductRelease entity",
			"product", techName, "version", version, "asset", serv.ID, "error", errString(err))
		return
	}

	edge, err := e.Session.DB().CreateEdge(ctx, &dbt.Edge{
		Relation:   &general.SimpleRelation{Name: "release"},
		FromEntity: productEntity,
		ToEntity:   releaseEntity,
	})
	if err != nil || edge == nil {
		ts.log.Error("failed to create release edge",
			"product", techName, "version", version, "asset", serv.ID, "error", errString(err))
		return
	}

	src := &general.SourceProperty{Source: ts.source.Name, Confidence: ts.source.Confidence}
	_, _ = e.Session.DB().CreateEntityProperty(ctx, releaseEntity, src)
	_, _ = e.Session.DB().CreateEdgeProperty(ctx, edge, src)

	ts.log.Info("product release recorded",
		"product", techName, "version", version, "release", releaseName, "asset", serv.ID)
}
