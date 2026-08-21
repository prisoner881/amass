// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	oamplat "github.com/owasp-amass/open-asset-model/platform"
	"golang.org/x/net/html"
)

// pageLinks harvests hostnames from links embedded in a target's default
// web page - single fetch, no following, no recursion. It does NOT make
// its own HTTP request: http_probes already fetches the root page as
// part of -active service discovery and stores the full response body
// on the Service entity (serv.Output). This plugin reads that body
// directly, which means it generates zero network traffic of its own -
// there is no code path here that could send anything anywhere, active
// egress or otherwise, because nothing is ever dialed. The one request
// this data depends on already went through Clients().Active in
// http_probes, with the existing fail-closed handling.
//
// Unlike every FQDN-sourced plugin in this codebase, discovered
// hostnames are stored REGARDLESS of scope. A link on a target's page
// pointing to a third-party domain is still a useful data point - the
// engine's own scope gating (Known-FQDN, HasSLDInScope) already ensures
// an out-of-scope entity sits inertly in the graph without triggering
// any further enumeration against it, so this is safe by construction,
// not just by omission.
type pageLinks struct {
	name   string
	log    *slog.Logger
	source *et.Source
}

func NewPageLinks() et.Plugin {
	return &pageLinks{
		name: "Page-Links",
		source: &et.Source{
			Name:       "Page-Links",
			Confidence: 60,
		},
	}
}

func (pl *pageLinks) Name() string {
	return pl.name
}

func (pl *pageLinks) Start(r et.Registry) error {
	pl.log = r.Log().WithGroup("plugin").With("name", pl.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       pl,
		Name:         pl.name + "-Handler",
		Position:     43,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   []string{string(oam.FQDN)},
		EventType:    oam.Service,
		Callback:     pl.check,
	}); err != nil {
		return err
	}

	pl.log.Info("Plugin started")
	return nil
}

func (pl *pageLinks) Stop() {
	pl.log.Info("Plugin stopped")
}

func (pl *pageLinks) check(e *et.Event) error {
	serv, ok := e.Entity.Asset.(*oamplat.Service)
	if !ok {
		return errors.New("failed to extract the Service asset")
	}

	// Belt-and-suspenders, matching the same reasoning already applied to
	// JARM: a Service entity can only exist because http_probes created
	// it, and http_probes only runs when -active is set. That makes this
	// check redundant today, but explicit rather than relying solely on
	// that transitive fact protects against it silently becoming untrue
	// if some future plugin ever creates Service entities another way.
	if !e.Session.Config().Active {
		return nil
	}

	if serv.Output == "" {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.Service), string(oam.FQDN), pl.name)
	if err != nil {
		return err
	}

	var names []*dbt.Entity
	if !support.AssetMonitoredWithinTTL(e.Session, e.Entity, pl.source, since) {
		if base := pl.originURL(e, since); base != nil {
			names = append(names, pl.harvest(e, serv.Output, base)...)
		}
		support.MarkAssetMonitored(e.Session, e.Entity, pl.source)
	}

	if len(names) > 0 {
		pl.process(e, names)
	}
	return nil
}

// originURL reconstructs the page's own URL from the Service entity's
// incoming PortRelation edge (same technique used by JARMFingerprint to
// find what a Service is attached to) plus an outgoing "certificate"
// edge to distinguish http from https, since Service itself doesn't
// store a scheme. Needed to resolve relative links (href="/about")
// into absolute hostnames.
func (pl *pageLinks) originURL(e *et.Event, since time.Time) *url.URL {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 15*time.Second)
	defer cancel()

	var host string
	var port int
	if edges, err := e.Session.DB().IncomingEdges(ctx, e.Entity, since); err == nil {
		for _, edge := range edges {
			portrel, ok := edge.Relation.(*oamgen.PortRelation)
			if !ok || portrel.Protocol != "TCP" {
				continue
			}
			a, err := e.Session.DB().FindEntityById(ctx, edge.FromEntity.ID)
			if err != nil || a == nil {
				continue
			}
			switch v := a.Asset.(type) {
			case *oamdns.FQDN:
				host = v.Name
			case *oamnet.IPAddress:
				host = v.Address.String()
			default:
				continue
			}
			port = portrel.PortNumber
		}
	}
	if host == "" || port == 0 {
		return nil
	}

	scheme := "http"
	if edges, err := e.Session.DB().OutgoingEdges(ctx, e.Entity, since, "certificate"); err == nil && len(edges) > 0 {
		scheme = "https"
	}

	raw := scheme + "://" + host
	if !(scheme == "http" && port == 80) && !(scheme == "https" && port == 443) {
		raw += ":" + strconv.Itoa(port)
	}

	u, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	return u
}

// linkAttrs mirrors the attribute set already used by the (unused,
// recursive) Crawl() primitive in internal/net/http/http.go - that list
// was sound, just attached to machinery this plugin deliberately
// doesn't want (following, its own client, a scope filter that would
// drop exactly what we want to keep).
var linkAttrs = map[string]bool{
	"action": true, "cite": true, "data": true, "formaction": true,
	"href": true, "longdesc": true, "poster": true, "src": true,
	"srcset": true, "xmlns": true,
}

func (pl *pageLinks) harvest(e *et.Event, body string, base *url.URL) []*dbt.Entity {
	hosts := make(map[string]struct{})

	tokenizer := html.NewTokenizer(strings.NewReader(body))
	for {
		tt := tokenizer.Next()
		if tt == html.ErrorToken {
			break // end of document or a parse error - either way, stop
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}

		tok := tokenizer.Token()
		for _, attr := range tok.Attr {
			if !linkAttrs[strings.ToLower(attr.Key)] || attr.Val == "" {
				continue
			}

			resolved, err := base.Parse(attr.Val)
			if err != nil {
				continue
			}
			h := strings.ToLower(strings.TrimSpace(resolved.Hostname()))
			if h != "" {
				hosts[h] = struct{}{}
			}
		}
	}

	// Deliberately NOT filtered by scope - see the type-level comment.
	var names []string
	for h := range hosts {
		names = append(names, h)
	}

	return pl.store(e, names)
}

func (pl *pageLinks) store(e *et.Event, names []string) []*dbt.Entity {
	return support.StoreFQDNsWithSource(e.Session, names, pl.source, pl.name, pl.name+"-Handler")
}

func (pl *pageLinks) process(e *et.Event, assets []*dbt.Entity) {
	support.ProcessFQDNsWithSource(e, assets, pl.source)
}
