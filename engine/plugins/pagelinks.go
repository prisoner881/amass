// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamfile "github.com/owasp-amass/open-asset-model/file"
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
		if base, parent := pl.originURL(e, since); base != nil {
			names = append(names, pl.harvest(e, serv.Output, base, parent)...)
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
func (pl *pageLinks) originURL(e *et.Event, since time.Time) (*url.URL, *dbt.Entity) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 15*time.Second)
	defer cancel()

	var host string
	var port int
	var parent *dbt.Entity
	if edges, err := e.Session.DB().IncomingEdges(ctx, e.Entity, since); err == nil {
		for _, edge := range edges {
			portrel, ok := edge.Relation.(*oamgen.PortRelation)
			if !ok || !strings.EqualFold(portrel.Protocol, "tcp") {
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
			parent = a
			port = portrel.PortNumber
		}
	}
	if host == "" || port == 0 {
		return nil, nil
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
		return nil, nil
	}
	return u, parent
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

// maxLinksPerPage bounds how many distinct link URLs are recorded as
// provenance for a single page. It is a safety valve against pathological
// documents - a sitemap or directory index can carry tens of thousands of
// links - and not a policy limit: at a normal page's few hundred links it
// never binds.
//
// The cap deliberately applies ONLY to URL provenance entities, never to
// hostname extraction. Every hostname on the page is still discovered and
// stored regardless of this value, because that is the primary mission;
// the URLs are supporting detail about where a hostname was seen.
const maxLinksPerPage = 1000

func (pl *pageLinks) harvest(e *et.Event, body string, base *url.URL, parent *dbt.Entity) []*dbt.Entity {
	hosts := make(map[string]struct{})
	links := make(map[string]*url.URL)

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
			if h == "" {
				continue
			}
			hosts[h] = struct{}{}

			// Fragments are stripped so that /page and /page#section
			// collapse to one entity - they are the same resource, and
			// keeping both would inflate the graph for no benefit.
			resolved.Fragment = ""
			if raw := resolved.String(); raw != "" {
				if _, dup := links[raw]; !dup && len(links) < maxLinksPerPage {
					links[raw] = resolved
				}
			}
		}
	}

	// Deliberately NOT filtered by scope - see the type-level comment.
	var names []string
	for h := range hosts {
		names = append(names, h)
	}

	entities := pl.store(e, names)
	pl.storeProvenance(e, base, parent, links, entities)
	return entities
}

func (pl *pageLinks) store(e *et.Event, names []string) []*dbt.Entity {
	return support.StoreFQDNsWithSource(e.Session, names, pl.source, pl.name, pl.name+"-Handler")
}

// storeProvenance records WHERE each discovered hostname was seen, by
// building the chain the Open Asset Model already sanctions for exactly
// this purpose:
//
//	URL(page) --file--> File --contains--> URL(link) --domain--> FQDN
//
// Every hop is a declared relation: urlRels permits "file" to File and
// "domain" to FQDN, and fileRels permits "contains" to URL. No model
// extension is required, and CreateEdge validates all three against
// ValidRelationship, so a wrong label fails rather than silently doing
// nothing. Modeling the fetched page itself as a File matches the model's
// own definition - a File is any web-accessible resource retrieved over
// HTTP - and "contains" is documented as linking content discovered in a
// File into the greater graph, which is precisely what a page link is.
//
// This is additive. The FQDN entities and their dispatch are unchanged,
// so hostname discovery behaves exactly as before whether or not any of
// the work below succeeds. Failures here are logged and abandoned rather
// than propagated, for the same reason: provenance detail must never be
// able to cost an asset.
//
// Note this creates a URL entity per distinct link, which is the dominant
// cost of the feature - a page with 200 links mints up to 200 entities
// plus one File. On a persistent database re-enumerated weekly these
// accumulate, deduplicated by URL. maxLinksPerPage bounds the worst case.
func (pl *pageLinks) storeProvenance(e *et.Event, base *url.URL, parent *dbt.Entity, links map[string]*url.URL, fqdns []*dbt.Entity) {
	if base == nil || len(links) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	// Index the FQDN entities that store() just created, so each link URL
	// can be joined to the hostname entity it refers to without a second
	// round of database lookups.
	byName := make(map[string]*dbt.Entity, len(fqdns))
	for _, ent := range fqdns {
		if fq, ok := ent.Asset.(*oamdns.FQDN); ok {
			byName[strings.ToLower(fq.Name)] = ent
		}
	}

	src := &oamgen.SourceProperty{Source: pl.source.Name, Confidence: pl.source.Confidence}

	originURL := support.RawURLToOAM(base.String())
	if originURL == nil {
		return
	}
	originEnt, err := e.Session.DB().CreateAsset(ctx, originURL)
	if err != nil || originEnt == nil {
		pl.log.Error("failed to create the origin URL asset",
			"url", base.String(), "error", linkErr(err))
		return
	}
	_, _ = e.Session.DB().CreateEntityProperty(ctx, originEnt, src)

	// The page as a File. Name is left empty for a bare directory or root
	// path, where a basename would be "/" or "." rather than anything
	// meaningful.
	var fname string
	if p := strings.TrimSuffix(originURL.Path, "/"); p != "" {
		fname = path.Base(p)
	}
	fileEnt, err := e.Session.DB().CreateAsset(ctx, &oamfile.File{
		URL:  originURL.Raw,
		Name: fname,
		Type: "html",
	})
	if err != nil || fileEnt == nil {
		pl.log.Error("failed to create the File asset for the page",
			"url", originURL.Raw, "error", linkErr(err))
		return
	}
	_, _ = e.Session.DB().CreateEntityProperty(ctx, fileEnt, src)

	if edge, err := e.Session.DB().CreateEdge(ctx, &dbt.Edge{
		Relation:   &oamgen.SimpleRelation{Name: "file"},
		FromEntity: originEnt,
		ToEntity:   fileEnt,
	}); err == nil && edge != nil {
		_, _ = e.Session.DB().CreateEdgeProperty(ctx, edge, src)
	} else {
		pl.log.Error("failed to create the URL->File edge",
			"url", originURL.Raw, "error", linkErr(err))
	}

	// Anchor the origin URL to the host it was served from. Without this
	// edge the crawled hostname is only recoverable by reading the URL's
	// own host attribute, which makes both of the questions this feature
	// exists to answer into text joins rather than graph traversals:
	//
	//   "which FQDN was crawled to find this one" walks backwards
	//   FQDN <-domain- URL <-contains- File <-file- URL(origin) -domain-> FQDN(origin)
	//
	//   "what did crawling this FQDN find" walks the same path forwards,
	//   starting from the incoming domain edges of FQDN(origin).
	//
	// The second direction relies on incoming-edge traversal because
	// fqdnRels declares no outgoing relation toward URL - an FQDN cannot
	// point at a URL in this model, only the reverse - so the edge has to
	// exist for the question to be answerable at all.
	//
	// The relation label depends on what the Service hangs off: urlRels
	// permits "domain" to FQDN and "ip_address" to IPAddress, and an
	// http_probes Service can be parented by either.
	if parent != nil {
		var label string
		switch parent.Asset.(type) {
		case *oamdns.FQDN:
			label = "domain"
		case *oamnet.IPAddress:
			label = "ip_address"
		}
		if label != "" {
			if edge, err := e.Session.DB().CreateEdge(ctx, &dbt.Edge{
				Relation:   &oamgen.SimpleRelation{Name: label},
				FromEntity: originEnt,
				ToEntity:   parent,
			}); err == nil && edge != nil {
				_, _ = e.Session.DB().CreateEdgeProperty(ctx, edge, src)
			} else {
				pl.log.Error("failed to anchor the origin URL to its host",
					"url", originURL.Raw, "relation", label, "error", linkErr(err))
			}
		}
	}

	for raw, link := range links {
		linkURL := support.RawURLToOAM(raw)
		if linkURL == nil {
			continue
		}
		linkEnt, err := e.Session.DB().CreateAsset(ctx, linkURL)
		if err != nil || linkEnt == nil {
			continue
		}
		_, _ = e.Session.DB().CreateEntityProperty(ctx, linkEnt, src)

		if edge, err := e.Session.DB().CreateEdge(ctx, &dbt.Edge{
			Relation:   &oamgen.SimpleRelation{Name: "contains"},
			FromEntity: fileEnt,
			ToEntity:   linkEnt,
		}); err == nil && edge != nil {
			_, _ = e.Session.DB().CreateEdgeProperty(ctx, edge, src)
		}

		// Join the link back to the hostname entity it names. The lookup
		// is against the resolved URL's host rather than the raw
		// attribute value, so relative links resolve to the origin's own
		// hostname exactly as harvest() recorded it.
		host := strings.ToLower(strings.TrimSpace(link.Hostname()))
		fqdnEnt, ok := byName[host]
		if !ok {
			continue
		}
		if edge, err := e.Session.DB().CreateEdge(ctx, &dbt.Edge{
			Relation:   &oamgen.SimpleRelation{Name: "domain"},
			FromEntity: linkEnt,
			ToEntity:   fqdnEnt,
		}); err == nil && edge != nil {
			_, _ = e.Session.DB().CreateEdgeProperty(ctx, edge, src)
		}
	}
}

func (pl *pageLinks) process(e *et.Event, assets []*dbt.Entity) {
	support.ProcessFQDNsWithSource(e, assets, pl.source)
}

// linkErr renders an error for logging without assuming it is non-nil.
// The database helpers used above can return (nil, nil) - a failure with
// no error value - so calling err.Error() directly on these paths would
// turn a logged warning into a panic.
func linkErr(err error) string {
	if err == nil {
		return "no error returned, but the operation produced no entity"
	}
	return err.Error()
}
