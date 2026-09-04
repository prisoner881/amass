// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	oamplat "github.com/owasp-amass/open-asset-model/platform"
)

func StoreFQDNsWithSource(session et.Session, names []string, src *et.Source, plugin, handler string) []*dbt.Entity {
	var results []*dbt.Entity

	if len(names) == 0 || src == nil {
		return results
	}

	ctx, cancel := context.WithTimeout(session.Ctx(), 30*time.Second)
	defer cancel()

	for _, name := range names {
		if a, err := session.DB().CreateAsset(ctx, &oamdns.FQDN{Name: name}); err == nil && a != nil {
			results = append(results, a)
			_, _ = session.DB().CreateEntityProperty(ctx, a, &oamgen.SourceProperty{
				Source:     src.Name,
				Confidence: src.Confidence,
			})
		} else {
			session.Log().Error(err.Error(), slog.Group("plugin", "name", plugin, "handler", handler))
		}
	}

	return results
}

func StoreEmailsWithSource(session et.Session, emails []string, src *et.Source, plugin, handler string) []*dbt.Entity {
	var results []*dbt.Entity

	if len(emails) == 0 || src == nil {
		return results
	}

	ctx, cancel := context.WithTimeout(session.Ctx(), 30*time.Second)
	defer cancel()

	for _, e := range emails {
		email := strings.ToLower(e)

		if a, err := session.DB().CreateAsset(ctx, &oamgen.Identifier{
			UniqueID: fmt.Sprintf("%s:%s", oamgen.EmailAddress, email),
			ID:       email,
			Type:     oamgen.EmailAddress,
		}); err == nil && a != nil {
			results = append(results, a)
			_, _ = session.DB().CreateEntityProperty(ctx, a, &oamgen.SourceProperty{
				Source:     src.Name,
				Confidence: src.Confidence,
			})
		} else {
			session.Log().Error(err.Error(), slog.Group("plugin", "name", plugin, "handler", handler))
		}
	}

	return results
}

func MarkAssetMonitored(session et.Session, asset *dbt.Entity, src *et.Source) {
	if asset == nil || src == nil {
		return
	}

	ctx, cancel := context.WithTimeout(session.Ctx(), 3*time.Second)
	defer cancel()

	_, _ = session.DB().CreateEntityProperty(ctx, asset, oamgen.SimpleProperty{
		PropertyName:  "last_monitored",
		PropertyValue: src.Name,
	})
}

func AssetMonitoredWithinTTL(session et.Session, asset *dbt.Entity, src *et.Source, since time.Time) bool {
	if asset == nil || src == nil || since.IsZero() {
		return false
	}

	ctx, cancel := context.WithTimeout(session.Ctx(), 3*time.Second)
	defer cancel()

	if tags, err := session.DB().FindEntityTags(ctx, asset, since, "last_monitored"); err == nil && len(tags) > 0 {
		for _, tag := range tags {
			if tag.Property.Value() == src.Name {
				return true
			}
		}
	}

	return false
}

func CreateServiceAsset(session et.Session, src *dbt.Entity, rel oam.Relation, serv *oamplat.Service, cert *oamcert.TLSCertificate) (*dbt.Entity, error) {
	var srvs []*dbt.Entity

	ctx, cancel := context.WithTimeout(session.Ctx(), 30*time.Second)
	defer cancel()

	if rport, ok := rel.(*oamgen.PortRelation); ok && src != nil && serv != nil {
		srcs := []*dbt.Entity{src}

		if _, ok := src.Asset.(*oamdns.FQDN); ok {
			// check for IP assresses associated with the FQDN
			if edges, err := session.DB().OutgoingEdges(ctx, src, time.Time{}, "dns_record"); err == nil && len(edges) > 0 {
				for _, edge := range edges {
					if to, err := session.DB().FindEntityById(ctx, edge.ToEntity.ID); err == nil && to != nil {
						if _, ok := to.Asset.(*oamnet.IPAddress); ok {
							srcs = append(srcs, to)
						}
					}
				}
			}
		}

		// go though the hosts that could have previously associated with the service
		for _, s := range srcs {
			if edges, err := session.DB().OutgoingEdges(ctx, s, time.Time{}); err == nil && len(edges) > 0 {
				for _, edge := range edges {
					if eport, ok := edge.Relation.(*oamgen.PortRelation); ok &&
						eport.PortNumber == rport.PortNumber && strings.EqualFold(eport.Protocol, rport.Protocol) {
						if to, err := session.DB().FindEntityById(ctx, edge.ToEntity.ID); err == nil && to != nil {
							if srv, ok := to.Asset.(*oamplat.Service); ok && srv.OutputLen != 0 && srv.OutputLen == serv.OutputLen {
								srvs = append(srvs, to)
							}
						}
					}
				}
			}
		}
	}

	var match *dbt.Entity
	for _, srv := range srvs {
		var num int

		s, valid := srv.Asset.(*oamplat.Service)
		if !valid {
			continue
		}

		// compare some of the service attributes to find a match
		for _, key := range []string{"Server", "X-Powered-By"} {
			if server1, ok := serv.Attributes[key]; ok && server1[0] != "" {
				if server2, ok := s.Attributes[key]; ok && server1[0] == server2[0] {
					num++
				} else {
					num--
				}
			}
		}

		if cert != nil {
			if edges, err := session.DB().OutgoingEdges(ctx, srv, time.Time{}, "certificate"); err == nil && len(edges) > 0 {
				var found bool

				for _, edge := range edges {
					if t, err := session.DB().FindEntityById(ctx, edge.ToEntity.ID); err == nil && t != nil {
						if c, ok := t.Asset.(*oamcert.TLSCertificate); ok && c.SerialNumber == cert.SerialNumber {
							found = true
							break
						}
					}
				}

				if found {
					num++
				} else {
					continue
				}
			}
		}

		if num > 0 {
			match = srv
			break
		}
	}

	if match == nil {
		if a, err := session.DB().CreateAsset(ctx, serv); err == nil && a != nil {
			match = a
		} else {
			return nil, errors.New("failed to create the OAM Service asset")
		}
	}

	_, err := session.DB().CreateEdge(ctx, &dbt.Edge{
		Relation:   rel,
		FromEntity: src,
		ToEntity:   match,
	})
	return match, err
}

// ResolvingFQDNs returns every FQDN with a dns_record edge pointing at
// the given entity (expected to be an IPAddress). Shared low-level
// primitive behind HasInScopeFQDN below and PreferredSNIHostname in
// certharvest.go - both need the same underlying lookup, just for
// different purposes (a scope-membership check vs. picking a hostname
// to present via SNI). Returns nil if none exist or the lookup fails.
//
// The extra FindEntityById call per edge is required, not optional -
// confirmed directly against the real asset-db source (both its
// current default branch and v0.24.4, the specific version this
// project pins): IncomingEdges/OutgoingEdges never hydrate
// FromEntity/ToEntity beyond a bare ID. Their own edge construction
// literally only sets &dbt.Entity{ID: ...} - .Asset is always nil on
// what they return directly, regardless of how long the edge has
// existed or which session created it. Using edge.FromEntity.Asset
// directly, without this lookup, was a real, genuine bug this
// function used to have: every single call silently returned zero
// FQDNs, for every target, every time - confirmed directly via a live
// diagnostic showing IncomingEdges itself correctly finding real
// edges (rawEdgeCount=2, rawErr=<nil>) while this function's own
// original logic still produced zero usable FQDNs from them.
func ResolvingFQDNs(ctx context.Context, session et.Session, ent *dbt.Entity) []*oamdns.FQDN {
	edges, err := session.DB().IncomingEdges(ctx, ent, time.Time{}, "dns_record")
	if err != nil {
		return nil
	}

	var fqdns []*oamdns.FQDN
	for _, edge := range edges {
		if edge.FromEntity == nil {
			continue
		}
		fromEnt, err := session.DB().FindEntityById(ctx, edge.FromEntity.ID)
		if err != nil || fromEnt == nil {
			continue
		}
		if fqdn, ok := fromEnt.Asset.(*oamdns.FQDN); ok {
			fqdns = append(fqdns, fqdn)
		}
	}
	return fqdns
}

// HasInScopeFQDN checks whether at least one FQDN with a dns_record
// edge pointing at the given entity (expected to be an IPAddress) is
// itself confirmed in scope. This is the deliberate, targeted gate for
// netblock scope registration in ip_netblock.go and
// whois/bgptools/netblock.go - see the comment on the Scope.Add() call
// site in ip_netblock.go for the full reasoning. An IP discovered via
// a genuine forward DNS resolution from an in-scope domain passes; an
// IP that only has a reverse-DNS (ptr_record) path, or no in-scope
// FQDN pointing to it at all, does not - PTR records are a well-known
// unreliable signal for this purpose (frequently misconfigured,
// pointing at unrelated organizations), so a bare reverse-DNS hit
// alone deliberately isn't treated as sufficient here.
func HasInScopeFQDN(ctx context.Context, session et.Session, ent *dbt.Entity) bool {
	for _, fqdn := range ResolvingFQDNs(ctx, session, ent) {
		if _, conf := session.Scope().IsAssetInScope(fqdn, 0); conf > 0 {
			return true
		}
	}
	return false
}

// PreferredSNIHostname picks the best available hostname to present
// via SNI when initiating a raw TLS handshake against a bare IP -
// preferring one that's confirmed in scope (most likely the actual,
// intended target of this enumeration), falling back to any resolving
// hostname otherwise. Returns an empty string if no resolving FQDN
// exists at all (e.g. an IP discovered via netblock sweep with no
// forward DNS record of its own), meaning the caller should omit SNI
// entirely - many modern, virtually-hosted TLS servers require a
// correct SNI value to know which certificate to present, and may
// reset or refuse a connection that arrives without one; this exists
// specifically to give a raw TLS handshake against a bare IP the same
// chance of success that a normal, hostname-driven client would have.
func PreferredSNIHostname(ctx context.Context, session et.Session, ent *dbt.Entity) string {
	fqdns := ResolvingFQDNs(ctx, session, ent)
	if len(fqdns) == 0 {
		return ""
	}

	for _, fqdn := range fqdns {
		if _, conf := session.Scope().IsAssetInScope(fqdn, 0); conf > 0 {
			return fqdn.Name
		}
	}
	return fqdns[0].Name
}

// OpenPortConfidence is the confidence value attached to a
// "port_prefilter"-sourced open_port property. Deliberately a plain
// property write, not a Source/Finding-based ProcessAssetsWithSource
// call - the pre-filter's job is a single, simple fact per port
// ("this connected"), not a discovered relationship between two
// separate entities, so the lighter-weight, direct
// CreateEntityProperty path used by Tech-Stack's own icon property
// (see storeProduct in enrich/techstack.go) is the right precedent to
// follow here, not the Finding-based pattern used elsewhere in this
// package.
const openPortPropertyName = "open_port"

// StoreOpenPort records that the given port answered a plain TCP
// connect attempt against ent (expected to be an IPAddress). One
// property per port, rather than a single combined/encoded value -
// keeps this consistent with how the rest of the schema already
// stores repeated, multi-valued facts about an entity (see the
// "icon" property precedent above), and keeps the read side
// (OpenPortsForIP) a simple, single FindEntityTags call.
func StoreOpenPort(ctx context.Context, session et.Session, ent *dbt.Entity, port int) error {
	_, err := session.DB().CreateEntityProperty(ctx, ent, &oamgen.SimpleProperty{
		PropertyName:  openPortPropertyName,
		PropertyValue: strconv.Itoa(port),
	})
	return err
}

// OpenPortsForIP returns every port confirmed open (via StoreOpenPort)
// on the given entity, expected to be an IPAddress, whose confirmation
// is no older than since. Returns an empty slice, not an error, if none
// exist yet or the lookup fails - the same "nothing found is not
// exceptional" contract as ResolvingFQDNs and PreferredSNIHostname
// above, since a genuinely new IP that the port_prefilter hasn't
// reached yet is an expected, ordinary state, not a fault condition.
//
// since is required rather than optional, and callers should pass
// PrefilterTTLStartTime's value. This previously passed time.Time{},
// which disables the filter entirely and returns every open_port
// property ever written for the entity. That is correct for a
// throwaway database but wrong for a persistent one: nothing prunes
// these properties, and a rescan that finds a port closed does not
// remove the existing property - it simply stops refreshing it. The
// set therefore only ever grows, so a port open once is reported open
// forever. Three consequences, all bad on a re-enumeration schedule:
// the expensive downstream probes (http_probes, protocol_probes) keep
// paying full connect timeouts on ports that closed long ago; a
// closure can never be detected, which defeats the point of
// re-enumerating; and the resulting data reports exposure that no
// longer exists, which is the one place in this pipeline the error
// runs toward false positives rather than false negatives.
//
// Filtering on since is safe because the underlying lookup tests
// updated_at, not created_at, and the tag upsert refreshes updated_at
// on conflict (verified against asset-db's entity_get_tags and
// entity_tag_upsert). A still-open port re-confirmed by any later scan
// keeps its timestamp current and stays visible; only ports that
// stopped being confirmed age out. Within a single enumeration nothing
// changes at all, since properties written moments earlier sit well
// inside any TTL window.
func OpenPortsForIP(ctx context.Context, session et.Session, ent *dbt.Entity, since time.Time) []int {
	tags, err := session.DB().FindEntityTags(ctx, ent, since, openPortPropertyName)
	if err != nil {
		return nil
	}

	var ports []int
	for _, tag := range tags {
		prop, ok := tag.Property.(*oamgen.SimpleProperty)
		if !ok {
			continue
		}
		if port, err := strconv.Atoi(prop.PropertyValue); err == nil {
			ports = append(ports, port)
		}
	}
	return ports
}

// ResolvedIPsForFQDN walks outgoing dns_record edges from the given
// entity (expected to be an FQDN) forward to whatever IPAddress
// entities it actually resolves to - the mirror image of
// ResolvingFQDNs above, which walks the same edge type in the
// opposite direction (from an IP backward to the FQDNs resolving to
// it). Follows CNAME-style intermediate FQDN hops up to maxHops deep
// (real, multi-hop CNAME chains are common - confirmed directly
// against real targets earlier in this project) rather than either a
// single hop, which would miss them, or unbounded recursion, which
// risks looping forever against a circular or misconfigured DNS
// chain. Returns whatever distinct IPAddress entities were reached,
// deduplicated by their database ID; an empty slice if none are
// reachable within the hop limit.
func ResolvedIPsForFQDN(ctx context.Context, session et.Session, ent *dbt.Entity) []*dbt.Entity {
	const maxHops = 5

	var ips []*dbt.Entity
	seen := make(map[string]struct{})
	frontier := []*dbt.Entity{ent}

	for hop := 0; hop < maxHops && len(frontier) > 0; hop++ {
		var next []*dbt.Entity

		for _, cur := range frontier {
			edges, err := session.DB().OutgoingEdges(ctx, cur, time.Time{}, "dns_record")
			if err != nil {
				continue
			}
			for _, edge := range edges {
				if edge.ToEntity == nil {
					continue
				}
				toEnt, err := session.DB().FindEntityById(ctx, edge.ToEntity.ID)
				if err != nil || toEnt == nil {
					continue
				}
				if _, dup := seen[toEnt.ID]; dup {
					continue
				}
				seen[toEnt.ID] = struct{}{}

				switch toEnt.Asset.(type) {
				case *oamnet.IPAddress:
					ips = append(ips, toEnt)
				case *oamdns.FQDN:
					// A CNAME-style intermediate hop - keep walking
					// forward from here on the next iteration.
					next = append(next, toEnt)
				}
			}
		}
		frontier = next
	}
	return ips
}

// openPortCountPropertyName is a deliberately separate property from
// openPortPropertyName itself (one entry per open port found) - this
// one is a single, explicit count of how many ports were found open
// on a given IP in total, stored once per scan. Storing the raw
// count directly, rather than only a derived true/false "flagged"
// property, keeps the signal itself independent of whatever threshold
// currently defines "likely decoy" (see LikelyDecoyThreshold) - the
// same real count remains queryable and directly useful even if that
// threshold changes later, and it lets anyone reviewing results later
// see how extreme a given case actually was, not just whether it
// crossed some line.
const openPortCountPropertyName = "open_port_count"

// StoreOpenPortCount records the total number of ports found open on
// ent (expected to be an IPAddress) during a single port_prefilter
// scan pass. Called once per scan, alongside (not instead of) the
// individual StoreOpenPort calls for each open port found.
func StoreOpenPortCount(ctx context.Context, session et.Session, ent *dbt.Entity, count int) error {
	_, err := session.DB().CreateEntityProperty(ctx, ent, &oamgen.SimpleProperty{
		PropertyName:  openPortCountPropertyName,
		PropertyValue: strconv.Itoa(count),
	})
	return err
}

// PruneStalePortData deletes every open_port property on ent whose
// port is not in keep, and every open_port_count property whose value
// is not len(keep). Returns the number of properties removed.
//
// This is what makes stored port data mean "the ports open as of the
// most recent completed scan" rather than "every port ever seen open".
// No open/closed history is retained by design: a port that stops
// answering simply ceases to exist here, which is both what consumers
// want and what keeps the entity_tag table from accumulating rows
// indefinitely across repeated enumerations of the same asset.
//
// Pruning is by VALUE, not by timestamp, and that choice is load-
// bearing. A timestamp cutoff would have to compare a Go-side clock
// reading against updated_at values written by Postgres's own now(),
// so any clock skew between the engine and the database could make
// properties written seconds ago look older than the cutoff and get
// deleted. Comparing port numbers against the set just observed open
// has no such dependency and is exactly as expressive, since no
// history is being kept.
//
// Callers must only invoke this after a scan that ran to completion.
// scanPorts returns whatever it managed to collect if the session
// context is cancelled mid-sweep, and pruning against a partial result
// would delete ports that are genuinely open but were never reached.
// EnsureOpenPortsScanned guards this explicitly.
func PruneStalePortData(ctx context.Context, session et.Session, ent *dbt.Entity, keep []int) int {
	ports := make(map[string]struct{}, len(keep))
	for _, port := range keep {
		ports[strconv.Itoa(port)] = struct{}{}
	}

	removed := pruneTagsNotIn(ctx, session, ent, openPortPropertyName, ports)
	removed += pruneTagsNotIn(ctx, session, ent, openPortCountPropertyName,
		map[string]struct{}{strconv.Itoa(len(keep)): {}})
	return removed
}

// pruneTagsNotIn removes every property named name on ent whose value
// is absent from keep. Individual delete failures are counted as
// not-removed and otherwise ignored: a row that survives a failed
// delete is stale but harmless, since OpenPortsForIP's own since
// filter still excludes it from results, and the next completed scan
// will attempt the delete again.
//
// The lookup deliberately passes time.Time{} rather than a TTL window.
// Everywhere else in this file an unfiltered read is the bug; here it
// is the entire point, because the rows this function exists to delete
// are precisely the ones a TTL window would hide.
func pruneTagsNotIn(ctx context.Context, session et.Session, ent *dbt.Entity, name string, keep map[string]struct{}) int {
	tags, err := session.DB().FindEntityTags(ctx, ent, time.Time{}, name)
	if err != nil {
		// Includes the ordinary "no tags found for entity" case, which
		// is not exceptional - a first-ever scan has nothing to prune.
		return 0
	}

	var removed int
	for _, tag := range tags {
		prop, ok := tag.Property.(*oamgen.SimpleProperty)
		if !ok {
			continue
		}
		if _, found := keep[prop.PropertyValue]; found {
			continue
		}
		if err := session.DB().DeleteEntityTag(ctx, tag.ID); err == nil {
			removed++
		}
	}
	return removed
}

// registrationContactRels are the RDAP contact relation types trusted as
// evidence of who a netblock is assigned to.
//
// registrant and technical_contact are deliberately EXCLUDED. Registrant
// email identifiers are barely populated in practice (2 of 64 observed in
// a real database, versus 58 of 58 for abuse and 62 of 62 for admin), and
// technical contacts frequently name a third party even on a correctly
// registered block - a Linode range was observed carrying
// ip-admin@akamai.com as its technical contact. Abuse and admin contacts
// are the two the registries treat as authoritative for the assignee.
var registrationContactRels = []string{"abuse_contact", "admin_contact"}

// NetblockRegisteredToScopedDomain reports whether a Netblock's RDAP
// registration contacts prove it is assigned to an organization already
// in scope, by walking:
//
//	Netblock -registration-> IPNetRecord
//	        -abuse_contact|admin_contact-> ContactRecord -id-> Identifier
//
// and testing the email address's domain against the session's configured
// domains with Config().IsDomainInScope - an exact suffix match on a
// registered domain, never a fuzzy or heuristic comparison.
//
// This exists because netblock ownership is otherwise unprovable. IPs
// discovered by neighbourhood sweep (support.IPAddressSweep) have no FQDN
// of their own, so HasInScopeFQDN rejects them and they are never scanned
// - measured at 4,532 discovered-but-unassessed IP-only assets in a single
// enumeration, many inside blocks the client demonstrably owns. Those are
// exactly the forgotten hosts this tool exists to find, and an attacker
// enumerating a netblock does not need a hostname to reach them.
//
// The check must be deterministic and must fail closed, because a false
// positive directs active scan traffic at somebody else's network. Every
// weaker signal was considered and rejected:
//
//   - Organization NAME matching (e.g. "MUZO-NET" against muzo.com) needs
//     fuzzy comparison, and fuzzy comparison is precisely where a subtle
//     bug scans an unrelated /16.
//   - Mere presence in the graph is what caused the original scope
//     explosion, where any netblock touched by any resolution became
//     in-scope, pulling in Cloudflare, AWS, Azure and Google ranges.
//   - Registry allocation TYPE (ASSIGNED PI and similar) indicates
//     provider independence but not WHO the assignee is.
//
// An email domain is the one field that is both machine-comparable and
// registry-asserted. Verified against real data: cloud and CDN blocks
// return their own operators (amazon.com, microsoft.com, cloudflare.com,
// akamai.com) and are correctly rejected, while blocks belonging to the
// target return the target's own domains and are correctly admitted.
//
// Note this deliberately does NOT admit blocks belonging to acquired
// subsidiaries whose domains are not in the seed list - a block observed
// registered to tsys.com, a subsidiary of the target, is rejected because
// tsys.com was not supplied. That is a false negative and it is the
// correct direction to err.
func NetblockRegisteredToScopedDomain(ctx context.Context, session et.Session, netblock *dbt.Entity) bool {
	if netblock == nil {
		return false
	}

	// Netblock -registration-> IPNetRecord -abuse_contact|admin_contact-> ContactRecord
	//
	// Reading the registration record from the DATABASE rather than from
	// a dispatched event is the whole point of this entry point. RDAP
	// only dispatches an IPNetRecord event on the run that first fetches
	// it; on every later run netblock.lookup() returns nil and nothing
	// downstream ever fires. So any check that waits for an IPNetRecord
	// or ContactRecord event works exactly once and never again. Reading
	// stored state works on every run after the first, which is the
	// production configuration - a persistent database re-enumerated on
	// a schedule.
	regs, err := session.DB().OutgoingEdges(ctx, netblock, time.Time{}, "registration")
	if err != nil || len(regs) == 0 {
		return false
	}

	var edges []*dbt.Edge
	for _, reg := range regs {
		ipnet, err := session.DB().FindEntityById(ctx, reg.ToEntity.ID)
		if err != nil || ipnet == nil {
			continue
		}
		if found, err := session.DB().OutgoingEdges(ctx, ipnet,
			time.Time{}, registrationContactRels...); err == nil {
			edges = append(edges, found...)
		}
	}
	if len(edges) == 0 {
		return false
	}

	for _, edge := range edges {
		contact, err := session.DB().FindEntityById(ctx, edge.ToEntity.ID)
		if err != nil || contact == nil {
			continue
		}

		ids, err := session.DB().OutgoingEdges(ctx, contact, time.Time{}, "id")
		if err != nil {
			continue
		}

		for _, ide := range ids {
			ident, err := session.DB().FindEntityById(ctx, ide.ToEntity.ID)
			if err != nil || ident == nil {
				continue
			}

			id, ok := ident.Asset.(*oamgen.Identifier)
			if !ok || id.Type != oamgen.EmailAddress {
				continue
			}

			// An email address, not a bare domain: everything after the
			// last '@'. Reject anything without exactly one usable
			// domain part rather than guessing.
			at := strings.LastIndex(id.ID, "@")
			if at < 0 || at == len(id.ID)-1 {
				continue
			}

			domain := strings.ToLower(strings.TrimSpace(id.ID[at+1:]))
			if domain == "" {
				continue
			}

			// IsDomainInScope performs an exact registered-domain suffix
			// match against the configured seed list. A contact at
			// mail.corp.example.com matches a seed of example.com; a
			// contact at notexample.com does not.
			if session.Config().IsDomainInScope(domain) {
				return true
			}
		}
	}
	return false
}
