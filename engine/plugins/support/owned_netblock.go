// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"time"

	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

// OwnedNetblockSource tags IPs synthesized because an RDAP contact
// email domain matched a seed domain.
var OwnedNetblockSource = &et.Source{
	Name:       "Owned-Netblock",
	Confidence: 100,
}

const (
	ownedMinPrefixBits = 16
	ownedFillBatchLog  = 4096
)

var (
	ownedFillOnce sync.Map // cidr string -> *sync.Once
)

// NetblockOwnedBySeed is true when an RDAP contact email on this
// netblock's IPNetRecord uses a domain in the session seed list.
// Fail-closed: missing edges, no email, or a cloud/personal mailbox
// all return false. Existing HasInScopeFQDN admission is unchanged.
func NetblockOwnedBySeed(ctx context.Context, session et.Session, nb *dbt.Entity) (bool, string) {
	if session == nil || nb == nil {
		return false, ""
	}
	if _, ok := nb.Asset.(*oamnet.Netblock); !ok {
		return false, ""
	}

	recs, err := session.DB().OutgoingEdges(ctx, nb, time.Time{}, "registration")
	if err != nil {
		return false, ""
	}
	for _, re := range recs {
		if re.ToEntity == nil {
			continue
		}
		ipnet, err := session.DB().FindEntityById(ctx, re.ToEntity.ID)
		if err != nil || ipnet == nil {
			continue
		}
		if email, ok := seedContactEmail(ctx, session, ipnet); ok {
			return true, email
		}
	}
	return false, ""
}

func seedContactEmail(ctx context.Context, session et.Session, ipnet *dbt.Entity) (string, bool) {
	edges, err := session.DB().OutgoingEdges(ctx, ipnet, time.Time{},
		"registrant", "admin_contact", "abuse_contact", "technical_contact")
	if err != nil {
		return "", false
	}
	for _, ce := range edges {
		if ce.ToEntity == nil {
			continue
		}
		cr, err := session.DB().FindEntityById(ctx, ce.ToEntity.ID)
		if err != nil || cr == nil {
			continue
		}
		ids, err := session.DB().OutgoingEdges(ctx, cr, time.Time{}, "id")
		if err != nil {
			continue
		}
		for _, ie := range ids {
			if ie.ToEntity == nil {
				continue
			}
			ident, err := session.DB().FindEntityById(ctx, ie.ToEntity.ID)
			if err != nil || ident == nil {
				continue
			}
			id, ok := ident.Asset.(*general.Identifier)
			if !ok || id.Type != general.EmailAddress {
				continue
			}
			dom := emailDomain(id.ID)
			if dom != "" && session.Config().IsDomainInScope(dom) {
				return id.ID, true
			}
		}
	}
	return "", false
}

func emailDomain(email string) string {
	email = strings.ToLower(strings.TrimSpace(email))
	at := strings.LastIndex(email, "@")
	if at < 0 || at+1 >= len(email) {
		return ""
	}
	return strings.TrimSpace(email[at+1:])
}

// PrefixEligibleForFill is IPv4 with mask /16 or longer (smaller or
// equal to a class-B). IPv6 and /15-or-shorter are refused.
func PrefixEligibleForFill(p netip.Prefix) bool {
	if !p.IsValid() || p.Addr().Is6() {
		return false
	}
	return p.Bits() >= ownedMinPrefixBits && p.Bits() <= 32
}

// AdmitOwnedNetblock adds the CIDR to session scope when the contact
// walk hits a seed domain. Eligible IPv4 blocks are filled in a
// background goroutine so the caller (RDAP) is not blocked for a /16.
func AdmitOwnedNetblock(e *et.Event, nbEnt *dbt.Entity) bool {
	if e == nil || e.Session == nil || nbEnt == nil {
		return false
	}
	nb, ok := nbEnt.Asset.(*oamnet.Netblock)
	if !ok {
		return false
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 15*time.Second)
	owned, email := NetblockOwnedBySeed(ctx, e.Session, nbEnt)
	cancel()
	if !owned {
		return false
	}

	e.Session.Scope().Add(nb)
	e.Session.Log().Info("netblock attributed to seed via RDAP contact",
		"cidr", nb.CIDR.String(), "email", email,
		"plugin", OwnedNetblockSource.Name)

	if !e.Session.Config().Active || !PrefixEligibleForFill(nb.CIDR) {
		if !PrefixEligibleForFill(nb.CIDR) {
			e.Session.Log().Info("owned netblock not filled (IPv6 or prefix shorter than /16)",
				"cidr", nb.CIDR.String())
		}
		return true
	}

	startOwnedFill(e.Session, e.Dispatcher, nbEnt, nb)
	return true
}

// FinishOwnedNetblockFills runs at session end: admit any scoped
// netblock whose contacts now match, and wait for in-flight fills
// so synthesized IPs reach Port-Prefilter before shutdown.
func FinishOwnedNetblockFills(s et.Session, d et.Dispatcher) {
	if s == nil || d == nil || !s.Config().Active {
		return
	}
	log := s.Log().WithGroup("plugin").With("name", OwnedNetblockSource.Name)
	SetEndWorkPhase(s, "owned-fill")

	for _, n := range s.Scope().Netblocks() {
		if n == nil || !PrefixEligibleForFill(n.CIDR) {
			continue
		}
		ctx, cancel := context.WithTimeout(s.Ctx(), 15*time.Second)
		ents, err := s.DB().CreateAsset(ctx, n)
		cancel()
		if err != nil || ents == nil {
			continue
		}
		if ok, _ := NetblockOwnedBySeed(s.Ctx(), s, ents); !ok {
			continue
		}
		s.Scope().Add(n)
		startOwnedFill(s, d, ents, n)
	}

	deadline := time.Now().Add(3 * time.Hour)
	for time.Now().Before(deadline) {
		if s.Done() {
			return
		}
		q, l, _, err := s.Backlog().Counts(oam.IPAddress)
		if err == nil && q == 0 && l == 0 {
			log.Info("owned-netblock fill drained")
			return
		}
		time.Sleep(2 * time.Second)
	}
	log.Warn("timed out waiting for owned-netblock fill to drain")
}

func startOwnedFill(s et.Session, d et.Dispatcher, nbEnt *dbt.Entity, nb *oamnet.Netblock) {
	key := nb.CIDR.String()
	once, _ := ownedFillOnce.LoadOrStore(key, &sync.Once{})
	once.(*sync.Once).Do(func() {
		go fillOwnedNetblock(s, d, nbEnt, nb)
	})
}

func fillOwnedNetblock(s et.Session, d et.Dispatcher, nbEnt *dbt.Entity, nb *oamnet.Netblock) {
	log := s.Log().WithGroup("plugin").With("name", OwnedNetblockSource.Name)
	pfx := nb.CIDR
	log.Info("starting owned-netblock fill", "cidr", pfx.String())

	var created, dispatched, skipped int
	eachUsableIPv4(pfx, func(addr netip.Addr) bool {
		if s.Done() || s.Ctx().Err() != nil {
			return false
		}
		ctx, cancel := context.WithTimeout(s.Ctx(), 10*time.Second)
		ipEnt, err := s.DB().CreateAsset(ctx, &oamnet.IPAddress{
			Address: addr,
			Type:    "IPv4",
		})
		if err != nil || ipEnt == nil {
			cancel()
			skipped++
			return true
		}
		_, _ = s.DB().CreateEntityProperty(ctx, ipEnt, &general.SourceProperty{
			Source:     OwnedNetblockSource.Name,
			Confidence: OwnedNetblockSource.Confidence,
		})
		if edge, eerr := s.DB().CreateEdge(ctx, &dbt.Edge{
			Relation:   &general.SimpleRelation{Name: "contains"},
			FromEntity: nbEnt,
			ToEntity:   ipEnt,
		}); eerr == nil && edge != nil {
			_, _ = s.DB().CreateEdgeProperty(ctx, edge, &general.SourceProperty{
				Source:     OwnedNetblockSource.Name,
				Confidence: OwnedNetblockSource.Confidence,
			})
		}
		cancel()
		created++

		if d != nil {
			ev := &et.Event{
				Name:       addr.String(),
				Entity:     ipEnt,
				Dispatcher: d,
				Session:    s,
			}
			if s.Backlog() != nil && s.Backlog().Has(ipEnt) {
				_ = d.ResubmitEvent(ev)
			} else {
				_ = d.DispatchEvent(ev)
			}
			dispatched++
		}
		if created%ownedFillBatchLog == 0 {
			log.Info("owned-netblock fill progress",
				"cidr", pfx.String(), "created", created, "dispatched", dispatched)
		}
		return true
	})

	log.Info("owned-netblock fill finished",
		"cidr", pfx.String(), "created", created, "dispatched", dispatched, "skipped", skipped)
}

func eachUsableIPv4(p netip.Prefix, fn func(netip.Addr) bool) {
	if !PrefixEligibleForFill(p) {
		return
	}
	p = p.Masked()
	hostBits := 32 - p.Bits()
	total := 1 << hostBits
	addr := p.Addr()
	for i := 0; i < total; i++ {
		skip := hostBits >= 2 && (i == 0 || i == total-1)
		if !skip {
			if !fn(addr) {
				return
			}
		}
		addr = addr.Next()
	}
}
