// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package protocol_probes

import (
	"context"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

const (
	sweepIdlePoll    = 2 * time.Second
	sweepIdleTimeout = 2 * time.Minute
	sweepDrainWait   = 15 * time.Minute
	sweepMaxResubmit = 500
)

// SweepMissedIPs is the session-end catch-up for Protocol-Probes.
//
// It runs only against IPs that this session already processed
// (backlog state=done), that have open_port tags, that have no
// Protocol-Probes last_monitored mark inside the transform TTL, and
// that resolve from an FQDN in the seed-domain scope. Those are the
// hosts that hit position 43 with an empty port list, or that were
// scanned only from the FQDN pipeline.
//
// Must be called while the session context and dispatcher pump are
// still alive — before Session.Kill().
func SweepMissedIPs(s et.Session, d et.Dispatcher) {
	if s == nil || d == nil || s.Backlog() == nil {
		return
	}
	if !s.Config().Active {
		return
	}

	log := s.Log().WithGroup("plugin").With("name", "Protocol-Probes").With("handler", "session-end-sweep")
	support.SetEndWorkPhase(s, "idle-wait")

	if !waitIPIdle(s, sweepIdleTimeout) {
		log.Warn("IP pipeline still busy; sweeping only Done rows")
	}

	support.SetEndWorkPhase(s, "listing")
	ids, err := s.Backlog().ListDone(oam.IPAddress)
	if err != nil {
		log.Error("failed to list Done IP backlog rows", "error", err.Error())
		return
	}

	prefilterSince, err := support.PrefilterTTLStartTime(s)
	if err != nil {
		log.Error("failed to compute prefilter TTL window", "error", err.Error())
		return
	}
	protoSince, err := support.TTLStartTime(s.Config(), string(oam.IPAddress), string(oam.Service), "Protocol-Probes")
	if err != nil {
		log.Error("failed to compute Protocol-Probes TTL window", "error", err.Error())
		return
	}

	src := &et.Source{Name: "Protocol-Probes", Confidence: 80}
	var submitted int
	support.SetEndWorkCandidates(s, len(ids))
	support.SetEndWorkPhase(s, "requeue")

	for _, id := range ids {
		if submitted >= sweepMaxResubmit {
			log.Warn("sweep cap reached", "cap", sweepMaxResubmit)
			break
		}

		ctx, cancel := context.WithTimeout(s.Ctx(), 5*time.Second)
		ent, ferr := s.DB().FindEntityById(ctx, id)
		cancel()
		if ferr != nil || ent == nil {
			continue
		}
		if _, ok := ent.Asset.(*oamnet.IPAddress); !ok {
			continue
		}

		if !seedScopedIP(s, ent) {
			continue
		}

		ports := support.OpenPortsForIP(s.Ctx(), s, ent, prefilterSince)
		if len(ports) == 0 {
			continue
		}
		if support.AssetMonitoredWithinTTL(s, ent, src, protoSince) {
			continue
		}

		ev := &et.Event{
			Name:       string(oam.IPAddress) + ": " + ent.Asset.Key(),
			Entity:     ent,
			Dispatcher: d,
			Session:    s,
		}

		var submitErr error
		if s.Backlog().Has(ent) {
			submitErr = d.ResubmitEvent(ev)
		} else {
			submitErr = d.DispatchEvent(ev)
		}
		if submitErr != nil {
			log.Warn("failed to requeue IP for Protocol-Probes",
				"ip", ent.Asset.Key(), "error", submitErr.Error())
			continue
		}
		submitted++
		support.AddEndWorkRequeued(s, 1)
		log.Info("requeued IP for Protocol-Probes",
			"ip", ent.Asset.Key(), "open_ports", len(ports))
	}

	if submitted == 0 {
		support.SetEndWorkPhase(s, "done")
		log.Info("session-end sweep found no missed IPs")
		return
	}

	log.Info("session-end sweep requeued IPs", "count", submitted)
	support.SetEndWorkPhase(s, "drain")
	if !waitIPIdle(s, sweepDrainWait) {
		log.Warn("timed out waiting for swept IPs to drain")
	}
	support.SetEndWorkPhase(s, "done")
}

func seedScopedIP(s et.Session, ent *dbt.Entity) bool {
	ctx, cancel := context.WithTimeout(s.Ctx(), 5*time.Second)
	defer cancel()

	for _, fqdn := range support.ResolvingFQDNs(ctx, s, ent) {
		if s.Config().IsDomainInScope(fqdn.Name) {
			return true
		}
	}
	return false
}

func waitIPIdle(s et.Session, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if s.Done() {
			return false
		}
		q, l, _, err := s.Backlog().Counts(oam.IPAddress)
		if err == nil && q == 0 && l == 0 {
			return true
		}
		time.Sleep(sweepIdlePoll)
	}
	return false
}