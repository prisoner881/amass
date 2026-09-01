// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	et "github.com/owasp-amass/amass/v5/engine/types"
	amassnet "github.com/owasp-amass/amass/v5/internal/net"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"golang.org/x/sync/singleflight"
)

// PortPrefilterSource is the single, shared source identity for every
// open_port property this package writes, regardless of which
// plugin's code path actually triggered the scan - port_prefilter's
// own IPAddress-triggered handler, or http_probes' fqdn_endpoint.go
// calling in on a resolved IP ahead of that handler ever reaching it.
// Using one shared identity keeps AssetMonitoredWithinTTL/
// MarkAssetMonitored's own dedup and caching consistent no matter
// which caller gets there first - two different Source identities for
// what is, underneath, the exact same fact ("this port answered a
// connect attempt") would defeat the TTL cache entirely, since each
// caller would only ever see its own history, not the other's.
var PortPrefilterSource = &et.Source{
	Name:       "Port-Prefilter",
	Confidence: 100,
}

// PortPrefilterScanTimeout deliberately reuses protocol_probes' own
// PeekTimeout value rather than introducing a new, untested, possibly
// -shorter one - shortening timeouts trades real data quality (false
// negatives on slow-but-legitimate hosts) for speed, a tradeoff not
// agreed to in the design this package's port-prefilter logic comes
// from. A TCP connect (SYN -> SYN-ACK round trip) is a fundamentally
// faster operation than waiting for an application-layer banner, so
// this value functions as a safety ceiling for filtered/black-holed
// ports here, not a tight, latency-sensitive budget.
const PortPrefilterScanTimeout = 2 * time.Second

// maxConcurrentPortsPerIP bounds how many of a single IP's own ports
// get connect-attempted at once. Deliberately not unbounded -
// launching one goroutine per port for an nmap-top-1000-scale sweep,
// all at once, for a single IP, would create very large instantaneous
// connection counts for a stage whose entire purpose is to be a
// cheap, early filter rather than a new bottleneck of its own.
//
// Raised from an original value of 25 specifically to address a real,
// confirmed problem: a live goroutine dump during a large-scale
// enumeration showed every one of http_probes' fqdn_endpoint.go
// concurrency slots simultaneously blocked inside a single scan at
// once, each taking up to ~80 seconds at the original concurrency
// level - full details in fqdn_endpoint.go's own history. 100 roughly
// quarters that worst case; it mitigates the severity of that
// specific failure mode, it doesn't eliminate it on its own (see
// OpenPortsForFQDN's own doc comment in database.go for the actual,
// structural fix that does).
//
// Worth being explicit about a real, known gap this raises the stakes
// on slightly: unlike protocol_probes, scanPorts never acquires the
// shared, session-wide NetSem connection semaphore at all - it only
// ever respects this constant's own, local, per-call bound. This is a
// deliberate exemption, not an oversight (port_prefilter's own
// connections are short-lived and empirically shown, at real scale,
// to rarely find open ports at all), but it does mean this constant
// is the only thing bounding this specific stage's own instantaneous
// connection count - there is no shared backstop catching it if this
// value were raised much further.
const maxConcurrentPortsPerIP = 100

var scanGroup singleflight.Group

// EnsureOpenPortsScanned is the single, shared entry point for the
// connect-scan pre-filter, callable from either port_prefilter's own
// IPAddress-triggered handler or http_probes' fqdn_endpoint.go acting
// on a specific, already-resolved IP ahead of that handler. Returns
// whatever ports are confirmed open on ent (expected to be an
// IPAddress) - scanning fresh if this IP hasn't been checked within
// the TTL window yet, or returning the already-cached result
// (support.OpenPortsForIP) if it has, regardless of which caller
// originally triggered that earlier scan.
//
// Independently checks scope for this specific ent before doing
// anything else, on every call, regardless of caller - necessary
// because http_probes' own FQDN-triggered path lives on a completely
// separate pipeline from port_prefilter's IPAddress-triggered one,
// with no ordering guarantee between them (verified directly against
// engine/registry/pipelines.go's own BuildAssetPipeline: ordering is
// only guaranteed within a single EventType's own pipeline, not
// across two different ones). A given IP's own in-scope status isn't
// intrinsic to the IP - it depends on whether ip_netblock.go has
// already registered its containing netblock, which is guaranteed to
// have already happened via port_prefilter's own IPAddress-pipeline
// position, but is not guaranteed yet when reached via a resolved
// FQDN on the separate FQDN pipeline. Skipping an IP whose scope
// status hasn't resolved yet on this specific call is the safe,
// conservative choice - the same in-scope IP still gets scanned
// reliably later via its own, guaranteed IPAddress-triggered path
// regardless, so this is never a permanent coverage gap, only ever a
// difference in which call happens to do the work first.
//
// Concurrent calls for the same IP (its own IPAddress-triggered
// invocation racing one or more FQDN-triggered ones that happen to
// resolve to it) are collapsed via singleflight, keyed on the
// entity's own database ID - the same kind of check-then-act race
// bgptools' own netblock/autsys lookup()-before-query() pattern
// guards against with a mutex, applied here with a purpose-built tool
// instead of a hand-rolled lock, since x/sync/singleflight was
// already an indirect dependency of this module.
func EnsureOpenPortsScanned(e *et.Event, ent *dbt.Entity, dial amassnet.DialContext) []int {
	if _, conf := e.Session.Scope().IsAssetInScope(ent.Asset, 0); conf <= 0 {
		return nil
	}

	ports := e.Session.Config().Scope.Ports
	if len(ports) == 0 {
		return nil
	}

	ip, ok := ent.Asset.(*oamnet.IPAddress)
	if !ok {
		return nil
	}

	result, err, _ := scanGroup.Do(ent.ID, func() (interface{}, error) {
		ctx := e.Session.Ctx()

		since, err := TTLStartTime(e.Session.Config(), string(oam.IPAddress), string(oam.IPAddress), PortPrefilterSource.Name)
		if err != nil {
			return nil, err
		}

		if AssetMonitoredWithinTTL(e.Session, ent, PortPrefilterSource, since) {
			return OpenPortsForIP(ctx, e.Session, ent), nil
		}

		open := scanPorts(ctx, dial, ip.Address.String(), ports)
		for _, port := range open {
			// Deliberately not surfacing individual per-port storage
			// errors to the caller - a single failed property write
			// shouldn't fail the whole scan for every other port that
			// did store correctly. Matches this package's own existing
			// contract elsewhere (see ResolvingFQDNs, PreferredSNIHostname
			// above): callers get the best available answer, not a
			// hard failure over a partial, non-critical write issue.
			_ = StoreOpenPort(ctx, e.Session, ent, port)
		}
		// Stored once per scan, alongside the individual open_port
		// properties above - the raw signal LikelyDecoyThreshold/
		// IsLikelyDecoy read back later, independent of whichever
		// threshold happens to define "likely decoy" at query time.
		_ = StoreOpenPortCount(ctx, e.Session, ent, len(open))

		// Marked monitored unconditionally, even when open is empty -
		// this is what makes "genuinely scanned, nothing open" and
		// "never scanned yet" distinguishable from each other, rather
		// than both looking identical to a caller that only checked
		// whether any open_port properties exist.
		MarkAssetMonitored(e.Session, ent, PortPrefilterSource)
		return open, nil
	})
	if err != nil {
		return nil
	}

	open, _ := result.([]int)
	return open
}

// scanPorts connect-attempts every port in ports against addr,
// concurrently but bounded by maxConcurrentPortsPerIP, and returns
// only the ones where the connection succeeded. Connects and
// immediately closes on success - no read, no banner, no
// application-layer data exchanged at all - this stage exists purely
// to answer "is anything listening here," leaving what's actually
// running to protocol_probes and http_probes further down the
// pipeline.
// prefilterScanned and prefilterOpen are plain package-level atomic
// counters, not tied to any Session - a deliberate, simpler choice
// than session-scoped tracking, since this fork's own deployment
// model runs exactly one session per engine process, with containers
// brought down between separate enumerations rather than reused. That
// makes a global counter correct as-is for this fork's actual usage;
// it would not be for a deployment running multiple concurrent
// sessions in one long-lived process, or reusing a process across
// separate enumerations without a reset in between.
var (
	prefilterScanned atomic.Int64
	prefilterOpen    atomic.Int64
)

// PrefilterStats returns the cumulative number of ports scanned and
// found open across every EnsureOpenPortsScanned call so far -
// intended for dashboard/monitoring display during active
// development (see the port_prefilter effectiveness discussion this
// originated from), not for any decision-making in a production
// deployment, where nothing is expected to read these values at all.
func PrefilterStats() (scanned, open int64) {
	return prefilterScanned.Load(), prefilterOpen.Load()
}

func scanPorts(ctx context.Context, dial amassnet.DialContext, addr string, ports []int) []int {
	if dial == nil {
		dial = amassnet.NewDialContext(PortPrefilterScanTimeout)
	}

	sem := make(chan struct{}, maxConcurrentPortsPerIP)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var open []int

	for _, port := range ports {
		wg.Add(1)
		sem <- struct{}{}

		go func(port int) {
			defer wg.Done()
			defer func() { <-sem }()

			target := net.JoinHostPort(addr, strconv.Itoa(port))
			prefilterScanned.Add(1)

			conn, err := dial(ctx, "tcp", target)
			if err != nil {
				return
			}
			_ = conn.Close()
			prefilterOpen.Add(1)

			mu.Lock()
			open = append(open, port)
			mu.Unlock()
		}(port)
	}
	wg.Wait()

	return open
}
