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
// launching one goroutine per port for a broad sweep, all at once, for
// a single IP, would create very large instantaneous connection
// counts for a stage whose entire purpose is to be a cheap, early
// filter rather than a new bottleneck of its own.
//
// This value has a real, confirmed history worth knowing before
// changing it again. Originally 25. Briefly raised to 100 to reduce
// how long a single scan could take, after a live goroutine dump
// showed http_probes' fqdn_endpoint.go handler slots blocked inside a
// single scan simultaneously. That raise directly caused a severe,
// confirmed regression at real scale: port_prefilter runs at
// support.HighHandlerInstances (32) concurrent handler instances, so
// 32 x 100 = 3,200 peak simultaneous connections - verified, via
// `docker exec engine sh -c 'ulimit -n'`, to exceed the deployment's
// then-current 1,024 file-descriptor ceiling by a wide margin, versus
// 32 x 25 = 800 at the original value, comfortably under it. The
// practical effect was total, sustained silence across the entire
// engine, not just this stage - scanPorts never acquires the shared,
// session-wide NetSem semaphore at all (a deliberate exemption, see
// below), so nothing else in the system caught this before every
// dial() attempt, from any plugin needing a socket, started failing.
// Reverted to 25 for that reason, paired with shrinking the configured
// port range itself (nmap-top-1000 down to nmap-top-100).
//
// Now 100 again, but on a different footing: the file-descriptor
// ceiling that made the earlier raise fatal has been removed. The
// engine container is deployed with an explicit nofile limit of 8,192
// (compose.yaml), confirmed at runtime by the same `ulimit -n` check
// that originally diagnosed the failure. Full worst-case arithmetic at
// this value: 32 x 100 = 3,200 from port_prefilter's own handler,
// 16 x 100 = 1,600 from http_probes' fqdn_endpoint (which scans its
// resolved IPs sequentially, so 100 per slot, not per IP), plus
// NetSem's own 500 - roughly 5,300 against 8,192, leaving about 35%
// headroom.
//
// The measurement that motivated it: at 25, with a 100-port list, a
// cold scan runs four sequential batches of PortPrefilterScanTimeout,
// so ~8s per IP. A live run showed fqdn_endpoint's 16 handler slots
// averaging 9.4s of occupancy per event - saturated, doing almost
// nothing but scanning - which stalled service detection entirely
// (NetSem idle at 0/500 while Service, URL, TLSCertificate and Product
// counts flatlined, since scanPorts holds a slot without holding a
// NetSem token). At 100, one batch covers the whole list, so the same
// scan is ~2s and those slots return to HTTP probing between scans.
//
// Worth being explicit about the same, still-standing gap this
// history exposed: unlike protocol_probes, scanPorts never acquires
// NetSem at all - it only ever respects this constant's own, local,
// per-call bound. This remains a deliberate exemption, not an
// oversight, but it's the reason this constant alone is what
// determines this stage's own worst-case instantaneous connection
// count, and why raising it again warrants the same file-descriptor
// math shown above, not just a throughput judgment call. Note also
// that the 8,192 limit is a property of the deployment, not of this
// code: this value and that ulimit have to move together, and a
// deployment that does not set it inherits Docker's 1,024 default and
// will reproduce the original failure exactly.
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
// PrefilterTTLStartTime returns the cutoff before which a stored
// open_port property is considered stale. It is the single source of
// truth for that window: EnsureOpenPortsScanned uses it to decide
// whether an IP needs rescanning at all, and the passive consumers
// (http_probes' ipaddr_endpoint, protocol_probes) use the same value
// when reading results back, so "we did not rescan because the data is
// fresh" and "this is the data we consider fresh" can never disagree.
//
// Deriving both from one call also means the window follows the
// IPAddress->IPAddress transformation's configured TTL automatically,
// rather than needing a second constant kept in sync by hand.
func PrefilterTTLStartTime(session et.Session) (time.Time, error) {
	return TTLStartTime(session.Config(), string(oam.IPAddress), string(oam.IPAddress), PortPrefilterSource.Name)
}

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

		since, err := PrefilterTTLStartTime(e.Session)
		if err != nil {
			return nil, err
		}

		if AssetMonitoredWithinTTL(e.Session, ent, PortPrefilterSource, since) {
			return OpenPortsForIP(ctx, e.Session, ent, since), nil
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

		// Prune AFTER storing, never before. Deleting first and then
		// writing the fresh set would leave a window - brief, but real
		// - in which this IP has no open_port properties at all.
		// scanGroup serializes concurrent scans of the same entity but
		// nothing serializes readers, so a passive consumer
		// (ipaddr_endpoint, protocol_probes) landing in that window
		// would see an empty port list, skip probing entirely, and
		// mark itself monitored for the full TTL. That is exactly the
		// starvation failure already observed in protocol_probes, and
		// writing first avoids it: the entity holds a complete, valid
		// set at every instant, and only genuinely stale rows are
		// removed.
		//
		// Skipped when the session context is already cancelled. In
		// that case scanPorts returned early with a partial result,
		// and pruning against it would delete ports that are open but
		// simply were not reached before shutdown. Leaving stale rows
		// behind for one pass is recoverable; deleting live ones is
		// not, and OpenPortsForIP's since filter already prevents the
		// survivors from affecting anything downstream.
		if ctx.Err() == nil {
			_ = PruneStalePortData(ctx, e.Session, ent, open)
		}

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

// scanPorts connect-attempts every port in ports against addr,
// concurrently but bounded by maxConcurrentPortsPerIP, and returns
// only the ones where the connection succeeded. Connects and
// immediately closes on success - no read, no banner, no
// application-layer data exchanged at all - this stage exists purely
// to answer "is anything listening here," leaving what's actually
// running to protocol_probes and http_probes further down the
// pipeline.
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

// OpenPortsForFQDN resolves ent (expected to be an FQDN) to its own
// IPs via ResolvedIPsForFQDN, calls EnsureOpenPortsScanned for each
// one, and returns the union of whatever ports came back open across
// all of them. Unlike EnsureOpenPortsScanned's own single-IP contract,
// this actively triggers a scan on each resolved IP if one hasn't
// happened yet, rather than only reading back an existing result -
// necessary because http_probes' fqdn_endpoint.go may well reach a
// given IP before port_prefilter's own, separate IPAddress-pipeline
// position ever does (see EnsureOpenPortsScanned's own doc comment
// for the full cross-pipeline ordering reasoning).
//
// This only ever changes which ports get tried by the caller - never
// the actual connection target, which fqdn_endpoint.go always builds
// from the FQDN's own name, not from any IP this function touches -
// so fqdn_endpoint.go's whole reason for existing (connecting by
// hostname for correct, unambiguous SNI on virtually-hosted targets,
// rather than by a bare, possibly-shared IP) is fully preserved. A
// hostname resolving to several, differently-configured IPs means
// this can over-include ports only genuinely open on one of them - a
// deliberate tradeoff toward completeness over precision, not an
// oversight; see the design discussion this function originated from
// for the full reasoning.
func OpenPortsForFQDN(e *et.Event, ent *dbt.Entity, dial amassnet.DialContext) []int {
	seen := make(map[int]struct{})
	var ports []int

	for _, ip := range ResolvedIPsForFQDN(e.Session.Ctx(), e.Session, ent) {
		for _, port := range EnsureOpenPortsScanned(e, ip, dial) {
			if _, dup := seen[port]; dup {
				continue
			}
			seen[port] = struct{}{}
			ports = append(ports, port)
		}
	}
	return ports
}
