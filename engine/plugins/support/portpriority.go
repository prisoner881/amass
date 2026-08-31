// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"sort"
	"time"
)

// LikelyDecoyThreshold is the open-port count above which an IP is
// treated as likely showing decoy/fabricated results, rather than
// genuinely running that many real services at once (e.g. an
// Imperva-style WAF or similar edge infrastructure that accepts a
// connection on most or all probed ports regardless of what, if
// anything, is actually listening).
//
// 50 was chosen with a deliberately wide margin on both sides, not as
// a tightly-derived number: even a genuinely, unusually multi-purpose
// real host - web, mail, database, remote access, and FTP all running
// together - realistically tops out somewhere in the 15-30 port range
// from a 1000-port list. Independently-verified ground truth from an
// actual target during this feature's own development
// (webdisk.coconinocomets.com, confirmed via nmap) showed 8 genuinely
// open ports out of an 18-port list - a real, unusually service-rich
// host, still nowhere close to 50. WAF/edge infrastructure built to
// look maximally present, by contrast, typically shows hundreds, not
// a borderline number. This is a starting point, meant to be tuned
// against real, observed data from actually-flagged assets over time,
// not treated as a final, precisely-derived answer.
const LikelyDecoyThreshold = 50

// DecoyTimeBudget bounds total processing time for a single IP once
// it's been flagged via LikelyDecoyThreshold. Not applied to
// non-flagged assets at all - confirmed directly against the real
// source that neither protocol_probes nor http_probes impose any
// per-asset time limit today, so non-flagged assets keep their
// existing, deliberately unbounded behavior; port count alone already
// keeps their worst-case time reasonable, since the only way to
// approach the pathological, many-minutes-per-asset scenario this
// budget exists to prevent is the same high-port-count situation
// LikelyDecoyThreshold is built to catch in the first place.
//
// 90 seconds is generous enough, combined with SortByFrequencyDesc
// below, to get a genuine "best effort" sample of the most-likely-to
// -be-real ports before cutting off, while remaining dramatically
// shorter than the unbounded worst case (up to ~33 minutes for a
// single IP, sequentially, at protocol_probes' own 2-second per-port
// timeout) that motivated this feature in the first place.
const DecoyTimeBudget = 90 * time.Second

// PortFrequency returns nmap's own real, published open-frequency
// value for the given TCP port (see portfreq_data.go), or 0 if the
// port has no entry in that source data at all. A port absent from
// nmap's own research data sorts last, after every port that does
// have real frequency data - a reasonable default, since the absence
// itself is a real (if weak) signal that nmap's own scanning found
// this port worth tracking too rarely to include.
func PortFrequency(port int) float64 {
	return portFrequency[port]
}

// SortByFrequencyDesc sorts ports in place, most-likely-to-be-open
// first, using nmap's own real, published frequency data. Applied
// universally to every IP's port list, not just ones flagged by
// LikelyDecoyThreshold - the ordering itself is harmless for a
// normal, non-flagged asset (every port still eventually gets tried
// either way), and only meaningfully changes outcomes for a flagged
// one, where DecoyTimeBudget may cut processing off before the full
// list is reached - in which case having already tried the
// highest-value ports first is exactly the point.
func SortByFrequencyDesc(ports []int) {
	sort.Slice(ports, func(i, j int) bool {
		return PortFrequency(ports[i]) > PortFrequency(ports[j])
	})
}

// IsLikelyDecoy reports whether a port count crosses
// LikelyDecoyThreshold - a single, small, named predicate rather than
// an inline comparison at every call site, so the threshold's own
// meaning stays centralized in one place.
func IsLikelyDecoy(openPortCount int) bool {
	return openPortCount > LikelyDecoyThreshold
}

// DecoyDeadline returns the wall-clock deadline a sequential,
// loop-based caller (protocol_probes' own port loop) should stop
// processing at, given how many ports it's about to work through. The
// zero time.Time is returned for a non-flagged count - callers should
// treat a zero deadline as "no limit at all," e.g.:
//
//	deadline := support.DecoyDeadline(len(ports))
//	for _, port := range ports {
//	    if !deadline.IsZero() && time.Now().After(deadline) {
//	        break
//	    }
//	    ...
//	}
func DecoyDeadline(numPorts int) time.Time {
	if !IsLikelyDecoy(numPorts) {
		return time.Time{}
	}
	return time.Now().Add(DecoyTimeBudget)
}

// DecoyTimeoutChannel returns a channel a concurrent,
// fan-out-then-collect caller (http_probes' own goroutine-per-port
// design) can select against alongside its own results channel, to
// stop waiting once DecoyTimeBudget elapses for a flagged asset. A
// nil channel is returned for a non-flagged count - selecting on a
// nil channel blocks forever on that specific case without any
// special-casing needed at the call site, since Go's own select
// semantics simply never consider a nil channel ready, e.g.:
//
//	timeout := support.DecoyTimeoutChannel(len(ports))
//	for range count {
//	    select {
//	    case results := <-fch:
//	        ...
//	    case <-timeout:
//	        return findings // stop waiting, keep whatever arrived so far
//	    }
//	}
func DecoyTimeoutChannel(numPorts int) <-chan time.Time {
	if !IsLikelyDecoy(numPorts) {
		return nil
	}
	return time.After(DecoyTimeBudget)
}
