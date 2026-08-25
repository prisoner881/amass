// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package protocol_probes

import (
	"sync"

	recog "github.com/runZeroInc/recog-go"
)

// recog_client.go wraps Rapid7's Recog fingerprint database - the
// non-HTTP equivalent of what wappalyzergo already does for web
// technology, verified directly (real build, real match, against real
// bundled fingerprint data) before any of this code was written.

var (
	recogOnce sync.Once
	recogSet  *recog.FingerprintSet
	recogErr  error
)

// loadRecog loads the embedded Recog fingerprint database once per
// engine process - the same one-time, process-wide caching pattern
// already used elsewhere for static, non-target-specific resources
// (e.g. the domain-RDAP IANA bootstrap file), since there's no
// session-specific reason to reload this per session.
func loadRecog() (*recog.FingerprintSet, error) {
	recogOnce.Do(func() {
		recogSet, recogErr = recog.LoadFingerprints()
	})
	return recogSet, recogErr
}

// RecogMatch is a normalized, minimal view of a Recog fingerprint
// match - just the fields this project maps onto Product/
// ProductRelease, not Recog's full raw Values map (which can include
// other fields like hw.* or a CPE string not currently consumed here).
type RecogMatch struct {
	Vendor  string
	Product string
	Version string
	// OS-level fields are populated when a fingerprint identifies the
	// underlying operating system alongside (or instead of) the
	// service itself - e.g. an OpenSSH banner build string revealing
	// the host is running FreeBSD 4.3, confirmed directly in testing.
	OSVendor  string
	OSProduct string
	OSVersion string
}

// MatchBanner runs data against a single named Recog fingerprint
// database (e.g. "ssh_banners.xml") and returns a normalized result. A
// false second return means no fingerprint matched - not an error,
// simply "Recog doesn't recognize this specific banner," which is
// expected and unremarkable even for well-covered protocols; no
// fingerprint database covers every real-world variant.
func MatchBanner(dbName, data string) (RecogMatch, bool) {
	fset, err := loadRecog()
	if err != nil || fset == nil {
		return RecogMatch{}, false
	}

	result := fset.MatchFirst(dbName, data)
	if result == nil || !result.Matched {
		return RecogMatch{}, false
	}

	get := func(key string) string { return result.Values[key] }
	return RecogMatch{
		Vendor:    get("service.vendor"),
		Product:   get("service.product"),
		Version:   get("service.version"),
		OSVendor:  get("os.vendor"),
		OSProduct: get("os.product"),
		OSVersion: get("os.version"),
	}, true
}

// MatchAnyBanner tries data against each named database in order,
// returning the first match. This is the mechanism that resolves
// genuine banner ambiguity (e.g. SMTP and FTP both commonly opening
// with the same "220 " prefix) - rather than guessing which protocol
// produced a banner, every plausible candidate is tried and whichever
// one's fingerprint database actually recognizes the banner wins.
func MatchAnyBanner(data string, dbNames ...string) (RecogMatch, bool) {
	for _, name := range dbNames {
		if m, ok := MatchBanner(name, data); ok {
			return m, ok
		}
	}
	return RecogMatch{}, false
}
