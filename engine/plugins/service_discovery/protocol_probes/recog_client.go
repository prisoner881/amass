// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package protocol_probes

import (
	"sync"

	recog "github.com/runZeroInc/recog-go"
)

// recog_client.go wraps Rapid7's Recog fingerprint database — the
// non-HTTP equivalent of what wappalyzergo already does for web
// technology. Fingerprints are embedded in recog-go
// (recogxml_vfsdata.go); this file does not vendor XML. Database names
// passed to IdentifyBanner (e.g. "imap_banners.xml") must match
// filenames in that embed. Adding a database is a one-line change to
// ambiguousBannerDBs / sshBannerDBs in plugin.go.

var (
	recogOnce sync.Once
	recogSet  *recog.FingerprintSet
	recogErr  error
)

// loadRecog loads the embedded Recog fingerprint database once per
// engine process — the same one-time, process-wide caching pattern
// already used elsewhere for static, non-target-specific resources
// (e.g. the domain-RDAP IANA bootstrap file).
func loadRecog() (*recog.FingerprintSet, error) {
	recogOnce.Do(func() {
		recogSet, recogErr = recog.LoadFingerprints()
	})
	return recogSet, recogErr
}

// RecogMatch is a normalized, minimal view of a Recog fingerprint
// match — just the fields this project maps onto Product /
// ProductRelease, not Recog's full raw Values map.
type RecogMatch struct {
	Vendor    string
	Product   string
	Version   string
	OSVendor  string
	OSProduct string
	OSVersion string
}

// RecogResult is IdentifyBanner's report: either a match plus which
// candidate/database produced it, or enough diagnostic information for
// the caller to log why nothing was stored.
type RecogResult struct {
	RecogMatch
	Matched    bool
	Database   string
	Input      string
	LoadError  error
	MissingDBs []string
	Candidates []string
}

func matchToRecog(values map[string]string) RecogMatch {
	if values == nil {
		return RecogMatch{}
	}
	get := func(key string) string { return values[key] }
	return RecogMatch{
		Vendor:    get("service.vendor"),
		Product:   get("service.product"),
		Version:   get("service.version"),
		OSVendor:  get("os.vendor"),
		OSProduct: get("os.product"),
		OSVersion: get("os.version"),
	}
}

// IdentifyBanner normalizes the raw peek (see BannerCandidates) and
// tries each candidate against each named Recog database; first match
// wins. A false Matched is not an error — Recog does not cover every
// banner. LoadError and MissingDBs are the cases that mean Recog never
// had a chance.
func IdentifyBanner(data string, dbNames ...string) RecogResult {
	candidates := BannerCandidates(data)

	fset, err := loadRecog()
	if err != nil || fset == nil {
		return RecogResult{LoadError: err, Candidates: candidates}
	}

	var missing, usable []string
	for _, db := range dbNames {
		if _, ok := fset.Databases[db]; ok {
			usable = append(usable, db)
		} else {
			missing = append(missing, db)
		}
	}

	for _, cand := range candidates {
		for _, db := range usable {
			result := fset.MatchFirst(db, cand)
			if result == nil || !result.Matched {
				continue
			}
			return RecogResult{
				RecogMatch: matchToRecog(result.Values),
				Matched:    true,
				Database:   db,
				Input:      cand,
				MissingDBs: missing,
				Candidates: candidates,
			}
		}
	}

	return RecogResult{
		MissingDBs: missing,
		Candidates: candidates,
	}
}

// MatchBanner runs data against a single named Recog database after
// normalization. Prefer IdentifyBanner at call sites that need to log
// which candidate or database hit.
func MatchBanner(dbName, data string) (RecogMatch, bool) {
	res := IdentifyBanner(data, dbName)
	return res.RecogMatch, res.Matched
}

// MatchAnyBanner tries data against each named database in order after
// normalization. Prefer IdentifyBanner when the caller needs to log
// the miss path.
func MatchAnyBanner(data string, dbNames ...string) (RecogMatch, bool) {
	res := IdentifyBanner(data, dbNames...)
	return res.RecogMatch, res.Matched
}

func recogDBCount(fset *recog.FingerprintSet) int {
	if fset == nil {
		return 0
	}
	return len(fset.Databases)
}

func recogMissing(fset *recog.FingerprintSet, dbNames []string) []string {
	if fset == nil {
		return append([]string(nil), dbNames...)
	}
	var missing []string
	for _, db := range dbNames {
		if _, ok := fset.Databases[db]; !ok {
			missing = append(missing, db)
		}
	}
	return missing
}
