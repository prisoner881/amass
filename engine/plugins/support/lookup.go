// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
)

// A data source plugin marks an asset monitored (MarkAssetMonitored) only
// when its lookup completed: the source answered, even if the answer was
// empty. A lookup that failed (transport error, unexpected status, rate
// limit, a call skipped because the rate-limit wait was too long, a body
// that did not decode) leaves the asset unmarked, so the next session
// retries it instead of skipping that source for the whole TTL. The
// failure is logged through LogLookupFailure.

// HTTPLookupFailure returns why a request did not produce a usable
// answer, or "" when it did: a 200 response with a body.
func HTTPLookupFailure(resp *amasshttp.Response, err error) string {
	switch {
	case err != nil:
		return err.Error()
	case resp == nil:
		return "no response"
	case resp.StatusCode != 200:
		return fmt.Sprintf("HTTP %d", resp.StatusCode)
	case resp.Body == "":
		return "empty response body"
	}
	return ""
}

// lookupFailureInterval is the most often one plugin logs a failed lookup.
const lookupFailureInterval = time.Minute

type lookupFailureState struct {
	last       time.Time
	suppressed int
}

var (
	lookupFailureMu     sync.Mutex
	lookupFailureByName = make(map[string]*lookupFailureState)
)

// LogLookupFailure logs that a plugin's lookup of target did not complete
// and was left unmarked for a retry. A source that is down fails on every
// lookup, so each plugin logs at most one line per minute; the next line
// reports how many failures were folded into it.
func LogLookupFailure(log *slog.Logger, plugin, target, reason string) {
	if log == nil {
		return
	}

	now := time.Now()
	lookupFailureMu.Lock()
	st, ok := lookupFailureByName[plugin]
	if !ok {
		st = &lookupFailureState{}
		lookupFailureByName[plugin] = st
	}
	if !st.last.IsZero() && now.Sub(st.last) < lookupFailureInterval {
		st.suppressed++
		lookupFailureMu.Unlock()
		return
	}
	suppressed := st.suppressed
	st.last = now
	st.suppressed = 0
	lookupFailureMu.Unlock()

	log.Warn("lookup failed; not marked, will retry next session",
		"target", target, "reason", reason, "failures_since_last_log", suppressed)
}
