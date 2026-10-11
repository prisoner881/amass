// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package rdap

import (
	"errors"

	"github.com/openrdap/rdap"
)

// rdapLookupFailure reports why an RDAP request got no answer, or "" when it
// got one. Besides a record, these are answers that a retry cannot change, so
// the asset is marked monitored: the object does not exist (an RDAP 404), no
// RDAP server covers the query (bootstrap has no match, or does not support
// the query type), or the query itself is invalid. Every other error - no
// server answered (network errors, 429, 5xx, undecodable bodies), a timeout,
// or a failed bootstrap download - leaves the asset unmarked for a retry.
func rdapLookupFailure(err error) string {
	if err == nil {
		return ""
	}
	var ce *rdap.ClientError
	if errors.As(err, &ce) {
		switch ce.Type {
		case rdap.ObjectDoesNotExist, rdap.BootstrapNoMatch, rdap.BootstrapNotSupported, rdap.InputError:
			return ""
		}
	}
	return err.Error()
}
