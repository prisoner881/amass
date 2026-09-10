// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package protocol_probes

import "testing"

func TestPgInt8Array(t *testing.T) {
	if got := pgInt8Array(nil); got != "{}" {
		t.Fatalf("empty: %q", got)
	}
	if got := pgInt8Array([]int64{1, 2, 99}); got != "{1,2,99}" {
		t.Fatalf("got %q", got)
	}
}
