// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package v1

import "testing"

func TestReadJSONError(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"message only", `{"error":"session not found","code":404}`, "session not found"},
		{"with details", `{"error":"failed to create session","details":"active proxy socks5h://p:1080 is not usable: dial failed","code":500}`,
			"failed to create session: active proxy socks5h://p:1080 is not usable: dial failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readJSONError(tc.in)
			if err != nil || got != tc.want {
				t.Errorf("got (%q, %v), want %q", got, err, tc.want)
			}
		})
	}
	if _, err := readJSONError("not json"); err == nil {
		t.Error("expected an error for a non-JSON body")
	}
}
