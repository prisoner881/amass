// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"net/netip"
	"testing"
)

func TestIsNonRoutableAddress(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"10.1.2.3", true},         // RFC 1918
		{"172.16.0.1", true},       // RFC 1918
		{"172.31.255.254", true},   // RFC 1918
		{"192.168.1.1", true},      // RFC 1918
		{"127.0.0.1", true},        // loopback
		{"169.254.169.254", true},  // link-local (cloud metadata)
		{"100.64.0.1", true},       // CGNAT shared address space
		{"0.0.0.0", true},          // unspecified
		{"224.0.0.1", true},        // multicast
		{"::1", true},              // IPv6 loopback
		{"fe80::1", true},          // IPv6 link-local
		{"fd00::1", true},          // IPv6 unique local (RFC 4193)
		{"::ffff:10.0.0.1", true},  // IPv4-mapped private
		{"8.8.8.8", false},         // public
		{"172.32.0.1", false},      // just outside 172.16.0.0/12
		{"1.1.1.1", false},         // public
		{"2606:4700::1111", false}, // public IPv6
		{"::ffff:8.8.8.8", false},  // IPv4-mapped public
	}

	for _, c := range cases {
		if got := IsNonRoutableAddress(netip.MustParseAddr(c.addr)); got != c.want {
			t.Errorf("IsNonRoutableAddress(%s) = %v, want %v", c.addr, got, c.want)
		}
	}

	if !IsNonRoutableAddress(netip.Addr{}) {
		t.Error("IsNonRoutableAddress(zero Addr) = false, want true")
	}
}
