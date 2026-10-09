// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"net/netip"

	amassnet "github.com/owasp-amass/amass/v5/internal/net"
)

// IsNonRoutableAddress reports whether addr can never be an Internet-facing
// target host: RFC 1918 and RFC 4193 private ranges, loopback, link-local,
// multicast, unspecified, and the other special-use blocks listed in
// amassnet.ReservedCIDRs (the same list http_probes already uses to skip
// reserved addresses). A public name that resolves to one of these is
// split-horizon or misconfigured DNS; actively probing the address from
// the engine only reaches the engine's own host or local network.
func IsNonRoutableAddress(addr netip.Addr) bool {
	if !addr.IsValid() {
		return true
	}

	addr = addr.Unmap()
	if addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() {
		return true
	}

	reserved, _ := amassnet.IsReservedAddress(addr.String())
	return reserved
}
