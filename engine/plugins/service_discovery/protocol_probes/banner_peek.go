// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package protocol_probes

import (
	"context"
	"net"
	"time"
)

// maxPeekBytes bounds how much unsolicited data gets buffered per
// connection. Generous for any realistic banner - SSH banners are
// capped at 255 bytes by RFC 4253, and most other banner-first
// protocols' initial greetings are well under 1KB - while still
// keeping per-connection memory use bounded.
const maxPeekBytes = 4096

// PeekResult holds the outcome of a single banner-peek attempt.
type PeekResult struct {
	// Data holds whatever bytes were read before the timeout or a
	// clean EOF/reset. Empty when nothing arrived.
	Data []byte
	// Silent is true when nothing arrived before the timeout expired -
	// the expected, normal signature of HTTP, HTTPS, or any
	// implicit-TLS service, none of which send unsolicited data.
	Silent bool
	// Err holds any error other than a read timeout (e.g. connection
	// refused, DNS failure). A read timeout itself is not an error
	// here - "nothing arrived" (Silent=true) is a legitimate, expected
	// outcome for a large share of the ports this will be run against.
	Err error
}

// PeekBanner opens a plain TCP connection to addr, writes nothing at
// all, and reads for up to timeout to see whether the remote end sends
// something unprompted. This is the entire signal behind classifying a
// port as "banner-first" (SSH, SMTP, FTP, POP3, and similar - protocols
// that greet the client before it sends anything) versus
// "client-speaks-first" (HTTP, HTTPS, and every implicit-TLS service) -
// without needing to understand or emulate any specific protocol.
func PeekBanner(ctx context.Context, addr string, timeout time.Duration) PeekResult {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return PeekResult{Err: err}
	}
	defer conn.Close()

	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return PeekResult{Err: err}
	}

	buf := make([]byte, maxPeekBytes)
	n, err := conn.Read(buf)
	if err != nil {
		if n == 0 {
			// Covers both a genuine read-deadline timeout and a clean
			// EOF/reset with zero bytes read - both are treated as
			// silence for classification purposes, since there is
			// nothing to classify either way. Distinguishing "timed
			// out" from "connection closed immediately" isn't useful
			// here: neither case produced a banner to work with.
			return PeekResult{Silent: true}
		}
		// Some data WAS read before the error (e.g. the remote sent a
		// banner and then immediately closed the connection) - that
		// data is still real and useful, so it's returned rather than
		// discarded just because the read didn't end cleanly.
	}

	return PeekResult{Data: buf[:n]}
}
