// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package protocol_probes

import "strings"

// ProtocolGuess is a coarse, cheap classification of a banner-peeked
// port, made without any real protocol parsing - just enough to route
// the port to the right next step. It deliberately does not try to
// resolve genuine ambiguity (e.g. SMTP and FTP both commonly open with
// the same "220 " prefix) - that resolution is Recog's job, once its
// fingerprint matching is wired in, not this function's.
type ProtocolGuess int

const (
	// GuessSilent means nothing arrived within the peek timeout -
	// consistent with HTTP, HTTPS, or any implicit-TLS service, all of
	// which wait for the client to speak first. These ports proceed to
	// existing HTTP probing and the generic implicit-TLS cert harvest,
	// unchanged from how they're already handled today.
	GuessSilent ProtocolGuess = iota

	// GuessSSH means the banner unambiguously matches SSH's mandatory
	// RFC 4253 format. The "SSH-" prefix is not used as an opening by
	// any other common protocol, so this classification is treated as
	// certain - HTTP probing is skipped entirely for these ports.
	GuessSSH

	// GuessAmbiguousBanner means something arrived that looks like a
	// banner-first greeting, but the specific protocol isn't resolved
	// here. Routed to Recog's fingerprint matching rather than guessed
	// at this layer.
	GuessAmbiguousBanner
)

// ClassifyPeek makes a cheap, best-effort classification of peeked
// bytes. It never claims more certainty than it has: real product/
// version identification is Recog's responsibility, not this
// function's - this only decides which next step a port should be
// routed to.
func ClassifyPeek(data []byte) ProtocolGuess {
	if len(data) == 0 {
		return GuessSilent
	}

	if strings.HasPrefix(string(data), "SSH-") {
		return GuessSSH
	}

	return GuessAmbiguousBanner
}
