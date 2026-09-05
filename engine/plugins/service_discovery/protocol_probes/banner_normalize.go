// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package protocol_probes

import "strings"

// greetingPrefixes are on-the-wire status tokens Recog fingerprints do
// not include. Recog's examples are the *field* after the protocol
// greeting: "Dovecot ready." not "+OK Dovecot ready.\r\n". SSH is the
// exception — those patterns start with "^SSH-" — so SSH banners are
// left intact by stripGreeting (none of these prefixes match them).
var greetingPrefixes = []string{
	"+OK ",
	"+OK",
	"-ERR ",
	"220-",
	"220 ",
	"221 ",
	"421 ",
	"200 ",
	"201 ",
	"400 ",
	"502 ",
}

// BannerCandidates returns the distinct strings Recog should be tried
// against, in preference order.
//
// The raw peek is never a Recog input as-is: trailing CR/LF makes every
// `$`-anchored fingerprint miss, and POP/IMAP/SMTP/FTP/NNTP greetings
// are not part of the fingerprint patterns (Recog's own examples drop
// them; imap_banners.xml even documents that "* OK " is expected to
// have been removed before matching).
//
// Order is load-bearing. The full trimmed banner is first so SSH (and
// anything whose fingerprints include the protocol token) still
// matches. Greeting-stripped forms come next so Dovecot/Postfix/etc.
// can match. First and last lines cover multiline FTP (220- … 220).
func BannerCandidates(raw string) []string {
	s := strings.ReplaceAll(raw, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}

	seen := make(map[string]struct{})
	var out []string
	add := func(x string) {
		x = strings.TrimSpace(x)
		if x == "" {
			return
		}
		if _, dup := seen[x]; dup {
			return
		}
		seen[x] = struct{}{}
		out = append(out, x)
	}

	add(s)
	stripped := stripGreeting(s)
	add(stripped)
	// IMAP Recog patterns accept either "Dovecot ready." or
	// "[CAPABILITY …] Dovecot ready." — keep both.
	add(stripIMAPCapability(stripped))

	lines := strings.Split(s, "\n")
	add(lines[0])
	add(stripGreeting(lines[0]))
	add(stripIMAPCapability(stripGreeting(lines[0])))
	if n := len(lines); n > 1 {
		add(lines[n-1])
		add(stripGreeting(lines[n-1]))
	}
	return out
}

// stripGreeting removes a leading POP/IMAP/SMTP/FTP/NNTP status token.
// For IMAP untagged responses the "* OK " / "* PREAUTH " / "* BYE "
// prefix is removed but an optional [CAPABILITY …] block is kept —
// imap_banners.xml matches that form directly.
func stripGreeting(s string) string {
	s = strings.TrimSpace(s)

	if strings.HasPrefix(s, "* ") {
		rest := strings.TrimSpace(s[2:])
		for _, tag := range []string{"OK ", "OK", "PREAUTH ", "BYE "} {
			if strings.HasPrefix(rest, tag) {
				return strings.TrimSpace(rest[len(tag):])
			}
		}
	}

	for _, p := range greetingPrefixes {
		if strings.HasPrefix(s, p) {
			return strings.TrimSpace(s[len(p):])
		}
	}
	return s
}

func stripIMAPCapability(s string) string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "[") {
		return s
	}
	end := strings.Index(s, "]")
	if end < 0 {
		return s
	}
	return strings.TrimSpace(s[end+1:])
}
