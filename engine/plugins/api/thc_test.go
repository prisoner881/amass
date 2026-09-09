// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/netip"
	"reflect"
	"testing"
)

func TestParseTHCDomainCSV(t *testing.T) {
	t.Parallel()

	withHeader := "apex_domain,domain,country\n" +
		"example.com,www.example.com,US\n" +
		"example.com,mail.example.com,US\n" +
		"example.com,www.example.com,US\n"
	got := parseTHCDomainCSV(withHeader)
	want := []string{"www.example.com", "mail.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("headered csv: got %v want %v", got, want)
	}

	headerless := "www.example.com,1.2.3.4\napi.example.com,1.2.3.5\n"
	got = parseTHCDomainCSV(headerless)
	want = []string{"www.example.com", "api.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("headerless csv: got %v want %v", got, want)
	}

	if len(parseTHCDomainCSV("")) != 0 {
		t.Fatal("empty body should yield no names")
	}
}

func TestV4Slash24(t *testing.T) {
	t.Parallel()
	addr := netip.MustParseAddr("64.69.195.18")
	got, ok := v4slash24(addr)
	if !ok || got != "64.69.195.0/24" {
		t.Fatalf("got %q ok=%v", got, ok)
	}
	v6 := netip.MustParseAddr("2001:db8::1")
	if _, ok := v4slash24(v6); ok {
		t.Fatal("v6 should be rejected")
	}
}
