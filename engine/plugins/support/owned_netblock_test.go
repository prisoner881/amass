package support

import (
	"net/netip"
	"testing"
)

func TestEmailDomain(t *testing.T) {
	cases := map[string]string{
		"Abuse@buffalo.edu":        "buffalo.edu",
		"noc@cit.buffalo.edu":      "cit.buffalo.edu",
		"not-an-email":             "",
		"":                         "",
		"@buffalo.edu":             "buffalo.edu",
	}
	for in, want := range cases {
		if got := emailDomain(in); got != want {
			t.Errorf("emailDomain(%q)=%q want %q", in, got, want)
		}
	}
}

func TestPrefixEligibleForFill(t *testing.T) {
	ok := []string{"128.205.0.0/16", "128.205.1.0/24", "199.33.167.0/24", "10.0.0.1/32"}
	no := []string{"128.204.0.0/15", "10.0.0.0/8", "2620:cc:8000::/48", "0.0.0.0/0"}
	for _, c := range ok {
		p := netip.MustParsePrefix(c)
		if !PrefixEligibleForFill(p) {
			t.Errorf("%s should be eligible", c)
		}
	}
	for _, c := range no {
		p := netip.MustParsePrefix(c)
		if PrefixEligibleForFill(p) {
			t.Errorf("%s should be refused", c)
		}
	}
}

func TestEachUsableIPv4SkipsNetworkBroadcast(t *testing.T) {
	p := netip.MustParsePrefix("10.0.0.0/30")
	var got []string
	eachUsableIPv4(p, func(a netip.Addr) bool {
		got = append(got, a.String())
		return true
	})
	if len(got) != 2 || got[0] != "10.0.0.1" || got[1] != "10.0.0.2" {
		t.Fatalf("got %v want [10.0.0.1 10.0.0.2]", got)
	}
}
