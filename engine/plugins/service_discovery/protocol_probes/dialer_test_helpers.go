package protocol_probes

import (
	"context"
	"net"

	amassnet "github.com/owasp-amass/amass/v5/internal/net"
)

// unreachableAddr is a TEST-NET-1 (RFC 5737) address - guaranteed
// non-routable, reserved specifically for documentation and testing.
// If a function under test tried to dial this directly, ignoring an
// injected dialer, the call would hang or fail outright rather than
// succeeding via the redirect below.
const unreachableAddr = "192.0.2.1:9"

// redirectingDialer returns an amassnet.DialContext that ignores
// whatever address it's asked to dial and connects to realAddr
// instead, recording that it was actually invoked. This is the
// strongest available proof that a function genuinely uses its
// injected dialer rather than silently falling back to a direct
// connection: a function with that bug would try to reach
// unreachableAddr directly and fail, not quietly succeed via this
// redirect.
func redirectingDialer(realAddr string) (amassnet.DialContext, *bool) {
	called := false
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		called = true
		var d net.Dialer
		return d.DialContext(ctx, network, realAddr)
	}, &called
}
