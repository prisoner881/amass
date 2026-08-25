package protocol_probes

import (
	"context"
	"net"
	"testing"
	"time"
)

// startBannerServer starts a real local listener that writes the given
// banner immediately upon accepting a connection, mimicking SSH/SMTP/
// FTP-style banner-first behavior.
func startBannerServer(t *testing.T, banner string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start test listener: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte(banner))
		time.Sleep(200 * time.Millisecond) // keep open briefly
	}()

	return ln.Addr().String()
}

// startSilentServer starts a real local listener that accepts the
// connection but writes nothing, mimicking HTTP/HTTPS/implicit-TLS
// behavior (waits for the client to speak first).
func startSilentServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start test listener: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		time.Sleep(500 * time.Millisecond) // hold open, say nothing
	}()

	return ln.Addr().String()
}

func TestPeekBanner_ReceivesRealBanner(t *testing.T) {
	addr := startBannerServer(t, "SSH-2.0-OpenSSH_9.6\r\n")

	result := PeekBanner(context.Background(), nil, addr, 2*time.Second)

	if result.Err != nil {
		t.Fatalf("unexpected error: %v", result.Err)
	}
	if result.Silent {
		t.Fatal("expected Silent=false, got true - banner was not captured")
	}
	got := string(result.Data)
	want := "SSH-2.0-OpenSSH_9.6\r\n"
	if got != want {
		t.Errorf("got data %q, want %q", got, want)
	}
}

func TestPeekBanner_SilentServer(t *testing.T) {
	addr := startSilentServer(t)

	result := PeekBanner(context.Background(), nil, addr, 300*time.Millisecond)

	if result.Err != nil {
		t.Fatalf("unexpected error: %v", result.Err)
	}
	if !result.Silent {
		t.Errorf("expected Silent=true, got false with data %q", result.Data)
	}
	if len(result.Data) != 0 {
		t.Errorf("expected empty data on silence, got %q", result.Data)
	}
}

func TestPeekBanner_ConnectionRefused(t *testing.T) {
	// A closed listener on a real, bound-then-released port should
	// reliably produce a connection-refused error, not a timeout.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to allocate a port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close() // release it immediately - nothing is listening now

	result := PeekBanner(context.Background(), nil, addr, 2*time.Second)

	if result.Err == nil {
		t.Fatal("expected a connection error, got nil")
	}
	if result.Silent {
		t.Error("a connection failure should not be reported as Silent")
	}
}

func TestPeekBanner_EndToEndClassification(t *testing.T) {
	// A realistic end-to-end check: peek a real SSH-banner server, then
	// feed the result straight into ClassifyPeek, exactly as the
	// eventual plugin code will do.
	addr := startBannerServer(t, "SSH-2.0-OpenSSH_9.6\r\n")

	result := PeekBanner(context.Background(), nil, addr, 2*time.Second)
	guess := ClassifyPeek(result.Data)

	if guess != GuessSSH {
		t.Errorf("end-to-end classification = %v, want GuessSSH", guess)
	}
}

// TestPeekBanner_UsesInjectedDialer and TestPeekBanner_NilDialerFallsBackToDirect
// prove the dependency-injection design added for active-proxy-egress
// compatibility genuinely works, not just that it compiles. See
// PeekBanner's own doc comment for the full reasoning: this function
// must be able to route through the operator's configured active proxy
// once feature/active-proxy-egress is merged, without further changes
// to this function itself.
func TestPeekBanner_UsesInjectedDialer(t *testing.T) {
	realAddr := startBannerServer(t, "SSH-2.0-OpenSSH_9.6\r\n")
	dial, called := redirectingDialer(realAddr)

	// unreachableAddr is passed as the target - if PeekBanner ignored
	// the injected dialer and dialed directly, this would fail or hang
	// rather than succeeding via the redirect.
	result := PeekBanner(context.Background(), dial, unreachableAddr, 2*time.Second)

	if !*called {
		t.Fatal("injected dialer was never invoked - PeekBanner is not using the supplied dial function")
	}
	if result.Err != nil {
		t.Fatalf("unexpected error (would indicate the real, unreachable address was dialed instead): %v", result.Err)
	}
	if string(result.Data) != "SSH-2.0-OpenSSH_9.6\r\n" {
		t.Errorf("got data %q, want the real test server's banner", result.Data)
	}
}

func TestPeekBanner_NilDialerFallsBackToDirect(t *testing.T) {
	// Confirms the documented nil-dial fallback actually works, using a
	// real local server reached via a real, direct connection.
	addr := startBannerServer(t, "220 mail.example.com ESMTP\r\n")

	result := PeekBanner(context.Background(), nil, addr, 2*time.Second)

	if result.Err != nil {
		t.Fatalf("unexpected error: %v", result.Err)
	}
	if string(result.Data) != "220 mail.example.com ESMTP\r\n" {
		t.Errorf("got data %q, want the real banner", result.Data)
	}
}
