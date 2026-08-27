package protocol_probes

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"
)

// generateSelfSignedCert produces a genuine, real self-signed
// certificate and key pair for a local test TLS server - not a canned
// fixture, actually generated fresh each test run.
func generateSelfSignedCert(t *testing.T, commonName string) tls.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject:      pkix.Name{CommonName: commonName, Organization: []string{"Test Org"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}
}

func startTLSServer(t *testing.T, cert tls.Certificate) string {
	t.Helper()

	config := &tls.Config{Certificates: []tls.Certificate{cert}}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", config)
	if err != nil {
		t.Fatalf("failed to start TLS listener: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// tls.Listener.Accept() returns lazily - the server side of the
		// handshake isn't actually driven until Handshake() is called
		// explicitly, or a Read/Write happens.
		if tconn, ok := conn.(*tls.Conn); ok {
			_ = tconn.Handshake()
		}
		time.Sleep(300 * time.Millisecond)
	}()

	return ln.Addr().String()
}

func TestDialAndGetCertChain_RealHandshake(t *testing.T) {
	const cn = "test.example.com"
	cert := generateSelfSignedCert(t, cn)
	addr := startTLSServer(t, cert)

	certs, err := dialAndGetCertChain(context.Background(), nil, addr, "", 2*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("expected exactly 1 certificate, got %d", len(certs))
	}
	if certs[0].Subject.CommonName != cn {
		t.Errorf("got CommonName %q, want %q", certs[0].Subject.CommonName, cn)
	}
	if certs[0].SerialNumber.Int64() != 12345 {
		t.Errorf("got serial %v, want 12345", certs[0].SerialNumber)
	}
}

func TestDialAndGetCertChain_PlainTCPRefusesGracefully(t *testing.T) {
	// A real, plain (non-TLS) TCP server should cause a clean handshake
	// failure, not a panic or hang - simulating what happens if this
	// function is ever pointed at a port that isn't actually TLS.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start plain listener: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		time.Sleep(300 * time.Millisecond)
	}()

	_, err = dialAndGetCertChain(context.Background(), nil, ln.Addr().String(), "", 1*time.Second)
	if err == nil {
		t.Fatal("expected an error connecting to a non-TLS port, got nil")
	}
}

func TestDialAndGetCertChain_ConnectionRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to allocate a port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	_, err = dialAndGetCertChain(context.Background(), nil, addr, "", 2*time.Second)
	if err == nil {
		t.Fatal("expected a connection error, got nil")
	}
}

// TestDialAndGetCertChain_UsesInjectedDialer and
// TestDialAndGetCertChain_NilDialerFallsBackToDirect prove the
// dependency-injection design added for active-proxy-egress
// compatibility genuinely works, not just that it compiles. See
// HarvestCertificate's own doc comment in certharvest.go for the full
// reasoning.
func TestDialAndGetCertChain_UsesInjectedDialer(t *testing.T) {
	const cn = "dialer-injection-test.example.com"
	cert := generateSelfSignedCert(t, cn)
	realAddr := startTLSServer(t, cert)
	dial, called := redirectingDialer(realAddr)

	// unreachableAddr is passed as the target - if this function
	// ignored the injected dialer and dialed directly, this would fail
	// rather than succeeding via the redirect.
	certs, err := dialAndGetCertChain(context.Background(), dial, unreachableAddr, "", 2*time.Second)

	if !*called {
		t.Fatal("injected dialer was never invoked - dialAndGetCertChain is not using the supplied dial function")
	}
	if err != nil {
		t.Fatalf("unexpected error (would indicate the real, unreachable address was dialed instead): %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("expected exactly 1 certificate, got %d", len(certs))
	}
	if certs[0].Subject.CommonName != cn {
		t.Errorf("got CommonName %q, want %q - wrong server reached", certs[0].Subject.CommonName, cn)
	}
}

func TestDialAndGetCertChain_NilDialerFallsBackToDirect(t *testing.T) {
	const cn = "direct-fallback-test.example.com"
	cert := generateSelfSignedCert(t, cn)
	addr := startTLSServer(t, cert)

	certs, err := dialAndGetCertChain(context.Background(), nil, addr, "", 2*time.Second)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(certs) != 1 || certs[0].Subject.CommonName != cn {
		t.Errorf("did not correctly reach the real server via the direct fallback dialer")
	}
}

// TestDialAndGetCertChain_SendsCorrectSNI proves serverName is
// genuinely transmitted in the TLS ClientHello's SNI extension, not
// just accepted as a parameter that goes nowhere. Uses the server
// side's own GetCertificate callback - which the Go standard library
// invokes with the real, received ClientHelloInfo, including whatever
// SNI value the client actually sent - as the ground truth, rather
// than trusting the client's own account of what it did.
func TestDialAndGetCertChain_SendsCorrectSNI(t *testing.T) {
	const cn = "sni-capture-test.example.com"
	cert := generateSelfSignedCert(t, cn)

	var mu sync.Mutex
	var capturedSNI string

	config := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			mu.Lock()
			capturedSNI = hello.ServerName
			mu.Unlock()
			return &cert, nil
		},
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", config)
	if err != nil {
		t.Fatalf("failed to start TLS listener: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if tconn, ok := conn.(*tls.Conn); ok {
			_ = tconn.Handshake()
		}
		time.Sleep(300 * time.Millisecond)
	}()

	const expectedSNI = "the-resolved-hostname.example.com"
	_, err = dialAndGetCertChain(context.Background(), nil, ln.Addr().String(), expectedSNI, 2*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if capturedSNI != expectedSNI {
		t.Errorf("server received SNI %q, want %q - dialAndGetCertChain is not correctly passing serverName through to the TLS handshake",
			capturedSNI, expectedSNI)
	}
}

// TestDialAndGetCertChain_EmptyServerNameOmitsSNI confirms the other
// half of the contract: an empty serverName (the case when no
// resolving FQDN was found for a bare IP) results in no SNI extension
// being sent at all, exactly matching this function's behavior before
// serverName existed - not an empty-string SNI value, which is a
// different, invalid thing entirely.
func TestDialAndGetCertChain_EmptyServerNameOmitsSNI(t *testing.T) {
	const cn = "no-sni-test.example.com"
	cert := generateSelfSignedCert(t, cn)

	var mu sync.Mutex
	sniWasSet := false

	config := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			mu.Lock()
			sniWasSet = hello.ServerName != ""
			mu.Unlock()
			return &cert, nil
		},
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", config)
	if err != nil {
		t.Fatalf("failed to start TLS listener: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if tconn, ok := conn.(*tls.Conn); ok {
			_ = tconn.Handshake()
		}
		time.Sleep(300 * time.Millisecond)
	}()

	_, err = dialAndGetCertChain(context.Background(), nil, ln.Addr().String(), "", 2*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if sniWasSet {
		t.Error("expected no SNI extension when serverName is empty, but the server received one")
	}
}
