package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
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
		// explicitly, or a Read/Write happens. Without this, the
		// client's eager handshake in tls.DialWithDialer races against
		// a server that hasn't done its half yet.
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

	certs, err := dialAndGetCertChain(addr, 2*time.Second)
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

	_, err = dialAndGetCertChain(ln.Addr().String(), 1*time.Second)
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

	_, err = dialAndGetCertChain(addr, 2*time.Second)
	if err == nil {
		t.Fatal("expected a connection error, got nil")
	}
}
