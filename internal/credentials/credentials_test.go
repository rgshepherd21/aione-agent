package credentials

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// newStore builds a Store rooted at a temp directory. The cert/key/ca
// files don't have to exist yet — individual tests write only the file
// they care about.
func newStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	return New(
		filepath.Join(dir, "agent.crt"),
		filepath.Join(dir, "agent.key"),
		filepath.Join(dir, "ca.crt"),
	)
}

// writePEMCert generates a throwaway self-signed cert and writes it to
// path. Returns the PEM bytes for convenience.
func writePEMCert(t *testing.T, path string) []byte {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating cert: %v", err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("writing cert: %v", err)
	}
	return data
}

// TestCACertPool_EmptyFile documents the contract that an empty ca.crt
// is a legitimate "use the system trust store" signal from the backend
// (Azure Dev ships empty ca_cert_pem because ACA fronts us with a
// Let's Encrypt cert that's already in every host's root store).
func TestCACertPool_EmptyFile(t *testing.T) {
	s := newStore(t)
	if err := os.WriteFile(s.caPath, []byte{}, 0o600); err != nil {
		t.Fatalf("writing empty ca: %v", err)
	}

	pool, err := s.CACertPool()
	if err != nil {
		t.Fatalf("CACertPool() error = %v, want nil", err)
	}
	if pool != nil {
		t.Errorf("CACertPool() pool = %v, want nil (sentinel for system trust)", pool)
	}
}

// TestCACertPool_WhitespaceOnly covers the "backend serialised a
// blank string with a trailing newline" case, which should behave
// identically to a zero-byte file.
func TestCACertPool_WhitespaceOnly(t *testing.T) {
	s := newStore(t)
	if err := os.WriteFile(s.caPath, []byte("   \n\t\n"), 0o600); err != nil {
		t.Fatalf("writing whitespace ca: %v", err)
	}

	pool, err := s.CACertPool()
	if err != nil {
		t.Fatalf("CACertPool() error = %v, want nil", err)
	}
	if pool != nil {
		t.Errorf("CACertPool() pool = %v, want nil", pool)
	}
}

// TestCACertPool_ValidPEM covers the normal path: backend shipped a
// real CA bundle, we parse it into a pool.
func TestCACertPool_ValidPEM(t *testing.T) {
	s := newStore(t)
	writePEMCert(t, s.caPath)

	pool, err := s.CACertPool()
	if err != nil {
		t.Fatalf("CACertPool() error = %v, want nil", err)
	}
	if pool == nil {
		t.Fatal("CACertPool() pool = nil, want non-nil")
	}
}

// TestCACertPool_GarbageBytes covers the "backend shipped something,
// but it wasn't PEM" failure mode. We want a real error here — not
// silent fall-through to system trust — because that's a backend bug
// we need to surface.
func TestCACertPool_GarbageBytes(t *testing.T) {
	s := newStore(t)
	if err := os.WriteFile(s.caPath, []byte("not a cert, definitely not pem"), 0o600); err != nil {
		t.Fatalf("writing garbage ca: %v", err)
	}

	pool, err := s.CACertPool()
	if err == nil {
		t.Fatal("CACertPool() error = nil, want error on garbage bytes")
	}
	if pool != nil {
		t.Errorf("CACertPool() pool = %v, want nil on error", pool)
	}
}

// TestCACertPool_MissingFile surfaces the ReadFile error as-is so the
// caller can distinguish "backend said no CA" (empty → nil, nil) from
// "the file we expected to exist is missing" (real IO error).
func TestCACertPool_MissingFile(t *testing.T) {
	s := newStore(t)
	// Do not create caPath.

	_, err := s.CACertPool()
	if err == nil {
		t.Fatal("CACertPool() error = nil, want error on missing file")
	}
}
