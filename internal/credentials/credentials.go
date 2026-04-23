// Package credentials manages the agent's mTLS certificate lifecycle.
// Zero standing credentials: the agent holds no hard-coded secrets.
// Credentials are issued by the API at registration time and stored
// with 0600 permissions in the configured data directory.
package credentials

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Store manages the on-disk cert/key pair and the server CA bundle.
type Store struct {
	certPath string
	keyPath  string
	caPath   string
}

// New creates a Store using the provided file paths.
func New(certPath, keyPath, caPath string) *Store {
	return &Store{
		certPath: certPath,
		keyPath:  keyPath,
		caPath:   caPath,
	}
}

// Save atomically writes the cert, key, and CA bundle to disk.
// All files are written with 0600 permissions so only the agent
// process owner can read them.
func (s *Store) Save(certPEM, keyPEM, caPEM []byte) error {
	for _, dir := range []string{
		filepath.Dir(s.certPath),
		filepath.Dir(s.keyPath),
		filepath.Dir(s.caPath),
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("creating credential directory %s: %w", dir, err)
		}
	}

	writes := []struct {
		path string
		data []byte
	}{
		{s.certPath, certPEM},
		{s.keyPath, keyPEM},
		{s.caPath, caPEM},
	}

	for _, w := range writes {
		if err := atomicWrite(w.path, w.data, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// Exists reports whether all three credential files are present on disk.
func (s *Store) Exists() bool {
	for _, p := range []string{s.certPath, s.keyPath, s.caPath} {
		if _, err := os.Stat(p); os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// TLSCertificate loads and returns the agent's TLS certificate.
func (s *Store) TLSCertificate() (tls.Certificate, error) {
	return tls.LoadX509KeyPair(s.certPath, s.keyPath)
}

// CACertPool loads the server CA PEM and returns a cert pool.
//
// An empty (zero-byte) or whitespace-only ca.crt is a legitimate
// signal from the backend ("no custom CA; trust the public CA
// already on this host"). In that case we return ``(nil, nil)`` so
// ``tls.Config.RootCAs = nil`` falls through to the system trust
// store — which is exactly what we want when the backend is fronted
// by a public CA (Let's Encrypt via Azure Container Apps managed
// cert in Phase 1 Dev, for example).
//
// Only a file we could read but whose bytes are non-empty *and*
// didn't contain any parseable PEM blocks is a real error — that
// means the backend delivered garbage.
func (s *Store) CACertPool() (*x509.CertPool, error) {
	data, err := os.ReadFile(s.caPath)
	if err != nil {
		return nil, fmt.Errorf("reading CA bundle %s: %w", s.caPath, err)
	}

	if len(bytes.TrimSpace(data)) == 0 {
		return nil, nil
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("no valid certificates found in %s", s.caPath)
	}
	return pool, nil
}

// ExpiresAt returns the NotAfter time of the agent certificate.
func (s *Store) ExpiresAt() (time.Time, error) {
	data, err := os.ReadFile(s.certPath)
	if err != nil {
		return time.Time{}, fmt.Errorf("reading cert %s: %w", s.certPath, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return time.Time{}, fmt.Errorf("no PEM block in %s", s.certPath)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("parsing certificate: %w", err)
	}
	return cert.NotAfter, nil
}

// NeedsRenewal reports whether the cert expires within the given threshold.
func (s *Store) NeedsRenewal(threshold time.Duration) (bool, error) {
	exp, err := s.ExpiresAt()
	if err != nil {
		return false, err
	}
	return time.Until(exp) < threshold, nil
}

// Delete removes all credential files from disk.
func (s *Store) Delete() error {
	for _, p := range []string{s.certPath, s.keyPath, s.caPath} {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("removing %s: %w", p, err)
		}
	}
	return nil
}

// atomicWrite writes data to a temp file then renames it to path,
// ensuring readers never see a partial write.
func atomicWrite(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-")
	if err != nil {
		return fmt.Errorf("creating temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("writing temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("closing temp file: %w", err)
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("setting permissions on %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("renaming %s to %s: %w", tmpName, path, err)
	}
	return nil
}
