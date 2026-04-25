package dsl

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

// newTestServer spins up a stub of the BE registry endpoint. handler
// receives the *http.Request and returns the bundle to serve. Use it
// to test happy path, tampered responses, network errors, etc.
func newTestServer(t *testing.T, handler func(*http.Request) (*SignedBundle, int)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bundle, status := handler(r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if bundle != nil {
			_ = json.NewEncoder(w).Encode(bundle)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// ─── Fetch happy path ──────────────────────────────────────────────────────

func TestFetch_HappyPath(t *testing.T) {
	bundle := makeBundle(t, map[string]map[string]interface{}{"flush_dns_cache": basicAction("flush_dns_cache")}, time.Now())
	srv := newTestServer(t, func(r *http.Request) (*SignedBundle, int) {
		if r.URL.Path != "/api/v1/kal/registry" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		return bundle, 200
	})

	c := &RegistryClient{BaseURL: srv.URL, Secret: testSecret, RefreshDisabled: true}
	if err := c.Fetch(context.Background()); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	reg := c.Current()
	if reg == nil {
		t.Fatal("expected Current registry to be populated, got nil")
	}
	if _, ok := reg["flush_dns_cache"]; !ok {
		t.Errorf("expected flush_dns_cache in registry, got: %v", keys(reg))
	}
}

// ─── Fetch keeps existing on failure ───────────────────────────────────────

func TestFetch_KeepsExistingOnHTTPError(t *testing.T) {
	srv := newTestServer(t, func(r *http.Request) (*SignedBundle, int) { return nil, 503 })
	c := &RegistryClient{BaseURL: srv.URL, Secret: testSecret, RefreshDisabled: true}
	err := c.Fetch(context.Background())
	if err == nil {
		t.Fatal("expected HTTP-503 error, got nil")
	}
	if c.Current() != nil {
		t.Error("Current must remain nil after a failed initial fetch")
	}
}

func TestFetch_RejectsTamperedBundle(t *testing.T) {
	bundle := makeBundle(t, map[string]map[string]interface{}{"a": basicAction("a")}, time.Now())
	bundle.Signature = "00000000000000000000000000000000000000000000000000000000000000a0"
	srv := newTestServer(t, func(r *http.Request) (*SignedBundle, int) { return bundle, 200 })

	c := &RegistryClient{BaseURL: srv.URL, Secret: testSecret, RefreshDisabled: true}
	err := c.Fetch(context.Background())
	if !errors.Is(err, ErrSignatureMismatch) {
		t.Errorf("expected ErrSignatureMismatch, got: %v", err)
	}
}

func TestFetch_RejectsStaleBundle(t *testing.T) {
	stale := time.Now().Add(-25 * time.Hour)
	bundle := makeBundle(t, map[string]map[string]interface{}{"a": basicAction("a")}, stale)
	srv := newTestServer(t, func(r *http.Request) (*SignedBundle, int) { return bundle, 200 })

	c := &RegistryClient{BaseURL: srv.URL, Secret: testSecret, RefreshDisabled: true}
	err := c.Fetch(context.Background())
	if !errors.Is(err, ErrBundleStale) {
		t.Errorf("expected ErrBundleStale, got: %v", err)
	}
}

// ─── Cache: write + reload ─────────────────────────────────────────────────

func TestFetch_WritesCache_LoadCache_Verifies(t *testing.T) {
	bundle := makeBundle(t, map[string]map[string]interface{}{"a": basicAction("a")}, time.Now())
	srv := newTestServer(t, func(r *http.Request) (*SignedBundle, int) { return bundle, 200 })

	tmp := t.TempDir()
	cachePath := filepath.Join(tmp, "registry.json")

	c1 := &RegistryClient{BaseURL: srv.URL, Secret: testSecret, CachePath: cachePath, RefreshDisabled: true}
	if err := c1.Fetch(context.Background()); err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	// Independent client points at the cache only — no network. Should
	// load + verify the same bundle.
	c2 := &RegistryClient{Secret: testSecret, CachePath: cachePath, RefreshDisabled: true}
	if err := c2.LoadCache(); err != nil {
		t.Fatalf("LoadCache: %v", err)
	}
	if c2.Current() == nil {
		t.Error("LoadCache populated a registry but Current() is nil")
	}
	if _, ok := c2.Current()["a"]; !ok {
		t.Errorf("cache reload missing action 'a'; got: %v", keys(c2.Current()))
	}
}

func TestLoadCache_RejectsTamperedCache(t *testing.T) {
	bundle := makeBundle(t, map[string]map[string]interface{}{"a": basicAction("a")}, time.Now())
	tmp := t.TempDir()
	cachePath := filepath.Join(tmp, "registry.json")

	// Sign + write, then mutate after writing — typical post-write
	// disk-tamper scenario.
	if err := writeAtomic(cachePath, bundle); err != nil {
		t.Fatalf("setup: writeAtomic: %v", err)
	}

	// Re-read, mutate one field, write back unsigned.
	c := &RegistryClient{Secret: testSecret, CachePath: cachePath, RefreshDisabled: true}
	if err := c.LoadCache(); err != nil {
		t.Fatalf("LoadCache before tamper: %v", err)
	}

	// Now tamper: rewrite the cache JSON with a flipped tier.
	bundle.Actions["a"]["tier"] = 99
	if err := writeAtomic(cachePath, bundle); err != nil {
		t.Fatalf("setup: rewrite: %v", err)
	}

	c2 := &RegistryClient{Secret: testSecret, CachePath: cachePath, RefreshDisabled: true}
	err := c2.LoadCache()
	if !errors.Is(err, ErrSignatureMismatch) {
		t.Errorf("expected ErrSignatureMismatch on tampered cache, got: %v", err)
	}
}

func TestLoadCache_NoCacheConfigured(t *testing.T) {
	c := &RegistryClient{Secret: testSecret, RefreshDisabled: true}
	err := c.LoadCache()
	if err == nil || !contains(err.Error(), "cache path not configured") {
		t.Errorf("expected 'cache path not configured', got: %v", err)
	}
}
