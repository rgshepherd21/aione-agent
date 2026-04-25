package dsl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

// RegistryClient pulls + caches a signed KAL action registry from the BE.
// On startup the agent calls Fetch() once; a background goroutine then
// refreshes periodically (5 min default). The fetched registry replaces
// the embedded one for runtime dispatch — embedded is the bootstrap
// fallback only.
type RegistryClient struct {
	// HTTPClient performs the GET. Caller can override for tests or to
	// pin a custom CA / proxy. nil → http.DefaultClient.
	HTTPClient *http.Client

	// BaseURL is the BE root (e.g. https://aione-dev-api.../).
	// The client appends /api/v1/kal/registry.
	BaseURL string

	// Secret is the HMAC-SHA256 shared secret. Same value as
	// app.config.kal_signing_secret on the BE side.
	Secret string

	// CachePath is the on-disk JSON file the client writes the verified
	// bundle to after each successful fetch. On startup, before any
	// network call, the client warm-loads from this file so a temporarily
	// offline agent still has a registry to dispatch against.
	// Empty string disables the cache.
	CachePath string

	// RefreshInterval is the gap between background refreshes. 5 min by
	// default; set RefreshDisabled to disable the background goroutine
	// entirely (tests use this to make refresh deterministic).
	RefreshInterval  time.Duration
	RefreshDisabled  bool

	// current is the verified Registry currently in use. Atomic pointer
	// so dispatchers reading the registry never race with refreshes.
	current atomic.Pointer[Registry]
}

// LoadCache reads the on-disk cache file (if configured) into the
// in-memory registry. Verifies the cached bundle's signature + freshness
// before promoting it. Errors are non-fatal — caller should fall back
// to embedded.
func (c *RegistryClient) LoadCache() error {
	if c.CachePath == "" {
		return errors.New("dsl: cache path not configured")
	}
	data, err := os.ReadFile(c.CachePath)
	if err != nil {
		return fmt.Errorf("dsl: read cache: %w", err)
	}
	var bundle SignedBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return fmt.Errorf("dsl: parse cache: %w", err)
	}
	return c.adoptBundle(&bundle)
}

// Fetch pulls a fresh signed bundle from the BE, verifies it, and (on
// success) atomically replaces the current registry + writes the cache.
// On any failure (network, HTTP non-2xx, parse, signature, staleness)
// the existing in-memory registry is kept unchanged.
func (c *RegistryClient) Fetch(ctx context.Context) error {
	url := c.BaseURL + "/api/v1/kal/registry"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("dsl: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	res, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("dsl: HTTP GET %s: %w", url, err)
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 1024))
		return fmt.Errorf("dsl: %s returned %d: %s", url, res.StatusCode, string(body))
	}

	var bundle SignedBundle
	if err := json.NewDecoder(res.Body).Decode(&bundle); err != nil {
		return fmt.Errorf("dsl: decode bundle: %w", err)
	}

	if err := c.adoptBundle(&bundle); err != nil {
		return err
	}

	// Persist the verified bundle for offline-bootstrap.
	if c.CachePath != "" {
		if err := writeAtomic(c.CachePath, &bundle); err != nil {
			// Logged-but-not-fatal: cache write failure doesn't roll
			// back the in-memory adoption. The next successful fetch
			// will retry the cache write.
			return fmt.Errorf("dsl: registry adopted but cache write failed: %w", err)
		}
	}
	return nil
}

// adoptBundle verifies the bundle's signature + freshness, builds a
// Registry from it, and atomically swaps in the new one. Internal helper
// shared by LoadCache + Fetch.
func (c *RegistryClient) adoptBundle(bundle *SignedBundle) error {
	if err := VerifyBundle(bundle, c.Secret); err != nil {
		return err
	}

	reg := make(Registry, len(bundle.Actions))
	for id, raw := range bundle.Actions {
		// Reconstruct a *KALAction with what the bundle gives us. The
		// bundle has the same shape as KALAction.Raw, so we hydrate the
		// typed fields from it.
		action := &KALAction{
			ID:             asString(raw["id"]),
			Version:        asInt(raw["version"]),
			Tier:           asInt(raw["tier"]),
			Category:       asString(raw["category"]),
			Description:    asString(raw["description"]),
			Implementation: asString(raw["implementation"]),
			Idempotent:     asBool(raw["idempotent"]),
			Raw:            raw,
			SourcePath:     "(fetched-from-be)",
		}
		if sp, ok := raw["supported_platforms"].([]interface{}); ok {
			for _, entry := range sp {
				if m, ok := entry.(map[string]interface{}); ok {
					action.SupportedPlatforms = append(action.SupportedPlatforms, m)
				}
			}
		}
		reg[id] = action
	}

	c.current.Store(&reg)
	return nil
}

// Current returns the latest verified Registry, or nil if none has been
// adopted yet (cold-start before LoadCache + Fetch). Callers MUST handle
// nil and fall back to the embedded registry — the adapter for the
// agent's executor does this in dsl_dispatch.go.
func (c *RegistryClient) Current() Registry {
	p := c.current.Load()
	if p == nil {
		return nil
	}
	return *p
}

// StartRefreshLoop launches a goroutine that re-fetches at RefreshInterval
// (default 5 min) until ctx is cancelled. Errors are recorded but never
// abort the loop — transient network failures shouldn't tear down the
// registry that's already loaded.
//
// Returns immediately; cancel ctx to stop the loop.
func (c *RegistryClient) StartRefreshLoop(ctx context.Context, onError func(error)) {
	if c.RefreshDisabled {
		return
	}
	interval := c.RefreshInterval
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := c.Fetch(ctx); err != nil && onError != nil {
					onError(err)
				}
			}
		}
	}()
}

// writeAtomic writes the bundle to path via a temp file + rename, so a
// crash mid-write doesn't leave a half-written cache that fails to parse
// on next startup.
func writeAtomic(path string, bundle *SignedBundle) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".kal-registry-")
	if err != nil {
		return err
	}
	enc := json.NewEncoder(tmp)
	if err := enc.Encode(bundle); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}
