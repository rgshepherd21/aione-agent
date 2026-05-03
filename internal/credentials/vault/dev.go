// DevBackend — in-memory credential vault for dev / test.
//
// Sprint S3.b. Mirrors the platform-side ``DevVaultBackend`` shape so
// the seed JSON format is interchangeable: a top-level object keyed
// by id, each value a ``{type, principal, secret, attrs}`` map. The
// agent CLI's ``--vault-backend=dev`` flag selects this; CI also uses
// it via in-memory seeding.
//
// NEVER use in production. Secrets sit in process memory unprotected
// — fine for tests / lab work, wrong for any deployment that handles
// real customer credentials. Production uses ``AzureKVBackend`` or
// the (future, Sprint I weeks 6-7) ``SQLiteBackend`` with OS-keychain
// AEAD wrapping.

package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
)

// DevBackend is an in-memory ``Backend`` implementation seeded from
// either an inline JSON blob (env-var-friendly) or a JSON file on
// disk. Concurrent-safe — uses an RWMutex around the map so Put /
// Delete from a management goroutine don't race the dispatcher's
// Get calls.
type DevBackend struct {
	mu    sync.RWMutex
	store map[string]*Credentials
}

// NewDevBackend returns an empty DevBackend.
func NewDevBackend() *DevBackend {
	return &DevBackend{store: make(map[string]*Credentials)}
}

// NewDevBackendFromJSON parses an inline JSON blob and seeds the
// backend. Same shape as the backend's ``DevVaultBackend.from_json_string``:
//
//	{
//	  "lab-router-1": {
//	    "type":      "ssh_key",
//	    "principal": "admin",
//	    "secret":    "-----BEGIN OPENSSH PRIVATE KEY-----...",
//	    "attrs":     {"host": "10.0.0.1", "port": "22"}
//	  },
//	  "f7-ceos-1": {...}
//	}
//
// Empty / whitespace-only input → empty backend, matches "not
// configured" behavior. Any parse error is returned (so a typo in
// the env var fails the process at startup rather than producing
// silent ErrNotFound at request time).
func NewDevBackendFromJSON(raw string) (*DevBackend, error) {
	b := NewDevBackend()
	if isBlank(raw) {
		return b, nil
	}
	var raw_map map[string]rawCredEntry
	if err := json.Unmarshal([]byte(raw), &raw_map); err != nil {
		return nil, fmt.Errorf("vault: dev seed JSON parse: %w", err)
	}
	for id, entry := range raw_map {
		creds := entry.toCredentials()
		if err := creds.Validate(); err != nil {
			return nil, fmt.Errorf("vault: dev seed entry %q: %w", id, err)
		}
		b.store[id] = creds
	}
	return b, nil
}

// NewDevBackendFromFile reads a seed file from disk. Same payload
// shape as NewDevBackendFromJSON.
//
// Missing-file is NOT an error — the backend just starts empty,
// matching the "no seed configured" behavior. This lets dev workflows
// boot without a file and have it appear later. Parse errors on a
// present file ARE errors, same rationale as the JSON variant.
func NewDevBackendFromFile(path string) (*DevBackend, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return NewDevBackend(), nil
		}
		return nil, fmt.Errorf("vault: dev seed file %q: %w", path, err)
	}
	return NewDevBackendFromJSON(string(data))
}

// rawCredEntry is the wire shape of one seed entry, kept private so
// callers building DevBackend programmatically use Put with a
// validated Credentials struct rather than this loose form.
type rawCredEntry struct {
	Type      string            `json:"type"`
	Principal string            `json:"principal"`
	Secret    string            `json:"secret"`
	Attrs     map[string]string `json:"attrs"`
}

func (r rawCredEntry) toCredentials() *Credentials {
	attrs := r.Attrs
	if attrs == nil {
		attrs = map[string]string{}
	}
	return &Credentials{
		Type:      r.Type,
		Principal: r.Principal,
		Secret:    r.Secret,
		Attrs:     attrs,
	}
}

// Get returns the bundle for id, or ErrNotFound.
func (b *DevBackend) Get(_ context.Context, id string) (*Credentials, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	c, ok := b.store[id]
	if !ok {
		return nil, fmt.Errorf("dev backend: %q: %w", id, ErrNotFound)
	}
	// Copy on the way out — callers shouldn't be able to mutate the
	// store's view by editing the returned pointer's Attrs map.
	out := *c
	if c.Attrs != nil {
		out.Attrs = make(map[string]string, len(c.Attrs))
		for k, v := range c.Attrs {
			out.Attrs[k] = v
		}
	}
	return &out, nil
}

// Put stores or replaces an entry. Validates the bundle first; a
// malformed bundle never lands in the map.
func (b *DevBackend) Put(_ context.Context, id string, c *Credentials) error {
	if id == "" {
		return errors.New("dev backend: Put requires non-empty id")
	}
	if err := c.Validate(); err != nil {
		return fmt.Errorf("dev backend: Put %q: %w", id, err)
	}
	// Defensive copy on the way in — caller mutating after Put
	// shouldn't leak into the store.
	stored := *c
	if c.Attrs != nil {
		stored.Attrs = make(map[string]string, len(c.Attrs))
		for k, v := range c.Attrs {
			stored.Attrs[k] = v
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.store[id] = &stored
	return nil
}

// List returns all stored ids, sorted lexicographically. Empty slice
// when the vault is empty (never nil).
func (b *DevBackend) List(_ context.Context) ([]string, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	ids := make([]string, 0, len(b.store))
	for id := range b.store {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, nil
}

// Delete removes an entry, ErrNotFound if absent.
func (b *DevBackend) Delete(_ context.Context, id string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.store[id]; !ok {
		return fmt.Errorf("dev backend: %q: %w", id, ErrNotFound)
	}
	delete(b.store, id)
	return nil
}

// Close is a no-op for the in-memory backend.
func (b *DevBackend) Close() error { return nil }

// isBlank reports whether s is empty after trimming whitespace.
// Local helper — package strings would be a one-call dependency
// otherwise.
func isBlank(s string) bool {
	for _, r := range s {
		if r != ' ' && r != '\t' && r != '\n' && r != '\r' {
			return false
		}
	}
	return true
}
