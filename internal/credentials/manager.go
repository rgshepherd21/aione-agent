// Package credentials — manager.go
// Manager fetches and caches short-lived, per-action credentials from the
// platform. No secrets are stored on disk; the cache lives in memory only
// and entries are evicted when they expire.
package credentials

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/shepherdtech/aione-agent/internal/transport"
)

// ActionCred is a short-lived credential issued by the platform for one
// specific KAL action execution.
type ActionCred struct {
	// Type identifies the credential kind: "ssh_key", "api_token", "password", etc.
	Type string `json:"type"`
	// Principal is the username / identity the credential is issued for.
	Principal string `json:"principal"`
	// Secret is the actual credential value (key, token, password).
	// It is never written to disk.
	Secret string `json:"secret"`
	// Attrs holds any additional key/value metadata (host, port, scope, …).
	Attrs map[string]string `json:"attrs,omitempty"`
	// ExpiresAt is when the platform will reject this credential.
	ExpiresAt time.Time `json:"expires_at"`
}

// Valid reports whether the credential is present and not expired.
func (c *ActionCred) Valid() bool {
	return c != nil && c.Secret != "" && time.Now().Before(c.ExpiresAt)
}

type credIssueRequest struct {
	ActionID string `json:"action_id"`
	CredType string `json:"cred_type"`
}

type cachedCred struct {
	cred      ActionCred
	fetchedAt time.Time
}

// Manager fetches and in-memory-caches short-lived credentials from the
// platform API. It is safe for concurrent use.
type Manager struct {
	client *transport.Client
	mu     sync.Mutex
	cache  map[string]*cachedCred
}

// NewManager creates a Manager backed by the given API client.
func NewManager(client *transport.Client) *Manager {
	m := &Manager{
		client: client,
		cache:  make(map[string]*cachedCred),
	}
	return m
}

// Fetch returns a valid credential for the given action and type. It uses a
// cached value if still valid, otherwise fetches a new one from the platform.
func (m *Manager) Fetch(ctx context.Context, actionID, credType string) (*ActionCred, error) {
	key := actionID + ":" + credType

	m.mu.Lock()
	defer m.mu.Unlock()

	if entry, ok := m.cache[key]; ok && entry.cred.Valid() {
		log.Debug().
			Str("action_id", actionID).
			Str("cred_type", credType).
			Time("expires_at", entry.cred.ExpiresAt).
			Msg("credential cache hit")
		return &entry.cred, nil
	}

	log.Debug().Str("action_id", actionID).Str("cred_type", credType).Msg("fetching credential from platform")

	var cred ActionCred
	if err := m.client.PostJSON(ctx, "/api/v1/credentials/issue", credIssueRequest{
		ActionID: actionID,
		CredType: credType,
	}, &cred); err != nil {
		return nil, fmt.Errorf("issuing credential (action=%s type=%s): %w", actionID, credType, err)
	}

	if !cred.Valid() {
		return nil, fmt.Errorf("platform returned invalid or already-expired credential for action %s", actionID)
	}

	m.cache[key] = &cachedCred{cred: cred, fetchedAt: time.Now()}
	return &cred, nil
}

// Invalidate removes cached credentials for the given action.
// Call this after the action completes or fails so stale entries don't linger.
func (m *Manager) Invalidate(actionID string) {
	prefix := actionID + ":"
	m.mu.Lock()
	defer m.mu.Unlock()
	for k := range m.cache {
		if strings.HasPrefix(k, prefix) {
			delete(m.cache, k)
		}
	}
}

// Purge removes all expired entries. Call periodically to bound memory use.
func (m *Manager) Purge() {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, v := range m.cache {
		if now.After(v.cred.ExpiresAt) {
			delete(m.cache, k)
		}
	}
}

// StartPurger launches a background goroutine that calls Purge on interval.
func (m *Manager) StartPurger(ctx context.Context, interval time.Duration) {
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				m.Purge()
			}
		}
	}()
}
