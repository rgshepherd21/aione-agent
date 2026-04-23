// Package registration handles first-time agent registration against the
// AI One API using a one-time install token.  On success the API issues a
// client certificate + key that are persisted by the credentials store and
// used for all subsequent mTLS connections.
package registration

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/shepherdtech/aione-agent/internal/config"
	"github.com/shepherdtech/aione-agent/internal/credentials"
	"github.com/shepherdtech/aione-agent/internal/transport"
)

const registrationPath = "/api/v1/agents/register"

// RegisterRequest is the payload sent to the registration endpoint.
//
// Field names and JSON tags mirror the BE schema at
// app/schemas/agent.py::AgentRegisterRequest. If either side changes,
// the cross-repo contract regression test (drift doc item #14) should
// catch the drift before a live run does.
type RegisterRequest struct {
	InstallToken string `json:"install_token"`
	Name         string `json:"name"`
	AgentVersion string `json:"agent_version"`
	Platform     string `json:"platform"`
	Hostname     string `json:"hostname"`
}

// RegisterResponse is the payload returned by the registration endpoint.
//
// Field names and JSON tags mirror the BE schema at
// app/schemas/agent.py::AgentRegisterResponse. ca_cert_pem is optional
// (BE ships empty in dev; prod populates from Key Vault).
type RegisterResponse struct {
	AgentID       string                 `json:"agent_id"`
	TenantID      string                 `json:"tenant_id"`
	ClientCertPEM string                 `json:"client_cert_pem"`
	ClientKeyPEM  string                 `json:"client_key_pem"`
	CACertPEM     string                 `json:"ca_cert_pem"`
	CertExpiresAt time.Time              `json:"cert_expires_at"`
	Config        map[string]interface{} `json:"config"`
}

// stateFile holds persisted registration metadata alongside the certs.
//
// TenantID landed in the struct post-#26 so the agent can thread tenant
// scope into downstream components (state-capture posting). Older state
// files that pre-date the field decode with TenantID="" which callers
// guard on before enabling tenant-gated features.
type stateFile struct {
	AgentID      string    `json:"agent_id"`
	TenantID     string    `json:"tenant_id"`
	RegisteredAt time.Time `json:"registered_at"`
}

// Registrar manages the registration lifecycle.
type Registrar struct {
	cfg     *config.Config
	store   *credentials.Store
	client  *transport.Client
	version string
}

// New constructs a Registrar.  The transport client should be built without
// client certs (pre-registration) and updated after a successful registration.
func New(cfg *config.Config, store *credentials.Store, client *transport.Client, version string) *Registrar {
	return &Registrar{
		cfg:     cfg,
		store:   store,
		client:  client,
		version: version,
	}
}

// EnsureRegistered performs registration if the agent hasn't been registered
// yet, or if credentials are missing.  It is idempotent: a second call when
// credentials are already present does nothing.
//
// Returns agentID + tenantID so the caller can thread the tenant scope
// into downstream components (state-capture posting, audit headers). A
// zero tenantID is allowed from a legacy state file that pre-dates the
// field being persisted -- the caller should guard on it.
func (r *Registrar) EnsureRegistered(ctx context.Context) (agentID, tenantID string, err error) {
	// Check for existing state first.
	if id, tid, ok := r.loadState(); ok && r.store.Exists() {
		log.Info().Str("agent_id", id).Msg("agent already registered")
		return id, tid, nil
	}

	if r.cfg.Agent.InstallToken == "" {
		return "", "", fmt.Errorf("agent.install_token is required for first-time registration")
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Human-readable name: operator may set via config; fall back to hostname
	// so a zero-config install still registers with a sensible label.
	name := r.cfg.Agent.Name
	if name == "" {
		name = hostname
	}
	req := RegisterRequest{
		InstallToken: r.cfg.Agent.InstallToken,
		Name:         name,
		AgentVersion: r.version,
		Platform:     runtime.GOOS,
		Hostname:     hostname,
	}

	log.Info().Str("api", r.cfg.API.BaseURL).Msg("registering agent")

	var resp RegisterResponse
	if err := r.client.PostJSON(ctx, registrationPath, req, &resp); err != nil {
		return "", "", fmt.Errorf("registration API call: %w", err)
	}

	if resp.AgentID == "" {
		return "", "", fmt.Errorf("registration response missing agent_id")
	}
	if resp.ClientCertPEM == "" || resp.ClientKeyPEM == "" {
		return "", "", fmt.Errorf("registration response missing client cert/key material")
	}
	if resp.CACertPEM == "" {
		// BE ships empty ca_cert_pem in dev (by design, see aione-backend PR #26).
		// Agent falls back to the system trust store for subsequent HTTPS calls.
		log.Warn().Msg("registration response has empty ca_cert_pem; using system trust store")
	}

	// Persist credentials to disk.
	if err := r.store.Save([]byte(resp.ClientCertPEM), []byte(resp.ClientKeyPEM), []byte(resp.CACertPEM)); err != nil {
		return "", "", fmt.Errorf("saving credentials: %w", err)
	}

	// Persist registration state.
	if err := r.saveState(resp.AgentID, resp.TenantID); err != nil {
		log.Warn().Err(err).Msg("could not persist registration state")
	}

	log.Info().Str("agent_id", resp.AgentID).Msg("registration successful")
	return resp.AgentID, resp.TenantID, nil
}

func (r *Registrar) statePath() string {
	return filepath.Join(r.cfg.Agent.DataDir, "registration.json")
}

func (r *Registrar) saveState(agentID, tenantID string) error {
	if err := os.MkdirAll(r.cfg.Agent.DataDir, 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(stateFile{
		AgentID:      agentID,
		TenantID:     tenantID,
		RegisteredAt: time.Now(),
	})
	if err != nil {
		return err
	}
	return os.WriteFile(r.statePath(), data, 0o600)
}

func (r *Registrar) loadState() (string, string, bool) {
	data, err := os.ReadFile(r.statePath())
	if err != nil {
		return "", "", false
	}
	var s stateFile
	if err := json.Unmarshal(data, &s); err != nil {
		return "", "", false
	}
	return s.AgentID, s.TenantID, s.AgentID != ""
}
