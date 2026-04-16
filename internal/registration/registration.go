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

const registrationPath = "/v1/agents/register"

// RegisterRequest is the payload sent to the registration endpoint.
type RegisterRequest struct {
	InstallToken string   `json:"install_token"`
	Hostname     string   `json:"hostname"`
	OS           string   `json:"os"`
	Arch         string   `json:"arch"`
	Version      string   `json:"version"`
	Tags         []string `json:"tags"`
}

// RegisterResponse is the payload returned by the registration endpoint.
type RegisterResponse struct {
	AgentID string `json:"agent_id"`
	CertPEM string `json:"cert"`    // PEM-encoded client certificate
	KeyPEM  string `json:"key"`     // PEM-encoded private key
	CAPEM   string `json:"ca_cert"` // PEM-encoded server CA bundle
}

// stateFile holds persisted registration metadata alongside the certs.
type stateFile struct {
	AgentID     string    `json:"agent_id"`
	RegisteredAt time.Time `json:"registered_at"`
}

// Registrar manages the registration lifecycle.
type Registrar struct {
	cfg   *config.Config
	store *credentials.Store
	client *transport.Client
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
func (r *Registrar) EnsureRegistered(ctx context.Context) (agentID string, err error) {
	// Check for existing state first.
	if id, ok := r.loadState(); ok && r.store.Exists() {
		log.Info().Str("agent_id", id).Msg("agent already registered")
		return id, nil
	}

	if r.cfg.Agent.InstallToken == "" {
		return "", fmt.Errorf("agent.install_token is required for first-time registration")
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	req := RegisterRequest{
		InstallToken: r.cfg.Agent.InstallToken,
		Hostname:     hostname,
		OS:           runtime.GOOS,
		Arch:         runtime.GOARCH,
		Version:      r.version,
		Tags:         r.cfg.Agent.Tags,
	}

	log.Info().Str("api", r.cfg.API.BaseURL).Msg("registering agent")

	var resp RegisterResponse
	if err := r.client.PostJSON(ctx, registrationPath, req, &resp); err != nil {
		return "", fmt.Errorf("registration API call: %w", err)
	}

	if resp.AgentID == "" {
		return "", fmt.Errorf("registration response missing agent_id")
	}
	if resp.CertPEM == "" || resp.KeyPEM == "" || resp.CAPEM == "" {
		return "", fmt.Errorf("registration response missing credential material")
	}

	// Persist credentials to disk.
	if err := r.store.Save([]byte(resp.CertPEM), []byte(resp.KeyPEM), []byte(resp.CAPEM)); err != nil {
		return "", fmt.Errorf("saving credentials: %w", err)
	}

	// Persist registration state.
	if err := r.saveState(resp.AgentID); err != nil {
		log.Warn().Err(err).Msg("could not persist registration state")
	}

	log.Info().Str("agent_id", resp.AgentID).Msg("registration successful")
	return resp.AgentID, nil
}

func (r *Registrar) statePath() string {
	return filepath.Join(r.cfg.Agent.DataDir, "registration.json")
}

func (r *Registrar) saveState(agentID string) error {
	if err := os.MkdirAll(r.cfg.Agent.DataDir, 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(stateFile{AgentID: agentID, RegisteredAt: time.Now()})
	if err != nil {
		return err
	}
	return os.WriteFile(r.statePath(), data, 0o600)
}

func (r *Registrar) loadState() (string, bool) {
	data, err := os.ReadFile(r.statePath())
	if err != nil {
		return "", false
	}
	var s stateFile
	if err := json.Unmarshal(data, &s); err != nil {
		return "", false
	}
	return s.AgentID, s.AgentID != ""
}
