// Package vault — agent-side device credential storage.
//
// Sprint S3.b. Distinct from the two pre-existing credential concerns:
//
//   * ``internal/credentials/credentials.Store`` — the agent's own
//     mTLS identity (cert + key + CA, on disk), used for HTTPS auth
//     to the platform.
//
//   * ``internal/credentials/credentials.Manager`` — per-action device
//     credential fetcher that calls the platform's
//     ``/v1/credentials/issue`` endpoint. The platform resolves vault
//     references and hands the agent a per-action bundle. This is the
//     ``dev://`` and ``azure-kv://`` (centrally-managed) path.
//
// THIS package is the third concern: when a device's
// ``credential_ref`` is ``local://<id>``, the platform refuses to
// resolve it (V1.local invariant — see
// ``aione-backend/tests/test_local_scheme_invariant.py``). The agent
// resolves the ref locally, through one of the ``Backend``
// implementations in this package. ``DevBackend`` is the in-memory
// dev/test path; ``AzureKVBackend`` is the production path and reads
// secrets from a customer-owned Azure Key Vault via managed identity.
//
// Why a separate package
// ----------------------
// Two reasons. First, the surface is genuinely different: ``Store``
// is filesystem state, ``Manager`` is HTTP-fetch state, ``Backend``
// is a pluggable storage layer with multiple implementations. Second,
// the patent-claim split-plane semantics live HERE — the boundary
// between "platform resolves credentials" (Manager) and "agent
// resolves credentials" (Backend) is the interface seam that makes
// the architectural property reviewable.

package vault

import (
	"context"
	"errors"
)

// Credentials carries one device's auth bundle. Mirrors the shape
// of ``credentials.ActionCred`` and the platform's
// ``CredentialIssueResponse`` so call sites that switch between
// ``Manager.Fetch`` and ``Backend.Get`` see the same fields.
//
// Type values mirror ``sshclient.AuthMethod``: ``ssh_key`` /
// ``password`` / ``ssh_password`` / ``api_token`` / ``snmp_v3``.
// Backends store the type alongside the secret material so a caller
// asking for ``ssh_key`` doesn't get back a password by accident.
type Credentials struct {
	// Type discriminates the auth method (and consequently the shape
	// of Secret). REQUIRED.
	Type string

	// Principal is the username (SSH user, API account name, SNMPv3
	// security-name, etc.). REQUIRED.
	Principal string

	// Secret is the auth material, format-dependent on Type:
	// ``ssh_key``  — PEM-encoded SSH private key.
	// ``password`` / ``ssh_password`` — the password literal.
	// ``api_token`` — the bearer token.
	// REQUIRED.
	Secret string

	// Attrs is free-form metadata the caller may need (host, port,
	// SNMP engine ID, …). Optional; backends preserve the keys
	// they store, callers tolerate missing keys.
	Attrs map[string]string
}

// Validate returns nil iff the bundle has the three required fields.
// Backends call this before returning from Get so a malformed entry
// fails fast at lookup rather than at use.
func (c *Credentials) Validate() error {
	if c == nil {
		return errors.New("vault: nil Credentials")
	}
	if c.Type == "" {
		return errors.New("vault: Credentials.Type is required")
	}
	if c.Principal == "" {
		return errors.New("vault: Credentials.Principal is required")
	}
	if c.Secret == "" {
		return errors.New("vault: Credentials.Secret is required")
	}
	return nil
}

// Backend is the agent-side credential-store contract.
//
// Implementations:
//   - DevBackend (in-memory map, dev/test only)
//   - AzureKVBackend (production — customer-owned Azure Key Vault)
//
// Future implementations (deferred to Sprint I weeks 6-7 per the
// server-agent production plan): SQLiteBackend with OS-keychain-
// wrapped AEAD for the on-prem server-agent shape.
//
// All methods take a context for cancellation/timeout. Backend-
// specific errors should wrap ``ErrNotFound`` for "no entry for
// this id" so callers can distinguish "credential vault is
// reachable but empty" from "credential vault is broken".
type Backend interface {
	// Get resolves an id (typically a device id, but the backend
	// treats it as opaque) to a Credentials bundle. Returns
	// ErrNotFound if the id has no entry; any other error is a
	// backend-internal failure (network, auth, permissions, …).
	Get(ctx context.Context, id string) (*Credentials, error)

	// Put stores or replaces an entry. Used by management tooling
	// (the cred-management UI in Sprint I phase 3, the CLI vault
	// subcommand in this sprint) — not from the dispatch hot path.
	Put(ctx context.Context, id string, c *Credentials) error

	// List enumerates the ids the backend currently holds. Sorted
	// for diagnostic stability. Empty slice on empty vault, never
	// nil.
	List(ctx context.Context) ([]string, error)

	// Delete removes an entry. Returns ErrNotFound if the id was
	// already absent (so retries / scripted deletes don't error
	// noisily).
	Delete(ctx context.Context, id string) error

	// Close releases any backend resources (HTTP clients, file
	// handles). Idempotent — safe to call more than once.
	Close() error
}

// ErrNotFound is the sentinel returned by Get / Delete when the
// id has no entry. Wrap with ``fmt.Errorf("...: %w", ErrNotFound)``
// in implementation code so callers can use ``errors.Is`` to test.
var ErrNotFound = errors.New("vault: credential not found")
