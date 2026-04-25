package dsl

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"
)

// SignedBundle is the wire shape served by the BE at GET /api/v1/kal/registry.
// Mirrors the dict produced by aione-backend/app/services/kal_registry_signer.py
// — keep the JSON tags + types byte-compatible with the Python output.
type SignedBundle struct {
	Actions   map[string]map[string]interface{} `json:"actions"`
	Signature string                            `json:"signature"`
	SignedAt  string                            `json:"signed_at"` // ISO 8601 UTC
	Version   int                               `json:"version"`
}

// MaxBundleAge is the replay-defense window. Bundles older than this are
// rejected even if their signature verifies — protects against an attacker
// replaying a months-old bundle that happens to have a valid signature.
//
// 24h matches the value the BE-side docstring (kal_registry_signer.py)
// promises agents will enforce.
const MaxBundleAge = 24 * time.Hour

// ErrSignatureMismatch indicates the HMAC signature didn't verify.
var ErrSignatureMismatch = errors.New("dsl: registry signature verification failed")

// ErrBundleStale indicates the bundle's signed_at is older than MaxBundleAge.
var ErrBundleStale = errors.New("dsl: registry bundle is stale (older than 24h)")

// ErrBundleMissingFields indicates a malformed bundle (missing required keys
// or wrong types).
var ErrBundleMissingFields = errors.New("dsl: registry bundle missing required fields")

// CanonicalRegistryBytes returns the deterministic byte form of a registry's
// actions map. Sorts action ids lexicographically and concatenates each
// action's canonical body with no separator. MUST stay byte-identical to
// canonical_registry_bytes() in
// aione-backend/app/services/kal_registry_signer.py — drift on either side
// fails verification at runtime.
func CanonicalRegistryBytes(actions map[string]map[string]interface{}) ([]byte, error) {
	ids := make([]string, 0, len(actions))
	for id := range actions {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var out []byte
	for _, id := range ids {
		body, err := CanonicalActionBody(actions[id])
		if err != nil {
			return nil, fmt.Errorf("canonical body for %q: %w", id, err)
		}
		out = append(out, body...)
	}
	return out, nil
}

// VerifyBundle checks the HMAC-SHA256 signature against the canonical bytes
// of the bundle's actions, plus enforces the staleness window. Used by the
// registry client before loading a fetched bundle into the live registry.
func VerifyBundle(bundle *SignedBundle, secret string) error {
	if secret == "" {
		return errors.New("dsl: HMAC secret must not be empty")
	}
	if bundle == nil || bundle.Signature == "" {
		return ErrBundleMissingFields
	}

	// Staleness check first — cheaper than HMAC, and a stale bundle is
	// invalid regardless of signature.
	signedAt, err := time.Parse(time.RFC3339Nano, bundle.SignedAt)
	if err != nil {
		// Fall back to RFC3339 (some Python isoformat outputs lack the
		// nanosecond suffix). If both fail, the bundle's bad.
		signedAt, err = time.Parse(time.RFC3339, bundle.SignedAt)
		if err != nil {
			return fmt.Errorf("dsl: parse signed_at %q: %w", bundle.SignedAt, err)
		}
	}
	if time.Since(signedAt) > MaxBundleAge {
		return ErrBundleStale
	}

	body, err := CanonicalRegistryBytes(bundle.Actions)
	if err != nil {
		return fmt.Errorf("dsl: canonical bytes: %w", err)
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))

	provided, err := hex.DecodeString(bundle.Signature)
	if err != nil {
		return fmt.Errorf("dsl: signature is not valid hex: %w", err)
	}
	expectedRaw, _ := hex.DecodeString(expected)

	if !hmac.Equal(expectedRaw, provided) {
		return ErrSignatureMismatch
	}
	return nil
}
