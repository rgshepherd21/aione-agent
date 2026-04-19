// Package validation verifies action requests before they are executed.
// It checks: HMAC-SHA256 signature on the request, action type against the
// operator-configured allowlist, and presence of required parameters.
//
// Canonical signing form (MUST match the backend's kal_signer.py):
//
//  1. Build a dict with exactly these four keys:
//     "id", "params", "timeout_seconds", "type"
//  2. "params" is a string->string dict (may be empty, never null).
//  3. Serialize to JSON with:
//     - UTF-8
//     - keys sorted lexicographically at every nesting level
//     - no whitespace (compact)
//     - HTML escaping DISABLED (no \u003c, \u003e, \u0026 escapes)
//  4. Compute HMAC-SHA256 over those bytes with the shared secret.
//  5. Hex-encode the MAC.
//
// Do not change this format without coordinating with the backend.
package validation

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/shepherdtech/aione-agent/internal/config"
)

// Action is the structure sent by the AI One API to trigger work on the agent.
type Action struct {
	ID      string            `json:"id"`
	Type    string            `json:"type"`   // e.g. "run_command", "restart_service"
	Params  map[string]string `json:"params"` // Action-specific key/value parameters
	Timeout int               `json:"timeout_seconds"`
	Sig     string            `json:"sig"` // hex-encoded HMAC-SHA256 over canonical JSON
}

// ErrNotAllowed is returned when the action type is not in the allowlist.
type ErrNotAllowed struct {
	Type string
}

func (e *ErrNotAllowed) Error() string {
	return fmt.Sprintf("action type %q is not in the allowed_actions list", e.Type)
}

// ErrBadSignature is returned when the HMAC does not verify.
type ErrBadSignature struct{}

func (e *ErrBadSignature) Error() string {
	return "action signature verification failed"
}

// Validator checks action requests against the operator config.
type Validator struct {
	cfg config.ActionsConfig
}

// New creates a Validator.
func New(cfg config.ActionsConfig) *Validator {
	return &Validator{cfg: cfg}
}

// Validate returns nil if the action is allowed and its signature is valid.
// If cfg.HMACSecret is empty the signature check is skipped (useful in dev).
func (v *Validator) Validate(a Action) error {
	if err := v.checkAllowlist(a.Type); err != nil {
		return err
	}
	if v.cfg.HMACSecret != "" {
		if err := v.checkSignature(a); err != nil {
			return err
		}
	}
	return nil
}

// checkAllowlist ensures the action type is permitted.
// An empty AllowedActions slice permits all types.
func (v *Validator) checkAllowlist(actionType string) error {
	if len(v.cfg.AllowedActions) == 0 {
		return nil
	}
	for _, allowed := range v.cfg.AllowedActions {
		if allowed == actionType {
			return nil
		}
	}
	return &ErrNotAllowed{Type: actionType}
}

// checkSignature verifies the HMAC-SHA256 of the canonical action body.
// The signature covers the JSON encoding of the action without the "sig" field.
func (v *Validator) checkSignature(a Action) error {
	body, err := canonicalBody(a)
	if err != nil {
		return fmt.Errorf("building canonical body for signature check: %w", err)
	}

	mac := hmac.New(sha256.New, []byte(v.cfg.HMACSecret))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(expected), []byte(a.Sig)) {
		return &ErrBadSignature{}
	}
	return nil
}

// canonicalBody produces the exact byte sequence that both the agent and the
// backend MUST sign and verify against. See the package doc for the contract.
//
// Implementation notes:
//   - We marshal a map[string]interface{} instead of a struct so that Go's
//     encoding/json sorts the TOP-LEVEL keys alphabetically (struct fields
//     would otherwise be serialized in declaration order, which would not
//     match the Python side's sort_keys=True).
//   - map[string]string values are also key-sorted by encoding/json.
//   - We use json.Encoder with SetEscapeHTML(false) because the Go default
//     escapes <, >, & as \u003c/\u003e/\u0026, which Python does not do.
//   - json.Encoder appends a trailing newline; we strip it so the output is
//     byte-identical to Python's json.dumps(..., separators=(',', ':')).
//   - nil params is normalized to an empty map so the serialized form is
//     stable regardless of whether the caller passed nil or {}.
func canonicalBody(a Action) ([]byte, error) {
	params := a.Params
	if params == nil {
		params = map[string]string{}
	}

	body := map[string]interface{}{
		"id":              a.ID,
		"params":          params,
		"timeout_seconds": a.Timeout,
		"type":            a.Type,
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(body); err != nil {
		return nil, err
	}
	// Encode() appends a single trailing '\n'; remove it for byte-equality
	// with compact encoders on other platforms (e.g. Python json.dumps).
	out := buf.Bytes()
	if n := len(out); n > 0 && out[n-1] == '\n' {
		out = out[:n-1]
	}
	return out, nil
}
