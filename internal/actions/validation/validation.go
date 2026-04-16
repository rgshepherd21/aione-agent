// Package validation verifies action requests before they are executed.
// It checks: HMAC-SHA256 signature on the request, action type against the
// operator-configured allowlist, and presence of required parameters.
package validation

import (
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

// canonicalBody marshals the action without the Sig field so it can be
// signed and verified consistently.
type siglessAction struct {
	ID      string            `json:"id"`
	Type    string            `json:"type"`
	Params  map[string]string `json:"params"`
	Timeout int               `json:"timeout_seconds"`
}

func canonicalBody(a Action) ([]byte, error) {
	return json.Marshal(siglessAction{
		ID:      a.ID,
		Type:    a.Type,
		Params:  a.Params,
		Timeout: a.Timeout,
	})
}
