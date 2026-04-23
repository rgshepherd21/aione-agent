package validation

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/shepherdtech/aione-agent/internal/config"
)

// TestCanonicalBody_GoldenFormat pins the canonical signing format. If this
// test fails, the Go signer and the Python verifier (aione-backend/app/
// services/kal_signer.py) will disagree and every action signature check
// will fail in production. Do NOT "fix" this test by regenerating the
// expected bytes — either revert the change, or update kal_signer.py at
// the same time and regenerate both together.
func TestCanonicalBody_GoldenFormat(t *testing.T) {
	cases := []struct {
		name     string
		action   Action
		expected string
	}{
		{
			name: "basic action with two params",
			action: Action{
				ID:      "act-001",
				Type:    "restart_service",
				Params:  map[string]string{"service": "sshd", "host": "router-1"},
				Timeout: 30,
			},
			// Keys sorted top-level AND inside params, compact, no HTML escape.
			expected: `{"id":"act-001","params":{"host":"router-1","service":"sshd"},"timeout_seconds":30,"type":"restart_service"}`,
		},
		{
			name: "nil params normalized to empty object",
			action: Action{
				ID:      "act-002",
				Type:    "collect_diagnostics",
				Params:  nil,
				Timeout: 60,
			},
			expected: `{"id":"act-002","params":{},"timeout_seconds":60,"type":"collect_diagnostics"}`,
		},
		{
			name: "values with HTML-sensitive chars must not be escaped",
			action: Action{
				ID:      "act-003",
				Type:    "run_command",
				Params:  map[string]string{"cmd": "echo <ok> & done"},
				Timeout: 5,
			},
			expected: `{"id":"act-003","params":{"cmd":"echo <ok> & done"},"timeout_seconds":5,"type":"run_command"}`,
		},
		{
			// Cross-repo golden vector: MUST stay byte-identical to the
			// GOLDEN_CANONICAL_BODY fixture in
			// aione-backend/tests/test_flush_dns_cache_action.py (task
			// #16). The matching backend test pins the same bytes from
			// the Python signer side; if these two drift the agent will
			// reject every flush_dns_cache command with ErrBadSignature.
			name: "flush_dns_cache with empty params (KAL seed shape)",
			action: Action{
				ID:      "flush_dns_cache",
				Type:    "flush_dns_cache",
				Params:  map[string]string{},
				Timeout: 10,
			},
			expected: `{"id":"flush_dns_cache","params":{},"timeout_seconds":10,"type":"flush_dns_cache"}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := canonicalBody(tc.action)
			if err != nil {
				t.Fatalf("canonicalBody returned error: %v", err)
			}
			if string(got) != tc.expected {
				t.Errorf("canonical form mismatch\n  got:  %s\n  want: %s", string(got), tc.expected)
			}
		})
	}
}

func TestValidate_AcceptsCorrectSignature(t *testing.T) {
	secret := "test-secret-do-not-use-in-prod"
	v := New(config.ActionsConfig{
		HMACSecret:     secret,
		AllowedActions: []string{"restart_service"},
	})

	a := Action{
		ID:      "act-100",
		Type:    "restart_service",
		Params:  map[string]string{"service": "sshd"},
		Timeout: 30,
	}
	body, err := canonicalBody(a)
	if err != nil {
		t.Fatalf("canonicalBody: %v", err)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	a.Sig = hex.EncodeToString(mac.Sum(nil))

	if err := v.Validate(a); err != nil {
		t.Fatalf("Validate rejected a correctly signed action: %v", err)
	}
}

func TestValidate_RejectsTamperedParams(t *testing.T) {
	secret := "test-secret-do-not-use-in-prod"
	v := New(config.ActionsConfig{
		HMACSecret:     secret,
		AllowedActions: []string{"restart_service"},
	})

	a := Action{
		ID:      "act-101",
		Type:    "restart_service",
		Params:  map[string]string{"service": "sshd"},
		Timeout: 30,
	}
	body, _ := canonicalBody(a)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	a.Sig = hex.EncodeToString(mac.Sum(nil))

	// Tamper: change a param value AFTER signing.
	a.Params["service"] = "apache2"

	if err := v.Validate(a); err == nil {
		t.Fatal("Validate accepted a tampered action (expected ErrBadSignature)")
	} else if _, ok := err.(*ErrBadSignature); !ok {
		t.Fatalf("Validate returned unexpected error type: %T (%v)", err, err)
	}
}

// TestCanonicalBody_IgnoresCommandID pins the invariant that powers the
// dispatcher's CommandID propagation: the off-wire CommandID field on
// Action must NOT change the bytes that feed HMAC-SHA256. Otherwise
// threading the backend's outer command_id through the agent would
// invalidate every existing signature from kal_signer.py.
func TestCanonicalBody_IgnoresCommandID(t *testing.T) {
	base := Action{
		ID:      "flush_dns_cache",
		Type:    "flush_dns_cache",
		Params:  map[string]string{},
		Timeout: 10,
	}
	withCmdID := base
	withCmdID.CommandID = "daadb133-1ff0-4c12-bdc9-22db8cc24025"

	gotBase, err := canonicalBody(base)
	if err != nil {
		t.Fatalf("canonicalBody(base): %v", err)
	}
	gotWith, err := canonicalBody(withCmdID)
	if err != nil {
		t.Fatalf("canonicalBody(withCmdID): %v", err)
	}
	if string(gotBase) != string(gotWith) {
		t.Errorf(
			"CommandID leaked into canonical body\n  base: %s\n  with: %s",
			string(gotBase), string(gotWith),
		)
	}
}

// TestValidate_AcceptsSignatureRegardlessOfCommandID is the Validate-path
// complement to the canonical-body test: a signature computed before
// CommandID is set must still verify after the dispatcher populates it.
func TestValidate_AcceptsSignatureRegardlessOfCommandID(t *testing.T) {
	secret := "test-secret-do-not-use-in-prod"
	v := New(config.ActionsConfig{
		HMACSecret:     secret,
		AllowedActions: []string{"flush_dns_cache"},
	})

	a := Action{
		ID:      "flush_dns_cache",
		Type:    "flush_dns_cache",
		Params:  map[string]string{},
		Timeout: 10,
	}
	body, _ := canonicalBody(a)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	a.Sig = hex.EncodeToString(mac.Sum(nil))

	// Mimic dispatcher.buildAction stamping the outer command_id after
	// the backend has already signed the body.
	a.CommandID = "daadb133-1ff0-4c12-bdc9-22db8cc24025"

	if err := v.Validate(a); err != nil {
		t.Fatalf("Validate rejected action after CommandID stamp: %v", err)
	}
}

func TestValidate_RejectsDisallowedActionType(t *testing.T) {
	v := New(config.ActionsConfig{
		HMACSecret:     "", // signature check skipped so we isolate allowlist logic
		AllowedActions: []string{"restart_service"},
	})

	a := Action{
		ID:      "act-102",
		Type:    "format_disk", // not in allowlist
		Params:  map[string]string{"device": "/dev/sda"},
		Timeout: 5,
	}

	err := v.Validate(a)
	if err == nil {
		t.Fatal("Validate accepted a disallowed action type")
	}
	if _, ok := err.(*ErrNotAllowed); !ok {
		t.Fatalf("expected ErrNotAllowed, got %T (%v)", err, err)
	}
}
