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
