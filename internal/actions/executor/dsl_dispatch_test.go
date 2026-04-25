// Tests for the transport-aware DSL dispatch path (Sprint D / Task #2.5).
//
// These exercise the executor's runDSLAction and the default-case
// fallthrough in dispatch — the shell-vs-SSH branching driven by
// action.Raw["transport"].

package executor

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/shepherdtech/aione-agent/internal/actions/dsl"
)

// ─── Test fakes ─────────────────────────────────────────────────────────────

// fakeFetcher implements dsl.CredentialFetcher for testing the SSH path
// without standing up a real /v1/credentials/issue endpoint.
type fakeFetcher struct {
	cred  dsl.DeviceCredential
	err   error
	calls []fakeFetcherCall
}

type fakeFetcherCall struct {
	actionID string
	credType string
}

func (f *fakeFetcher) Fetch(_ context.Context, actionID, credType string) (dsl.DeviceCredential, error) {
	f.calls = append(f.calls, fakeFetcherCall{actionID, credType})
	if f.err != nil {
		return dsl.DeviceCredential{}, f.err
	}
	return f.cred, nil
}

// shellAction returns a minimal shell-transport action whose only
// executor for the test platform runs ``/bin/echo hello``. Builds the
// raw map directly so we don't need a YAML loader or schema.
func shellAction() *dsl.KALAction {
	return &dsl.KALAction{
		ID: "test_shell_action",
		Raw: map[string]interface{}{
			"id":             "test_shell_action",
			"version":        1,
			"tier":           1,
			"category":       "test/shell",
			"description":    "shell-transport test fixture",
			"implementation": "dsl",
			"idempotent":     true,
			"transport":      "shell",
			"executors": map[string]interface{}{
				"linux":   map[string]interface{}{"binary": "/bin/echo", "args": []interface{}{"ok"}},
				"darwin":  map[string]interface{}{"binary": "/bin/echo", "args": []interface{}{"ok"}},
				"windows": map[string]interface{}{"binary": "/bin/echo", "args": []interface{}{"ok"}},
			},
			"validators": map[string]interface{}{
				"post_execution": map[string]interface{}{
					"timeout_seconds": 5,
					"exit_code":       0,
				},
			},
			"state_capture": map[string]interface{}{"pre": "none", "post": "stateless"},
			"rollback": map[string]interface{}{
				"possible":  false,
				"rationale": "test fixture has no state",
			},
			"parameters": map[string]interface{}{
				"schema": map[string]interface{}{
					"type":                 "object",
					"properties":           map[string]interface{}{},
					"additionalProperties": false,
				},
			},
		},
	}
}

// sshAction returns a transport=ssh action with a single cisco_iosxe
// executor block. Doesn't actually open SSH connections — the ssh
// dispatch test only verifies that runDSLAction routes through
// RunDeviceAction (which fails fast when it can't reach the host).
func sshAction() *dsl.KALAction {
	return &dsl.KALAction{
		ID: "test_ssh_action",
		Raw: map[string]interface{}{
			"id":             "test_ssh_action",
			"version":        1,
			"tier":           1,
			"category":       "test/ssh",
			"description":    "ssh-transport test fixture",
			"implementation": "dsl",
			"idempotent":     true,
			"transport":      "ssh",
			"cred_type":      "ssh_key",
			"device_executors": map[string]interface{}{
				"cisco_iosxe": map[string]interface{}{
					"command": "show version",
				},
			},
			"validators": map[string]interface{}{
				"post_execution": map[string]interface{}{
					"timeout_seconds": 5,
					"exit_code":       0,
				},
			},
			"state_capture": map[string]interface{}{"pre": "none", "post": "stateless"},
			"rollback": map[string]interface{}{
				"possible":  false,
				"rationale": "read-only show command",
			},
			"parameters": map[string]interface{}{
				"schema": map[string]interface{}{
					"type":                 "object",
					"properties":           map[string]interface{}{},
					"additionalProperties": false,
				},
			},
		},
	}
}

// ─── Tests ──────────────────────────────────────────────────────────────────

func TestRunDSLAction_ShellTransportRoutesThroughRun(t *testing.T) {
	e := &Executor{}
	out, err := e.runDSLAction(
		context.Background(),
		shellAction(),
		map[string]string{},
		dsl.DeviceTarget{}, // unused for shell
	)
	if err != nil {
		t.Fatalf("shell dispatch: %v", err)
	}
	if !strings.Contains(out, "ok") && !strings.Contains(out, "succeeded") {
		t.Errorf("shell stdout: got %q, expected 'ok' or fallback message", out)
	}
}

func TestRunDSLAction_SSHTransportRoutesThroughRunDeviceAction(t *testing.T) {
	// Use a fake fetcher that returns an obviously-fake key so the SSH
	// dial fails fast on connection refused. We're not testing the SSH
	// driver here — just that runDSLAction routes through it for
	// transport=ssh actions.
	fetcher := &fakeFetcher{
		cred: dsl.DeviceCredential{
			Type:      "ssh_key",
			Principal: "rojadmin",
			// A garbage secret that ssh.ParsePrivateKey will reject.
			// The point is to exercise the dispatch path — we don't
			// need a real handshake, just proof of routing.
			Secret:    "-----BEGIN OPENSSH PRIVATE KEY-----not-a-real-key-----END OPENSSH PRIVATE KEY-----",
			ExpiresAt: time.Now().Add(10 * time.Minute),
		},
	}
	e := &Executor{credFetcher: fetcher}

	_, err := e.runDSLAction(
		context.Background(),
		sshAction(),
		map[string]string{},
		dsl.DeviceTarget{
			ActionExecutionID: "11111111-2222-3333-4444-555555555555",
			Vendor:            "cisco_iosxe",
			Host:              "127.0.0.1",
			Port:              1, // unused — fetch fires before dial
		},
	)
	// Expect a failure (parse private key OR dial), but it MUST come
	// through the device-action path. Verify by asserting the fetcher
	// was called — no fetcher call means the shell path was wrongly
	// taken.
	if err == nil {
		t.Fatal("expected SSH dispatch to fail (fake key + no real device)")
	}
	if len(fetcher.calls) == 0 {
		t.Fatal("expected CredentialFetcher.Fetch to be called for transport=ssh action")
	}
	if fetcher.calls[0].credType != "ssh_key" {
		t.Errorf("expected ssh_key cred_type, got %q", fetcher.calls[0].credType)
	}
	if fetcher.calls[0].actionID != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("expected target.ActionExecutionID forwarded as actionID, got %q",
			fetcher.calls[0].actionID)
	}
}

func TestRunDSLAction_SSHWithoutFetcherFailsFast(t *testing.T) {
	// No credFetcher set — runDSLAction must surface the misconfiguration
	// rather than nil-deref.
	e := &Executor{}
	_, err := e.runDSLAction(
		context.Background(),
		sshAction(),
		map[string]string{},
		dsl.DeviceTarget{
			ActionExecutionID: "x",
			Vendor:            "cisco_iosxe",
			Host:              "127.0.0.1",
		},
	)
	if err == nil {
		t.Fatal("expected error when SSH action dispatched without a fetcher")
	}
	if !strings.Contains(err.Error(), "credential fetcher") &&
		!strings.Contains(err.Error(), "SetCredentialFetcher") {
		t.Errorf("error should mention the missing fetcher: %v", err)
	}
}

func TestRunDSLAction_AbsentTransportTreatedAsShell(t *testing.T) {
	// An action without a transport field at all should run via the
	// shell path. Backward compatibility for actions authored before
	// Sprint D's schema landed.
	action := shellAction()
	delete(action.Raw, "transport")

	e := &Executor{}
	_, err := e.runDSLAction(
		context.Background(),
		action,
		map[string]string{},
		dsl.DeviceTarget{},
	)
	if err != nil {
		t.Fatalf("absent-transport dispatch: %v", err)
	}
}

func TestCredentialFetcherAdapter_NilMgrFailsCleanly(t *testing.T) {
	a := NewCredentialFetcher(nil)
	_, err := a.Fetch(context.Background(), "x", "ssh_key")
	if err == nil {
		t.Fatal("expected error from nil-manager adapter")
	}
}

func TestCredentialFetcherAdapter_NilReceiverFailsCleanly(t *testing.T) {
	var a *CredentialFetcherAdapter
	_, err := a.Fetch(context.Background(), "x", "ssh_key")
	if err == nil {
		t.Fatal("expected error from nil-receiver adapter")
	}
}

// ─── Sentinel guard ─────────────────────────────────────────────────────────

func TestErrAdapterIsCheckable(t *testing.T) {
	a := NewCredentialFetcher(nil)
	_, err := a.Fetch(context.Background(), "x", "ssh_key")
	if !errors.Is(err, errAdapterUnconfigured) {
		t.Errorf("expected errors.Is(err, errAdapterUnconfigured) to be true, got %v", err)
	}
}
