package dsl

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"
)

// makeAction is a test helper that builds a *KALAction from a YAML
// fragment, validating it through the same path production uses (so
// the test corpus stays schema-valid). The `id` is auto-generated to
// avoid duplicate-id errors when multiple tests run in the same process.
func makeAction(t *testing.T, id, yamlBody string) *KALAction {
	t.Helper()
	tmp := t.TempDir()
	writeYAML(t, tmp, "action.yaml", strings.Replace(yamlBody, "{{ID}}", id, 1))
	reg, err := LoadRegistry(tmp, schemaPath(t))
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}
	action, ok := reg[id]
	if !ok {
		t.Fatalf("registry missing %q after load (have %v)", id, keys(reg))
	}
	return action
}

// echoYAML is a parameterless action that runs `echo hello` and expects
// exit code 0. Linux/macOS only — Windows shells are loader-blocklisted,
// and the executor tests using this fixture skip on Windows.
const echoYAML = `
id: {{ID}}
version: 1
tier: 1
category: network/dns
description: "Echo smoke for executor tests."
implementation: dsl
parameters:
  schema:
    type: object
    properties: {}
    additionalProperties: false
idempotent: true
supported_platforms:
  - { os: linux,  archs: [amd64, arm64] }
  - { os: darwin, archs: [amd64, arm64] }
executors:
  linux:
    binary: /bin/echo
    args: [hello]
  darwin:
    binary: /bin/echo
    args: [hello]
validators:
  post_execution:
    exit_code: 0
    timeout_seconds: 5
state_capture:
  pre: none
  post: stateless
rollback:
  possible: false
  rationale: "Echo has no persistent state to roll back."
`

// failingPrimaryWithFallbackYAML primary uses a binary that doesn't exist
// → spawn fails → fallback to the real echo. Exercises the fallback walk.
// Linux/macOS only (Windows shells are blocklisted).
const failingPrimaryWithFallbackYAML = `
id: {{ID}}
version: 1
tier: 1
category: network/dns
description: "Primary fails (ENOENT), fallback succeeds."
implementation: dsl
parameters:
  schema:
    type: object
    properties: {}
    additionalProperties: false
idempotent: true
supported_platforms:
  - { os: linux,  archs: [amd64, arm64] }
  - { os: darwin, archs: [amd64, arm64] }
executors:
  linux:
    binary: /usr/bin/this_binary_does_not_exist_12345
    args: []
    fallbacks:
      - { binary: /bin/echo, args: [hello] }
  darwin:
    binary: /usr/bin/this_binary_does_not_exist_12345
    args: []
    fallbacks:
      - { binary: /bin/echo, args: [hello] }
validators:
  post_execution:
    exit_code: 0
    timeout_seconds: 5
state_capture:
  pre: none
  post: stateless
rollback:
  possible: false
  rationale: "Test fallback path; no real state involved."
`

// paramYAML accepts a string parameter and interpolates it into args.
// Schema requires the param. Linux/macOS only.
const paramYAML = `
id: {{ID}}
version: 1
tier: 1
category: network/dns
description: "Param interpolation smoke."
implementation: dsl
parameters:
  schema:
    type: object
    properties:
      target:
        type: string
        minLength: 1
    required: [target]
    additionalProperties: false
idempotent: true
supported_platforms:
  - { os: linux,  archs: [amd64, arm64] }
  - { os: darwin, archs: [amd64, arm64] }
executors:
  linux:
    binary: /bin/echo
    args: ['{{target}}']
  darwin:
    binary: /bin/echo
    args: ['{{target}}']
validators:
  post_execution:
    exit_code: 0
    timeout_seconds: 5
state_capture:
  pre: none
  post: stateless
rollback:
  possible: false
  rationale: "Echo has no persistent state to roll back."
`

// ─── Tests ────────────────────────────────────────────────────────────────

func TestRun_HappyPath_Echo(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test fixture is Linux/macOS only — Windows shells are loader-blocklisted")
	}
	action := makeAction(t, "echo_test", echoYAML)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out, err := Run(ctx, action, nil)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if !out.Success {
		t.Errorf("expected success, got Outcome: %+v", out)
	}
	if out.ExitCode != 0 {
		t.Errorf("exit code = %d, want 0", out.ExitCode)
	}
	if out.ExecutorUsed != "primary" {
		t.Errorf("executor used = %q, want primary", out.ExecutorUsed)
	}
	if !strings.Contains(out.Stdout, "hello") {
		t.Errorf("stdout missing expected output: %q", out.Stdout)
	}
}

func TestRun_FallbackSucceedsAfterPrimaryENOENT(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test fixture is Linux/macOS only")
	}
	action := makeAction(t, "fallback_test", failingPrimaryWithFallbackYAML)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out, err := Run(ctx, action, nil)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if !out.Success {
		t.Errorf("expected success via fallback, got Outcome: %+v", out)
	}
	if out.ExecutorUsed != "fallback[1]" {
		t.Errorf("executor used = %q, want fallback[1]", out.ExecutorUsed)
	}
	if len(out.AttemptErrs) != 1 {
		t.Errorf("expected 1 attempt error (primary), got %d: %v", len(out.AttemptErrs), out.AttemptErrs)
	}
}

func TestRun_ParameterInterpolation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test fixture is Linux/macOS only")
	}
	action := makeAction(t, "param_test", paramYAML)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out, err := Run(ctx, action, map[string]interface{}{"target": "world"})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if !out.Success {
		t.Errorf("expected success, got Outcome: %+v", out)
	}
	if !strings.Contains(out.Stdout, "world") {
		t.Errorf("stdout doesn't contain interpolated value: %q", out.Stdout)
	}
}

func TestRun_ParameterValidationFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test fixture is Linux/macOS only")
	}
	action := makeAction(t, "param_validate_test", paramYAML)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Missing required `target` → schema violation.
	out, err := Run(ctx, action, map[string]interface{}{})
	if err == nil {
		t.Fatal("expected param validation error, got nil")
	}
	if out.Success {
		t.Error("Outcome.Success should be false on validation failure")
	}
	if !strings.Contains(err.Error(), "parameter validation") {
		t.Errorf("error doesn't say 'parameter validation': %v", err)
	}
}

func TestRun_UnsupportedPlatformErrors(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test fixture is Linux/macOS only")
	}
	action := makeAction(t, "platform_test", echoYAML)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Force a platform the action doesn't declare.
	_, err := RunForPlatform(ctx, action, nil, "freebsd")
	if err == nil {
		t.Fatal("expected unsupported-platform error, got nil")
	}
	if !strings.Contains(err.Error(), "no executor for OS") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRun_TimeoutKillsProcess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test uses /bin/sleep — Linux/macOS only")
	}

	// Force a 1-second timeout on a sleep 10.
	yaml := `
id: {{ID}}
version: 1
tier: 1
category: network/dns
description: "Timeout test."
implementation: dsl
parameters:
  schema:
    type: object
    properties: {}
    additionalProperties: false
idempotent: true
supported_platforms:
  - { os: linux,  archs: [amd64, arm64] }
  - { os: darwin, archs: [amd64, arm64] }
executors:
  linux:
    binary: /bin/sleep
    args: ['10']
  darwin:
    binary: /bin/sleep
    args: ['10']
validators:
  post_execution:
    exit_code: 0
    timeout_seconds: 1
state_capture:
  pre: none
  post: stateless
rollback:
  possible: false
  rationale: "No state."
`
	action := makeAction(t, "timeout_test", yaml)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	out, err := Run(ctx, action, nil)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Run returned unexpected error: %v", err)
	}
	if out.Success {
		t.Error("expected failure on timeout, got success")
	}
	if !out.TimedOut {
		t.Errorf("expected TimedOut=true, got Outcome: %+v", out)
	}
	if elapsed > 3*time.Second {
		t.Errorf("timeout did not fire promptly: elapsed %v", elapsed)
	}
}
