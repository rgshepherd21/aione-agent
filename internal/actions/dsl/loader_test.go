package dsl

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// validYAML is the minimal-valid action template; per-test mutations
// flip one field at a time. Mirrors _VALID_YAML in
// aione-backend/tests/test_kal_registry.py so the suites stay
// recognizably parallel.
const validYAML = `
id: test_action
version: 1
tier: 1
category: network/dns
description: "Test action for registry loader unit tests."
implementation: dsl

parameters:
  schema:
    type: object
    properties: {}
    additionalProperties: false

idempotent: true

supported_platforms:
  - { os: linux, archs: [amd64] }

executors:
  linux:
    binary: /usr/bin/echo
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
  rationale: "Test action has no state to roll back."
`

// schemaPath returns the absolute path to the embedded-mirror schema
// file, used for tests that load with on-disk fixtures.
func schemaPath(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return filepath.Join(wd, "kal", "schema", "action.schema.json")
}

func writeYAML(t *testing.T, dir, subpath, content string) string {
	t.Helper()
	full := filepath.Join(dir, subpath)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(full, []byte(strings.TrimSpace(content)+"\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return full
}

// ─── Happy path: the embedded registry loads cleanly ──────────────────────

func TestLoadEmbeddedRegistry_FlushDNSPresent(t *testing.T) {
	reg, err := LoadEmbeddedRegistry()
	if err != nil {
		t.Fatalf("LoadEmbeddedRegistry returned error: %v", err)
	}
	action, ok := reg["flush_dns_cache"]
	if !ok {
		t.Fatalf("expected flush_dns_cache in registry, got keys: %v", keys(reg))
	}
	if action.Tier != 1 {
		t.Errorf("flush_dns_cache.Tier = %d, want 1", action.Tier)
	}
	if !action.Idempotent {
		t.Errorf("flush_dns_cache.Idempotent = false, want true")
	}
	if action.Implementation != "dsl" {
		t.Errorf("flush_dns_cache.Implementation = %q, want dsl", action.Implementation)
	}
}

// ─── Cross-field rule failures (mirror Python test_kal_registry.py) ───────

func TestLoadRegistry_DuplicateIDRejected(t *testing.T) {
	tmp := t.TempDir()
	writeYAML(t, tmp, "a/first.yaml", validYAML)
	writeYAML(t, tmp, "b/second.yaml", validYAML)

	_, err := LoadRegistry(tmp, schemaPath(t))
	if err == nil {
		t.Fatal("expected duplicate-id error, got nil")
	}
	if !strings.Contains(err.Error(), "duplicate action id 'test_action'") {
		t.Errorf("unexpected error message: %v", err)
	}
	if !strings.Contains(err.Error(), "first.yaml") {
		t.Errorf("error doesn't reference first-seen file: %v", err)
	}
}

func TestLoadRegistry_ShellBinaryRejected(t *testing.T) {
	tmp := t.TempDir()
	writeYAML(t, tmp, "shell.yaml", strings.Replace(validYAML, "/usr/bin/echo", "/bin/sh", 1))

	_, err := LoadRegistry(tmp, schemaPath(t))
	if err == nil {
		t.Fatal("expected shell-binary error, got nil")
	}
	if !strings.Contains(err.Error(), "is a shell") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestLoadRegistry_UnknownInterpolationRejected(t *testing.T) {
	tmp := t.TempDir()
	yaml := strings.Replace(validYAML, "args: [hello]", "args: ['{{target}}']", 1)
	writeYAML(t, tmp, "bad_interp.yaml", yaml)

	_, err := LoadRegistry(tmp, schemaPath(t))
	if err == nil {
		t.Fatal("expected interpolation error, got nil")
	}
	if !strings.Contains(err.Error(), "{{target}}") {
		t.Errorf("error doesn't quote token: %v", err)
	}
	if !strings.Contains(err.Error(), "not a declared parameter") {
		t.Errorf("error doesn't mention rule: %v", err)
	}
}

func TestLoadRegistry_UnreachableExecutorRejected(t *testing.T) {
	tmp := t.TempDir()
	yaml := strings.Replace(validYAML,
		"executors:\n  linux:",
		"executors:\n  linux:\n    binary: /usr/bin/echo\n    args: [hello]\n  darwin:",
		1)
	writeYAML(t, tmp, "orphan.yaml", yaml)

	_, err := LoadRegistry(tmp, schemaPath(t))
	if err == nil {
		t.Fatal("expected unreachable-executor error, got nil")
	}
	if !strings.Contains(err.Error(), "darwin") {
		t.Errorf("error doesn't name orphan OS: %v", err)
	}
	if !strings.Contains(err.Error(), "not in supported_platforms") {
		t.Errorf("error doesn't mention rule: %v", err)
	}
}

func TestLoadRegistry_SchemaViolationSurfacesField(t *testing.T) {
	tmp := t.TempDir()
	// tier=7 is outside the schema enum {1,2,3,4,5}.
	writeYAML(t, tmp, "bad_tier.yaml", strings.Replace(validYAML, "tier: 1", "tier: 7", 1))

	_, err := LoadRegistry(tmp, schemaPath(t))
	if err == nil {
		t.Fatal("expected schema violation, got nil")
	}
	if !strings.Contains(err.Error(), "schema violation") {
		t.Errorf("error doesn't say 'schema violation': %v", err)
	}
	if !strings.Contains(err.Error(), "tier") {
		t.Errorf("error doesn't reference field path: %v", err)
	}
}

func TestLoadRegistry_Tier1MustBeIdempotent(t *testing.T) {
	tmp := t.TempDir()
	writeYAML(t, tmp, "non_idempotent.yaml",
		strings.Replace(validYAML, "idempotent: true", "idempotent: false", 1))

	_, err := LoadRegistry(tmp, schemaPath(t))
	if err == nil {
		t.Fatal("expected tier-1-idempotent error, got nil")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "idempotent") {
		t.Errorf("error doesn't mention idempotent rule: %v", err)
	}
}

func TestLoadRegistry_EmptyDirReturnsEmptyRegistry(t *testing.T) {
	tmp := t.TempDir()
	reg, err := LoadRegistry(tmp, schemaPath(t))
	if err != nil {
		t.Fatalf("expected nil error on empty dir, got: %v", err)
	}
	if len(reg) != 0 {
		t.Errorf("expected empty registry, got %d entries", len(reg))
	}
}

// ─── helpers ──────────────────────────────────────────────────────────────

func keys(reg Registry) []string {
	out := make([]string, 0, len(reg))
	for k := range reg {
		out = append(out, k)
	}
	return out
}
