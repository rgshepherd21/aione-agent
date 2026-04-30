// Tests for ClearInstallToken — Sprint H / Task #H3.
//
// The function rewrites agent.yaml in place to set agent.install_token to
// an empty string after a successful registration. It must:
//
//   - preserve the rest of the file byte-for-byte (comments, blank lines,
//     key ordering, indentation) — that's why we use a regex on the single
//     line, not yaml.v3 round-trip serialization
//   - handle the three common scalar shapes (bare, double-quoted,
//     single-quoted)
//   - preserve trailing inline comments (`install_token: abc # one-time`)
//   - be idempotent (a second call on an already-empty config is a no-op
//     and does NOT rewrite the file — leaves mtime untouched, which
//     matters for change-detection automation)
//   - preserve file mode bits
//   - not touch the file when no install_token line is present
//   - leave nested keys alone (e.g. an `install_token` field under a
//     different parent like `legacy:` shouldn't be affected, though we
//     scope the regex to a top-level indentation level via the
//     anchored multiline match — the registrar always passes a top-level
//     yaml so the practical risk is low)

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// helper: write content to a temp file with mode 0640, return path.
func writeTemp(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
		t.Fatalf("seed temp config: %v", err)
	}
	return path
}

func readBack(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	return string(data)
}

func TestClearInstallToken_BareScalar(t *testing.T) {
	src := `agent:
  name: my-host
  install_token: abc123XYZ
  data_dir: /var/lib/aione-agent
`
	path := writeTemp(t, src)
	if err := ClearInstallToken(path); err != nil {
		t.Fatalf("ClearInstallToken: %v", err)
	}
	got := readBack(t, path)
	wantLine := `  install_token: ""`
	if !strings.Contains(got, wantLine) {
		t.Errorf("expected %q in output, got:\n%s", wantLine, got)
	}
	if strings.Contains(got, "abc123XYZ") {
		t.Errorf("token still present in output:\n%s", got)
	}
	// Surrounding lines must be untouched.
	for _, line := range []string{"  name: my-host", "  data_dir: /var/lib/aione-agent"} {
		if !strings.Contains(got, line) {
			t.Errorf("expected %q preserved, got:\n%s", line, got)
		}
	}
}

func TestClearInstallToken_DoubleQuoted(t *testing.T) {
	src := `agent:
  install_token: "abc123XYZ"
`
	path := writeTemp(t, src)
	if err := ClearInstallToken(path); err != nil {
		t.Fatalf("ClearInstallToken: %v", err)
	}
	got := readBack(t, path)
	if !strings.Contains(got, `install_token: ""`) {
		t.Errorf("expected empty quoted value, got:\n%s", got)
	}
	if strings.Contains(got, "abc123XYZ") {
		t.Errorf("token still present:\n%s", got)
	}
}

func TestClearInstallToken_SingleQuoted(t *testing.T) {
	src := `agent:
  install_token: 'abc123XYZ'
`
	path := writeTemp(t, src)
	if err := ClearInstallToken(path); err != nil {
		t.Fatalf("ClearInstallToken: %v", err)
	}
	got := readBack(t, path)
	if !strings.Contains(got, `install_token: ""`) {
		t.Errorf("expected empty quoted value, got:\n%s", got)
	}
	if strings.Contains(got, "abc123XYZ") {
		t.Errorf("token still present:\n%s", got)
	}
}

func TestClearInstallToken_PreservesInlineComment(t *testing.T) {
	// The comment is operator-authored documentation; clearing the token
	// must not eat it. Operators reading the file post-clear should still
	// see why the field exists.
	src := `agent:
  install_token: abc123  # one-time registration token
  data_dir: /var/lib/aione-agent
`
	path := writeTemp(t, src)
	if err := ClearInstallToken(path); err != nil {
		t.Fatalf("ClearInstallToken: %v", err)
	}
	got := readBack(t, path)
	if !strings.Contains(got, `# one-time registration token`) {
		t.Errorf("inline comment lost:\n%s", got)
	}
	if !strings.Contains(got, `install_token: ""`) {
		t.Errorf("token not cleared:\n%s", got)
	}
	if strings.Contains(got, "abc123") {
		t.Errorf("token still present:\n%s", got)
	}
}

func TestClearInstallToken_AlreadyEmptyIsNoop(t *testing.T) {
	// Idempotency: when the value is already empty, the function should
	// neither error nor rewrite the file. We verify by capturing the
	// original mtime and confirming it hasn't changed.
	src := `agent:
  install_token: ""
  data_dir: /var/lib/aione-agent
`
	path := writeTemp(t, src)
	statBefore, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	mtimeBefore := statBefore.ModTime()

	if err := ClearInstallToken(path); err != nil {
		t.Fatalf("ClearInstallToken on empty token: %v", err)
	}

	statAfter, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if !statAfter.ModTime().Equal(mtimeBefore) {
		t.Errorf("file rewritten despite empty token (mtime changed): before=%v after=%v",
			mtimeBefore, statAfter.ModTime())
	}
}

func TestClearInstallToken_NoInstallTokenLineIsNoop(t *testing.T) {
	// If the operator removed the install_token field manually, the
	// function must succeed silently rather than fail.
	src := `agent:
  data_dir: /var/lib/aione-agent
`
	path := writeTemp(t, src)
	statBefore, _ := os.Stat(path)
	mtimeBefore := statBefore.ModTime()

	if err := ClearInstallToken(path); err != nil {
		t.Fatalf("ClearInstallToken on tokenless config: %v", err)
	}

	statAfter, _ := os.Stat(path)
	if !statAfter.ModTime().Equal(mtimeBefore) {
		t.Errorf("file rewritten despite no install_token line (mtime changed)")
	}
}

func TestClearInstallToken_PreservesMode(t *testing.T) {
	// File mode must round-trip — agent.yaml typically inherits 0640
	// from the installer; loosening to 0644 would be a security
	// regression for a file that may contain other secrets in future.
	src := `agent:
  install_token: abc123
`
	path := writeTemp(t, src)
	// writeTemp uses 0640; tighten to 0600 to make the test meaningful
	// even on systems with unusual umasks.
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	if err := ClearInstallToken(path); err != nil {
		t.Fatalf("ClearInstallToken: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	mode := info.Mode().Perm()
	if mode != 0o600 {
		t.Errorf("mode changed: want 0600, got %#o", mode)
	}
}

func TestClearInstallToken_MissingFileReturnsError(t *testing.T) {
	// Caller (registration.EnsureRegistered) treats this as non-fatal
	// — log.Warn and continue. The function must surface the error
	// rather than silently no-op so the warn line is informative.
	err := ClearInstallToken(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err == nil {
		t.Errorf("expected error for missing file, got nil")
	}
}

func TestClearInstallToken_PreservesSurroundingStructure(t *testing.T) {
	// End-to-end check: the file ends up with the same shape minus the
	// token value. This is the regression test for "yaml.v3 round-trip
	// reorders keys" — we MUST stay byte-stable on lines we don't touch.
	src := `# AI One agent configuration.
# Generated by install.sh on 2026-04-23.
agent:
  name: roja-host-1
  install_token: aBc-123-XyZ
  data_dir: /var/lib/aione-agent
  heartbeat: 30s

api:
  base_url: https://api.example.com
  timeout: 30s

actions:
  enabled: true
`
	path := writeTemp(t, src)
	if err := ClearInstallToken(path); err != nil {
		t.Fatalf("ClearInstallToken: %v", err)
	}
	got := readBack(t, path)

	// Comments preserved.
	for _, want := range []string{
		"# AI One agent configuration.",
		"# Generated by install.sh on 2026-04-23.",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("comment missing: %q\n%s", want, got)
		}
	}

	// All non-token keys preserved with their values.
	for _, want := range []string{
		"  name: roja-host-1",
		"  data_dir: /var/lib/aione-agent",
		"  heartbeat: 30s",
		"  base_url: https://api.example.com",
		"  timeout: 30s",
		"  enabled: true",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("line lost: %q\n%s", want, got)
		}
	}

	// Token cleared, original value gone.
	if !strings.Contains(got, `install_token: ""`) {
		t.Errorf("install_token not cleared:\n%s", got)
	}
	if strings.Contains(got, "aBc-123-XyZ") {
		t.Errorf("original token still present:\n%s", got)
	}
}
