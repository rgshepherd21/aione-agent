package executor

import (
	"context"
	"errors"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"github.com/shepherdtech/aione-agent/internal/config"
)

// Helper that constructs a minimal Executor without the shared
// concurrency limiter — we only test flushDNSCache here, which does
// not touch e.sem or e.validator. Using New() would require wiring
// more config than we need.
func newTestExecutor(t *testing.T) *Executor {
	t.Helper()
	return &Executor{
		cfg: config.ActionsConfig{Timeout: 5 * time.Second},
	}
}

// withGoos overrides the package-level goos var for the duration of
// the test. Restored via t.Cleanup so parallel subtests don't leak
// state across siblings.
func withGoos(t *testing.T, value string) {
	t.Helper()
	orig := goos
	goos = value
	t.Cleanup(func() { goos = orig })
}

// withLinuxFlushers overrides both linux paths for the duration of
// the test.
func withLinuxFlushers(t *testing.T, primary, fallback string) {
	t.Helper()
	origP, origF := linuxFlusherPrimary, linuxFlusherFallback
	linuxFlusherPrimary = primary
	linuxFlusherFallback = fallback
	t.Cleanup(func() {
		linuxFlusherPrimary = origP
		linuxFlusherFallback = origF
	})
}

// TestFlushDNSCache_UnsupportedOS pins the security contract that
// any OS outside the seeded supported_device_types returns the typed
// sentinel error rather than silently succeeding. Cross-platform —
// runs on every CI target.
func TestFlushDNSCache_UnsupportedOS(t *testing.T) {
	cases := []string{"darwin", "plan9", "freebsd", "openbsd"}
	for _, os := range cases {
		t.Run(os, func(t *testing.T) {
			withGoos(t, os)

			e := newTestExecutor(t)
			out, err := e.flushDNSCache(context.Background(), nil)

			if err == nil {
				t.Fatalf("expected ErrUnsupportedOS, got nil err (out=%q)", out)
			}
			if !errors.Is(err, ErrUnsupportedOS) {
				t.Fatalf("error chain does not contain ErrUnsupportedOS: %v", err)
			}
			if out != "" {
				t.Errorf("unsupported-OS branch should return empty output, got %q", out)
			}
		})
	}
}

// TestFlushDNSCache_LinuxBothMissing verifies the typed error fires
// when neither resolvectl nor systemd-resolve is installed. Uses
// absolute paths that provably do not exist on any host.
//
// Runs on every platform (we override goos), but the "binary not
// found" semantics are identical across platforms for
// exec.CommandContext against a nonexistent absolute path.
func TestFlushDNSCache_LinuxBothMissing(t *testing.T) {
	withGoos(t, "linux")
	withLinuxFlushers(t,
		"/nonexistent/aione-test-primary-flusher",
		"/nonexistent/aione-test-fallback-flusher",
	)

	e := newTestExecutor(t)
	out, err := e.flushDNSCache(context.Background(), nil)

	if err == nil {
		t.Fatalf("expected ErrBothLinuxFlushersMissing, got nil err (out=%q)", out)
	}
	if !errors.Is(err, ErrBothLinuxFlushersMissing) {
		t.Fatalf("error chain does not contain ErrBothLinuxFlushersMissing: %v", err)
	}
	if out != "" {
		t.Errorf("both-missing branch should return empty output, got %q", out)
	}
}

// TestFlushDNSCache_LinuxFallback verifies that when the primary
// binary is missing but the fallback exists, the fallback is used.
// Relies on /bin/true being present; skipped on non-Linux hosts.
func TestFlushDNSCache_LinuxFallback(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("/bin/true unavailable on non-Linux hosts")
	}

	withGoos(t, "linux")
	withLinuxFlushers(t,
		"/nonexistent/aione-test-missing-flusher",
		"/bin/true",
	)

	e := newTestExecutor(t)
	out, err := e.flushDNSCache(context.Background(), nil)

	if err != nil {
		t.Fatalf("expected success via fallback, got error: %v (out=%q)", err, out)
	}
	// /bin/true prints nothing; runFlusher synthesizes a status.
	if out == "" {
		t.Errorf("expected non-empty synthesized status, got empty string")
	}
}

// TestFlushDNSCache_LinuxPrimaryFailsNonzero pins the rule that a
// nonzero exit from the primary does NOT fall through to the
// fallback. A detect-based implementation could mask a real flush
// failure by re-running the same operation with a different binary;
// this test trips if that regression ever lands.
//
// Uses /bin/false as the "primary" — it exists, exec's fine, and
// exits 1. The fallback path is set to one that would succeed if it
// were ever called, so the test fails loudly if the fallback does
// fire.
func TestFlushDNSCache_LinuxPrimaryFailsNonzero(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("/bin/false unavailable on non-Linux hosts")
	}

	withGoos(t, "linux")
	withLinuxFlushers(t, "/bin/false", "/bin/true")

	e := newTestExecutor(t)
	_, err := e.flushDNSCache(context.Background(), nil)

	if err == nil {
		t.Fatal("expected error from /bin/false, got nil — fallback may have masked it")
	}
	if errors.Is(err, ErrBothLinuxFlushersMissing) {
		t.Fatalf("fallback path fired on a real nonzero exit; should have stopped at primary: %v", err)
	}
}

// TestIsBinaryMissing directly exercises the helper so the
// classification rule is covered without spinning up real exec
// calls. Drift in Go's exec error shapes (e.g. a future Go release
// reshuffling wrapping) would trip here before it breaks the
// fallback logic silently.
func TestIsBinaryMissing(t *testing.T) {
	// Real-world shape: exec.Command against a bogus absolute path,
	// then .Run() — the error type we'd get at runtime from the
	// production runFlusher call.
	cmd := exec.Command("/nonexistent/aione-test-binary")
	runErr := cmd.Run()
	if runErr == nil {
		t.Fatal("setup: expected exec of a nonexistent path to error")
	}
	if !isBinaryMissing(runErr) {
		t.Errorf("isBinaryMissing returned false for a genuinely missing binary: %v", runErr)
	}

	// Negative control: nil err is not "missing".
	if isBinaryMissing(nil) {
		t.Error("isBinaryMissing(nil) should be false")
	}
}
