package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os/exec"
	"runtime"
	"strings"
)

// flush_dns_cache executor — the first KAL action to land on the
// aione-agent side (task #17). Seeded by aione-backend migration 021
// (``action_id='flush_dns_cache'``, execution_protocol=local,
// timeout_seconds=10, parameter_schema={additionalProperties: false}).
//
// The agent runs this on its own host; there is no SSH/WinRM target.
// On Windows we call ipconfig /flushdns; on Linux we call resolvectl
// flush-caches with a fallback to the older systemd-resolve binary.
// macOS and everything else return ErrUnsupportedOS so the
// dispatcher logs a hard failure rather than silently no-op'ing.
//
// Security mitigations (flagged during #17 scoping):
//
//  1. Absolute paths only. The agent runs as root/SYSTEM. A local
//     attacker with write access to an earlier directory on PATH
//     could shadow ipconfig/resolvectl/systemd-resolve with a
//     malicious binary. Pinning the absolute path defeats PATH
//     hijack.
//
//  2. No shell wrap. runCommand() in executor.go uses ``/bin/sh -c``
//     and ``cmd.exe /C`` — appropriate for user-authored run_command
//     actions, dangerous here because interpreter semantics could
//     leak (metachars, env lookup, job control). We call
//     exec.CommandContext directly against the absolute binary path.
//
//  3. Typed sentinel errors. ErrUnsupportedOS and
//     ErrBothLinuxFlushersMissing are distinct error values the
//     dispatcher / operator tooling can classify on, so "host
//     doesn't have a supported flusher" and "flush itself failed"
//     land in different incident queues.
//
//  4. Try-then-catch Linux fallback. A detect-then-execute pattern
//     (stat + exec) has a TOCTOU window where the candidate can be
//     swapped between the check and the run. We just try
//     linuxFlusherPrimary; if and only if the exec fails because the
//     binary is absent, we try linuxFlusherFallback. Nonzero exit
//     from the primary does NOT fall through — that's a real flush
//     failure and masking it with a second attempt would obscure
//     the diagnostic.
//
//  5. Unit-tested unsupported-OS path (see flush_dns_cache_test.go).
//     Pins the contract that future OS support has to add a branch
//     here rather than bypassing the guard.

// Overridable production values. Tests reassign these to exercise
// error paths; production code never writes to them. Package-level
// vars (not consts) solely for that reason.
var (
	// goos is the OS the flusher branches on. Defaults to
	// runtime.GOOS; tests override it to force a specific branch
	// regardless of the host they run on.
	goos = runtime.GOOS

	// windowsFlusher points at ipconfig.exe in System32, which on
	// a default Windows install is not user-writable.
	windowsFlusher = `C:\Windows\System32\ipconfig.exe`

	// linuxFlusherPrimary is the modern systemd-resolved control
	// tool, shipped on Ubuntu 20.04+, RHEL 8+, Debian 12+.
	linuxFlusherPrimary = "/usr/bin/resolvectl"

	// linuxFlusherFallback is the older name for the same tool —
	// still present on some LTS hosts (e.g. Ubuntu 18.04) and on
	// minimal images that haven't pulled in the renamed package.
	linuxFlusherFallback = "/usr/bin/systemd-resolve"
)

// ErrUnsupportedOS is returned when the host platform is outside the
// seeded supported_device_types (migration 021: server_windows,
// server_linux, workstation_windows, workstation_linux). Operators
// get a specific failure_reason so the remediation can be re-routed
// rather than quietly swallowed.
var ErrUnsupportedOS = errors.New("flush_dns_cache: host OS is not supported")

// ErrBothLinuxFlushersMissing is returned when neither resolvectl
// nor systemd-resolve is installed at its expected absolute path.
// Distinct from a nonzero exit because the operational response
// differs: "install systemd-resolved" vs. "debug the flush failure".
var ErrBothLinuxFlushersMissing = errors.New(
	"flush_dns_cache: neither " + linuxFlusherPrimary + " nor " +
		linuxFlusherFallback + " is available on this host",
)

// flushDNSCache clears the OS DNS resolver cache. Matches the KAL
// action seeded in aione-backend migration 021: no parameters, 10s
// timeout (the dispatcher enforces action.Timeout at the ctx layer).
//
// Signature matches the other executor methods so the dispatch
// switch in executor.go can route to it uniformly.
func (e *Executor) flushDNSCache(ctx context.Context, params map[string]string) (string, error) {
	// parameter_schema for this action is
	// {"additionalProperties": false, "properties": {}}. Any non-empty
	// params map would mean the backend's 422 guard let something
	// through; we intentionally ignore the value rather than erroring
	// so a field-drift bug on the backend doesn't also take this
	// remediation out of service.
	_ = params

	switch goos {
	case "windows":
		return runFlusher(ctx, windowsFlusher, "/flushdns")

	case "linux":
		out, err := runFlusher(ctx, linuxFlusherPrimary, "flush-caches")
		if err == nil {
			return out, nil
		}
		if !isBinaryMissing(err) {
			// Real failure — surface it rather than masking with the
			// fallback attempt.
			return out, err
		}

		out, err = runFlusher(ctx, linuxFlusherFallback, "flush-caches")
		if err == nil {
			return out, nil
		}
		if isBinaryMissing(err) {
			return "", ErrBothLinuxFlushersMissing
		}
		return out, err

	default:
		return "", fmt.Errorf("%w: %s", ErrUnsupportedOS, goos)
	}
}

// runFlusher exec's a single absolute-path binary with one argument,
// no shell, combining stdout+stderr in the error path. Split out so
// both OS branches share the same command-building discipline.
func runFlusher(ctx context.Context, path string, arg string) (string, error) {
	cmd := exec.CommandContext(ctx, path, arg)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		combined := strings.TrimSpace(stdout.String() + "\n" + stderr.String())
		return combined, fmt.Errorf("%s %s: %w", path, arg, err)
	}

	out := strings.TrimSpace(stdout.String())
	if out == "" {
		// resolvectl/systemd-resolve print nothing on success.
		// Synthesize a status so the execution row isn't blank in the
		// operator UI.
		return "flushed DNS cache", nil
	}
	return out, nil
}

// isBinaryMissing reports whether err indicates the executable file
// itself could not be found (as opposed to "found, ran, exited
// nonzero"). Wraps the two shapes the os/exec package uses.
func isBinaryMissing(err error) bool {
	if errors.Is(err, exec.ErrNotFound) {
		return true
	}
	if errors.Is(err, fs.ErrNotExist) {
		return true
	}
	// Dig one level: exec.Error wraps the stat failure on Linux as
	// a *fs.PathError; errors.Is usually handles it but being
	// explicit costs nothing and paves over any Go-version drift.
	var execErr *exec.Error
	if errors.As(err, &execErr) && errors.Is(execErr.Err, fs.ErrNotExist) {
		return true
	}
	return false
}
