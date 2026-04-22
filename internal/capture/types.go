// Package capture provides the agent-side state-capture primitive used by
// the Phase-A rollback pipeline. A Collector gathers device/host state,
// the primitive canonicalizes the payload, hashes it for drift detection,
// and returns a wire-ready Capture value that the caller POSTs to the
// backend's state_captures endpoint (coming in task #12).
//
// Wire shape mirrors aione-backend/migrations/versions/019_create_state_captures.py.
// The backend table columns are 1:1 with Capture struct fields, so this
// struct is the POST body once task #12 pins the endpoint path.
//
// Canonical form for payload_hash
// -------------------------------
// Hashing input is JSON with:
//   - UTF-8, no BOM
//   - keys sorted lexicographically at every nesting level
//   - compact separators: ","/":" (no whitespace)
//   - HTML escaping DISABLED (no \u003c/\u003e/\u0026)
//   - non-ASCII kept as raw UTF-8 (matches Python ensure_ascii=False)
//
// This is the same canonical form used by the KAL action signer
// (app/services/kal_signer.py / internal/actions/validation/validation.go).
// Reusing the spec means one mental model across both signing and capture
// hashing; see canonical.go for the Go implementation.
//
// payload_hash is drift detection, NOT tamper prevention. An attacker with
// DB write access can edit payload and hash together. The hash catches
// "a DBA hand-edited a row and forgot to recompute" before the rollback
// harness tries to restore from a corrupted snapshot. Tamper resistance
// requires HMAC-with-external-key and is deferred to Phase D.
package capture

// Capture type constants. Values MUST match the backend CHECK constraint
// `capture_type IN ('pre','post')` in migration 019. Use these constants
// everywhere instead of re-typing the literal strings so a future rename
// surfaces as a compile error instead of a silent DB 422.
const (
	CaptureTypePre  = "pre"
	CaptureTypePost = "post"
)

// Capture method constants — free-form labels for how the payload was
// collected. Backend column is VARCHAR(32), so keep values short.
// This is not a closed enum — new collectors may introduce new values
// (e.g. "netconf", "restconf") without a central registry edit; the
// constants here are just the common ones so callers avoid typos.
const (
	CaptureMethodShell   = "shell"
	CaptureMethodWMI     = "wmi"
	CaptureMethodSNMP    = "snmp"
	CaptureMethodFile    = "file"
	CaptureMethodSyscall = "syscall"
)
