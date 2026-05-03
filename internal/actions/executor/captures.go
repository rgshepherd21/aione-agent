package executor

import (
	"bytes"
	"context"
	"os/exec"
	"runtime"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/shepherdtech/aione-agent/internal/capture"
)

// CapturePoster is the transport surface the executor needs to ship a
// state capture to the backend. Aliases ``capture.Sink`` so the SSH-
// transport state-capture path (internal/actions/dsl) and this
// shell-bracket path share the same type. Tests can inject a recording
// fake that satisfies ``capture.Sink``; production wires the
// ``*capture.Poster`` from internal/capture/poster.go.
type CapturePoster = capture.Sink

// SetCaptureContext installs the agent/tenant identity and capture
// poster used by action brackets. Safe to call at most once during
// startup, before any Submit calls race with the setter. Passing a nil
// poster leaves capture disabled -- action execution is unaffected.
//
// Uses the same mu the rest of Executor uses so bracket helpers can
// read capture state under the same lock without a TOCTOU between a
// setter call and a concurrent Submit.
func (e *Executor) SetCaptureContext(agentID, tenantID string, poster CapturePoster) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.agentID = agentID
	e.tenantID = tenantID
	e.capturePoster = poster
}

// captureContextSnapshot returns a coherent identity triple under the
// lock, so callers inside execute goroutines don't see a partial read
// while SetCaptureContext is updating.
func (e *Executor) captureContextSnapshot() (agentID, tenantID string, poster CapturePoster) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.agentID, e.tenantID, e.capturePoster
}

// captureDNSState runs one pre- or post-capture for a flush_dns_cache
// action and POSTs it. Failures never surface as action errors -- a
// capture pipeline outage should never take DNS remediation offline.
// Callers wire it as: pre -> action -> post inside the dispatch switch.
func (e *Executor) captureDNSState(ctx context.Context, actionExecID, captureType string) {
	agentID, tenantID, poster := e.captureContextSnapshot()
	if poster == nil || agentID == "" || tenantID == "" {
		// Capture wiring not yet installed or identity missing -- no-op
		// so the action still runs unaffected.
		return
	}

	source := dnsStateSource()
	req := capture.Request{
		ActionExecutionID: actionExecID,
		AgentID:           agentID,
		TenantID:          tenantID,
		CaptureType:       captureType,
		CaptureMethod:     capture.CaptureMethodShell,
		CaptureSource:     source,
	}

	cap, collectErr := capture.Run(ctx, req, capture.CollectorFunc(collectDNSState))

	// capture.Run returns a well-formed failure Capture alongside the
	// collector error, so post either way -- the BE disambiguates
	// "pre failed" from "pre never ran" by row existence.
	if err := poster.Post(ctx, cap); err != nil {
		log.Warn().
			Err(err).
			Str("action_id", actionExecID).
			Str("capture_type", captureType).
			Msg("executor: posting state capture failed")
	}
	if collectErr != nil {
		log.Debug().
			Err(collectErr).
			Str("action_id", actionExecID).
			Str("capture_type", captureType).
			Str("source", source).
			Msg("executor: capture collector returned error (posted as failure)")
	}
}

// dnsStateSource returns the shell command used as CaptureSource. It is
// the operator-visible label for what produced the payload. Keep in sync
// with the actual command run in collectDNSState.
func dnsStateSource() string {
	if runtime.GOOS == "windows" {
		return `C:\Windows\System32\ipconfig.exe /displaydns`
	}
	return "/usr/bin/resolvectl statistics"
}

// collectDNSState gathers a snapshot of DNS-resolver state as a
// capture.Collector. Windows -> ipconfig /displaydns; Linux ->
// resolvectl statistics. Payload shape is intentionally flat --
// {"raw_output": "...", "host_os": "..."} -- so the backend can diff
// captures without a platform-specific parser.
//
// "Binary genuinely missing" is returned as a collector error so the
// capture.Run wrapper converts it into a failure-capture row. Nonzero
// exits (binary ran, gave an error) are embedded in raw_output and
// exit_error so a future diff still has something to compare against.
func collectDNSState(ctx context.Context) (map[string]any, error) {
	var (
		path string
		arg  string
	)
	switch runtime.GOOS {
	case "windows":
		path = `C:\Windows\System32\ipconfig.exe`
		arg = "/displaydns"
	case "linux":
		path = "/usr/bin/resolvectl"
		arg = "statistics"
	default:
		// Match the flusher's platform gate -- capture and remediation
		// share the same OS support matrix.
		return map[string]any{
			"raw_output": "",
			"host_os":    runtime.GOOS,
			"note":       "capture not implemented for this OS",
		}, nil
	}

	cmd := exec.CommandContext(ctx, path, arg)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	raw := strings.TrimSpace(stdout.String())
	if raw == "" {
		raw = strings.TrimSpace(stderr.String())
	}
	payload := map[string]any{
		"raw_output": raw,
		"host_os":    runtime.GOOS,
	}
	if runErr != nil {
		if isBinaryMissing(runErr) {
			return nil, runErr
		}
		payload["exit_error"] = runErr.Error()
	}
	return payload, nil
}
