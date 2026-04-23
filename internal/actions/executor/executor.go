// Package executor runs validated KAL actions received from the AI One API.
// Supported built-in action types:
//   - run_command      – run an arbitrary shell command (param: "command")
//   - restart_service  – restart a named OS service     (param: "service")
//   - collect_diagnostics – collect and return system diagnostics
//   - apply_config     – write a config snippet to a file (params: "path", "content")
package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/shepherdtech/aione-agent/internal/actions/validation"
	"github.com/shepherdtech/aione-agent/internal/capture"
	"github.com/shepherdtech/aione-agent/internal/config"
)

// Result is the outcome of executing one action.
//
// TimedOut is set when the per-action context deadline fired before the
// underlying work completed. The dispatcher maps this to the backend
// status "timed_out" (distinct from a generic "failed"), so downstream
// remediation UX can tell the two apart.
type Result struct {
	ActionID  string    `json:"action_id"`
	Success   bool      `json:"success"`
	Output    string    `json:"output"`
	Err       string    `json:"error,omitempty"`
	TimedOut  bool      `json:"timed_out,omitempty"`
	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at"`
}

// ResultSink receives action results for forwarding to the API.
type ResultSink func(Result)

// Executor runs actions within configured limits.
type Executor struct {
	cfg       config.ActionsConfig
	validator *validation.Validator
	sink      ResultSink
	sem       chan struct{}
	mu        sync.Mutex

	// Capture context -- set post-registration via SetCaptureContext.
	// When capturePoster is nil the per-action capture bracket is a
	// no-op so this works incrementally: the first action to opt into
	// bracketing gets it; bare actions stay bare.
	agentID       string
	tenantID      string
	capturePoster CapturePoster
}

// New creates an Executor.  sink is called (synchronously within the action
// goroutine) with each result. Pass nil to defer sink wiring and call
// SetResultSink later — see the dispatcher wire-up in service.go for
// why that helps: the dispatcher needs a reference to the executor
// (for Submit) before the executor can be given a reference to the
// dispatcher (for PostResult).
func New(cfg config.ActionsConfig, sink ResultSink) *Executor {
	sem := make(chan struct{}, cfg.MaxConcurrent)
	for i := 0; i < cfg.MaxConcurrent; i++ {
		sem <- struct{}{}
	}
	return &Executor{
		cfg:       cfg,
		validator: validation.New(cfg),
		sink:      sink,
		sem:       sem,
	}
}

// SetResultSink installs (or replaces) the result sink. Safe to call
// at most once during startup, before any Submit calls race with
// execution goroutines. Used to break the executor ↔ dispatcher cycle
// at construction time.
func (e *Executor) SetResultSink(sink ResultSink) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.sink = sink
}

// Submit validates and enqueues an action for execution.
// Returns an error immediately if the action fails validation or the
// concurrency limit is exceeded.
func (e *Executor) Submit(ctx context.Context, action validation.Action) error {
	if err := e.validator.Validate(action); err != nil {
		return fmt.Errorf("action validation: %w", err)
	}

	select {
	case <-e.sem:
	default:
		return fmt.Errorf("executor at capacity (%d concurrent actions)", e.cfg.MaxConcurrent)
	}

	go func() {
		defer func() { e.sem <- struct{}{} }()
		result := e.execute(ctx, action)
		if sink := e.currentSink(); sink != nil {
			sink(result)
		}
	}()

	return nil
}

// currentSink returns the installed sink under the lock, so concurrent
// SetResultSink writes don't race with reads in the execute goroutine.
func (e *Executor) currentSink() ResultSink {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.sink
}

func (e *Executor) execute(ctx context.Context, action validation.Action) Result {
	timeout := e.cfg.Timeout
	if action.Timeout > 0 {
		d := time.Duration(action.Timeout) * time.Second
		if d < timeout {
			timeout = d
		}
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()

	log.Info().
		Str("action_id", action.ID).
		Str("type", action.Type).
		Msg("executing action")

	output, err := e.dispatch(ctx, action)

	res := Result{
		ActionID:  action.ID,
		StartedAt: start,
		EndedAt:   time.Now(),
	}
	if err != nil {
		res.Err = err.Error()
		// Distinguish timeout from other failures so the dispatcher can
		// map it to status="timed_out" on the wire. errors.Is walks the
		// wrap chain, so a command exec error that wraps the context
		// deadline still gets classified correctly.
		if errors.Is(err, context.DeadlineExceeded) || ctx.Err() == context.DeadlineExceeded {
			res.TimedOut = true
		}
		log.Warn().Err(err).Bool("timed_out", res.TimedOut).Str("action_id", action.ID).Msg("action failed")
	} else {
		res.Success = true
		res.Output = output
		log.Info().Str("action_id", action.ID).Msg("action completed")
	}
	return res
}

func (e *Executor) dispatch(ctx context.Context, action validation.Action) (string, error) {
	switch action.Type {
	case "run_command":
		return e.runCommand(ctx, action.Params)
	case "restart_service":
		return e.restartService(ctx, action.Params)
	case "collect_diagnostics":
		return e.collectDiagnostics(ctx)
	case "apply_config":
		return e.applyConfig(ctx, action.Params)
	case "flush_dns_cache":
		// KAL action seeded by aione-backend migration 021. Executor
		// lives in flush_dns_cache.go in this package. Bracketed with
		// pre/post state captures via captureDNSState (see captures.go)
		// so the rollback pipeline has a before/after snapshot. Capture
		// failures are logged and swallowed -- the action's own success
		// is not coupled to capture-pipeline health.
		e.captureDNSState(ctx, action.ID, capture.CaptureTypePre)
		out, err := e.flushDNSCache(ctx, action.Params)
		e.captureDNSState(ctx, action.ID, capture.CaptureTypePost)
		return out, err
	default:
		return "", fmt.Errorf("unknown action type: %s", action.Type)
	}
}

func (e *Executor) runCommand(ctx context.Context, params map[string]string) (string, error) {
	command, ok := params["command"]
	if !ok || command == "" {
		return "", fmt.Errorf("run_command requires 'command' param")
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "cmd.exe", "/C", command)
	} else {
		cmd = exec.CommandContext(ctx, "/bin/sh", "-c", command)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		combined := strings.TrimSpace(stdout.String() + "\n" + stderr.String())
		return combined, fmt.Errorf("command exited: %w", err)
	}

	return strings.TrimSpace(stdout.String()), nil
}

func (e *Executor) restartService(ctx context.Context, params map[string]string) (string, error) {
	svcName, ok := params["service"]
	if !ok || svcName == "" {
		return "", fmt.Errorf("restart_service requires 'service' param")
	}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.CommandContext(ctx, "sc", "stop", svcName)
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Warn().Err(err).Str("service", svcName).Msgf("stop: %s", string(out))
		}
		cmd = exec.CommandContext(ctx, "sc", "start", svcName)
	case "darwin":
		cmd = exec.CommandContext(ctx, "launchctl", "kickstart", "-k", "system/"+svcName)
	default:
		cmd = exec.CommandContext(ctx, "systemctl", "restart", svcName)
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("restarting service %s: %w", svcName, err)
	}
	return strings.TrimSpace(string(out)), nil
}

func (e *Executor) collectDiagnostics(ctx context.Context) (string, error) {
	var parts []string

	cmds := diagnosticCommands()
	for label, args := range cmds {
		cmd := exec.CommandContext(ctx, args[0], args[1:]...)
		out, _ := cmd.CombinedOutput()
		parts = append(parts, fmt.Sprintf("=== %s ===\n%s", label, string(out)))
	}

	return strings.Join(parts, "\n\n"), nil
}

func (e *Executor) applyConfig(ctx context.Context, params map[string]string) (string, error) {
	path, ok := params["path"]
	if !ok || path == "" {
		return "", fmt.Errorf("apply_config requires 'path' param")
	}
	content, ok := params["content"]
	if !ok {
		return "", fmt.Errorf("apply_config requires 'content' param")
	}

	// Sanity check: don't write outside of expected directories.
	allowedPrefixes := []string{"/etc/aione", "/var/lib/aione"}
	if runtime.GOOS == "windows" {
		allowedPrefixes = []string{`C:\ProgramData\AIOne`}
	}

	allowed := false
	for _, prefix := range allowedPrefixes {
		if strings.HasPrefix(path, prefix) {
			allowed = true
			break
		}
	}
	if !allowed {
		return "", fmt.Errorf("apply_config: path %q is outside allowed directories", path)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", fmt.Errorf("creating parent directory: %w", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return "", fmt.Errorf("writing config to %s: %w", path, err)
	}

	return fmt.Sprintf("wrote %d bytes to %s", len(content), path), nil
}
