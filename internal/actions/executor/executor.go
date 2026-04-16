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
	"github.com/shepherdtech/aione-agent/internal/config"
)

// Result is the outcome of executing one action.
type Result struct {
	ActionID  string    `json:"action_id"`
	Success   bool      `json:"success"`
	Output    string    `json:"output"`
	Err       string    `json:"error,omitempty"`
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
}

// New creates an Executor.  sink is called (synchronously within the action
// goroutine) with each result.
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
		if e.sink != nil {
			e.sink(result)
		}
	}()

	return nil
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
		log.Warn().Err(err).Str("action_id", action.ID).Msg("action failed")
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

