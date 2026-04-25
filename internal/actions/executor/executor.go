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
	"github.com/shepherdtech/aione-agent/internal/actions/dsl"
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
//
// CommandID vs. ActionID: ActionID is the KAL action slug ("flush_dns_cache")
// -- stable across every dispatch of that action, used for type dispatch and
// capture bracketing. CommandID is the per-dispatch correlation id carried
// on the outer AgentCommand envelope, unique to this one execution. The
// dispatcher's buildResult wires CommandID through to the wire-level
// CommandResult.command_id the backend uses to locate the owning
// ActionExecution row. ActionID is preserved for log context / dedup paths
// that key off action type.
type Result struct {
	ActionID  string    `json:"action_id"`
	CommandID string    `json:"command_id,omitempty"`
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

	// DSL registry — lazy-loaded on first use. See dsl_dispatch.go for
	// the loader + the runDSLAction wiring. The hand-coded action
	// implementations in this package are the fallback when the DSL
	// registry doesn't have an entry for the requested action.
	dslOnce sync.Once
	dslReg  dsl.Registry
	dslErr  error

	// dslClient (optional) is the live BE-pull registry client. When
	// set + populated, dslRegistry() prefers it over the embedded
	// snapshot — letting the agent see action-library updates without
	// a binary rebuild. Wired up in service.go alongside exec.New.
	dslClient *dsl.RegistryClient

	// credFetcher (optional) is the credential fetcher used by SSH /
	// NETCONF / SNMP / cloud_api transport actions to obtain short-
	// lived per-action credentials from the platform. Sprint D / Task
	// #2.5. When nil, transport=ssh actions return a load-time error
	// before reaching the SSH driver. Wired up in service.go via
	// SetCredentialFetcher with an adapter that wraps
	// internal/credentials.Manager into the dsl.CredentialFetcher
	// interface (kept narrow on the dsl side so the dsl package
	// doesn't import credentials).
	credFetcher dsl.CredentialFetcher
}

// SetDSLClient attaches a registry client to the executor. The client's
// Current() registry takes precedence over the embedded one; falls back
// to embedded if the client hasn't pulled yet OR the pull failed. Safe
// to call any time before the first action dispatch.
func (e *Executor) SetDSLClient(c *dsl.RegistryClient) {
	e.dslClient = c
}

// SetCredentialFetcher attaches the per-action credential fetcher used
// by non-shell transport actions (SSH / NETCONF / SNMP / cloud_api).
// Sprint D / Task #2.5. Nil disables device-action dispatch — the
// executor will return an error if a transport=ssh action is dispatched
// without a fetcher, surfacing the misconfiguration loudly.
func (e *Executor) SetCredentialFetcher(f dsl.CredentialFetcher) {
	e.credFetcher = f
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
		CommandID: action.CommandID,
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
		// KAL action seeded by aione-backend migration 021. Bracketed
		// with pre/post state captures via captureDNSState (see
		// captures.go) so the rollback pipeline has a before/after
		// snapshot. Capture failures are logged and swallowed — the
		// action's own success is not coupled to capture-pipeline health.
		//
		// Routing: if the DSL registry has flush_dns_cache (the embedded
		// YAML at internal/actions/dsl/kal/actions/network/dns/), use
		// the generic DSL executor. Falls back to the hand-coded
		// implementation in flush_dns_cache.go ONLY if the DSL registry
		// failed to load (defensive — agent shouldn't bootkill on a
		// corrupt registry; see dslRegistry() in dsl_dispatch.go).
		// Pass action.CommandID (the per-dispatch correlation id that
		// equals action_executions.id on the backend) — NOT action.ID
		// (the KAL action slug). The state-captures endpoint validates
		// action_execution_id as a UUID; sending a slug 422s the POST.
		e.captureDNSState(ctx, action.CommandID, capture.CaptureTypePre)
		var out string
		var err error
		if e.dslHasAction("flush_dns_cache") {
			reg, regErr := e.dslRegistry()
			if regErr != nil {
				out, err = e.flushDNSCache(ctx, action.Params)
			} else {
				kalAction := reg["flush_dns_cache"]
				// flush_dns_cache is a shell-transport action — empty
				// DeviceTarget tells runDSLAction to skip the SSH path.
				out, err = e.runDSLAction(ctx, kalAction, action.Params, dsl.DeviceTarget{})
			}
		} else {
			out, err = e.flushDNSCache(ctx, action.Params)
		}
		e.captureDNSState(ctx, action.CommandID, capture.CaptureTypePost)
		return out, err
	default:
		// Sprint D / Task #2.5: any action.Type the hand-coded switch
		// doesn't recognize falls through to DSL dispatch. The DSL
		// registry's lookup-by-id determines whether the action is
		// real; transport-aware routing inside runDSLAction picks
		// shell vs SSH.
		if e.dslHasAction(action.Type) {
			reg, regErr := e.dslRegistry()
			if regErr != nil {
				return "", fmt.Errorf("dsl: registry: %w", regErr)
			}
			kalAction := reg[action.Type]
			target := dsl.DeviceTarget{
				ActionExecutionID: action.CommandID,
				Vendor:            action.DeviceVendor,
				Host:              action.DeviceHost,
				Port:              action.DevicePort,
			}
			return e.runDSLAction(ctx, kalAction, action.Params, target)
		}
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
