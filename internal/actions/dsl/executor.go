package dsl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

// Outcome is the result of running a KAL action via the generic DSL
// executor. Self-contained — the migration of the existing dispatch path
// (task #26) maps this to executor.Result at the call site so the dsl
// package stays free of the executor-package import dependency.
type Outcome struct {
	// Success is true iff one of the executors (primary or any fallback)
	// completed and its exit code matched validators.post_execution.exit_code.
	Success bool

	// ExecutorUsed names which executor actually ran successfully —
	// "primary" or "fallback[N]" (1-indexed). On total failure, the value
	// of the LAST executor attempted.
	ExecutorUsed string

	// ExitCode is the OS exit code of the executor that produced the
	// final outcome (0 on Success in the typical post-exec validator).
	ExitCode int

	// Stdout / Stderr are captured from the same executor that produced
	// the final outcome. Truncated to MaxCaptureBytes per stream to
	// bound result-frame size.
	Stdout string
	Stderr string

	// TimedOut is true iff the OS killed the process at the
	// validators.post_execution.timeout_seconds deadline.
	TimedOut bool

	StartedAt time.Time
	EndedAt   time.Time

	// AttemptErrs records the per-executor failure reasons in attempt
	// order. Empty on first-try success. Useful for debugging fallback
	// chains in production logs.
	AttemptErrs []string

	// Err is the high-level reason this Outcome is a failure (when
	// Success is false). Empty on success.
	Err string
}

// Duration is a convenience for callers logging the wall-clock duration.
func (o Outcome) Duration() time.Duration { return o.EndedAt.Sub(o.StartedAt) }

// MaxCaptureBytes caps the size of stdout / stderr captures per
// executor invocation. Enough for diagnostic output, small enough to
// keep the result frame under the API's body limit.
const MaxCaptureBytes = 64 * 1024

// HostPlatform returns the (os, arch) pair the executor will dispatch
// against by default. Exposed so tests can verify the host's matrix
// without re-reading runtime constants.
func HostPlatform() (string, string) { return runtime.GOOS, runtime.GOARCH }

// ─── Public API ──────────────────────────────────────────────────────────

// Run executes the given KAL action with the given parameters. Picks the
// executor block for the host's GOOS, expands {{param}} interpolation in
// args, runs via os/exec with the action-declared timeout, then runs the
// post-execution exit-code validator. On primary failure, walks the
// fallbacks list in declared order. Returns an Outcome describing what
// happened (whether or not it succeeded — error return is reserved for
// "we couldn't even attempt to run", e.g. unsupported platform / param
// validation / arg expansion).
func Run(ctx context.Context, action *KALAction, params map[string]interface{}) (Outcome, error) {
	return runOnPlatform(ctx, action, params, runtime.GOOS)
}

// RunForPlatform is the test-hook variant of Run that takes an explicit
// GOOS instead of using runtime.GOOS. Production callers should use Run.
func RunForPlatform(ctx context.Context, action *KALAction, params map[string]interface{}, goos string) (Outcome, error) {
	return runOnPlatform(ctx, action, params, goos)
}

// ─── Internals ───────────────────────────────────────────────────────────

func runOnPlatform(ctx context.Context, action *KALAction, params map[string]interface{}, goos string) (Outcome, error) {
	startedAt := time.Now().UTC()

	// 1. Validate parameters against the action's parameter schema.
	if err := validateParams(action, params); err != nil {
		return Outcome{
			StartedAt: startedAt,
			EndedAt:   time.Now().UTC(),
			Err:       fmt.Sprintf("parameter validation: %s", err),
		}, fmt.Errorf("dsl: parameter validation: %w", err)
	}

	// 2. Pick executor block for the current OS.
	primary, fallbacks, err := pickExecutorChain(action, goos)
	if err != nil {
		return Outcome{
			StartedAt: startedAt,
			EndedAt:   time.Now().UTC(),
			Err:       err.Error(),
		}, err
	}

	// 3. Read the timeout from validators.post_execution.timeout_seconds.
	// Per the schema this is required; the JSON Schema validator at load
	// time guarantees the field is present, but we defensively default
	// here so a future schema change doesn't crash the executor.
	timeout := readPostExecTimeout(action.Raw)
	expectExitCode := readPostExecExitCode(action.Raw)

	// 4. Walk primary → fallbacks in declared order. The first executor
	// to satisfy the validator wins; on validator-fail we fall through.
	chain := append([]map[string]interface{}{primary}, fallbacks...)
	out := Outcome{StartedAt: startedAt}

	for i, ex := range chain {
		label := "primary"
		if i > 0 {
			label = fmt.Sprintf("fallback[%d]", i)
		}
		out.ExecutorUsed = label

		args, err := expandArgs(ex, params)
		if err != nil {
			out.AttemptErrs = append(out.AttemptErrs,
				fmt.Sprintf("%s arg expansion: %s", label, err))
			continue
		}

		binary, _ := ex["binary"].(string)
		exitCode, stdout, stderr, timedOut, runErr := runOne(ctx, binary, args, timeout)
		out.ExitCode = exitCode
		out.Stdout = stdout
		out.Stderr = stderr
		out.TimedOut = timedOut

		if runErr != nil && !timedOut {
			// Failure that isn't a clean exit — record + try next fallback.
			// (Common case: ENOENT when the binary isn't installed on
			// this host. Validator never gets to run; fallback wins.)
			out.AttemptErrs = append(out.AttemptErrs,
				fmt.Sprintf("%s spawn/run: %s", label, runErr))
			continue
		}

		// Validator: post_execution.exit_code must match.
		if exitCode == expectExitCode {
			out.Success = true
			out.EndedAt = time.Now().UTC()
			return out, nil
		}

		out.AttemptErrs = append(out.AttemptErrs,
			fmt.Sprintf("%s exit_code=%d (want %d)", label, exitCode, expectExitCode))
		// Fall through to the next executor.
	}

	out.EndedAt = time.Now().UTC()
	out.Err = fmt.Sprintf("all %d executor(s) failed", len(chain))
	return out, nil
}

func pickExecutorChain(action *KALAction, goos string) (
	primary map[string]interface{},
	fallbacks []map[string]interface{},
	err error,
) {
	executors, ok := action.Raw["executors"].(map[string]interface{})
	if !ok {
		return nil, nil, fmt.Errorf("dsl: action %q has no executors block", action.ID)
	}
	spec, ok := executors[goos].(map[string]interface{})
	if !ok {
		return nil, nil, fmt.Errorf("dsl: action %q has no executor for OS %q (have %v)",
			action.ID, goos, sortedKeys(executors))
	}
	primary = spec
	if rawFB, ok := spec["fallbacks"].([]interface{}); ok {
		for _, fb := range rawFB {
			if m, ok := fb.(map[string]interface{}); ok {
				fallbacks = append(fallbacks, m)
			}
		}
	}
	return primary, fallbacks, nil
}

// expandArgs replaces every {{name}} token in the executor's args with the
// stringified value of the corresponding parameter. Missing params cause
// expansion to fail (loud). Schema-level interpolation-coverage was already
// checked at registry load (loader rule #6), so this is a runtime gate
// against parameters that ARE declared but weren't provided in the call.
func expandArgs(executor map[string]interface{}, params map[string]interface{}) ([]string, error) {
	rawArgs, _ := executor["args"].([]interface{})
	out := make([]string, 0, len(rawArgs))
	for _, a := range rawArgs {
		s, ok := a.(string)
		if !ok {
			return nil, fmt.Errorf("non-string arg in executor: %T %v", a, a)
		}
		expanded, err := expandOneArg(s, params)
		if err != nil {
			return nil, err
		}
		out = append(out, expanded)
	}
	return out, nil
}

func expandOneArg(s string, params map[string]interface{}) (string, error) {
	matches := interpolationRE.FindAllStringSubmatchIndex(s, -1)
	if len(matches) == 0 {
		return s, nil
	}
	var b strings.Builder
	last := 0
	for _, m := range matches {
		// m = [matchStart, matchEnd, group1Start, group1End]
		b.WriteString(s[last:m[0]])
		name := s[m[2]:m[3]]
		val, ok := params[name]
		if !ok {
			return "", fmt.Errorf("interpolation {{%s}} but no parameter named %q in call", name, name)
		}
		b.WriteString(fmt.Sprintf("%v", val))
		last = m[1]
	}
	b.WriteString(s[last:])
	return b.String(), nil
}

// runOne invokes binary with args, capping stdout / stderr, and enforces
// timeout via context cancellation. Returns exit code (or -1 if the
// process never started), captured streams, whether the timeout fired,
// and any spawn error (separate from non-zero exit, which is NOT a
// runErr — only spawn / unexpected I/O failures are).
func runOne(ctx context.Context, binary string, args []string, timeout time.Duration) (
	exitCode int, stdout, stderr string, timedOut bool, err error,
) {
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, binary, args...)
	var stdoutBuf, stderrBuf cappedBuffer
	stdoutBuf.cap = MaxCaptureBytes
	stderrBuf.cap = MaxCaptureBytes
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	runErr := cmd.Run()
	stdout = stdoutBuf.String()
	stderr = stderrBuf.String()
	timedOut = errors.Is(runCtx.Err(), context.DeadlineExceeded)

	if runErr == nil {
		exitCode = 0
		return
	}

	var ee *exec.ExitError
	if errors.As(runErr, &ee) {
		exitCode = ee.ExitCode()
		// Non-zero exit isn't a "spawn failure" — return nil err so the
		// caller goes through the validator path (might still be a
		// success per the action's exit_code validator).
		err = nil
		return
	}

	// Anything else (ENOENT, permission denied, timeout-induced kill,
	// etc.) is a real spawn failure.
	exitCode = -1
	err = runErr
	return
}

// cappedBuffer is a bytes.Buffer that silently drops writes past `cap`
// bytes. Bounds capture size to prevent runaway tools from flooding the
// result frame.
type cappedBuffer struct {
	bytes.Buffer
	cap int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	remaining := c.cap - c.Buffer.Len()
	if remaining <= 0 {
		return len(p), nil
	}
	if len(p) > remaining {
		p = p[:remaining]
	}
	return c.Buffer.Write(p)
}

// validateParams compiles the action's parameter schema and validates
// the call's params. JSON Schema's standard validation handles required
// fields, types, ranges, enums — leveraging the same rules that gate
// action authoring at registry load.
func validateParams(action *KALAction, params map[string]interface{}) error {
	parameters, _ := action.Raw["parameters"].(map[string]interface{})
	if parameters == nil {
		// Empty parameters block — nothing to validate.
		if len(params) > 0 {
			return fmt.Errorf("action %q declares no parameters but call passed %d", action.ID, len(params))
		}
		return nil
	}
	schemaMap, _ := parameters["schema"].(map[string]interface{})
	if schemaMap == nil {
		return nil
	}

	schemaJSON, err := json.Marshal(schemaMap)
	if err != nil {
		return fmt.Errorf("marshal parameter schema: %w", err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	if err := compiler.AddResource("inline://"+action.ID, bytes.NewReader(schemaJSON)); err != nil {
		return fmt.Errorf("add parameter schema: %w", err)
	}
	schema, err := compiler.Compile("inline://" + action.ID)
	if err != nil {
		return fmt.Errorf("compile parameter schema: %w", err)
	}

	// JSON-roundtrip params so number types align with what the schema expects.
	paramsJSON, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("marshal call params: %w", err)
	}
	var paramsForSchema interface{}
	if err := json.Unmarshal(paramsJSON, &paramsForSchema); err != nil {
		return fmt.Errorf("unmarshal call params: %w", err)
	}
	if err := schema.Validate(paramsForSchema); err != nil {
		return fmt.Errorf("%s", schemaErrorPath(err))
	}
	return nil
}

// readPostExecTimeout extracts validators.post_execution.timeout_seconds
// from the raw action map, defaulting to 30s if absent. Schema requires
// the field; default is defense in depth.
func readPostExecTimeout(raw map[string]interface{}) time.Duration {
	v, ok := raw["validators"].(map[string]interface{})
	if !ok {
		return 30 * time.Second
	}
	pe, ok := v["post_execution"].(map[string]interface{})
	if !ok {
		return 30 * time.Second
	}
	secs := asInt(pe["timeout_seconds"])
	if secs <= 0 {
		return 30 * time.Second
	}
	return time.Duration(secs) * time.Second
}

// readPostExecExitCode extracts the expected post-execution exit code,
// defaulting to 0 (the schema-required default for most actions).
func readPostExecExitCode(raw map[string]interface{}) int {
	v, ok := raw["validators"].(map[string]interface{})
	if !ok {
		return 0
	}
	pe, ok := v["post_execution"].(map[string]interface{})
	if !ok {
		return 0
	}
	return asInt(pe["exit_code"])
}

func sortedKeys(m map[string]interface{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	// stdlib sort to keep error messages stable across runs
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
