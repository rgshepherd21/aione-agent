// State-capture wiring for the DSL device executor (Sprint follow-up
// S2.a). Sits next to ``device_executor.go`` so the persistent-shell
// pre/post capture path can be reviewed in one place rather than
// scattered across the action runner.
//
// Wire model
// ----------
// Each ``state_capture`` phase declared in a KAL action YAML is
// either:
//
//   * A sentinel string — "stateless" / "none" / "snapshot_*" —
//     meaning "no structured capture for this phase". The executor
//     emits no rows for that side.
//
//   * A structured object — { commands: [...], parser: <slug> } —
//     meaning "run these commands in the persistent shell, feed the
//     joined output through this parser, and persist the parsed map
//     as a state_captures row." The executor uses the same Shell it
//     ran the action on, so capture commands share CLI mode state
//     with action commands (e.g. a config-mode pre-snapshot can read
//     `do show interface Et1 | json` without leaving config mode).
//
// CaptureSink (declared in this file) is the abstraction the
// executor uses to actually ship a built Capture. Production wires
// the real Poster from internal/capture; tests inject a recording
// fake so the executor's pre/post call sequence can be asserted
// without an HTTP round-trip.

package dsl

import (
	"context"
	"fmt"
	"strings"

	"github.com/shepherdtech/aione-agent/internal/capture"
	"github.com/shepherdtech/aione-agent/internal/capture/parsers"
	"github.com/shepherdtech/aione-agent/internal/transport/sshclient"
)

// CaptureSink is the narrow interface RunDeviceAction uses to ship
// a built Capture to the backend. Aliases ``capture.Sink`` so the
// shell-bracket path (internal/actions/executor) and this SSH path
// share the same type — production wires both to ``*capture.Poster``;
// tests inject recording fakes that satisfy the same interface.
//
// Sink errors are logged but do NOT fail the surrounding action —
// a transient capture-post failure shouldn't unwind a successful
// device mutation. The capture layer's idempotent
// (action_execution_id, capture_type) uniqueness on the backend
// means the rollback harness will still see the row on a later
// retry.
type CaptureSink = capture.Sink

// noopSink swallows captures silently. Used when the caller didn't
// hand the executor a sink (older test paths, dev_diag, etc.) so we
// don't crash; production callers should always supply a real sink.
type noopSink struct{}

func (noopSink) Post(_ context.Context, _ capture.Capture) error { return nil }

// statePhase is the parsed shape of one ``state_capture.pre`` or
// ``state_capture.post`` YAML field. ``Sentinel`` is non-empty when
// the YAML declared a string ("stateless" / "none" / "snapshot_*");
// in that case Commands and Parser are empty and the executor skips
// structured capture for that phase. When ``Sentinel`` is empty the
// other two fields are populated and the executor runs the
// collector.
//
// Both fields can never be set simultaneously — the schema's
// ``oneOf`` constraint guarantees it; readStateCapturePhase panics
// (in dev) / errors (in prod) if YAML parsing produced both.
type statePhase struct {
	Sentinel string   // empty when structured form is in use
	Commands []string // declared commands; non-nil only when structured
	Parser   string   // parser registry slug; non-empty only when structured
}

// stateCaptureSpec is the parsed shape of an action's whole
// ``state_capture`` block.
type stateCaptureSpec struct {
	Pre        statePhase
	Post       statePhase
	Invariants []string // free-form for MVP; backend validator interprets

	// PreRequired (Sprint follow-up Bucket A.2 / MEDIUM#9): when
	// true, RunDeviceAction aborts the action body if pre-capture
	// collection fails, rather than logging + continuing. Default
	// false preserves the historical posture: actions where running
	// against an unobserved baseline is acceptable. Set true on
	// actions whose body cannot be safely run without a known
	// pre-state (e.g. a config restore that diffs against pre).
	PreRequired bool
}

// readStateCaptureSpec extracts the state_capture block from a KAL
// action's Raw map. Returns the zero value when the YAML omitted it
// (defensive — schema requires the field, so this should never fire
// in practice). Panics on shape errors that the schema validator
// should have caught — those would indicate the action loader was
// bypassed.
func readStateCaptureSpec(raw map[string]interface{}, params map[string]interface{}) (stateCaptureSpec, error) {
	var out stateCaptureSpec
	block, ok := raw["state_capture"].(map[string]interface{})
	if !ok {
		return out, nil
	}
	pre, err := readStateCapturePhase(block["pre"], params, "pre")
	if err != nil {
		return out, err
	}
	post, err := readStateCapturePhase(block["post"], params, "post")
	if err != nil {
		return out, err
	}
	out.Pre = pre
	out.Post = post

	if invs, ok := block["invariants"].([]interface{}); ok {
		for _, item := range invs {
			if s, ok := item.(string); ok {
				out.Invariants = append(out.Invariants, s)
			}
		}
	}
	// pre_required (Bucket A.2 / MEDIUM#9). YAML omits → false.
	if pr, ok := block["pre_required"].(bool); ok {
		out.PreRequired = pr
	}
	return out, nil
}

// readStateCapturePhase parses one phase. ``raw`` is whatever the
// YAML put there — a string for the sentinel form, a map for the
// structured form. Anything else is a schema-violation error.
func readStateCapturePhase(raw interface{}, params map[string]interface{}, label string) (statePhase, error) {
	switch v := raw.(type) {
	case nil:
		// schema requires the field; treat absence as stateless to be
		// permissive at the agent layer (the schema validator catches
		// the violation at action-load time).
		return statePhase{Sentinel: "stateless"}, nil
	case string:
		return statePhase{Sentinel: v}, nil
	case map[string]interface{}:
		phase := statePhase{}
		if rawCmds, ok := v["commands"]; ok {
			cmds, err := expandStringList(rawCmds, params)
			if err != nil {
				return statePhase{}, fmt.Errorf("state_capture.%s.commands: %w", label, err)
			}
			phase.Commands = cmds
		}
		if parser, ok := v["parser"].(string); ok {
			phase.Parser = parser
		}
		if len(phase.Commands) == 0 || phase.Parser == "" {
			return statePhase{}, fmt.Errorf(
				"state_capture.%s structured form requires non-empty commands and parser", label,
			)
		}
		return phase, nil
	default:
		return statePhase{}, fmt.Errorf(
			"state_capture.%s: unexpected YAML type %T", label, raw,
		)
	}
}

// structured reports whether this phase requires the executor to
// run a collector. The sentinel form ("stateless" / "none") returns
// false; the structured form returns true.
func (p statePhase) structured() bool {
	return p.Sentinel == "" && len(p.Commands) > 0 && p.Parser != ""
}

// runShellCapture runs the phase's commands on the supplied
// persistent shell, feeds the joined output through the named
// parser, and returns a wire-ready Capture. The Capture's identity
// fields come from the supplied DeviceTarget; CaptureType
// distinguishes pre vs post.
//
// On any failure (parser missing, shell.Send error, parser error)
// the returned Capture has CaptureSucceeded=false with the error
// surfaced in ErrorMessage — the caller still has a row to ship so
// the backend can disambiguate "capture failed" from "capture never
// ran" (per the capture package's contract).
func runShellCapture(
	ctx context.Context,
	shell *sshclient.Shell,
	phase statePhase,
	captureType string,
	target DeviceTarget,
) (capture.Capture, error) {
	parserFn, err := parsers.Get(phase.Parser)
	if err != nil {
		// Unknown-parser config error — surface synchronously so the
		// caller's outcome reflects the misconfig clearly. We still
		// return a Capture so the row gets persisted (sink may drop).
		req := newCaptureRequest(target, captureType, phase)
		failed, _ := capture.Run(ctx, req, capture.CollectorFunc(func(_ context.Context) (map[string]any, error) {
			return nil, err
		}))
		return failed, err
	}
	collector := capture.CollectorFunc(func(ctx context.Context) (map[string]any, error) {
		var b strings.Builder
		for _, cmd := range phase.Commands {
			out, sendErr := shell.Send(ctx, cmd)
			if sendErr != nil {
				return nil, fmt.Errorf("send %q: %w", cmd, sendErr)
			}
			b.WriteString(out)
			b.WriteString("\n")
		}
		return parserFn(b.String())
	})
	req := newCaptureRequest(target, captureType, phase)
	return capture.Run(ctx, req, collector)
}

// newCaptureRequest fills the cross-cutting identity fields a
// capture row needs from the DeviceTarget. The capture package
// validates required fields — we surface the source of truth here
// so the caller doesn't have to.
func newCaptureRequest(target DeviceTarget, captureType string, phase statePhase) capture.Request {
	return capture.Request{
		ActionExecutionID: target.ActionExecutionID,
		AgentID:           target.AgentID,
		TenantID:          target.TenantID,
		DeviceID:          target.DeviceID,
		CaptureType:       captureType,
		CaptureMethod:     capture.CaptureMethodShell,
		CaptureSource:     strings.Join(phase.Commands, "; "),
	}
}
