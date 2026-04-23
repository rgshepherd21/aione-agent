// Dispatcher translates backend AgentCommand payloads into executor
// actions and posts AgentCommandResult payloads back to the backend.
//
// Wire contract mirrors aione-backend/app/schemas/agent.py; see
// types.go for the Go-side struct definitions and contract_test.go
// for the CI-time parity check against the canonical schema export.
//
// Ownership:
//
//   - heartbeat.Runner calls Deliver(cmds) after decoding each
//     HeartbeatResponse; dispatcher returns command_ids that it
//     accepted, which the Runner ships back as acked_command_ids on
//     the next heartbeat so the BE can dequeue them.
//
//   - The action executor's ResultSink is wired to PostResult, so
//     both the HTTP-poll path and the (currently deferred) WS-push
//     path funnel their results through here. For WS actions, the
//     Result.ActionID is used as the command_id; since WS-dispatched
//     commands don't have a BE-side ActionExecution row, the BE logs
//     a warning and returns 204 rather than erroring.
//
// Error handling:
//
//   - Commands with an unknown command_type or malformed payload are
//     reported as a failed CommandResult and still acked — the BE
//     should not keep redelivering a command the agent cannot handle.
//
//   - If executor.Submit returns a capacity error the command is NOT
//     acked, so the BE redelivers it on the next heartbeat cycle when
//     the executor may have a slot free.
//
//   - Dedup: once a command_id has been submitted, the dispatcher
//     remembers it until PostResult clears it. Guards against the BE
//     redelivering a command whose ack we sent but whose heartbeat
//     round-trip failed.
package dispatcher

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/shepherdtech/aione-agent/internal/actions/executor"
	"github.com/shepherdtech/aione-agent/internal/actions/validation"
)

// commandResultsPath is the backend endpoint that accepts
// AgentCommandResult payloads. Mirrors
// aione-backend/app/api/v1/agents.py::receive_command_results.
const commandResultsPath = "/api/v1/agents/command-results"

// Submitter is the executor surface the dispatcher needs. Kept as
// an interface so tests can inject a fake without a real executor.
type Submitter interface {
	Submit(ctx context.Context, a validation.Action) error
}

// Poster is the transport surface the dispatcher needs to POST
// result payloads. Kept as an interface so tests can inject a
// recording stub without a real HTTPS client.
type Poster interface {
	PostJSON(ctx context.Context, path string, body, dst interface{}) error
}

// Dispatcher is the translator between backend command wire shapes
// and the existing executor.
type Dispatcher struct {
	exec    Submitter
	client  Poster
	agentID string
	ctx     context.Context
	now     func() time.Time

	mu   sync.Mutex
	seen map[string]struct{}
}

// New constructs a Dispatcher. ctx is the long-running service
// context used to bound the POST of every CommandResult; when the
// service is shutting down the POSTs cancel alongside everything
// else.
func New(ctx context.Context, exec Submitter, client Poster, agentID string) *Dispatcher {
	return &Dispatcher{
		exec:    exec,
		client:  client,
		agentID: agentID,
		ctx:     ctx,
		now:     time.Now,
		seen:    make(map[string]struct{}),
	}
}

// Deliver processes a batch of pending commands from a heartbeat
// response. For each command it either submits an executor action
// (happy path), or synthesizes a failed CommandResult (unsupported
// type / malformed payload / expired). Returns the command_ids that
// should be acked on the next heartbeat.
func (d *Dispatcher) Deliver(cmds []PendingCommand) []string {
	acks := make([]string, 0, len(cmds))

	for _, cmd := range cmds {
		if cmd.CommandID == "" {
			log.Warn().Msg("dispatcher: received command with empty command_id; dropping")
			continue
		}

		if d.alreadySeen(cmd.CommandID) {
			// BE redelivered a command whose ack we already sent but
			// whose heartbeat hand-shake likely failed. Re-ack so the
			// BE dequeues; don't re-submit to the executor.
			acks = append(acks, cmd.CommandID)
			continue
		}

		// Expired commands go straight to a failed result.
		if cmd.ExpiresAt != nil && d.now().After(*cmd.ExpiresAt) {
			d.reportFailure(cmd.CommandID, "command expired before dispatch")
			acks = append(acks, cmd.CommandID)
			continue
		}

		action, err := buildAction(cmd)
		if err != nil {
			log.Warn().
				Err(err).
				Str("command_id", cmd.CommandID).
				Str("command_type", cmd.CommandType).
				Msg("dispatcher: translation failed; reporting as failed")
			d.reportFailure(cmd.CommandID, err.Error())
			acks = append(acks, cmd.CommandID)
			continue
		}

		if err := d.exec.Submit(d.ctx, action); err != nil {
			// Validation failures (bad signature / not in allowlist)
			// are terminal for this command — ack and report failed.
			// Capacity failures are retriable — don't ack, let the BE
			// redeliver next cycle.
			if isCapacityError(err) {
				log.Warn().
					Err(err).
					Str("command_id", cmd.CommandID).
					Msg("dispatcher: executor at capacity; not acking, will retry")
				continue
			}
			log.Warn().
				Err(err).
				Str("command_id", cmd.CommandID).
				Msg("dispatcher: executor rejected action; reporting as failed")
			d.reportFailure(cmd.CommandID, err.Error())
			acks = append(acks, cmd.CommandID)
			continue
		}

		d.markSeen(cmd.CommandID)
		acks = append(acks, cmd.CommandID)
		log.Info().
			Str("command_id", cmd.CommandID).
			Str("action_id", action.ID).
			Str("action_type", action.Type).
			Msg("dispatcher: command submitted to executor")
	}

	return acks
}

// PostResult is the ResultSink wired into the executor. It translates
// the executor's internal Result shape into the backend's wire
// AgentCommandResult and POSTs it to the command-results endpoint.
func (d *Dispatcher) PostResult(r executor.Result) {
	res := buildResult(r, d.agentID)

	// Clear dedup entry — the command is fully settled. Dedup is keyed on
	// the outer command_id (see markSeen(cmd.CommandID)), NOT the KAL
	// action slug: two separate dispatches of the same action need
	// distinct dedup entries, and ActionID collides. Historically this
	// used r.ActionID, which leaked entries forever; we now forget by
	// the correlation id the dispatcher threaded through.
	d.forget(res.CommandID)

	if err := d.client.PostJSON(d.ctx, commandResultsPath, res, nil); err != nil {
		log.Warn().
			Err(err).
			Str("command_id", res.CommandID).
			Str("status", res.Status).
			Msg("dispatcher: posting command result failed")
		return
	}

	log.Info().
		Str("command_id", res.CommandID).
		Str("status", res.Status).
		Msg("dispatcher: command result delivered")
}

// reportFailure synthesizes a failed CommandResult and POSTs it. Used
// when the dispatcher decides a command cannot be executed at all
// (bad type, malformed payload, expired, validator rejection).
func (d *Dispatcher) reportFailure(commandID, reason string) {
	msg := reason
	res := CommandResult{
		CommandID:   commandID,
		AgentID:     d.agentID,
		Status:      StatusFailed,
		Error:       &msg,
		CompletedAt: d.now(),
	}
	if err := d.client.PostJSON(d.ctx, commandResultsPath, res, nil); err != nil {
		log.Warn().
			Err(err).
			Str("command_id", commandID).
			Msg("dispatcher: posting synthesized failure failed")
	}
}

func (d *Dispatcher) alreadySeen(id string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, ok := d.seen[id]
	return ok
}

func (d *Dispatcher) markSeen(id string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.seen[id] = struct{}{}
}

func (d *Dispatcher) forget(id string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.seen, id)
}

// buildAction translates a backend AgentCommand into a validator-
// consumable Action. Only command_type="execute_kal" is understood
// for now; every other value returns an error so the caller can
// synthesize a failed CommandResult.
func buildAction(cmd PendingCommand) (validation.Action, error) {
	if cmd.CommandType != CommandTypeExecuteKAL {
		return validation.Action{}, fmt.Errorf("unsupported command_type %q", cmd.CommandType)
	}
	if cmd.Payload == nil {
		return validation.Action{}, fmt.Errorf("execute_kal payload is empty")
	}

	id, _ := cmd.Payload["id"].(string)
	typ, _ := cmd.Payload["type"].(string)
	sig, _ := cmd.Payload["sig"].(string)
	if id == "" || typ == "" {
		return validation.Action{}, fmt.Errorf("execute_kal payload missing id/type")
	}

	// Timeout: JSON numbers decode to float64 or json.Number depending
	// on decoder settings. Handle both.
	var timeout int
	switch v := cmd.Payload["timeout_seconds"].(type) {
	case float64:
		timeout = int(v)
	case json.Number:
		if n, err := v.Int64(); err == nil {
			timeout = int(n)
		}
	case int:
		timeout = v
	}

	// Params: JSON decodes to map[string]interface{}. Backend stringifies
	// values server-side (see remediation_service.build_signed_command),
	// so each value MUST be a string. Anything else is a parity bug and
	// the command fails — better to surface the drift than silently
	// coerce.
	params := map[string]string{}
	if raw, ok := cmd.Payload["params"].(map[string]interface{}); ok {
		for k, v := range raw {
			s, ok := v.(string)
			if !ok {
				return validation.Action{}, fmt.Errorf(
					"param %q is not a string (got %T) — check backend kal_signer canonicalization",
					k, v,
				)
			}
			params[k] = s
		}
	}

	return validation.Action{
		ID:      id,
		Type:    typ,
		Params:  params,
		Timeout: timeout,
		Sig:     sig,
		// Correlation id the backend will use to locate the ActionExecution
		// row on command-results writeback. Distinct from the KAL action
		// slug in `id`; see the Action struct doc for why this field is
		// off-wire / off-signature.
		CommandID: cmd.CommandID,
	}, nil
}

// buildResult translates an executor Result into the backend's
// AgentCommandResult wire shape.
//
// Status mapping:
//   - r.Success == true             → "succeeded"
//   - r.TimedOut == true            → "timed_out"
//   - otherwise                     → "failed"
//
// Output/Error/DurationMs are nil-ed when empty so JSON emits null
// rather than "" / 0, matching the backend's str | None fields.
func buildResult(r executor.Result, agentID string) CommandResult {
	status := StatusSucceeded
	if !r.Success {
		if r.TimedOut {
			status = StatusTimedOut
		} else {
			status = StatusFailed
		}
	}

	// Prefer the correlation id the dispatcher threaded through from the
	// outer AgentCommand envelope. Fall back to ActionID only so callers
	// that bypass the dispatcher (older tests, synthesized results) still
	// round-trip *something* — in production, CommandID is always set.
	cmdID := r.CommandID
	if cmdID == "" {
		cmdID = r.ActionID
	}
	res := CommandResult{
		CommandID:   cmdID,
		AgentID:     agentID,
		Status:      status,
		CompletedAt: r.EndedAt,
	}
	if r.Output != "" {
		o := r.Output
		res.Output = &o
	}
	if r.Err != "" {
		e := r.Err
		res.Error = &e
	}
	if !r.StartedAt.IsZero() && !r.EndedAt.IsZero() {
		ms := r.EndedAt.Sub(r.StartedAt).Milliseconds()
		res.DurationMs = &ms
	}
	return res
}

// isCapacityError is the dispatcher's cue to NOT ack the command so
// the BE will redeliver. executor.Submit uses fmt.Errorf with the
// sentinel phrase "executor at capacity"; we match on that because
// the executor doesn't expose a typed error (yet).
func isCapacityError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "executor at capacity")
}
