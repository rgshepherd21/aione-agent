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
	// SubmitRollback (Sprint follow-up S2.b.2) takes a parsed
	// rollback command and runs it on a separate executor path
	// that bypasses signed-KAL validation. Result delivery still
	// goes through the same ResultSink the regular path uses, so
	// the dispatcher's PostResult sees it identically.
	SubmitRollback(ctx context.Context, c executor.RollbackCommand) error
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

		// Sprint follow-up S2.b.2: command_type='rollback' takes a
		// separate dispatch path because rollback commands are unsigned
		// (HMAC-signed KAL bodies don't exist for synthesized rollbacks)
		// and have a different payload shape than execute_kal. The
		// rollback handler on the executor side bypasses the signed-KAL
		// allowlist.
		if cmd.CommandType == CommandTypeRollback {
			rb, err := buildRollbackCommand(cmd)
			if err != nil {
				log.Warn().
					Err(err).
					Str("command_id", cmd.CommandID).
					Msg("dispatcher: rollback translation failed; reporting as failed")
				d.reportFailure(cmd.CommandID, err.Error())
				acks = append(acks, cmd.CommandID)
				continue
			}
			if err := d.exec.SubmitRollback(d.ctx, rb); err != nil {
				if isCapacityError(err) {
					log.Warn().
						Err(err).
						Str("command_id", cmd.CommandID).
						Msg("dispatcher: executor at capacity; not acking rollback, will retry")
					continue
				}
				log.Warn().
					Err(err).
					Str("command_id", cmd.CommandID).
					Msg("dispatcher: executor rejected rollback; reporting as failed")
				d.reportFailure(cmd.CommandID, err.Error())
				acks = append(acks, cmd.CommandID)
				continue
			}
			d.markSeen(cmd.CommandID)
			acks = append(acks, cmd.CommandID)
			log.Info().
				Str("command_id", cmd.CommandID).
				Str("execution_id", rb.ExecutionID).
				Str("action_id_slug", rb.ActionIDSlug).
				Msg("dispatcher: rollback submitted to executor")
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

// buildRollbackCommand parses a CommandTypeRollback PendingCommand
// into an executor.RollbackCommand the executor can consume. Shape
// mirrors the backend's rollback_service.build_rollback_command
// output.
//
// Required fields: execution_id, action_id_slug, tenant_id,
// pre_state, payload_hash, captured_at. device_id is optional
// (can be null on the wire when the action targeted the agent host
// rather than a managed device — uncommon for rollback but possible).
//
// Sprint follow-up S2.b.2.
func buildRollbackCommand(cmd PendingCommand) (executor.RollbackCommand, error) {
	if cmd.Payload == nil {
		return executor.RollbackCommand{}, fmt.Errorf("rollback payload is empty")
	}

	executionID, _ := cmd.Payload["execution_id"].(string)
	actionSlug, _ := cmd.Payload["action_id_slug"].(string)
	tenantID, _ := cmd.Payload["tenant_id"].(string)
	if executionID == "" || actionSlug == "" || tenantID == "" {
		return executor.RollbackCommand{}, fmt.Errorf(
			"rollback payload missing one of execution_id / action_id_slug / tenant_id",
		)
	}
	deviceID, _ := cmd.Payload["device_id"].(string) // optional

	// Device targeting fields (S2.b.2 phase 2b). Same shape as the
	// execute_kal envelope; the agent's rollback executor uses them
	// to open a persistent shell for synthesis-from-YAML execution.
	// Empty strings / zero on the wire mean "no managed device" —
	// the rollback executor reports a clean failure rather than
	// trying to dial a nonexistent host.
	deviceVendor, _ := cmd.Payload["device_vendor"].(string)
	deviceHost, _ := cmd.Payload["device_host"].(string)
	var devicePort int
	switch v := cmd.Payload["device_port"].(type) {
	case float64:
		devicePort = int(v)
	case json.Number:
		if n, err := v.Int64(); err == nil {
			devicePort = int(n)
		}
	case int:
		devicePort = v
	}

	preState, _ := cmd.Payload["pre_state"].(map[string]interface{})
	if preState == nil {
		return executor.RollbackCommand{}, fmt.Errorf("rollback payload missing pre_state map")
	}

	payloadHash, _ := cmd.Payload["payload_hash"].(string)
	if payloadHash == "" {
		return executor.RollbackCommand{}, fmt.Errorf("rollback payload missing payload_hash")
	}

	capturedAtStr, _ := cmd.Payload["captured_at"].(string)
	if capturedAtStr == "" {
		return executor.RollbackCommand{}, fmt.Errorf("rollback payload missing captured_at")
	}
	capturedAt, err := time.Parse(time.RFC3339Nano, capturedAtStr)
	if err != nil {
		// Try RFC3339 (no nanoseconds) as a fallback — Python's
		// .isoformat() omits fractional seconds when they're zero.
		capturedAt, err = time.Parse(time.RFC3339, capturedAtStr)
		if err != nil {
			return executor.RollbackCommand{}, fmt.Errorf(
				"rollback captured_at %q is not RFC3339: %w", capturedAtStr, err,
			)
		}
	}

	// CredentialRef rides on the rollback envelope alongside the
	// device targeting fields (Sprint follow-up Bucket A.2 / HIGH#2).
	// Off-signature, like the device fields — the agent uses it to
	// decide between local-vault and platform-fetcher resolution.
	credentialRef, _ := cmd.Payload["credential_ref"].(string)

	return executor.RollbackCommand{
		CommandID:     cmd.CommandID,
		ExecutionID:   executionID,
		ActionIDSlug:  actionSlug,
		TenantID:      tenantID,
		DeviceID:      deviceID,
		DeviceVendor:  deviceVendor,
		DeviceHost:    deviceHost,
		DevicePort:    devicePort,
		PreState:      preState,
		PayloadHash:   payloadHash,
		CapturedAt:    capturedAt,
		CredentialRef: credentialRef,
	}, nil
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

	// Device-targeting fields (Sprint D / Task #2.5). The backend
	// populates these on the outer AgentCommand envelope when an action
	// targets a network device — they're how the agent's executor knows
	// which Device row to dial over SSH. They ride OUTSIDE the signed
	// KAL action body (the signed body is the inner ``payload``); the
	// envelope-level fields are validation-context, not action-state.
	// Absent / empty for shell actions.
	deviceVendor, _ := cmd.Payload["device_vendor"].(string)
	deviceHost, _ := cmd.Payload["device_host"].(string)
	var devicePort int
	switch v := cmd.Payload["device_port"].(type) {
	case float64:
		devicePort = int(v)
	case json.Number:
		if n, err := v.Int64(); err == nil {
			devicePort = int(n)
		}
	case int:
		devicePort = v
	}

	// State-capture identity (Sprint follow-up S2.a). Same wire
	// model as the device-target fields: the backend populates
	// them on the AgentCommand envelope for any device-targeted
	// action so the agent can stamp them on the resulting
	// state_captures rows. Empty for shell actions or for older
	// platforms that haven't started emitting them — the executor
	// then falls back to the agent's own AgentID / TenantID for
	// those scalar fields and skips capture for the device_id
	// (which has SET NULL ON DELETE on the backend column).
	deviceID, _ := cmd.Payload["device_id"].(string)
	tenantID, _ := cmd.Payload["tenant_id"].(string)

	// CredentialRef (Sprint S3.b). Same off-wire, off-signature
	// pattern as the device targeting fields. Backend populates on
	// the AgentCommand envelope so the agent can decide between
	// local-vault resolution (local://) and platform fetch.
	credentialRef, _ := cmd.Payload["credential_ref"].(string)

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
		CommandID:     cmd.CommandID,
		DeviceVendor:  deviceVendor,
		DeviceHost:    deviceHost,
		DevicePort:    devicePort,
		DeviceID:      deviceID,
		TenantID:      tenantID,
		CredentialRef: credentialRef,
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
