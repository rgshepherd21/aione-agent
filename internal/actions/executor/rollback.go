// Rollback dispatch path (Sprint follow-up S2.b.2).
//
// Lives in the executor package — and not the dispatcher package
// where the parsing originates — so the dispatcher can keep its
// existing one-way import of executor without introducing a cycle.
// The dispatcher's buildRollbackCommand parses a backend
// CommandTypeRollback PendingCommand into one of these and hands it
// to ``Executor.SubmitRollback``.
//
// Phase boundary
// --------------
// This file ships the dispatch wiring: the type, the executeRollback
// stub, the result envelope. The actual synthesis-from-YAML
// execution (running config-mode commands templated from
// ``rollback.synthesis`` YAML against a persistent shell) is the
// Phase 2 follow-up. For now executeRollback returns a clearly
// labeled stub Result so the wire round-trip closes — backend
// receives status='succeeded' (or whatever we choose) and finalizes
// the RollbackAttempt row, proving the auto-trigger → agent path.

package executor

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/shepherdtech/aione-agent/internal/actions/dsl"
)

// RollbackCommand is the parsed form of a CommandTypeRollback
// pending command. Fields mirror the payload built by the
// backend's ``rollback_service.build_rollback_command``.
//
// CommandID equals the backend's RollbackAttempt.id — that's what
// ``try_record_rollback_result`` keys on, so the result envelope
// must carry it through unchanged.
//
// ExecutionID is the parent ActionExecution.id — the agent uses
// this (not CommandID) when fetching credentials for the device,
// because the platform's credential issuer indexes on execution
// rows, not rollback-attempt rows.
//
// DeviceVendor / DeviceHost / DevicePort describe how to dial the
// managed device for the rollback's persistent shell. Same fields
// as execute_kal envelope; populated by the backend when the
// execution row's device_id resolved to a real Device row. Empty /
// zero when the action targeted the agent host rather than a
// managed device (no rollback path exists for those today).
//
// PreState is the state_payload from the original action's
// pre-capture. The rollback executor templates it into the YAML's
// ``rollback.synthesis`` commands so the device can be driven back
// to its captured baseline (e.g.
// ``description {{pre_state.description}}``).
type RollbackCommand struct {
	CommandID    string
	ExecutionID  string
	ActionIDSlug string
	TenantID     string
	DeviceID     string
	DeviceVendor string
	DeviceHost   string
	DevicePort   int
	PreState     map[string]interface{}
	PayloadHash  string
	CapturedAt   time.Time
}

// executeRollback is the inner-loop entry point invoked from the
// SubmitRollback goroutine. It looks up the original action in the
// DSL registry, hands off to ``dsl.RunRollback`` with a target
// constructed from the rollback command + agent identity, and maps
// the runner's outcome onto the executor's Result envelope.
//
// Sprint follow-up S2.b.2 phase 2b. Replaces the earlier stub with
// real synthesis-from-YAML execution: the runner reads
// ``action.rollback.spec.device_executors.<vendor>``, templates
// pre-state values into the commands, opens a persistent shell,
// runs them, and emits a ``rollback_post`` capture when the
// action's YAML state_capture.post is structured.
//
// ActionID on the Result intentionally carries the original action
// slug rather than ``"rollback_<slug>"`` — backend's
// try_record_rollback_result keys off CommandID
// (== RollbackAttempt.id), so ActionID is purely informational.
// Using the original slug makes the audit log read naturally as
// "rollback of X".
func (e *Executor) executeRollback(ctx context.Context, cmd RollbackCommand) Result {
	now := time.Now()
	res := Result{
		ActionID:  cmd.ActionIDSlug,
		CommandID: cmd.CommandID,
		StartedAt: now,
	}

	log.Info().
		Str("command_id", cmd.CommandID).
		Str("execution_id", cmd.ExecutionID).
		Str("action_id_slug", cmd.ActionIDSlug).
		Str("device_id", cmd.DeviceID).
		Str("device_vendor", cmd.DeviceVendor).
		Str("device_host", cmd.DeviceHost).
		Str("payload_hash", cmd.PayloadHash).
		Msg("executor: rollback dispatch received")

	if e.credFetcher == nil {
		res.EndedAt = time.Now()
		res.Err = "rollback received but executor has no credential fetcher; cannot dial device"
		return res
	}

	// Look up the original action in the agent's DSL registry. The
	// rollback's synthesis spec lives on the same YAML body the
	// action originally dispatched from, so we don't need a separate
	// rollback registry — same lookup-by-slug path the action took.
	if !e.dslHasAction(cmd.ActionIDSlug) {
		res.EndedAt = time.Now()
		res.Err = fmt.Sprintf(
			"rollback for action %q failed: action not in agent's KAL registry",
			cmd.ActionIDSlug,
		)
		return res
	}
	reg, regErr := e.dslRegistry()
	if regErr != nil {
		res.EndedAt = time.Now()
		res.Err = fmt.Sprintf("rollback registry load: %s", regErr)
		return res
	}
	action := reg[cmd.ActionIDSlug]

	// Pull the agent's identity from the capture context so the
	// rollback_post capture's tenant_id / agent_id match the rest of
	// the row's ancestry. Tenant from the rollback command's
	// envelope wins when present (matches the execute_kal merge
	// rule in executor.go's dispatch case).
	ctxAgentID, ctxTenantID, sink := e.captureContextSnapshot()
	tenantID := cmd.TenantID
	if tenantID == "" {
		tenantID = ctxTenantID
	}

	target := dsl.RollbackTarget{
		CommandID:   cmd.CommandID,
		ExecutionID: cmd.ExecutionID,
		TenantID:    tenantID,
		AgentID:     ctxAgentID,
		DeviceID:    cmd.DeviceID,
		Vendor:      cmd.DeviceVendor,
		Host:        cmd.DeviceHost,
		Port:        cmd.DevicePort,
		PreState:    cmd.PreState,
		// OriginalParams: the rollback command doesn't currently
		// carry the original action's parameter map. Most rollback
		// synthesis commands reference pre_state values rather than
		// original params, so this is acceptable for v1. v2 should
		// add an ``original_params`` field to the rollback wire
		// payload so e.g. ``description {{description}}`` (a
		// param-restoring rollback) becomes expressible.
		OriginalParams: nil,
	}

	outcome, err := dsl.RunRollback(ctx, action, target, e.credFetcher, sink)
	if err != nil {
		// RunRollback only returns a non-nil error for caller bugs
		// (nil action, missing fetcher / required identity). Surface
		// as the Result.Err so the operator sees the cause.
		res.EndedAt = time.Now()
		res.Err = fmt.Sprintf("rollback runner: %s", err)
		return res
	}

	res.StartedAt = outcome.StartedAt
	res.EndedAt = outcome.EndedAt
	res.Output = outcome.Stdout
	res.TimedOut = outcome.TimedOut
	if outcome.Success {
		res.Success = true
	} else {
		res.Err = outcome.Err
	}
	return res
}
