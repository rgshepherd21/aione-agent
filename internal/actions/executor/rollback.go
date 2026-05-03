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
// rows, not rollback-attempt rows. The rollback executor's first
// device-touching version will use this field to drive the
// CredentialFetcher.
//
// PreState is the state_payload from the original action's
// pre-capture. The rollback executor (Phase 2 follow-up) templates
// it into the YAML's ``rollback.synthesis`` commands so the device
// can be driven back to its captured baseline (e.g.
// ``description {{pre_state.description}}``).
type RollbackCommand struct {
	CommandID    string
	ExecutionID  string
	ActionIDSlug string
	TenantID     string
	DeviceID     string
	PreState     map[string]interface{}
	PayloadHash  string
	CapturedAt   time.Time
}

// executeRollback is the inner-loop entry point invoked from the
// SubmitRollback goroutine. It returns a Result the executor's
// ResultSink ships to the dispatcher, which POSTs it to
// ``/api/v1/agents/command-results`` exactly the same way an
// execute_kal completion is posted.
//
// CURRENT BEHAVIOR (S2.b.2 phase 2 stub):
//   - Logs that the rollback command was received with the
//     parent execution id, action slug, and pre-state hash for
//     audit traceability.
//   - Returns a Result with Success=false and a clear stdout
//     label so backend's ``try_record_rollback_result`` flips
//     the RollbackAttempt row to a terminal status without the
//     agent having actually touched the device.
//   - The status='failed' choice is deliberate: until the YAML-
//     driven synthesis runner lands, claiming success would be
//     misleading on the rollback_attempts row. ``status='failed'``
//     plus an explicit ``error_message`` ("agent rollback executor
//     not yet implemented") is the honest signal.
//
// FUTURE BEHAVIOR (next phase):
//   1. Look up cmd.ActionIDSlug in the DSL registry.
//   2. Pull the action's ``rollback.synthesis.<vendor>`` block.
//   3. Fetch credentials using cmd.ExecutionID (not CommandID).
//   4. Open a persistent shell, run synthesis pre_commands +
//      commands templated against PreState + the original action's
//      params.
//   5. Capture rollback_post state, post via the existing
//      capture.Sink.
//   6. Return a Result reflecting the actual device outcome.
func (e *Executor) executeRollback(_ context.Context, cmd RollbackCommand) Result {
	log.Info().
		Str("command_id", cmd.CommandID).
		Str("execution_id", cmd.ExecutionID).
		Str("action_id_slug", cmd.ActionIDSlug).
		Str("device_id", cmd.DeviceID).
		Str("payload_hash", cmd.PayloadHash).
		Msg("executor: rollback dispatch received (synthesis stub)")

	now := time.Now()
	return Result{
		// ActionID intentionally carries the original action slug
		// rather than a synthetic "rollback_<slug>" value — the
		// backend's try_record_rollback_result keys off CommandID
		// (== RollbackAttempt.id), so ActionID is purely
		// informational here. Using the original slug makes the
		// audit log read naturally as "rollback of X".
		ActionID:  cmd.ActionIDSlug,
		CommandID: cmd.CommandID,
		StartedAt: now,
		EndedAt:   now,
		Success:   false,
		Err: fmt.Sprintf(
			"agent rollback executor not yet implemented (S2.b.2 phase 2 stub); "+
				"received rollback for execution_id=%s action=%s — backend "+
				"will surface this as a failed RollbackAttempt with this "+
				"error_message so the operator can intervene",
			cmd.ExecutionID, cmd.ActionIDSlug,
		),
	}
}
