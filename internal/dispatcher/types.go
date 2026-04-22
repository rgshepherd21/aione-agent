// Package dispatcher wires the HTTP-poll command path: it drains
// HeartbeatResponse.pending_commands[] into the action executor and
// posts AgentCommandResult payloads back to the backend's
// /api/v1/agents/command-results endpoint.
//
// Wire shapes mirror aione-backend/app/schemas/agent.py. The
// contract test in this package verifies the Go struct tags against
// the canonical JSON export shipped by the backend
// (schemas-exports/agent-commands.v1.json) on every CI run.
package dispatcher

import "time"

// PendingCommand mirrors the backend's AgentCommand schema. Each
// element of HeartbeatResponse.pending_commands[] decodes into one
// of these. The payload field is deliberately untyped: for
// command_type="execute_kal" it carries the fields the existing
// validation.Action needs (id, type, params, timeout_seconds, sig)
// plus context fields the agent ignores (device_id, tenant_id, ...).
// Future command types will interpret payload differently.
type PendingCommand struct {
	CommandID   string                 `json:"command_id"`
	CommandType string                 `json:"command_type"`
	Payload     map[string]interface{} `json:"payload"`
	Priority    int                    `json:"priority"`
	ExpiresAt   *time.Time             `json:"expires_at,omitempty"`
}

// CommandResult mirrors the backend's AgentCommandResult schema.
// One of these is POSTed per executed command. Output/Error/
// DurationMs are pointers so zero values round-trip as JSON null
// (matching the backend's str | None / int | None fields).
//
// Status is enforced by the backend as one of: succeeded | failed |
// timed_out. Any other value returns 422.
type CommandResult struct {
	CommandID   string    `json:"command_id"`
	AgentID     string    `json:"agent_id"`
	Status      string    `json:"status"`
	Output      *string   `json:"output,omitempty"`
	Error       *string   `json:"error,omitempty"`
	DurationMs  *int64    `json:"duration_ms,omitempty"`
	CompletedAt time.Time `json:"completed_at"`
}

// Status constants matching the backend's AgentCommandResult regex:
// "^(succeeded|failed|timed_out)$".
const (
	StatusSucceeded = "succeeded"
	StatusFailed    = "failed"
	StatusTimedOut  = "timed_out"
)

// Command types recognized by the agent. Anything else is reported
// as a failed CommandResult so the backend can surface the mismatch
// rather than silently dropping the command.
const (
	CommandTypeExecuteKAL = "execute_kal"
)
