// Package heartbeat sends periodic liveness pings to the AI One API so the
// platform knows the agent is online and can surface real-time status.
package heartbeat

import (
	"context"
	"runtime"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/shepherdtech/aione-agent/internal/config"
	"github.com/shepherdtech/aione-agent/internal/transport"
)

const heartbeatPath = "/api/v1/agents/heartbeat"

// Payload is the JSON body sent with each heartbeat.
//
// Field names and JSON tags mirror the BE schema at
// app/schemas/agent.py::AgentHeartbeatRequest. BE validates strict
// ranges (cpu_percent 0-100, memory_mb >= 0, counts >= 0), so
// anything we stub must pass those bounds.
type Payload struct {
	AgentID              string     `json:"agent_id"`
	AgentVersion         string     `json:"agent_version"`
	UptimeSeconds        int64      `json:"uptime_seconds"`
	CPUPercent           float64    `json:"cpu_percent"`
	MemoryMB             int64      `json:"memory_mb"`
	ConnectedDeviceCount int        `json:"connected_device_count"`
	LocalQueueDepth      int        `json:"local_queue_depth"`
	LastTelemetryAt      *time.Time `json:"last_telemetry_at,omitempty"`
	AckedCommandIDs      []string   `json:"acked_command_ids"`
}

// HeartbeatResponse is the platform's response — may contain pending
// commands the agent should execute. Mirrors BE schema at
// app/schemas/agent.py::AgentHeartbeatResponse.
//
// MVP: we decode and log len(pending_commands); actual command
// execution wires up in a follow-on PR (command dispatcher).
type HeartbeatResponse struct {
	ReceivedAt      time.Time        `json:"received_at"`
	PendingCommands []PendingCommand `json:"pending_commands"`
	KALRulesVersion *string          `json:"kal_rules_version,omitempty"`
	KALRulesStale   bool             `json:"kal_rules_stale"`
}

// PendingCommand is one queued command from the platform.
// Mirrors BE schema at app/schemas/agent.py::AgentCommand.
type PendingCommand struct {
	CommandID   string                 `json:"command_id"`
	CommandType string                 `json:"command_type"`
	Payload     map[string]interface{} `json:"payload"`
	Priority    int                    `json:"priority"`
	ExpiresAt   *time.Time             `json:"expires_at,omitempty"`
}

// Runner sends heartbeats on a fixed interval until the context is cancelled.
type Runner struct {
	cfg     *config.Config
	client  *transport.Client
	agentID string
	version string
	startedAt time.Time
}

// New constructs a Runner.
func New(cfg *config.Config, client *transport.Client, agentID, version string) *Runner {
	return &Runner{
		cfg:       cfg,
		client:    client,
		agentID:   agentID,
		version:   version,
		startedAt: time.Now(),
	}
}

// Run sends a heartbeat immediately, then repeats on cfg.Agent.Heartbeat.
// It blocks until ctx is cancelled.
func (r *Runner) Run(ctx context.Context) {
	if err := r.send(ctx); err != nil {
		log.Warn().Err(err).Msg("initial heartbeat failed")
	}

	ticker := time.NewTicker(r.cfg.Agent.Heartbeat)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := r.send(ctx); err != nil {
				log.Warn().Err(err).Msg("heartbeat failed")
			}
		}
	}
}

func (r *Runner) send(ctx context.Context) error {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	// MVP stubs for the required BE fields we don't sample yet.
	// Real sources wire up in follow-on PRs:
	//   * cpu_percent: gopsutil or /proc/stat sampler (Month 4)
	//   * connected_device_count: from telemetry/collector registry (Month 4)
	//   * local_queue_depth: from buffer.Buffer.Len() (Month 4)
	payload := Payload{
		AgentID:              r.agentID,
		AgentVersion:         r.version,
		UptimeSeconds:        int64(time.Since(r.startedAt).Seconds()),
		CPUPercent:           0,
		MemoryMB:             int64(ms.Alloc / (1024 * 1024)),
		ConnectedDeviceCount: 0,
		LocalQueueDepth:      0,
		AckedCommandIDs:      []string{},
	}

	var resp HeartbeatResponse
	if err := r.client.PostJSON(ctx, heartbeatPath, payload, &resp); err != nil {
		return err
	}

	log.Debug().
		Str("agent_id", r.agentID).
		Int64("uptime", payload.UptimeSeconds).
		Int("pending_commands", len(resp.PendingCommands)).
		Msg("heartbeat sent")

	return nil
}
