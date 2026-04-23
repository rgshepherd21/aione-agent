// Package heartbeat sends periodic liveness pings to the AI One API so the
// platform knows the agent is online and can surface real-time status.
//
// The heartbeat is also the command transport for the HTTP-poll path:
// HeartbeatResponse.pending_commands[] is drained into the dispatcher,
// which returns the command_ids it accepted; those ship back on the
// next heartbeat as acked_command_ids so the BE can dequeue.
package heartbeat

import (
	"context"
	"runtime"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/shepherdtech/aione-agent/internal/config"
	"github.com/shepherdtech/aione-agent/internal/dispatcher"
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
// PendingCommand is defined in the dispatcher package (the BE wire
// shape is shared between the two paths); the contract_test there
// verifies parity with the canonical schema export.
type HeartbeatResponse struct {
	ReceivedAt      time.Time                   `json:"received_at"`
	PendingCommands []dispatcher.PendingCommand `json:"pending_commands"`
	KALRulesVersion *string                     `json:"kal_rules_version,omitempty"`
	KALRulesStale   bool                        `json:"kal_rules_stale"`
}

// Runner sends heartbeats on a fixed interval until the context is cancelled.
type Runner struct {
	cfg       *config.Config
	client    *transport.Client
	disp      *dispatcher.Dispatcher
	agentID   string
	version   string
	startedAt time.Time

	// lastAcks carries command_ids the dispatcher accepted on the most
	// recent heartbeat response. They are sent on the NEXT heartbeat
	// request so the BE can dequeue them from the agent's pending set.
	// A dropped heartbeat therefore delays the ack by one cycle — the
	// dispatcher's seen-map makes the redelivery idempotent.
	lastAcks []string
}

// New constructs a Runner. disp may be nil only in tests that don't
// exercise the command path; service.go always passes a real one.
func New(cfg *config.Config, client *transport.Client, disp *dispatcher.Dispatcher, agentID, version string) *Runner {
	return &Runner{
		cfg:       cfg,
		client:    client,
		disp:      disp,
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

	// BE rejects null arrays on acked_command_ids; always emit [] when
	// there's nothing to ack.
	acks := r.lastAcks
	if acks == nil {
		acks = []string{}
	}

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
		AckedCommandIDs:      acks,
	}

	var resp HeartbeatResponse
	if err := r.client.PostJSON(ctx, heartbeatPath, payload, &resp); err != nil {
		// Preserve lastAcks so the next heartbeat retries them.
		return err
	}

	// Hand off to the dispatcher and capture the acks to ship on the
	// NEXT heartbeat cycle.
	var nextAcks []string
	if r.disp != nil && len(resp.PendingCommands) > 0 {
		nextAcks = r.disp.Deliver(resp.PendingCommands)
	}
	r.lastAcks = nextAcks

	log.Debug().
		Str("agent_id", r.agentID).
		Int64("uptime", payload.UptimeSeconds).
		Int("pending_commands", len(resp.PendingCommands)).
		Int("dispatched_acks", len(nextAcks)).
		Msg("heartbeat sent")

	return nil
}
