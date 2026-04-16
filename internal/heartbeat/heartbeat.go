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

const heartbeatPath = "/v1/agents/heartbeat"

// Payload is the JSON body sent with each heartbeat.
type Payload struct {
	AgentID   string    `json:"agent_id"`
	Timestamp time.Time `json:"timestamp"`
	Version   string    `json:"version"`
	Uptime    int64     `json:"uptime_seconds"`
	GOOS      string    `json:"os"`
	GOARCH    string    `json:"arch"`
	GoVersion string    `json:"go_version"`
	NumCPU    int       `json:"num_cpu"`
	NumGo     int       `json:"num_goroutines"`
	MemAlloc  uint64    `json:"mem_alloc_bytes"`
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

	payload := Payload{
		AgentID:   r.agentID,
		Timestamp: time.Now().UTC(),
		Version:   r.version,
		Uptime:    int64(time.Since(r.startedAt).Seconds()),
		GOOS:      runtime.GOOS,
		GOARCH:    runtime.GOARCH,
		GoVersion: runtime.Version(),
		NumCPU:    runtime.NumCPU(),
		NumGo:     runtime.NumGoroutine(),
		MemAlloc:  ms.Alloc,
	}

	if err := r.client.PostJSON(ctx, heartbeatPath, payload, nil); err != nil {
		return err
	}

	log.Debug().
		Str("agent_id", r.agentID).
		Int64("uptime", payload.Uptime).
		Msg("heartbeat sent")

	return nil
}
