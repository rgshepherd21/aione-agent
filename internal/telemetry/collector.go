// Package telemetry defines the shared Event type and Collector interface
// used by all telemetry sub-packages (snmp, syslog, wmi, api).
package telemetry

import (
	"context"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/shepherdtech/aione-agent/internal/transport"
)

const telemetryPath = "/v1/agents/telemetry"

// Event is a single telemetry observation from any collector.
type Event struct {
	ID        string                 `json:"id"`
	AgentID   string                 `json:"agent_id"`
	Timestamp time.Time              `json:"timestamp"`
	Type      string                 `json:"type"`   // snmp | syslog | wmi | api
	Source    string                 `json:"source"` // Collector-specific identifier
	Data      map[string]interface{} `json:"data"`
}

// Collector is implemented by every telemetry source.
type Collector interface {
	Name() string
	// Run starts the collector and sends events on the provided channel.
	// It blocks until ctx is cancelled.
	Run(ctx context.Context, out chan<- Event) error
}

// Manager runs all registered collectors, fans their output into a single
// channel, and forwards events to the API (or drops them to the buffer caller).
type Manager struct {
	collectors []Collector
	client     *transport.Client
	agentID    string
	out        chan Event
}

// NewManager creates a Manager with a buffered event channel.
func NewManager(client *transport.Client, agentID string) *Manager {
	return &Manager{
		client:  client,
		agentID: agentID,
		out:     make(chan Event, 1024),
	}
}

// Register adds a collector to the manager.
func (m *Manager) Register(c Collector) {
	m.collectors = append(m.collectors, c)
}

// Out returns the channel that receives all collected events.
// The caller (service) drains this channel and either sends or buffers events.
func (m *Manager) Out() <-chan Event {
	return m.out
}

// Run starts all collectors in separate goroutines and blocks until ctx is
// cancelled or all collectors exit.
func (m *Manager) Run(ctx context.Context) {
	for _, c := range m.collectors {
		c := c
		go func() {
			log.Info().Str("collector", c.Name()).Msg("starting collector")
			if err := c.Run(ctx, m.out); err != nil && ctx.Err() == nil {
				log.Error().Err(err).Str("collector", c.Name()).Msg("collector exited with error")
			}
			log.Info().Str("collector", c.Name()).Msg("collector stopped")
		}()
	}
	<-ctx.Done()
}

// Send ships a batch of events to the API.
func Send(ctx context.Context, client *transport.Client, events []Event) error {
	return client.PostJSON(ctx, telemetryPath, events, nil)
}
