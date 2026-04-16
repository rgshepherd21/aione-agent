//go:build !windows

// Package wmi provides a no-op WMI collector on non-Windows platforms.
package wmi

import (
	"context"

	"github.com/shepherdtech/aione-agent/internal/config"
	"github.com/shepherdtech/aione-agent/internal/telemetry"
)

// Collector is a no-op on non-Windows systems.
type Collector struct {
	cfg     config.WMIConfig
	agentID string
}

// New creates a stub WMI collector that does nothing.
func New(cfg config.WMIConfig, agentID string) *Collector {
	return &Collector{cfg: cfg, agentID: agentID}
}

// Name implements telemetry.Collector.
func (c *Collector) Name() string { return "wmi" }

// Run returns immediately on non-Windows platforms.
func (c *Collector) Run(_ context.Context, _ chan<- telemetry.Event) error {
	return nil
}
