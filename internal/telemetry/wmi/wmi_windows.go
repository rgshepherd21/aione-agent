//go:build windows

// Package wmi polls Windows Management Instrumentation on Windows hosts.
// It uses PowerShell (no CGO required) to execute WQL queries and converts
// the JSON output into telemetry events.
package wmi

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/shepherdtech/aione-agent/internal/config"
	"github.com/shepherdtech/aione-agent/internal/telemetry"
)

// Collector polls WMI via PowerShell on Windows.
type Collector struct {
	cfg     config.WMIConfig
	agentID string
}

// New creates a WMI collector.
func New(cfg config.WMIConfig, agentID string) *Collector {
	return &Collector{cfg: cfg, agentID: agentID}
}

// Name implements telemetry.Collector.
func (c *Collector) Name() string { return "wmi" }

// Run implements telemetry.Collector.
func (c *Collector) Run(ctx context.Context, out chan<- telemetry.Event) error {
	if !c.cfg.Enabled {
		return nil
	}

	ticker := time.NewTicker(c.cfg.Interval)
	defer ticker.Stop()

	c.collectAll(ctx, out)

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			c.collectAll(ctx, out)
		}
	}
}

func (c *Collector) collectAll(ctx context.Context, out chan<- telemetry.Event) {
	for _, q := range c.cfg.Queries {
		if ctx.Err() != nil {
			return
		}
		rows, err := c.runQuery(ctx, q)
		if err != nil {
			log.Warn().Err(err).Str("query", q.Name).Msg("wmi query failed")
			continue
		}

		for i, row := range rows {
			ev := telemetry.Event{
				ID:        fmt.Sprintf("wmi-%s-%d-%d", q.Name, time.Now().UnixNano(), i),
				AgentID:   c.agentID,
				Timestamp: time.Now().UTC(),
				Type:      "wmi",
				Source:    q.Name,
				Data:      row,
			}
			select {
			case out <- ev:
			case <-ctx.Done():
				return
			default:
				log.Warn().Msg("wmi event channel full, dropping event")
			}
		}
	}
}

func (c *Collector) runQuery(ctx context.Context, q config.WMIQuery) ([]map[string]interface{}, error) {
	ns := q.Namespace
	if ns == "" {
		ns = `root\cimv2`
	}
	// Escape backslashes for PowerShell string
	ns = strings.ReplaceAll(ns, `\`, `\\`)
	query := strings.ReplaceAll(q.Query, `"`, `\"`)

	script := fmt.Sprintf(
		`Get-WmiObject -Namespace "%s" -Query "%s" | Select-Object * -ExcludeProperty __* | ConvertTo-Json -Depth 3 -Compress`,
		ns, query,
	)

	cmd := exec.CommandContext(ctx,
		"powershell.exe",
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-Command", script,
	)

	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("powershell WMI query: %w", err)
	}

	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" || trimmed == "null" {
		return nil, nil
	}

	// PowerShell returns an object when there's one result and an array for many.
	if trimmed[0] == '[' {
		var rows []map[string]interface{}
		if err := json.Unmarshal([]byte(trimmed), &rows); err != nil {
			return nil, fmt.Errorf("parsing WMI JSON array: %w", err)
		}
		return rows, nil
	}

	var single map[string]interface{}
	if err := json.Unmarshal([]byte(trimmed), &single); err != nil {
		return nil, fmt.Errorf("parsing WMI JSON object: %w", err)
	}
	return []map[string]interface{}{single}, nil
}
