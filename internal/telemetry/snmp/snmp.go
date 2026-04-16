// Package snmp polls network devices via SNMP and emits telemetry events.
package snmp

import (
	"context"
	"fmt"
	"time"

	g "github.com/gosnmp/gosnmp"
	"github.com/rs/zerolog/log"
	"github.com/shepherdtech/aione-agent/internal/config"
	"github.com/shepherdtech/aione-agent/internal/telemetry"
)

// Collector polls one or more SNMP targets on a fixed interval.
type Collector struct {
	cfg     config.SNMPConfig
	agentID string
}

// New creates an SNMP collector from the provided config.
func New(cfg config.SNMPConfig, agentID string) *Collector {
	return &Collector{cfg: cfg, agentID: agentID}
}

// Name implements telemetry.Collector.
func (c *Collector) Name() string { return "snmp" }

// Run implements telemetry.Collector. It ticks on cfg.Interval until ctx
// is cancelled.
func (c *Collector) Run(ctx context.Context, out chan<- telemetry.Event) error {
	if !c.cfg.Enabled {
		return nil
	}

	ticker := time.NewTicker(c.cfg.Interval)
	defer ticker.Stop()

	// Collect immediately on start.
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
	for _, target := range c.cfg.Targets {
		if ctx.Err() != nil {
			return
		}
		events, err := c.pollTarget(ctx, target)
		if err != nil {
			log.Warn().Err(err).Str("host", target.Host).Msg("snmp poll failed")
			continue
		}
		for _, ev := range events {
			select {
			case out <- ev:
			case <-ctx.Done():
				return
			default:
				log.Warn().Msg("snmp event channel full, dropping event")
			}
		}
	}
}

func (c *Collector) pollTarget(ctx context.Context, target config.SNMPTarget) ([]telemetry.Event, error) {
	params := &g.GoSNMP{
		Target:    target.Host,
		Port:      target.Port,
		Community: target.Community,
		Version:   snmpVersion(target.Version),
		Timeout:   5 * time.Second,
		Retries:   2,
		Context:   ctx,
	}

	if params.Port == 0 {
		params.Port = 161
	}

	if err := params.Connect(); err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", target.Host, err)
	}
	defer params.Conn.Close()

	result, err := params.Get(target.OIDs)
	if err != nil {
		return nil, fmt.Errorf("SNMP GET from %s: %w", target.Host, err)
	}

	data := make(map[string]interface{}, len(result.Variables))
	for _, v := range result.Variables {
		data[v.Name] = snmpValue(v)
	}

	return []telemetry.Event{{
		ID:        fmt.Sprintf("snmp-%s-%d", target.Host, time.Now().UnixNano()),
		AgentID:   c.agentID,
		Timestamp: time.Now().UTC(),
		Type:      "snmp",
		Source:    target.Host,
		Data:      data,
	}}, nil
}

func snmpVersion(v string) g.SnmpVersion {
	switch v {
	case "3":
		return g.Version3
	case "1":
		return g.Version1
	default:
		return g.Version2c
	}
}

func snmpValue(v g.SnmpPDU) interface{} {
	switch v.Type {
	case g.OctetString:
		return string(v.Value.([]byte))
	case g.Integer, g.Counter32, g.Gauge32, g.TimeTicks, g.Counter64, g.Uinteger32:
		return v.Value
	default:
		return fmt.Sprintf("%v", v.Value)
	}
}
