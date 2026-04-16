// Package api polls arbitrary HTTP endpoints and emits their responses as
// telemetry events.  Useful for scraping JSON status pages, health endpoints,
// or vendor APIs that expose metrics over REST.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/shepherdtech/aione-agent/internal/config"
	"github.com/shepherdtech/aione-agent/internal/telemetry"
)

// Collector polls configured HTTP endpoints on a fixed interval.
type Collector struct {
	cfg     config.APICollectorConfig
	agentID string
	http    *http.Client
}

// New creates an API collector.
func New(cfg config.APICollectorConfig, agentID string) *Collector {
	return &Collector{
		cfg:     cfg,
		agentID: agentID,
		http: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// Name implements telemetry.Collector.
func (c *Collector) Name() string { return "api-collector" }

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
	for _, ep := range c.cfg.Endpoints {
		if ctx.Err() != nil {
			return
		}
		ev, err := c.fetch(ctx, ep)
		if err != nil {
			log.Warn().Err(err).Str("endpoint", ep.Name).Msg("api collector fetch failed")
			continue
		}
		select {
		case out <- ev:
		case <-ctx.Done():
			return
		default:
			log.Warn().Str("endpoint", ep.Name).Msg("api collector event channel full, dropping")
		}
	}
}

func (c *Collector) fetch(ctx context.Context, ep config.CollectorEndpoint) (telemetry.Event, error) {
	method := ep.Method
	if method == "" {
		method = http.MethodGet
	}

	req, err := http.NewRequestWithContext(ctx, method, ep.URL, nil)
	if err != nil {
		return telemetry.Event{}, fmt.Errorf("building request for %s: %w", ep.Name, err)
	}
	for k, v := range ep.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return telemetry.Event{}, fmt.Errorf("fetching %s: %w", ep.URL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MB cap
	if err != nil {
		return telemetry.Event{}, fmt.Errorf("reading body from %s: %w", ep.URL, err)
	}

	data := map[string]interface{}{
		"status_code": resp.StatusCode,
		"url":         ep.URL,
	}

	// Attempt JSON decode; fall back to raw string.
	var parsed interface{}
	if json.Unmarshal(body, &parsed) == nil {
		data["body"] = parsed
	} else {
		data["body_raw"] = string(body)
	}

	return telemetry.Event{
		ID:        fmt.Sprintf("api-%s-%d", ep.Name, time.Now().UnixNano()),
		AgentID:   c.agentID,
		Timestamp: time.Now().UTC(),
		Type:      "api",
		Source:    ep.Name,
		Data:      data,
	}, nil
}
