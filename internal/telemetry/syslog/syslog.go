// Package syslog embeds a UDP/TCP syslog receiver and emits events for each
// received message.  It parses both RFC 3164 and RFC 5424 frames on a
// best-effort basis; unparseable messages are emitted as raw text.
package syslog

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/shepherdtech/aione-agent/internal/config"
	"github.com/shepherdtech/aione-agent/internal/telemetry"
)

// Collector listens for inbound syslog messages on UDP and/or TCP.
type Collector struct {
	cfg     config.SyslogConfig
	agentID string
}

// New creates a Syslog collector.
func New(cfg config.SyslogConfig, agentID string) *Collector {
	return &Collector{cfg: cfg, agentID: agentID}
}

// Name implements telemetry.Collector.
func (c *Collector) Name() string { return "syslog" }

// Run starts UDP and TCP listeners as required and forwards messages until
// ctx is cancelled.
func (c *Collector) Run(ctx context.Context, out chan<- telemetry.Event) error {
	if !c.cfg.Enabled {
		return nil
	}

	errCh := make(chan error, 2)

	if c.cfg.UDPAddr != "" {
		go func() { errCh <- c.listenUDP(ctx, out) }()
	}
	if c.cfg.TCPAddr != "" {
		go func() { errCh <- c.listenTCP(ctx, out) }()
	}

	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		return err
	}
}

func (c *Collector) listenUDP(ctx context.Context, out chan<- telemetry.Event) error {
	addr, err := net.ResolveUDPAddr("udp", c.cfg.UDPAddr)
	if err != nil {
		return fmt.Errorf("resolving UDP addr %s: %w", c.cfg.UDPAddr, err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("listening UDP %s: %w", c.cfg.UDPAddr, err)
	}
	defer conn.Close()

	log.Info().Str("addr", c.cfg.UDPAddr).Msg("syslog UDP listener started")

	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	buf := make([]byte, 65536)
	for {
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("UDP read: %w", err)
		}

		msg := string(buf[:n])
		ev := c.buildEvent(msg, remote.String())
		c.emit(ctx, out, ev)
	}
}

func (c *Collector) listenTCP(ctx context.Context, out chan<- telemetry.Event) error {
	ln, err := net.Listen("tcp", c.cfg.TCPAddr)
	if err != nil {
		return fmt.Errorf("listening TCP %s: %w", c.cfg.TCPAddr, err)
	}
	defer ln.Close()

	log.Info().Str("addr", c.cfg.TCPAddr).Msg("syslog TCP listener started")

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("TCP accept: %w", err)
		}
		go c.handleTCPConn(ctx, conn, out)
	}
}

func (c *Collector) handleTCPConn(ctx context.Context, conn net.Conn, out chan<- telemetry.Event) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 65536), 65536)

	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	for scanner.Scan() {
		msg := scanner.Text()
		if msg == "" {
			continue
		}
		ev := c.buildEvent(msg, remote)
		c.emit(ctx, out, ev)
	}
}

// buildEvent parses a raw syslog line into a telemetry event.
// Supports abbreviated RFC 3164 (<priority>timestamp host msg) parsing.
func (c *Collector) buildEvent(raw, remote string) telemetry.Event {
	data := map[string]interface{}{
		"raw":    raw,
		"remote": remote,
	}

	// Best-effort RFC 3164 parse: <PRI>Mon DD HH:MM:SS host msg
	if len(raw) > 4 && raw[0] == '<' {
		if end := strings.IndexByte(raw, '>'); end > 0 {
			data["priority"] = raw[1:end]
			rest := raw[end+1:]
			// Timestamp (15 chars) + space + host + space + message
			if len(rest) > 16 {
				data["syslog_ts"] = strings.TrimSpace(rest[:15])
				rest = strings.TrimSpace(rest[15:])
				parts := strings.SplitN(rest, " ", 2)
				if len(parts) == 2 {
					data["host"] = parts[0]
					data["message"] = parts[1]
				} else {
					data["message"] = rest
				}
			}
		}
	}

	return telemetry.Event{
		ID:        fmt.Sprintf("syslog-%d", time.Now().UnixNano()),
		AgentID:   c.agentID,
		Timestamp: time.Now().UTC(),
		Type:      "syslog",
		Source:    remote,
		Data:      data,
	}
}

func (c *Collector) emit(ctx context.Context, out chan<- telemetry.Event, ev telemetry.Event) {
	select {
	case out <- ev:
	case <-ctx.Done():
	default:
		log.Warn().Msg("syslog event channel full, dropping event")
	}
}
