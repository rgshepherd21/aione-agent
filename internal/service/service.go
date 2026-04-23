// Package service orchestrates every agent component and integrates with
// the OS service manager (systemd, launchd, Windows SCM) via kardianos/service.
package service

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/kardianos/service"
	"github.com/rs/zerolog/log"
	"github.com/shepherdtech/aione-agent/internal/actions/executor"
	"github.com/shepherdtech/aione-agent/internal/actions/validation"
	"github.com/shepherdtech/aione-agent/internal/buffer"
	"github.com/shepherdtech/aione-agent/internal/capture"
	"github.com/shepherdtech/aione-agent/internal/config"
	"github.com/shepherdtech/aione-agent/internal/credentials"
	"github.com/shepherdtech/aione-agent/internal/dispatcher"
	"github.com/shepherdtech/aione-agent/internal/heartbeat"
	"github.com/shepherdtech/aione-agent/internal/registration"
	"github.com/shepherdtech/aione-agent/internal/telemetry"
	telapi "github.com/shepherdtech/aione-agent/internal/telemetry/api"
	"github.com/shepherdtech/aione-agent/internal/telemetry/snmp"
	"github.com/shepherdtech/aione-agent/internal/telemetry/syslog"
	"github.com/shepherdtech/aione-agent/internal/telemetry/wmi"
	"github.com/shepherdtech/aione-agent/internal/transport"
	"github.com/shepherdtech/aione-agent/internal/updater"
)

// flushInterval is how often the service tries to ship buffered events.
const flushInterval = 15 * time.Second

// Agent is the top-level service object implementing kardianos/service.Program.
type Agent struct {
	cfg     *config.Config
	version string

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

// New constructs an Agent.
func New(cfg *config.Config, version string) (*Agent, error) {
	return &Agent{
		cfg:     cfg,
		version: version,
		done:    make(chan struct{}),
	}, nil
}

// Start implements service.Program. Called by the OS service manager.
func (a *Agent) Start(s service.Service) error {
	ctx, cancel := context.WithCancel(context.Background())
	a.mu.Lock()
	a.cancel = cancel
	a.mu.Unlock()

	go func() {
		defer close(a.done)
		if err := a.run(ctx); err != nil && ctx.Err() == nil {
			log.Error().Err(err).Msg("agent exited unexpectedly")
		}
	}()
	return nil
}

// Stop implements service.Program. Called by the OS service manager.
func (a *Agent) Stop(s service.Service) error {
	a.mu.Lock()
	if a.cancel != nil {
		a.cancel()
	}
	a.mu.Unlock()
	<-a.done
	return nil
}

// RunContext runs the agent with an externally provided context (interactive mode).
func (a *Agent) RunContext(ctx context.Context) error {
	cctx, cancel := context.WithCancel(ctx)
	a.mu.Lock()
	a.cancel = cancel
	a.mu.Unlock()
	defer cancel()
	return a.run(cctx)
}

// RunService registers with the OS service manager and blocks until stopped.
func (a *Agent) RunService() error {
	s, err := a.newOSService()
	if err != nil {
		return err
	}
	return s.Run()
}

// Control executes a service lifecycle action against the OS service manager.
// Supported actions: install, uninstall, start, stop, restart, status.
func (a *Agent) Control(action string) error {
	s, err := a.newOSService()
	if err != nil {
		return err
	}
	return service.Control(s, action)
}

// newOSService creates the kardianos service object used by RunService and Control.
func (a *Agent) newOSService() (service.Service, error) {
	svcConfig := &service.Config{
		Name:        "aione-agent",
		DisplayName: "AI One Agent",
		Description: "AI One telemetry collection and management agent",
		Option: service.KeyValue{
			"Restart": "on-failure",
		},
	}
	s, err := service.New(a, svcConfig)
	if err != nil {
		return nil, fmt.Errorf("creating OS service: %w", err)
	}
	return s, nil
}

// run is the main goroutine.  All components are started here.
func (a *Agent) run(ctx context.Context) error {
	cfg := a.cfg

	// --- Credential store -------------------------------------------------
	store := credentials.New(cfg.CertPath(), cfg.KeyPath(), cfg.CAPath())

	// --- Pre-registration transport (no mTLS yet) -------------------------
	preClient := transport.NewClient(transport.ClientConfig{
		BaseURL:            cfg.API.BaseURL,
		InsecureSkipVerify: cfg.Transport.InsecureSkipVerify,
		Timeout:            cfg.API.Timeout,
		RetryMax:           cfg.API.RetryMax,
		RetryDelay:         cfg.API.RetryDelay,
	})

	// --- Registration ------------------------------------------------------
	reg := registration.New(cfg, store, preClient, a.version)
	agentID, tenantID, err := reg.EnsureRegistered(ctx)
	if err != nil {
		return fmt.Errorf("registration: %w", err)
	}
	cfg.Agent.ID = agentID

	// --- Upgrade transport to mTLS ----------------------------------------
	// In dev (insecure_skip_verify=true), BE ships placeholder strings for
	// client_cert_pem/client_key_pem (see aione-backend app/api/v1/agents.py),
	// which fail to parse as PEM. Tolerate that here and fall through to plain
	// HTTP / skip-verify — prod keeps the hard-fail since real certs are
	// always minted there.
	cert, err := store.TLSCertificate()
	if err != nil {
		if !cfg.Transport.InsecureSkipVerify {
			return fmt.Errorf("loading agent certificate: %w", err)
		}
		log.Warn().Err(err).Msg("agent cert unavailable; continuing without client cert (insecure_skip_verify=true, dev mode)")
		cert = tls.Certificate{}
	}
	caPool, err := store.CACertPool()
	if err != nil {
		if !cfg.Transport.InsecureSkipVerify {
			return fmt.Errorf("loading CA pool: %w", err)
		}
		log.Warn().Err(err).Msg("CA pool unavailable; using system trust (insecure_skip_verify=true, dev mode)")
		caPool = nil
	}

	mTLSClient := transport.NewClient(transport.ClientConfig{
		BaseURL:            cfg.API.BaseURL,
		Cert:               cert,
		CACertPool:         caPool,
		InsecureSkipVerify: cfg.Transport.InsecureSkipVerify,
		Timeout:            cfg.API.Timeout,
		RetryMax:           cfg.API.RetryMax,
		RetryDelay:         cfg.API.RetryDelay,
	})
	mTLSClient.SetIdentity(agentID, a.version)

	// --- Offline buffer ---------------------------------------------------
	bufFile := ""
	if cfg.Buffer.DataFile != "" {
		bufFile = cfg.Buffer.DataFile
	} else if cfg.Buffer.Enabled {
		bufFile = filepath.Join(cfg.Agent.DataDir, "buffer.json")
	}
	maxSize := cfg.Buffer.MaxSize
	if maxSize <= 0 {
		maxSize = 10_000
	}
	buf, err := buffer.New(maxSize, bufFile)
	if err != nil {
		return fmt.Errorf("creating buffer: %w", err)
	}

	// --- Telemetry manager ------------------------------------------------
	mgr := telemetry.NewManager(mTLSClient, agentID)
	mgr.Register(snmp.New(cfg.Telemetry.SNMP, agentID))
	mgr.Register(syslog.New(cfg.Telemetry.Syslog, agentID))
	mgr.Register(wmi.New(cfg.Telemetry.WMI, agentID))
	mgr.Register(telapi.New(cfg.Telemetry.API, agentID))

	// --- Action executor + command dispatcher -----------------------------
	// The executor and dispatcher reference each other (dispatcher
	// submits actions into the executor; executor's result sink posts
	// results back through the dispatcher). Break the cycle by
	// constructing the executor with a nil sink, then wiring
	// SetResultSink after the dispatcher exists.
	exec := executor.New(cfg.Actions, nil)
	disp := dispatcher.New(ctx, exec, mTLSClient, agentID)
	exec.SetResultSink(disp.PostResult)

	// --- State-capture poster --------------------------------------------
	// Wire the capture-bracket path into the executor. With this wired,
	// flush_dns_cache (and any future bracketed action) ships pre/post
	// Capture rows to /api/v1/agents/state-captures. A zero tenantID
	// leaves capture disabled -- legacy state files that pre-date the
	// tenant_id field land here without a crash.
	if tenantID != "" {
		exec.SetCaptureContext(agentID, tenantID, capture.NewPoster(mTLSClient))
	} else {
		log.Warn().Msg("no tenant_id from registration; capture bracket disabled")
	}

	// --- WebSocket --------------------------------------------------------
	wsURL := wsURL(cfg.API.BaseURL, agentID)
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		RootCAs:            caPool,
		InsecureSkipVerify: cfg.Transport.InsecureSkipVerify, //nolint:gosec
	}
	// Only attach client cert if we have one (dev mode may have none).
	if cert.Certificate != nil {
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	wsClient := transport.NewWSClient(wsURL, tlsCfg, agentID, a.version)
	wsClient.Handle("action", func(msg transport.WSMessage) error {
		return a.handleWSMessage(ctx, msg, exec)
	})

	// --- Launch all components in goroutines ------------------------------
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		mgr.Run(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		hb := heartbeat.New(cfg, mTLSClient, disp, agentID, a.version)
		hb.Run(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		wsClient.Run(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		up := updater.New(cfg.Updater, mTLSClient, a.version)
		up.Run(ctx)
	}()

	// --- Telemetry fan-out: send or buffer --------------------------------
	wg.Add(1)
	go func() {
		defer wg.Done()
		a.drainTelemetry(ctx, mgr.Out(), buf, mTLSClient)
	}()

	log.Info().
		Str("agent_id", agentID).
		Str("version", a.version).
		Msg("agent running")

	<-ctx.Done()
	wg.Wait()
	log.Info().Msg("agent stopped")
	return nil
}

// drainTelemetry reads from the telemetry output channel.  If the API call
// succeeds it also flushes any buffered events.  On failure events go to the
// ring buffer.
func (a *Agent) drainTelemetry(ctx context.Context, in <-chan telemetry.Event, buf *buffer.RingBuffer, client *transport.Client) {
	flush := time.NewTicker(flushInterval)
	defer flush.Stop()

	batch := make([]telemetry.Event, 0, 64)

	ship := func(events []telemetry.Event) {
		if len(events) == 0 {
			return
		}
		if err := telemetry.Send(ctx, client, events); err != nil {
			log.Warn().Err(err).Int("count", len(events)).Msg("telemetry send failed, buffering")
			for _, ev := range events {
				buf.Push(ev)
			}
		}
	}

	for {
		select {
		case <-ctx.Done():
			if len(batch) > 0 {
				for _, ev := range batch {
					buf.Push(ev)
				}
			}
			return

		case ev, ok := <-in:
			if !ok {
				return
			}
			batch = append(batch, ev)
			if len(batch) >= 64 {
				ship(batch)
				batch = batch[:0]
			}

		case <-flush.C:
			// Flush current batch.
			ship(batch)
			batch = batch[:0]

			// Attempt to drain the offline buffer.
			if buffered := buf.Drain(); len(buffered) > 0 {
				log.Info().Int("count", len(buffered)).Msg("flushing buffered telemetry")
				if err := telemetry.Send(ctx, client, buffered); err != nil {
					log.Warn().Err(err).Msg("buffer flush failed, re-buffering")
					for _, ev := range buffered {
						buf.Push(ev)
					}
				}
			}
		}
	}
}

// handleWSMessage handles inbound "action" WebSocket messages.
func (a *Agent) handleWSMessage(ctx context.Context, msg transport.WSMessage, exec *executor.Executor) error {
	var action validation.Action
	if err := json.Unmarshal(msg.Payload, &action); err != nil {
		return fmt.Errorf("parsing action payload: %w", err)
	}
	return exec.Submit(ctx, action)
}

// wsURL converts the HTTP base URL to a WebSocket URL.
func wsURL(baseURL, agentID string) string {
	ws := baseURL
	if len(ws) > 5 && ws[:5] == "https" {
		ws = "wss" + ws[5:]
	} else if len(ws) > 4 && ws[:4] == "http" {
		ws = "ws" + ws[4:]
	}
	return ws + "/v1/agents/" + agentID + "/ws"
}
