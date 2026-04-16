package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/kardianos/service"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/shepherdtech/aione-agent/internal/config"
	agentservice "github.com/shepherdtech/aione-agent/internal/service"
)

// Populated by -ldflags at build time.
var (
	version   = "dev"
	buildTime = "unknown"
	gitCommit = "unknown"
)

func main() {
	var (
		configPath  = flag.String("config", defaultConfigPath(), "path to agent.yaml")
		showVersion = flag.Bool("version", false, "print version and exit")
		svcAction   = flag.String("service", "", "service control action: install|uninstall|start|stop|status")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("aione-agent %s (commit %s, built %s)\n", version, gitCommit, buildTime)
		os.Exit(0)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: loading config: %v\n", err)
		os.Exit(1)
	}

	setupLogging(cfg)

	svc, err := agentservice.New(cfg, version)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create agent")
	}

	// Handle service control actions (install/uninstall/etc.)
	if *svcAction != "" {
		if err := controlService(svc, *svcAction); err != nil {
			log.Fatal().Err(err).Str("action", *svcAction).Msg("service control failed")
		}
		return
	}

	// Run interactively or as an OS service.
	if service.Interactive() {
		runInteractive(svc)
	} else {
		if err := svc.RunService(); err != nil {
			log.Fatal().Err(err).Msg("service exited with error")
		}
	}
}

func runInteractive(svc *agentservice.Agent) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		log.Info().Str("signal", sig.String()).Msg("received shutdown signal")
		cancel()
	}()

	if err := svc.RunContext(ctx); err != nil {
		log.Fatal().Err(err).Msg("agent exited with error")
	}
}

func setupLogging(cfg *config.Config) {
	level, err := zerolog.ParseLevel(cfg.Log.Level)
	if err != nil {
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)

	if cfg.Log.File != "" {
		f, err := os.OpenFile(cfg.Log.File, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: cannot open log file %s: %v\n", cfg.Log.File, err)
		} else {
			log.Logger = log.Output(f)
			return
		}
	}

	if cfg.Log.Pretty {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	}
}

// controlService handles service lifecycle management.
func controlService(svc *agentservice.Agent, action string) error {
	return svc.Control(action)
}
