// Sentinel - Blue Team Defensive Agent
// Main entry point with CLI interface.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/sentinel-agent/sentinel/internal/alerting"
	"github.com/sentinel-agent/sentinel/internal/config"
	"github.com/sentinel-agent/sentinel/internal/engine"
	"github.com/sentinel-agent/sentinel/internal/gateway"
	"github.com/sentinel-agent/sentinel/internal/platform"
	"github.com/sentinel-agent/sentinel/internal/response"
	"github.com/sentinel-agent/sentinel/internal/storage"
	"github.com/sentinel-agent/sentinel/internal/types"
)

var (
	Version   = "dev"
	BuildTime = "unknown"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "init":
		cmdInit()
	case "run":
		cmdRun()
	case "status":
		cmdStatus()
	case "version":
		fmt.Printf("Sentinel %s (built %s)\n", Version, BuildTime)
	case "rules":
		cmdRules()
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`Sentinel - Blue Team Defensive Agent

Usage:
  sentinel <command> [options]

Commands:
  init       Initialize configuration and database
  run        Start the agent (main daemon)
  status     Show agent health and queue status
  rules      Manage detection rules (list, enable, disable)
  version    Print version information
  help       Show this help

Run 'sentinel run' to start monitoring. The WebUI will be available at http://127.0.0.1:8080

Configuration: sentinel.yaml (created by 'sentinel init')`)
}

// cmdInit creates default configuration and data directories.
func cmdInit() {
	configPath := "sentinel.yaml"
	if _, err := os.Stat(configPath); err == nil {
		fmt.Println("sentinel.yaml already exists. Delete it to re-initialize.")
		return
	}

	cfg := config.DefaultConfig()

	// Create data directory.
	if err := os.MkdirAll(cfg.Agent.DataDir, 0750); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating data directory: %v\n", err)
		os.Exit(1)
	}

	// Create rules directory if not exists.
	if err := os.MkdirAll(cfg.Agent.RulesDir, 0750); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating rules directory: %v\n", err)
		os.Exit(1)
	}

	// Save default config.
	if err := cfg.Save(configPath); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving config: %v\n", err)
		os.Exit(1)
	}

	// Initialize database.
	logger := zerolog.New(os.Stdout).With().Timestamp().Logger()
	store, err := storage.NewSQLite(cfg.Storage.DSN, logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing database: %v\n", err)
		os.Exit(1)
	}
	store.Close()

	fmt.Println("✓ Sentinel initialized successfully!")
	fmt.Printf("  Config: %s\n", configPath)
	fmt.Printf("  Data:   %s\n", cfg.Agent.DataDir)
	fmt.Printf("  Rules:  %s\n", cfg.Agent.RulesDir)
	fmt.Printf("  DB:     %s\n", cfg.Storage.DSN)
	fmt.Println("\nEdit sentinel.yaml to configure log sources and alerts.")
	fmt.Println("Run 'sentinel run' to start the agent.")
}

// cmdRun starts the main Sentinel daemon.
func cmdRun() {
	// Load config.
	cfg, err := config.Load("sentinel.yaml")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		fmt.Println("Run 'sentinel init' to create a default configuration.")
		os.Exit(1)
	}

	// Setup logger.
	logger := setupLogger(cfg.Logging)
	logger.Info().
		Str("version", Version).
		Str("platform", cfg.Agent.Platform).
		Msg("starting Sentinel")

	// Create context with signal handling.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		logger.Info().Str("signal", sig.String()).Msg("shutdown signal received")
		cancel()
	}()

	// Initialize storage.
	store, err := storage.NewSQLite(cfg.Storage.DSN, logger)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to initialize storage")
	}
	defer store.Close()

	// Initialize platform manager.
	platformMgr := platform.NewManager(cfg.Engine.BufferSize, logger)

	// Register platform-specific log sources.
	registerSources(cfg, platformMgr, logger)

	// Register file watchers from config.
	for _, f := range cfg.Sources.Files {
		paths := []platform.WatchedPath{{
			Path:     f.Path,
			Category: f.Category,
			Parser:   f.Parser,
			Pattern:  f.Pattern,
		}}
		fw, err := platform.NewFileWatcher(paths, logger)
		if err != nil {
			logger.Warn().Err(err).Str("path", f.Path).Msg("skipping file source")
			continue
		}
		platformMgr.Register(fw)
	}

	// Initialize detection engine.
	eng := engine.New(cfg.Engine.Workers, platformMgr.Events(), logger)

	// Load detection rules.
	rulesDir := cfg.Agent.RulesDir
	if !filepath.IsAbs(rulesDir) {
		rulesDir, _ = filepath.Abs(rulesDir)
	}
	if err := eng.LoadRules(rulesDir); err != nil {
		logger.Warn().Err(err).Msg("error loading some rules")
	}

	// Initialize response orchestrator.
	executor := response.NewPlatformExecutor(logger)
	orchestrator := response.NewOrchestrator(cfg.Response, executor, store, logger)

	// Wire up: engine incidents → create incidents in store + queue actions.
	go func() {
		for incident := range eng.Incidents() {
			now := time.Now()
			inc := &types.Incident{
				ID:          fmt.Sprintf("inc_%d", now.UnixNano()),
				Title:       incident.Message,
				Description: incident.Rule.Description,
				Severity:    incident.Severity,
				Status:      types.IncidentOpen,
				RuleID:      incident.Rule.ID,
				Events:      []string{incident.Event.ID},
				SourceIP:    incident.Fields["source_ip"],
				TargetUser:  incident.Fields["username"],
				CreatedAt:   now,
				UpdatedAt:   now,
			}
			if err := store.SaveIncident(inc); err != nil {
				logger.Error().Err(err).Msg("failed to save incident")
			}

			// Save the triggering event.
			store.SaveEvent(&incident.Event)

			// Broadcast to WebUI via SSE.
			if webServer != nil {
				webServer.BroadcastEvent("new_event", incident.Message)
			}
		}
	}()

	// Wire up: engine actions → orchestrator queue.
	go func() {
		for action := range eng.Actions() {
			if err := orchestrator.QueueAction(action); err != nil {
				logger.Error().Err(err).Msg("failed to queue action")
			}
		}
	}()

	// Start expiry checker.
	go orchestrator.ExpireStaleActions(ctx)

	// Initialize Telegram bot if configured.
	var tgBot *alerting.TelegramBot
	if cfg.Telegram.Enabled {
		tgBot, err = alerting.NewTelegramBot(cfg.Telegram, orchestrator, logger)
		if err != nil {
			logger.Error().Err(err).Msg("failed to initialize telegram bot")
		} else {
			// Wire alerts to Telegram.
			orchestrator.OnAction(func(a types.ResponseAction) {
				tgBot.SendAlert(a)
			})
			orchestrator.OnExecute(func(a types.ResponseAction) {
				tgBot.SendExecutionNotice(a)
			})
			go tgBot.Start()
			defer tgBot.Stop()
		}
	}

	// Start WebUI server.
	if cfg.Web.Enabled {
		webServer = gateway.NewServer(cfg.Web, store, eng, orchestrator, logger)

		// Wire alerts to WebUI SSE.
		orchestrator.OnAction(func(a types.ResponseAction) {
			webServer.BroadcastEvent("notification",
				fmt.Sprintf(`<div class="toast %s"><strong>%s</strong>: %s → %s</div>`,
					a.Severity.String(), a.Type, a.Target, a.Reason))
		})

		go func() {
			if err := webServer.Start(ctx); err != nil {
				logger.Error().Err(err).Msg("web server error")
			}
		}()
	}

	// Start platform log collection.
	if err := platformMgr.Start(ctx); err != nil {
		logger.Warn().Err(err).Msg("no log sources started (configure sources in sentinel.yaml)")
	}

	// Start detection engine.
	eng.Start(ctx)

	logger.Info().
		Int("rules", eng.RuleCount()).
		Strs("sources", platformMgr.SourceNames()).
		Bool("webui", cfg.Web.Enabled).
		Bool("telegram", cfg.Telegram.Enabled).
		Bool("dry_run", cfg.Response.DryRun).
		Msg("Sentinel is running")

	if cfg.Web.Enabled {
		logger.Info().Msgf("WebUI available at http://%s", cfg.Web.ListenAddr)
	}

	// Wait for shutdown.
	<-ctx.Done()
	logger.Info().Msg("Sentinel shutting down")
	platformMgr.Stop()
}

// cmdStatus prints a quick health summary.
func cmdStatus() {
	cfg, err := config.Load("sentinel.yaml")
	if err != nil {
		fmt.Println("Error: Could not load config. Is Sentinel initialized?")
		os.Exit(1)
	}

	logger := zerolog.Nop()

	store, err := storage.NewSQLite(cfg.Storage.DSN, logger)
	if err != nil {
		fmt.Println("Error: Could not connect to database.")
		os.Exit(1)
	}
	defer store.Close()

	events, _ := store.EventCount()
	incidents, _ := store.IncidentCount()
	pending, _ := store.PendingActionCount()

	fmt.Println("Sentinel Status")
	fmt.Println("═══════════════")
	fmt.Printf("  Platform:       %s\n", cfg.Agent.Platform)
	fmt.Printf("  Storage:        %s (%s)\n", cfg.Storage.Driver, cfg.Storage.DSN)
	fmt.Printf("  Total Events:   %d\n", events)
	fmt.Printf("  Open Incidents: %d\n", incidents)
	fmt.Printf("  Pending Queue:  %d\n", pending)
	fmt.Printf("  Dry Run:        %v\n", cfg.Response.DryRun)
	fmt.Printf("  WebUI:          %v (%s)\n", cfg.Web.Enabled, cfg.Web.ListenAddr)
	fmt.Printf("  Telegram:       %v\n", cfg.Telegram.Enabled)
}

// cmdRules manages detection rules.
func cmdRules() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: sentinel rules <list|enable|disable> [rule-id]")
		return
	}

	cfg, err := config.Load("sentinel.yaml")
	if err != nil {
		fmt.Println("Error: Could not load config.")
		os.Exit(1)
	}

	rulesDir := cfg.Agent.RulesDir
	if !filepath.IsAbs(rulesDir) {
		rulesDir, _ = filepath.Abs(rulesDir)
	}

	rules, err := engine.LoadRulesFromDir(rulesDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading rules: %v\n", err)
		os.Exit(1)
	}

	switch os.Args[2] {
	case "list":
		fmt.Printf("Detection Rules (%d loaded)\n", len(rules))
		fmt.Println("════════════════════════════")
		for _, r := range rules {
			status := "✓"
			if r.Status == "disabled" {
				status = "✗"
			}
			fmt.Printf("  [%s] %-25s  %-8s  %s\n", status, r.ID, r.Severity, r.Title)
		}
	default:
		fmt.Printf("Unknown rules subcommand: %s\n", os.Args[2])
	}
}

// registerSources registers platform-specific log sources based on config.
func registerSources(cfg *config.Config, mgr *platform.Manager, logger zerolog.Logger) {
	switch cfg.Agent.Platform {
	case "windows":
		if cfg.Sources.EventLog != nil && cfg.Sources.EventLog.Enabled {
			src := platform.NewEventLogSource(cfg.Sources.EventLog.Channels, logger)
			mgr.Register(src)
			logger.Info().
				Strs("channels", cfg.Sources.EventLog.Channels).
				Msg("registered Windows Event Log source")
		}
	case "linux":
		// Journald and syslog registration would go here for Linux builds.
		logger.Info().Msg("Linux log sources registration (journald/syslog) requires Linux build")
	}
}

// setupLogger configures zerolog based on config.
func setupLogger(cfg config.LoggingConfig) zerolog.Logger {
	var logger zerolog.Logger

	// Set level.
	level, err := zerolog.ParseLevel(cfg.Level)
	if err != nil {
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)

	// Set output.
	if cfg.Format == "console" {
		output := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}
		logger = zerolog.New(output).With().Timestamp().Caller().Logger()
	} else {
		logger = zerolog.New(os.Stdout).With().Timestamp().Logger()
	}

	return logger
}

// webServer is a package-level reference for wiring SSE broadcasts.
var webServer *gateway.Server
