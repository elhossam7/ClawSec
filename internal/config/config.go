// Package config handles Sentinel configuration loading and validation.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level Sentinel configuration.
type Config struct {
	Agent    AgentConfig    `yaml:"agent"`
	Sources  SourcesConfig  `yaml:"sources"`
	Engine   EngineConfig   `yaml:"engine"`
	Response ResponseConfig `yaml:"response"`
	Web      WebConfig      `yaml:"web"`
	Telegram TelegramConfig `yaml:"telegram"`
	Storage  StorageConfig  `yaml:"storage"`
	Logging  LoggingConfig  `yaml:"logging"`
}

// AgentConfig configures the core agent behavior.
type AgentConfig struct {
	Hostname string `yaml:"hostname"`
	DataDir  string `yaml:"data_dir"`
	RulesDir string `yaml:"rules_dir"`
	Platform string `yaml:"platform"` // auto-detected if empty
}

// SourcesConfig defines which log sources to monitor.
type SourcesConfig struct {
	Syslog   *SyslogSource   `yaml:"syslog,omitempty"`
	EventLog *EventLogSource `yaml:"eventlog,omitempty"`
	Files    []FileSource    `yaml:"files,omitempty"`
	Docker   *DockerSource   `yaml:"docker,omitempty"`
	Journald *JournaldSource `yaml:"journald,omitempty"`
}

// SyslogSource monitors syslog.
type SyslogSource struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"` // e.g., /var/log/syslog
}

// EventLogSource monitors Windows Event Log channels.
type EventLogSource struct {
	Enabled  bool     `yaml:"enabled"`
	Channels []string `yaml:"channels"` // e.g., Security, System, Application
}

// FileSource monitors arbitrary log files.
type FileSource struct {
	Path     string `yaml:"path"`
	Category string `yaml:"category"` // e.g., "web", "auth"
	Parser   string `yaml:"parser"`   // "auto", "json", "regex"
	Pattern  string `yaml:"pattern"`  // regex pattern for parsing
}

// DockerSource monitors Docker container logs.
type DockerSource struct {
	Enabled    bool     `yaml:"enabled"`
	Socket     string   `yaml:"socket"` // e.g., /var/run/docker.sock
	Containers []string `yaml:"containers,omitempty"` // empty = all
}

// JournaldSource monitors systemd journal.
type JournaldSource struct {
	Enabled bool     `yaml:"enabled"`
	Units   []string `yaml:"units,omitempty"` // empty = all
}

// EngineConfig tunes the detection engine.
type EngineConfig struct {
	Workers        int           `yaml:"workers"`
	BufferSize     int           `yaml:"buffer_size"`
	CorrelationTTL time.Duration `yaml:"correlation_ttl"`
}

// ResponseConfig controls the response orchestrator.
type ResponseConfig struct {
	AutoApprove    bool          `yaml:"auto_approve"`    // dangerous: auto-execute actions
	ApprovalExpiry time.Duration `yaml:"approval_expiry"` // how long before pending actions expire
	RollbackWindow time.Duration `yaml:"rollback_window"` // how long rollback is available
	DryRun         bool          `yaml:"dry_run"`         // log actions instead of executing
}

// WebConfig controls the htmx WebUI server.
type WebConfig struct {
	Enabled    bool   `yaml:"enabled"`
	ListenAddr string `yaml:"listen_addr"` // e.g., 127.0.0.1:8080
	TLSCert    string `yaml:"tls_cert,omitempty"`
	TLSKey     string `yaml:"tls_key,omitempty"`
	SessionKey string `yaml:"session_key"`
	TOTPIssuer string `yaml:"totp_issuer"`
}

// TelegramConfig controls the Telegram alert bot.
type TelegramConfig struct {
	Enabled      bool    `yaml:"enabled"`
	BotToken     string  `yaml:"bot_token"`
	AllowedChats []int64 `yaml:"allowed_chats"` // Whitelisted chat IDs
	WebhookURL   string  `yaml:"webhook_url,omitempty"`
}

// StorageConfig controls the persistence layer.
type StorageConfig struct {
	Driver string `yaml:"driver"` // "sqlite" or "postgres"
	DSN    string `yaml:"dsn"`    // connection string / file path
}

// LoggingConfig controls structured logging.
type LoggingConfig struct {
	Level  string `yaml:"level"`  // debug, info, warn, error
	Format string `yaml:"format"` // json, console
	Output string `yaml:"output"` // stdout, file path
}

// DefaultConfig returns a sensible default configuration.
func DefaultConfig() *Config {
	hostname, _ := os.Hostname()
	platform := runtime.GOOS

	cfg := &Config{
		Agent: AgentConfig{
			Hostname: hostname,
			DataDir:  "./data",
			RulesDir: "./rules",
			Platform: platform,
		},
		Sources: SourcesConfig{
			Files: []FileSource{},
		},
		Engine: EngineConfig{
			Workers:        4,
			BufferSize:     10000,
			CorrelationTTL: 10 * time.Minute,
		},
		Response: ResponseConfig{
			AutoApprove:    false,
			ApprovalExpiry: 1 * time.Hour,
			RollbackWindow: 24 * time.Hour,
			DryRun:         true, // Safe default
		},
		Web: WebConfig{
			Enabled:    true,
			ListenAddr: "127.0.0.1:8080",
			TOTPIssuer: "Sentinel",
		},
		Telegram: TelegramConfig{
			Enabled: false,
		},
		Storage: StorageConfig{
			Driver: "sqlite",
			DSN:    "./data/sentinel.db",
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "console",
			Output: "stdout",
		},
	}

	// Platform-specific defaults
	if platform == "linux" {
		cfg.Sources.Journald = &JournaldSource{Enabled: true}
		cfg.Sources.Syslog = &SyslogSource{Enabled: true, Path: "/var/log/syslog"}
		cfg.Sources.Files = append(cfg.Sources.Files, FileSource{
			Path: "/var/log/auth.log", Category: "auth", Parser: "auto",
		})
	} else if platform == "windows" {
		cfg.Sources.EventLog = &EventLogSource{
			Enabled:  true,
			Channels: []string{"Security", "System", "Application"},
		}
	}

	return cfg
}

// Load reads a YAML config file and merges it with defaults.
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil // Use defaults
		}
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return cfg, nil
}

// Save writes the config to a YAML file.
func (c *Config) Save(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("creating config directory: %w", err)
	}

	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("writing config: %w", err)
	}

	return nil
}

// Validate checks required fields and constraints.
func (c *Config) Validate() error {
	if c.Agent.DataDir == "" {
		return fmt.Errorf("agent.data_dir is required")
	}
	if c.Agent.RulesDir == "" {
		return fmt.Errorf("agent.rules_dir is required")
	}
	if c.Storage.Driver != "sqlite" && c.Storage.Driver != "postgres" {
		return fmt.Errorf("storage.driver must be 'sqlite' or 'postgres', got %q", c.Storage.Driver)
	}
	if c.Web.Enabled && c.Web.ListenAddr == "" {
		return fmt.Errorf("web.listen_addr is required when web is enabled")
	}
	if c.Telegram.Enabled && c.Telegram.BotToken == "" {
		return fmt.Errorf("telegram.bot_token is required when telegram is enabled")
	}
	if c.Engine.Workers < 1 {
		c.Engine.Workers = 1
	}
	if c.Engine.BufferSize < 100 {
		c.Engine.BufferSize = 100
	}
	return nil
}
