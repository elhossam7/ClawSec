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
	AI       AIConfig       `yaml:"ai"`
	Skills   SkillsConfig   `yaml:"skills"`
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
	Socket     string   `yaml:"socket"`               // e.g., /var/run/docker.sock
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

// AIConfig configures the LLM-powered agent runtime.
type AIConfig struct {
	Provider string `yaml:"provider"` // "anthropic", "openai", "ollama", "gemini"
	APIKey   string `yaml:"api_key"`  // Or use env var: ${ANTHROPIC_API_KEY}
	Model    string `yaml:"model"`    // e.g. "claude-sonnet-4-20250514"
	Endpoint string `yaml:"endpoint"` // For ollama / custom endpoint

	// Fallback models tried in order when the primary model returns 429 / rate-limit.
	FallbackModels []string `yaml:"fallback_models,omitempty"`

	// Behaviour
	AutoAnalyze  bool    `yaml:"auto_analyze"`   // Analyse all incidents automatically
	MaxToolCalls int     `yaml:"max_tool_calls"` // Prevent infinite loops
	Temperature  float64 `yaml:"temperature"`    // LLM creativity (0.0-1.0)

	// Safety
	RequireApprovalAboveRisk int     `yaml:"require_approval_above_risk"` // 1-10
	ConfidenceThreshold      float64 `yaml:"confidence_threshold"`        // Min confidence for auto-execution
}

// SkillsConfig holds API keys used by investigation skills.
type SkillsConfig struct {
	ThreatIntel ThreatIntelConfig `yaml:"threat_intel"`
}

// ThreatIntelConfig holds external threat-intel API keys.
type ThreatIntelConfig struct {
	AbuseIPDBKey  string `yaml:"abuseipdb_key"`
	VirusTotalKey string `yaml:"virustotal_key"`
}

// RateLimitConfig configures per-action rate limits.
type RateLimitConfig struct {
	Max    int           `yaml:"max"`
	Window time.Duration `yaml:"window"`
}

// ResolveEnv replaces ${VAR} references in config strings with their env values.
func ResolveEnv(s string) string {
	if len(s) > 3 && s[0] == '$' && s[1] == '{' && s[len(s)-1] == '}' {
		envKey := s[2 : len(s)-1]
		if v := os.Getenv(envKey); v != "" {
			return v
		}
	}
	return s
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
		AI: AIConfig{
			Provider:                 "",
			AutoAnalyze:              false,
			MaxToolCalls:             10,
			Temperature:              0.3,
			RequireApprovalAboveRisk: 7,
			ConfidenceThreshold:      0.85,
		},
	}

	// Platform-specific defaults
	switch platform {
	case "linux":
		cfg.Sources.Journald = &JournaldSource{Enabled: true}
		cfg.Sources.Syslog = &SyslogSource{Enabled: true, Path: "/var/log/syslog"}
		cfg.Sources.Files = append(cfg.Sources.Files, FileSource{
			Path: "/var/log/auth.log", Category: "auth", Parser: "auto",
		})
	case "windows":
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

	// Resolve env vars for AI config.
	if c.AI.APIKey != "" {
		c.AI.APIKey = ResolveEnv(c.AI.APIKey)
	}
	if c.Skills.ThreatIntel.AbuseIPDBKey != "" {
		c.Skills.ThreatIntel.AbuseIPDBKey = ResolveEnv(c.Skills.ThreatIntel.AbuseIPDBKey)
	}
	if c.Skills.ThreatIntel.VirusTotalKey != "" {
		c.Skills.ThreatIntel.VirusTotalKey = ResolveEnv(c.Skills.ThreatIntel.VirusTotalKey)
	}

	// Validate AI config when a provider is set.
	if c.AI.Provider != "" {
		switch c.AI.Provider {
		case "anthropic", "openai", "ollama", "gemini":
			// ok
		default:
			return fmt.Errorf("ai.provider must be 'anthropic', 'openai', 'ollama', or 'gemini', got %q", c.AI.Provider)
		}
		if c.AI.Provider != "ollama" && c.AI.APIKey == "" {
			return fmt.Errorf("ai.api_key is required for provider %q", c.AI.Provider)
		}
		if c.AI.Model == "" {
			return fmt.Errorf("ai.model is required when ai.provider is set")
		}
		if c.AI.MaxToolCalls < 1 {
			c.AI.MaxToolCalls = 10
		}
	}

	return nil
}
