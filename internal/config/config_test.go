package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// ResolveEnv
// ---------------------------------------------------------------------------

func TestResolveEnv(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		envKey string
		envVal string
		want   string
	}{
		{
			name:   "resolves set env var",
			input:  "${MY_TEST_VAR}",
			envKey: "MY_TEST_VAR",
			envVal: "resolved_value",
			want:   "resolved_value",
		},
		{
			name:   "returns original when env var is empty",
			input:  "${EMPTY_VAR}",
			envKey: "EMPTY_VAR",
			envVal: "",
			want:   "${EMPTY_VAR}",
		},
		{
			name:  "returns original when env var not set",
			input: "${UNSET_VAR_THAT_DOES_NOT_EXIST}",
			want:  "${UNSET_VAR_THAT_DOES_NOT_EXIST}",
		},
		{
			name:  "plain string unchanged",
			input: "hello",
			want:  "hello",
		},
		{
			name:  "empty string unchanged",
			input: "",
			want:  "",
		},
		{
			name:  "dollar without braces unchanged",
			input: "$HOME",
			want:  "$HOME",
		},
		{
			name:  "incomplete syntax missing closing brace",
			input: "${NOCLOSE",
			want:  "${NOCLOSE",
		},
		{
			name:  "too short to match (len 3)",
			input: "${}", // len == 3, needs > 3
			want:  "${}",
		},
		{
			name:   "single char variable name resolves (len 4)",
			input:  "${X}",
			envKey: "X",
			envVal: "xval",
			want:   "xval",
		},
		{
			name:  "variable reference embedded in larger string unchanged",
			input: "prefix${VAR}suffix",
			want:  "prefix${VAR}suffix",
		},
		{
			name:  "opening brace only",
			input: "${",
			want:  "${",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Set env if specified.
			if tc.envKey != "" {
				if tc.envVal != "" {
					t.Setenv(tc.envKey, tc.envVal)
				} else {
					// Ensure it is explicitly set to empty.
					os.Setenv(tc.envKey, tc.envVal)
					t.Cleanup(func() { os.Unsetenv(tc.envKey) })
				}
			}

			got := ResolveEnv(tc.input)
			if got != tc.want {
				t.Errorf("ResolveEnv(%q) = %q; want %q", tc.input, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// DefaultConfig
// ---------------------------------------------------------------------------

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig() returned nil")
	}

	// --- Agent ---
	if cfg.Agent.DataDir != "./data" {
		t.Errorf("Agent.DataDir = %q; want %q", cfg.Agent.DataDir, "./data")
	}
	if cfg.Agent.RulesDir != "./rules" {
		t.Errorf("Agent.RulesDir = %q; want %q", cfg.Agent.RulesDir, "./rules")
	}
	if cfg.Agent.Platform != runtime.GOOS {
		t.Errorf("Agent.Platform = %q; want %q", cfg.Agent.Platform, runtime.GOOS)
	}
	if cfg.Agent.Hostname == "" {
		t.Log("Agent.Hostname is empty (os.Hostname may have failed); skipping hostname assertion")
	}

	// --- Engine ---
	if cfg.Engine.Workers != 4 {
		t.Errorf("Engine.Workers = %d; want 4", cfg.Engine.Workers)
	}
	if cfg.Engine.BufferSize != 10000 {
		t.Errorf("Engine.BufferSize = %d; want 10000", cfg.Engine.BufferSize)
	}

	// --- Web ---
	if !cfg.Web.Enabled {
		t.Error("Web.Enabled = false; want true")
	}
	if cfg.Web.ListenAddr != "127.0.0.1:8080" {
		t.Errorf("Web.ListenAddr = %q; want %q", cfg.Web.ListenAddr, "127.0.0.1:8080")
	}

	// --- Storage ---
	if cfg.Storage.Driver != "sqlite" {
		t.Errorf("Storage.Driver = %q; want %q", cfg.Storage.Driver, "sqlite")
	}
	if cfg.Storage.DSN != "./data/sentinel.db" {
		t.Errorf("Storage.DSN = %q; want %q", cfg.Storage.DSN, "./data/sentinel.db")
	}

	// --- Response ---
	if !cfg.Response.DryRun {
		t.Error("Response.DryRun = false; want true")
	}
	if cfg.Response.AutoApprove {
		t.Error("Response.AutoApprove = true; want false")
	}

	// --- AI ---
	if cfg.AI.MaxToolCalls != 10 {
		t.Errorf("AI.MaxToolCalls = %d; want 10", cfg.AI.MaxToolCalls)
	}
	if cfg.AI.Temperature != 0.3 {
		t.Errorf("AI.Temperature = %f; want 0.3", cfg.AI.Temperature)
	}

	// --- Webhook ---
	if cfg.Webhook.Enabled {
		t.Error("Webhook.Enabled = true; want false")
	}

	// --- Slack ---
	if cfg.Slack.Enabled {
		t.Error("Slack.Enabled = true; want false")
	}

	// --- Telegram ---
	if cfg.Telegram.Enabled {
		t.Error("Telegram.Enabled = true; want false")
	}

	// --- Logging ---
	if cfg.Logging.Level != "info" {
		t.Errorf("Logging.Level = %q; want %q", cfg.Logging.Level, "info")
	}
	if cfg.Logging.Format != "console" {
		t.Errorf("Logging.Format = %q; want %q", cfg.Logging.Format, "console")
	}
}

// ---------------------------------------------------------------------------
// Load
// ---------------------------------------------------------------------------

func TestLoad_NonExistentFile(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "does_not_exist.yml"))
	if err != nil {
		t.Fatalf("Load() returned unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("Load() returned nil config for non-existent file")
	}
	// Should equal defaults.
	if cfg.Agent.DataDir != "./data" {
		t.Errorf("Agent.DataDir = %q; want default %q", cfg.Agent.DataDir, "./data")
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yml")
	if err := os.WriteFile(path, []byte("{{{{not yaml at all::::"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() expected error for invalid YAML, got nil")
	}
	if !strings.Contains(err.Error(), "parsing config") {
		t.Errorf("error = %q; want it to contain %q", err.Error(), "parsing config")
	}
}

func TestLoad_ValidYAML_MergesWithDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sentinel.yml")

	yaml := `
agent:
  data_dir: /custom/data
  rules_dir: /custom/rules
engine:
  workers: 8
  buffer_size: 20000
storage:
  driver: postgres
  dsn: "postgres://localhost/sentinel"
web:
  enabled: false
`
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() returned unexpected error: %v", err)
	}

	// Overridden values.
	if cfg.Agent.DataDir != "/custom/data" {
		t.Errorf("Agent.DataDir = %q; want %q", cfg.Agent.DataDir, "/custom/data")
	}
	if cfg.Agent.RulesDir != "/custom/rules" {
		t.Errorf("Agent.RulesDir = %q; want %q", cfg.Agent.RulesDir, "/custom/rules")
	}
	if cfg.Engine.Workers != 8 {
		t.Errorf("Engine.Workers = %d; want 8", cfg.Engine.Workers)
	}
	if cfg.Engine.BufferSize != 20000 {
		t.Errorf("Engine.BufferSize = %d; want 20000", cfg.Engine.BufferSize)
	}
	if cfg.Storage.Driver != "postgres" {
		t.Errorf("Storage.Driver = %q; want %q", cfg.Storage.Driver, "postgres")
	}

	// Defaults preserved for fields not in YAML.
	if cfg.Response.DryRun != true {
		t.Error("Response.DryRun should remain true (default)")
	}
	if cfg.AI.MaxToolCalls != 10 {
		t.Errorf("AI.MaxToolCalls = %d; want default 10", cfg.AI.MaxToolCalls)
	}
}

func TestLoad_ValidationFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad_config.yml")

	yaml := `
agent:
  data_dir: ""
  rules_dir: ""
`
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() expected validation error, got nil")
	}
	if !strings.Contains(err.Error(), "invalid config") {
		t.Errorf("error = %q; want it to contain %q", err.Error(), "invalid config")
	}
}

func TestLoad_ReadPermissionError(t *testing.T) {
	// On Windows, file permission semantics differ; skip this test there.
	if runtime.GOOS == "windows" {
		t.Skip("skipping permission test on Windows")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "unreadable.yml")
	if err := os.WriteFile(path, []byte("agent:\n  data_dir: /a\n"), 0000); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() expected error for unreadable file, got nil")
	}
	if !strings.Contains(err.Error(), "reading config") {
		t.Errorf("error = %q; want it to contain %q", err.Error(), "reading config")
	}
}

// ---------------------------------------------------------------------------
// Save
// ---------------------------------------------------------------------------

func TestSave_CreatesDirectoriesAndFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "dir", "sentinel.yml")

	cfg := DefaultConfig()
	if err := cfg.Save(path); err != nil {
		t.Fatalf("Save() returned unexpected error: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat after Save: %v", err)
	}
	if info.Size() == 0 {
		t.Error("saved file is empty")
	}

	// Verify Unix permissions (skip on Windows which has different permission model).
	if runtime.GOOS != "windows" {
		perm := info.Mode().Perm()
		if perm != 0600 {
			t.Errorf("file permissions = %o; want 0600", perm)
		}
	}
}

func TestSave_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roundtrip.yml")

	original := DefaultConfig()
	original.Agent.DataDir = "/roundtrip/data"
	original.Agent.RulesDir = "/roundtrip/rules"
	original.Engine.Workers = 16
	original.Storage.Driver = "postgres"
	original.Storage.DSN = "postgres://localhost/test"
	original.Web.Enabled = false

	if err := original.Save(path); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load() after Save() error: %v", err)
	}

	if loaded.Agent.DataDir != original.Agent.DataDir {
		t.Errorf("DataDir = %q; want %q", loaded.Agent.DataDir, original.Agent.DataDir)
	}
	if loaded.Engine.Workers != original.Engine.Workers {
		t.Errorf("Workers = %d; want %d", loaded.Engine.Workers, original.Engine.Workers)
	}
	if loaded.Storage.Driver != original.Storage.Driver {
		t.Errorf("Storage.Driver = %q; want %q", loaded.Storage.Driver, original.Storage.Driver)
	}
	if loaded.Web.Enabled != original.Web.Enabled {
		t.Errorf("Web.Enabled = %v; want %v", loaded.Web.Enabled, original.Web.Enabled)
	}
}

// ---------------------------------------------------------------------------
// Validate
// ---------------------------------------------------------------------------

func TestValidate(t *testing.T) {
	// helper returns a valid baseline config.
	validCfg := func() *Config {
		c := DefaultConfig()
		return c
	}

	tests := []struct {
		name    string
		modify  func(c *Config)
		wantErr string // substring expected in error; empty means no error
	}{
		// --- happy path ---
		{
			name:    "default config is valid",
			modify:  func(c *Config) {},
			wantErr: "",
		},

		// --- agent ---
		{
			name:    "missing agent.data_dir",
			modify:  func(c *Config) { c.Agent.DataDir = "" },
			wantErr: "agent.data_dir is required",
		},
		{
			name:    "missing agent.rules_dir",
			modify:  func(c *Config) { c.Agent.RulesDir = "" },
			wantErr: "agent.rules_dir is required",
		},

		// --- storage ---
		{
			name:    "invalid storage.driver",
			modify:  func(c *Config) { c.Storage.Driver = "mysql" },
			wantErr: "storage.driver must be 'sqlite' or 'postgres'",
		},
		{
			name:    "storage.driver sqlite accepted",
			modify:  func(c *Config) { c.Storage.Driver = "sqlite" },
			wantErr: "",
		},
		{
			name:    "storage.driver postgres accepted",
			modify:  func(c *Config) { c.Storage.Driver = "postgres" },
			wantErr: "",
		},

		// --- web ---
		{
			name: "web enabled without listen_addr",
			modify: func(c *Config) {
				c.Web.Enabled = true
				c.Web.ListenAddr = ""
			},
			wantErr: "web.listen_addr is required when web is enabled",
		},
		{
			name: "web disabled without listen_addr is fine",
			modify: func(c *Config) {
				c.Web.Enabled = false
				c.Web.ListenAddr = ""
			},
			wantErr: "",
		},

		// --- telegram ---
		{
			name: "telegram enabled without bot_token",
			modify: func(c *Config) {
				c.Telegram.Enabled = true
				c.Telegram.BotToken = ""
			},
			wantErr: "telegram.bot_token is required when telegram is enabled",
		},
		{
			name: "telegram enabled with bot_token is fine",
			modify: func(c *Config) {
				c.Telegram.Enabled = true
				c.Telegram.BotToken = "123:ABC"
			},
			wantErr: "",
		},
		{
			name: "telegram disabled without bot_token is fine",
			modify: func(c *Config) {
				c.Telegram.Enabled = false
				c.Telegram.BotToken = ""
			},
			wantErr: "",
		},

		// --- webhook ---
		{
			name: "webhook enabled without url",
			modify: func(c *Config) {
				c.Webhook.Enabled = true
				c.Webhook.URL = ""
			},
			wantErr: "webhook.url is required when webhook is enabled",
		},
		{
			name: "webhook enabled with url is fine",
			modify: func(c *Config) {
				c.Webhook.Enabled = true
				c.Webhook.URL = "https://example.com/hook"
			},
			wantErr: "",
		},

		// --- slack ---
		{
			name: "slack enabled without webhook_url",
			modify: func(c *Config) {
				c.Slack.Enabled = true
				c.Slack.WebhookURL = ""
			},
			wantErr: "slack.webhook_url is required when slack is enabled",
		},
		{
			name: "slack enabled with webhook_url is fine",
			modify: func(c *Config) {
				c.Slack.Enabled = true
				c.Slack.WebhookURL = "https://hooks.slack.com/services/T/B/X"
			},
			wantErr: "",
		},

		// --- engine ---
		{
			name: "engine workers clamped to minimum 1",
			modify: func(c *Config) {
				c.Engine.Workers = 0
			},
			wantErr: "", // not an error, just clamped
		},
		{
			name: "engine buffer_size clamped to minimum 100",
			modify: func(c *Config) {
				c.Engine.BufferSize = 50
			},
			wantErr: "", // not an error, just clamped
		},

		// --- ai provider ---
		{
			name: "invalid ai.provider",
			modify: func(c *Config) {
				c.AI.Provider = "deepseek"
				c.AI.APIKey = "key"
				c.AI.Model = "model"
			},
			wantErr: "ai.provider must be",
		},
		{
			name: "ai.provider anthropic accepted",
			modify: func(c *Config) {
				c.AI.Provider = "anthropic"
				c.AI.APIKey = "sk-ant-test"
				c.AI.Model = "claude-sonnet-4-20250514"
			},
			wantErr: "",
		},
		{
			name: "ai.provider openai accepted",
			modify: func(c *Config) {
				c.AI.Provider = "openai"
				c.AI.APIKey = "sk-test"
				c.AI.Model = "gpt-4"
			},
			wantErr: "",
		},
		{
			name: "ai.provider ollama accepted without api_key",
			modify: func(c *Config) {
				c.AI.Provider = "ollama"
				c.AI.APIKey = ""
				c.AI.Model = "llama3"
			},
			wantErr: "",
		},
		{
			name: "ai.provider gemini accepted",
			modify: func(c *Config) {
				c.AI.Provider = "gemini"
				c.AI.APIKey = "AIza-test"
				c.AI.Model = "gemini-pro"
			},
			wantErr: "",
		},

		// --- ai api_key ---
		{
			name: "ai.api_key required for anthropic",
			modify: func(c *Config) {
				c.AI.Provider = "anthropic"
				c.AI.APIKey = ""
				c.AI.Model = "claude-sonnet-4-20250514"
			},
			wantErr: "ai.api_key is required for provider",
		},
		{
			name: "ai.api_key required for openai",
			modify: func(c *Config) {
				c.AI.Provider = "openai"
				c.AI.APIKey = ""
				c.AI.Model = "gpt-4"
			},
			wantErr: "ai.api_key is required for provider",
		},
		{
			name: "ai.api_key required for gemini",
			modify: func(c *Config) {
				c.AI.Provider = "gemini"
				c.AI.APIKey = ""
				c.AI.Model = "gemini-pro"
			},
			wantErr: "ai.api_key is required for provider",
		},
		{
			name: "ai.api_key NOT required for ollama",
			modify: func(c *Config) {
				c.AI.Provider = "ollama"
				c.AI.APIKey = ""
				c.AI.Model = "llama3"
			},
			wantErr: "",
		},

		// --- ai model ---
		{
			name: "ai.model required when provider set",
			modify: func(c *Config) {
				c.AI.Provider = "anthropic"
				c.AI.APIKey = "key"
				c.AI.Model = ""
			},
			wantErr: "ai.model is required when ai.provider is set",
		},

		// --- ai max_tool_calls ---
		{
			name: "ai.max_tool_calls clamped to default when < 1",
			modify: func(c *Config) {
				c.AI.Provider = "ollama"
				c.AI.Model = "llama3"
				c.AI.MaxToolCalls = 0
			},
			wantErr: "", // clamped, not an error
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validCfg()
			tc.modify(cfg)

			err := cfg.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Fatalf("Validate() expected error containing %q, got nil", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("Validate() error = %q; want it to contain %q", err.Error(), tc.wantErr)
				}
			}
		})
	}
}

// TestValidate_EngineWorkersClamped verifies that workers below 1 are silently
// corrected rather than rejected.
func TestValidate_EngineWorkersClamped(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Engine.Workers = -5

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}
	if cfg.Engine.Workers != 1 {
		t.Errorf("Engine.Workers = %d after Validate(); want 1", cfg.Engine.Workers)
	}
}

// TestValidate_EngineBufferSizeClamped verifies that buffer_size below 100 is
// silently corrected.
func TestValidate_EngineBufferSizeClamped(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Engine.BufferSize = 10

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}
	if cfg.Engine.BufferSize != 100 {
		t.Errorf("Engine.BufferSize = %d after Validate(); want 100", cfg.Engine.BufferSize)
	}
}

// TestValidate_AIMaxToolCallsClamped verifies that max_tool_calls below 1 gets
// reset to the default of 10 when a provider is set.
func TestValidate_AIMaxToolCallsClamped(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AI.Provider = "ollama"
	cfg.AI.Model = "llama3"
	cfg.AI.MaxToolCalls = 0

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}
	if cfg.AI.MaxToolCalls != 10 {
		t.Errorf("AI.MaxToolCalls = %d after Validate(); want 10", cfg.AI.MaxToolCalls)
	}
}

// TestValidate_ResolvesEnvInAPIKey verifies that Validate resolves ${VAR}
// references in AI.APIKey.
func TestValidate_ResolvesEnvInAPIKey(t *testing.T) {
	t.Setenv("SENTINEL_TEST_API_KEY", "sk-resolved-key")

	cfg := DefaultConfig()
	cfg.AI.Provider = "anthropic"
	cfg.AI.Model = "claude-sonnet-4-20250514"
	cfg.AI.APIKey = "${SENTINEL_TEST_API_KEY}"

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}
	if cfg.AI.APIKey != "sk-resolved-key" {
		t.Errorf("AI.APIKey = %q; want %q", cfg.AI.APIKey, "sk-resolved-key")
	}
}

// TestValidate_ResolvesEnvInThreatIntelKeys verifies that Validate resolves
// ${VAR} references in threat-intel API keys.
func TestValidate_ResolvesEnvInThreatIntelKeys(t *testing.T) {
	t.Setenv("SENTINEL_ABUSEIPDB", "abuse-key-123")
	t.Setenv("SENTINEL_VIRUSTOTAL", "vt-key-456")

	cfg := DefaultConfig()
	cfg.Skills.ThreatIntel.AbuseIPDBKey = "${SENTINEL_ABUSEIPDB}"
	cfg.Skills.ThreatIntel.VirusTotalKey = "${SENTINEL_VIRUSTOTAL}"

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}
	if cfg.Skills.ThreatIntel.AbuseIPDBKey != "abuse-key-123" {
		t.Errorf("AbuseIPDBKey = %q; want %q", cfg.Skills.ThreatIntel.AbuseIPDBKey, "abuse-key-123")
	}
	if cfg.Skills.ThreatIntel.VirusTotalKey != "vt-key-456" {
		t.Errorf("VirusTotalKey = %q; want %q", cfg.Skills.ThreatIntel.VirusTotalKey, "vt-key-456")
	}
}

// ---------------------------------------------------------------------------
// Load + Validate integration: AI with env-resolved key via YAML
// ---------------------------------------------------------------------------

func TestLoad_AIProviderWithEnvResolvedKey(t *testing.T) {
	t.Setenv("SENTINEL_OPENAI_KEY", "sk-live-openai")

	dir := t.TempDir()
	path := filepath.Join(dir, "ai.yml")

	yaml := `
agent:
  data_dir: ./data
  rules_dir: ./rules
ai:
  provider: openai
  api_key: "${SENTINEL_OPENAI_KEY}"
  model: gpt-4
  max_tool_calls: 5
`
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() returned unexpected error: %v", err)
	}
	if cfg.AI.APIKey != "sk-live-openai" {
		t.Errorf("AI.APIKey = %q; want %q", cfg.AI.APIKey, "sk-live-openai")
	}
	if cfg.AI.MaxToolCalls != 5 {
		t.Errorf("AI.MaxToolCalls = %d; want 5", cfg.AI.MaxToolCalls)
	}
}

// ---------------------------------------------------------------------------
// Save edge case: overwrite existing file
// ---------------------------------------------------------------------------

func TestSave_OverwritesExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "overwrite.yml")

	cfg1 := DefaultConfig()
	cfg1.Agent.DataDir = "/first"
	cfg1.Agent.RulesDir = "/first"
	if err := cfg1.Save(path); err != nil {
		t.Fatalf("first Save() error: %v", err)
	}

	cfg2 := DefaultConfig()
	cfg2.Agent.DataDir = "/second"
	cfg2.Agent.RulesDir = "/second"
	if err := cfg2.Save(path); err != nil {
		t.Fatalf("second Save() error: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if loaded.Agent.DataDir != "/second" {
		t.Errorf("Agent.DataDir = %q; want %q", loaded.Agent.DataDir, "/second")
	}
}

// ---------------------------------------------------------------------------
// DefaultConfig: platform-specific sources
// ---------------------------------------------------------------------------

func TestDefaultConfig_PlatformSources(t *testing.T) {
	cfg := DefaultConfig()

	switch runtime.GOOS {
	case "linux":
		if cfg.Sources.Journald == nil || !cfg.Sources.Journald.Enabled {
			t.Error("expected Journald source to be enabled on linux")
		}
		if cfg.Sources.Syslog == nil || !cfg.Sources.Syslog.Enabled {
			t.Error("expected Syslog source to be enabled on linux")
		}
		if len(cfg.Sources.Files) == 0 {
			t.Error("expected at least one file source on linux")
		}
	case "windows":
		if cfg.Sources.EventLog == nil || !cfg.Sources.EventLog.Enabled {
			t.Error("expected EventLog source to be enabled on windows")
		}
		if len(cfg.Sources.EventLog.Channels) == 0 {
			t.Error("expected EventLog channels to be populated on windows")
		}
	}
}
