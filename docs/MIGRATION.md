# Migration Guide

## Upgrading from Rule-Based Sentinel to AI Agent

This guide covers migrating an existing Sentinel deployment to include AI agent capabilities.

### Prerequisites

- Go 1.22+
- An LLM provider: Anthropic API key, OpenAI API key, or local Ollama instance
- (Optional) AbuseIPDB and/or VirusTotal API keys for threat intel skills

### Step 1: Update Binary

```bash
go build -o sentinel ./cmd/sentinel/
```

### Step 2: Database Migration

The new schema is applied automatically on startup. Four new tables are created:
- `agent_memory` — persistent fact storage
- `analysis_logs` — AI analysis audit trail
- `tool_executions` — tool invocation audit
- `chat_sessions` — interactive chat context

**No existing data is modified or deleted.** Migrations are additive.

### Step 3: Configure AI Provider

Add the `ai` section to `sentinel.yaml`:

```yaml
ai:
  provider: "anthropic"
  api_key: "${ANTHROPIC_API_KEY}"
  model: "claude-sonnet-4-20250514"
  auto_analyze: false               # Start with manual mode
  require_approval_above_risk: 7
  confidence_threshold: 0.85
```

Set your API key as an environment variable:
```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

### Step 4: Test with Chat

Start Sentinel and use the chat interface to verify the AI agent works:

```bash
./sentinel run
# Open http://127.0.0.1:8080 → Chat
# Ask: "What incidents have occurred in the last hour?"
```

### Step 5: Enable Auto-Analysis

Once confident, enable automatic incident routing to the AI agent:

```yaml
ai:
  auto_analyze: true
```

### Step 6: Configure Threat Intel (Optional)

```yaml
skills:
  threat_intel:
    abuseipdb_key: "${ABUSEIPDB_KEY}"
    virustotal_key: "${VIRUSTOTAL_KEY}"
```

### Rollback

To disable AI features entirely, either:
1. Remove/empty the `ai.provider` field in `sentinel.yaml`
2. Set `ai.auto_analyze: false` to keep chat but disable auto-analysis

Sentinel will revert to pure SIGMA-rule processing. No data is lost.

### Breaking Changes

**None.** The AI agent is purely additive:
- All existing SIGMA rules continue to work
- Existing response actions/approval workflow unchanged
- WebUI dashboard and approval queue unmodified
- Telegram bot integration unmodified
- All existing API endpoints preserved

### New API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/chat` | POST | Interactive chat with the AI agent |
| `/v1/stream` | GET | SSE stream for real-time agent events |

### New Database Tables

| Table | Purpose |
|-------|---------|
| `agent_memory` | Persistent facts learned by the agent |
| `analysis_logs` | Full audit of every AI analysis |
| `tool_executions` | Record of every tool the agent invoked |
| `chat_sessions` | Chat conversation context persistence |
