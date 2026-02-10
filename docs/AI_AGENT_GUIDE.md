# Sentinel AI Agent Guide

## Overview

Sentinel has been extended from a rule-based SIGMA detection engine into an **autonomous SOC AI Agent**. The agent uses LLM-driven decision-making to analyze security incidents, propose defensive actions, and interact conversationally with analysts.

### Architecture: Senses → Brain → Hands

```
Log Sources → Detection Engine (SIGMA rules) → AI Agent (LLM) → Skills (tools) → Response Orchestrator
                                                    ↑                                      ↓
                                               Memory (SQLite)                    Human Approval Queue
```

- **Senses**: Platform log collectors + SIGMA detection rules (unchanged)
- **Brain**: LLM-powered agent runtime with tool-use loop
- **Hands**: Skills (firewall, process management, forensics, threat intel)
- **Memory**: Persistent fact storage + analysis audit trail

## Configuration

Enable AI features in `sentinel.yaml`:

```yaml
ai:
  provider: "anthropic"          # anthropic | openai | ollama
  api_key: "${ANTHROPIC_API_KEY}" # Env var expansion supported
  model: "claude-sonnet-4-20250514"
  endpoint: ""                   # Custom endpoint (required for ollama)
  auto_analyze: true             # Route detections to AI agent
  max_tool_calls: 10             # Max tool-use iterations per analysis
  temperature: 0.3               # Lower = more deterministic
  require_approval_above_risk: 7 # Risk 1-10; above this → human review
  confidence_threshold: 0.85     # Below this → human review

skills:
  threat_intel:
    abuseipdb_key: "${ABUSEIPDB_KEY}"
    virustotal_key: "${VIRUSTOTAL_KEY}"
```

### Provider Setup

| Provider | Requirements |
|----------|-------------|
| **Anthropic** | `ANTHROPIC_API_KEY` env var, model like `claude-sonnet-4-20250514` |
| **OpenAI** | `OPENAI_API_KEY` env var, model like `gpt-4o` |
| **Ollama** | Local Ollama server, set `endpoint: "http://localhost:11434"`, no API key needed |

## How It Works

### Incident Analysis Flow

1. SIGMA rule triggers a detection → creates an `Incident`
2. If `auto_analyze: true`, the incident is routed to the AI agent
3. Agent builds context from memory (known facts about the source IP, rule history)
4. Agent enters an LLM tool-use loop:
   - LLM analyzes the incident and decides which tools to call
   - Tools execute (e.g., check if IP is internal, query threat intel)
   - Results feed back into the conversation
   - Loop continues until LLM reaches a conclusion (max iterations enforced)
5. Agent produces a structured analysis: observation, reasoning, recommendation
6. If risk score > threshold OR confidence < threshold → requires human approval
7. Otherwise, proposed action enters the approval queue (or auto-executes if configured)

### Chat Interface

Analysts can interact with the agent via:
- **WebUI**: `/api/chat` endpoint (htmx-powered)
- **Streaming**: `/v1/stream` SSE endpoint for real-time reasoning traces

Example chat:
```
Analyst: "What's happening with IP 203.0.113.5?"
Agent: [calls search_incidents, check_ip_reputation tools]
       "203.0.113.5 has triggered ssh_brute_force 3 times in the last hour.
        AbuseIPDB shows 92% abuse confidence from Russia. Recommend blocking."
```

## Safety Guardrails

1. **Input Validation**: All user inputs and tool parameters sanitized against prompt injection and command injection
2. **Policy Engine**: Rate limits per action type (e.g., max 10 IP blocks/hour)
3. **Protected Ranges**: Internal CIDRs (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) cannot be blocked
4. **Human-in-the-Loop**: High-risk actions always require approval
5. **Audit Trail**: Every analysis and tool execution logged to SQLite

## Backward Compatibility

- If `ai.provider` is empty/unset, Sentinel operates in pure SIGMA mode (no LLM calls)
- All existing rules, response actions, and WebUI features work unchanged
- AI features are additive — they enhance, not replace, the detection pipeline
