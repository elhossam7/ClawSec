# Prompting Guide

## How the AI Agent Uses Prompts

Sentinel's AI agent uses structured system prompts to guide LLM behavior. Understanding the prompting architecture helps you tune the agent's personality and tool selection.

## System Prompt Structure

### Incident Analysis Prompt

```
[Identity]     → "You are Sentinel, an autonomous SOC analyst AI agent"
[Tools]        → Available skill definitions (auto-generated from registry)
[Principles]   → Operating rules (verify before acting, prefer reversible actions, etc.)
[Response Format] → Required JSON structure for analysis output
```

### Chat Prompt

```
[Identity]     → "You are Sentinel, a security analyst assistant"
[Context]      → Previous conversation context from memory
[Tools]        → Same tools available as in analysis mode
```

## LLM Response Format

The agent expects the LLM to return structured JSON:

```json
{
  "observation": "What was detected (factual summary)",
  "analysis": "Why this matters (threat assessment)",
  "recommendation": {
    "action": "block_ip",
    "target": "203.0.113.5",
    "confidence": 0.95,
    "risk_score": 3,
    "reasoning": "Known malicious IP, safe to block"
  },
  "alternatives": [
    {"action": "alert_admin", "risk_score": 1, "reasoning": "Monitor instead"}
  ],
  "requires_human": false
}
```

## Operating Principles

The system prompt instructs the agent to follow these principles:

1. **Verify before acting** — Always check if an IP is internal before blocking
2. **Prefer reversible actions** — Temporary blocks over permanent ones
3. **Escalate when uncertain** — Set `requires_human: true` if confidence is low
4. **Explain reasoning** — Every recommendation must include justification
5. **Use tools** — Don't guess; use `check_ip_reputation`, `search_incidents`, etc.

## Tuning the Agent

### Temperature

| Value | Behavior |
|-------|----------|
| 0.1 | Very deterministic, minimal creativity |
| 0.3 | **Default** — balanced, reliable analysis |
| 0.7 | More exploratory, wider tool usage |
| 1.0 | Maximum creativity (not recommended for security) |

### Confidence Threshold

Controls when human approval is required:
- `0.95` — Very strict, almost everything needs approval
- `0.85` — **Default** — agent handles clear-cut cases autonomously
- `0.70` — Permissive, agent handles most cases

### Risk Score Threshold

Controls escalation for dangerous actions:
- `5` — Conservative, most blocks need approval
- `7` — **Default** — only high-risk actions escalated
- `9` — Permissive, only critical actions need approval

### Max Tool Calls

Limits the agent's tool-use loop iterations:
- `5` — Quick analysis, may miss context
- `10` — **Default** — thorough investigation
- `20` — Deep dive, higher token cost

## Customizing Prompts

System prompts are defined in `internal/agent/prompts.go`. Key constants:

- `SystemPrompt` — Main analysis prompt template
- `ChatSystemPrompt` — Interactive chat prompt
- `BuildSystemPrompt()` — Renders template with available tools
- `BuildIncidentPrompt()` — Constructs incident-specific context

To modify the agent's behavior, edit the prompt constants and rebuild.

## Provider-Specific Notes

### Anthropic Claude
- Best tool-use support via native `tool_use` content blocks
- Supports `anthropic-version: 2023-06-01` header
- Models: `claude-sonnet-4-20250514`, `claude-3-5-haiku-20241022`

### OpenAI GPT
- Tool use via function calling API
- Models: `gpt-4o`, `gpt-4o-mini`

### Ollama (Local)
- Tool use support depends on the model
- Recommended models: `llama3.1`, `mistral`, `qwen2.5`
- Longer timeout (300s) configured by default
- No API key required
