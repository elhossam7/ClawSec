# Security Model

## Threat Model

The AI agent introduces new attack surfaces that require layered defenses:

| Threat | Mitigation |
|--------|------------|
| Prompt injection via log data | Input sanitization + banned pattern detection |
| Tool parameter injection | Shell character validation on all string params |
| Excessive automated actions | Per-action rate limits (PolicyEngine) |
| Blocking internal infrastructure | Protected CIDR allow-lists |
| LLM hallucination → wrong action | Confidence thresholds + human approval for high-risk |
| API key exposure | Environment variable expansion (`${VAR}` syntax) |
| Audit evasion | All analyses and tool calls logged to SQLite |

## Input Validation

### Prompt Injection Detection
The `InputValidator` checks all user inputs against 14 regex patterns:
- "ignore previous instructions"
- "you are now DAN"
- "print your system prompt"
- "forget your instructions"
- "reveal your instructions"
- "bypass your safety filters"
- "override your training"
- And more...

### Tool Parameter Sanitization
All string parameters passed to tools are checked for:
- Shell metacharacters: `;`, `&&`, `||`, `|`, `$(`, `` ` ``
- Dangerous commands: `rm -rf`, `dd if=`, `curl`, `wget`, `nc`, `ncat`
- Redirect operators: `>>`, `<<`

## Policy Engine

### Rate Limits (defaults)
| Action | Max per Hour |
|--------|-------------|
| `block_ip` | 10 |
| `kill_process` | 5 |
| `disable_user` | 5 |
| `llm_api_call` | 100 |

Rate limits use a sliding window that resets automatically.

### Protected Resources
- **Internal CIDRs**: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8
- **System processes**: init, systemd, sshd, kernel (cannot be killed)

### Human-in-the-Loop
Actions require human approval when:
1. `risk_score > require_approval_above_risk` (default: 7)
2. `confidence < confidence_threshold` (default: 0.85)
3. The LLM explicitly sets `requires_human: true`

## Audit Trail

Every AI interaction is persisted:

### `analysis_logs` table
- Incident ID, provider, model, reasoning text
- Actions proposed (JSON), confidence, risk score
- Token usage, duration, timestamp

### `tool_executions` table
- Analysis ID, tool name, parameters (JSON)
- Result (JSON), success/failure, duration
- Timestamp

### `agent_memory` table
- Learned facts with source attribution
- Confidence scores, access counts
- Creation and last-accessed timestamps

## Environment Variables

Never put API keys directly in `sentinel.yaml`. Use environment variable expansion:

```yaml
ai:
  api_key: "${ANTHROPIC_API_KEY}"
skills:
  threat_intel:
    abuseipdb_key: "${ABUSEIPDB_KEY}"
    virustotal_key: "${VIRUSTOTAL_KEY}"
```

## Recommendations

1. **Start with `auto_analyze: false`** — manually test the agent via chat before enabling auto-analysis
2. **Use Ollama for testing** — no API keys needed, runs locally
3. **Review analysis logs regularly** — check for reasoning quality and false positives
4. **Tune rate limits** — adjust based on your environment's incident volume
5. **Keep `dry_run: true`** until you trust the agent's recommendations
