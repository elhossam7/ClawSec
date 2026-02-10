# Skills Reference

Skills are self-contained security capabilities the AI agent can invoke during incident analysis or chat. Each skill validates its inputs, executes a platform action, and returns structured results.

## Available Skills

### `block_ip` — Firewall Skill
Block an IP address using the system firewall.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `ip` | string | Yes | IPv4/IPv6 address to block |
| `duration` | integer | No | Block duration in seconds (0=permanent, max 86400) |
| `reason` | string | Yes | Justification for blocking |

**Safety**: Rejects IPs in protected CIDR ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8). Rate limited to 10/hour.

**Platform**: Linux → `iptables -A INPUT -s <ip> -j DROP` | Windows → `New-NetFirewallRule`

---

### `kill_process` — Process Skill
Terminate a process by PID.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `pid` | integer | Yes | Process ID to terminate |
| `reason` | string | Yes | Justification |

**Safety**: Protected processes (init, systemd, sshd, kernel) cannot be killed. Rate limited to 5/hour.

---

### `get_process_info` — Process Info Skill
Get detailed information about a running process.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `pid` | integer | Yes | Process ID to inspect |

**Platform**: Linux → `ps -p <pid> -o ...` | Windows → `Get-Process -Id <pid> | ConvertTo-Json`

---

### `get_logs` — Log Search Skill
Search the event log database for matching entries.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `keyword` | string | No | Text to search in raw log data |
| `source` | string | No | Filter by log source |
| `category` | string | No | Filter by event category |
| `limit` | integer | No | Max results (default 50, max 100) |

---

### `search_incidents` — Incident Search Skill
Search past incidents by various criteria.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source_ip` | string | No | Filter by source IP |
| `rule_id` | string | No | Filter by detection rule |
| `status` | string | No | Filter by status (open/resolved/escalated) |
| `limit` | integer | No | Max results (default 20, max 50) |

---

### `check_if_internal` — Internal IP Check
Determine if an IP is on an internal/private network (RFC 1918).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `ip` | string | Yes | IP address to check |

**Returns**: Whether the IP is internal and which CIDR range it matches.

---

### `query_asset` — Asset Query Skill
Look up what's known about an IP address from incidents, events, and agent memory.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `ip` | string | Yes | IP address to query |

**Returns**: Recent incidents, event count, and stored facts about the IP.

---

### `check_ip_reputation` — IP Reputation (AbuseIPDB)
Query AbuseIPDB for an IP's abuse reputation.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `ip` | string | Yes | IP address to check |

**Requires**: `ABUSEIPDB_KEY` in `skills.threat_intel.abuseipdb_key` config.

**Returns**: Abuse confidence score (0-100), country, ISP, total reports.

---

### `check_file_hash` — Hash Reputation (VirusTotal)
Check a file hash against VirusTotal.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `hash` | string | Yes | MD5 (32), SHA1 (40), or SHA256 (64) hash |

**Requires**: `VIRUSTOTAL_KEY` in `skills.threat_intel.virustotal_key` config.

**Returns**: Detection ratio, threat label, scan results.

---

## Creating Custom Skills

Implement the `Tool` interface from `internal/skills`:

```go
type Tool interface {
    Name() string
    Description() string
    ParametersSchema() map[string]interface{}
    Validate(params map[string]interface{}) error
    Execute(ctx context.Context, params map[string]interface{}) (*types.ToolResult, error)
}
```

Register in `cmd/sentinel/main.go`:

```go
aiAgent.RegisterTool(myskills.NewCustomSkill(logger))
```

The skill will automatically become available to the LLM agent.
