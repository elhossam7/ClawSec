# Sentinel 🛡️

**Blue Team Defensive Agent** — Cross-platform security monitoring with real-time threat detection, semi-automated response, and multi-channel alerting.

Sentinel watches system logs in real-time, detects threats using SIGMA-compatible rules, queues response actions for human approval via Telegram/WebUI, and executes defensive responses with full rollback support.

## Features

- **Cross-Platform**: Linux (journald, syslog, file watchers) and Windows (Event Log, file watchers)
- **SIGMA-Compatible Rules**: Community-standard detection format with Sentinel response extensions
- **Semi-Automated Response**: Actions require human approval before execution (configurable)
- **Correlation Engine**: Threshold-based detection (e.g., "5 failed logins in 5 minutes from same IP")
- **WebUI Dashboard**: Real-time htmx dashboard with SSE live updates, no JavaScript frameworks
- **Telegram Bot**: Real-time alerts with inline approve/deny buttons
- **Rollback Support**: Undo executed actions within a configurable time window
- **Audit Trail**: Every action is logged for accountability
- **Dry Run Mode**: Test detection and response without executing real actions

## Quick Start

### 1. Build
```bash
git clone https://github.com/sentinel-agent/sentinel.git
cd sentinel
go mod tidy
make build
```

### 2. Initialize
```bash
./bin/sentinel init
```
This creates `sentinel.yaml` with platform-appropriate defaults.

### 3. Configure
Edit `sentinel.yaml` to set up log sources:
```yaml
sources:
  files:
    - path: /var/log/auth.log
      category: auth
      parser: auto
    - path: /var/log/nginx/access.log
      category: web
      parser: auto

response:
  dry_run: true   # Set to false when ready for real actions
  auto_approve: false

web:
  enabled: true
  listen_addr: "127.0.0.1:8080"

telegram:
  enabled: false
  bot_token: "YOUR_BOT_TOKEN"
  allowed_chats: [123456789]
```

### 4. Run
```bash
./bin/sentinel run
```

Open http://127.0.0.1:8080 — Login with `admin` / `sentinel` (change immediately).

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Sentinel Agent                        │
│                                                         │
│  ┌─────────┐  ┌──────────┐  ┌────────────┐            │
│  │ Platform │  │Detection │  │  Response   │            │
│  │ Manager  │→ │ Engine   │→ │Orchestrator │            │
│  │          │  │          │  │             │            │
│  │• Syslog  │  │• Rules   │  │• Queue      │            │
│  │• EventLog│  │• Correlat│  │• Execute    │            │
│  │• Files   │  │• Match   │  │• Rollback   │            │
│  │• Journald│  │          │  │             │            │
│  └─────────┘  └──────────┘  └──────┬──────┘            │
│                                     │                    │
│  ┌──────────────────────────────────┼──────────────┐    │
│  │              Gateway             │              │    │
│  │  ┌─────────┐  ┌──────────┐ ┌────┴─────┐       │    │
│  │  │  WebUI  │  │ REST API │ │ Telegram │       │    │
│  │  │  htmx   │  │          │ │   Bot    │       │    │
│  │  │  +SSE   │  │          │ │          │       │    │
│  │  └─────────┘  └──────────┘ └──────────┘       │    │
│  └────────────────────────────────────────────────┘    │
│                                                         │
│  ┌─────────────┐                                       │
│  │   SQLite    │ ← Events, Incidents, Actions, Audit   │
│  └─────────────┘                                       │
└─────────────────────────────────────────────────────────┘
```

## Detection Rules

Rules follow the SIGMA format with Sentinel extensions for response actions:

```yaml
id: ssh_brute_force
title: SSH Brute Force Detected
severity: high
status: active

logsource:
  category: auth
  product: linux

detection:
  selection:
    "raw|contains":
      - "Failed password"
      - "authentication failure"
  condition: selection

correlation:
  group_by: [source_ip]
  threshold: 5
  window: 5m

response:
  - type: block_ip
    target_field: source_ip
```

### Built-in Rules
| Rule | Severity | Description |
|------|----------|-------------|
| `ssh_brute_force` | High | SSH failed login threshold |
| `rdp_brute_force` | High | Windows RDP failed login threshold |
| `sqli_detection` | Critical | SQL injection patterns in web logs |
| `privilege_escalation` | Critical | Sudo abuse, privilege assignment |
| `path_traversal` | High | Directory traversal in web requests |
| `container_escape` | Critical | Docker socket mounting, nsenter |

## CLI Commands

```
sentinel init        Initialize config and database
sentinel run         Start the agent
sentinel status      Show health and queue status
sentinel rules list  List all detection rules
sentinel version     Print version
```

## Telegram Bot Commands

```
/status     Show agent health
/pending    List pending actions
/approve    Approve an action
/deny       Deny an action
/rollback   Rollback an executed action
/help       Show available commands
```

## Response Actions

| Action | Linux | Windows |
|--------|-------|---------|
| `block_ip` | iptables/ufw | New-NetFirewallRule |
| `disable_user` | usermod -L | Disable-LocalUser |
| `kill_process` | kill -9 | taskkill /F |
| `isolate_container` | docker network disconnect | docker network disconnect |

All actions support rollback within the configured window (default: 24h).

## Deployment

### Systemd (Linux)
```bash
sudo cp bin/sentinel /usr/local/bin/
sudo cp deployments/sentinel.service /etc/systemd/system/
sudo useradd -r -s /bin/false sentinel
sudo mkdir -p /opt/sentinel && sudo chown sentinel: /opt/sentinel
sudo systemctl enable --now sentinel
```

### Docker
```bash
docker-compose -f deployments/docker-compose.yml up -d
```

## Security Considerations

- WebUI binds to `127.0.0.1` by default — use a reverse proxy for remote access
- Change default admin credentials immediately after first login
- Telegram bot only responds to whitelisted `allowed_chats`
- `dry_run: true` is the safe default — test rules before enabling real responses
- All actions require approval unless `auto_approve: true` is set (not recommended)
- Comprehensive audit trail for accountability

## Development

```bash
make test          # Run tests
make lint          # Run linter  
make build-all     # Cross-compile for Linux + Windows
```

## License

MIT
