# Sentinel - Blue Team Defensive Agent

## Project Overview
Sentinel is a cross-platform security monitoring agent built in Go with an htmx WebUI and Telegram bot integration. It watches system logs in real-time, detects threats using SIGMA-compatible rules, and orchestrates semi-automated defensive responses.

## Architecture
- **Core Agent** (Go): Log collection, detection engine, response orchestrator
- **WebUI** (htmx + Go templates): Dashboard, approval queue, rule management
- **Telegram Bot** (Go, telegram-bot-api): Real-time alerts and approval workflow
- **Storage**: SQLite (default), PostgreSQL option for scale

## Key Directories
- `/cmd/sentinel/` — Main binary entry point and CLI
- `/internal/` — Core packages (engine, platform, gateway, storage, etc.)
- `/rules/` — SIGMA-compatible YAML detection rules
- `/web/` — HTML templates and static assets
- `/deployments/` — Dockerfile, systemd unit, docker-compose

## Development Guidelines
- Use Go idioms: interfaces, error wrapping, structured logging
- Build tags for platform-specific code (`//go:build linux`, `//go:build windows`)
- All response actions require approval unless explicitly configured otherwise
- Detection rules follow SIGMA format with sentinel extensions
- WebUI uses htmx for reactivity, no JavaScript frameworks
