# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

**XPFarm** is a Go-based vulnerability scanner that wraps 10+ open-source security tools (Subfinder, Naabu, Httpx, Nuclei, Nmap, CVEMap, Gowitness, Katana, URLFinder, Wappalyzer) behind a unified web UI on port `:8888`. It also ships an AI binary/malware analysis agent called **Overlord**, backed by OpenCode running in a separate Docker container on port `:3000`.

## Build & Run Commands

```bash
# Full stack (recommended for development)
./xpfarm.sh build          # Build Docker containers
./xpfarm.sh up             # Start full stack (xpfarm + overlord + optional mobsf)
./xpfarm.sh down           # Stop containers

# Go only (skips Overlord, faster iteration)
./xpfarm.sh onlyGo         # Compile and run binary natively
./xpfarm.sh onlyGo -debug  # Same with debug logging + Gin debug mode

# Direct Go build
go build -o xpfarm main.go
```

There are no automated tests or linting configurations in this project.

## Architecture

### Entry Point & Startup Sequence (`main.go`)
1. Parse flags (`-debug`)
2. Initialize SQLite database (WAL mode, single connection, 30s timeout, 64MB cache)
3. Register 10 tool modules via the module registry
4. Health-check + auto-install missing tools
5. Index Nuclei templates in background goroutine
6. Start Gin web server on `:8888`

### Internal Package Layout

| Package | Role |
|---|---|
| `internal/core/` | 8-stage scan pipeline (`manager.go`), target resolution, Nuclei template plan engine, global search |
| `internal/database/` | SQLite models via GORM — 11 tables |
| `internal/modules/` | Pluggable tool wrappers + registry |
| `internal/ui/` | Gin server, REST API, embedded HTML templates |
| `internal/overlord/` | Reverse proxy to OpenCode serve API + SSE streaming |
| `internal/notifications/` | Discord & Telegram callbacks on scan lifecycle |
| `pkg/utils/` | Logger, Cloudflare IP detector, binary resolver, target helpers |

### 8-Stage Scan Pipeline (`internal/core/manager.go`)

```
1. Subfinder       → subdomain enumeration
2. Filter & Save   → resolve, Cloudflare/localhost check, alive status
3. Naabu           → port scanning (5-worker pool via Go channels)
4. Nmap            → service/version detection
5. Httpx           → HTTP probing + metadata
6. Parallel Web    → Gowitness (screenshots) + Katana (crawl) + URLFinder + Wappalyzer
7. CVEMap          → CVE lookup by detected product/version
8. Nuclei          → vuln scanning with smart template plan engine
```

### Database Domain Model

```
Asset
  └── Target (IP / domain / URL / CIDR)
        ├── Port         (service, product, version)
        ├── WebAsset     (URL, title, tech stack, screenshot, Katana output)
        ├── Vulnerability (Nuclei findings)
        ├── CVE          (CVSS, EPSS, KEV)
        └── ScanResult   (raw tool output)

ScanProfile    — per-asset feature toggles (port/web/vuln scope)
NucleiTemplate — indexed templates with version tracking
SavedSearch    — user regex-based search presets
Setting        — key-value config store
```

**Critical:** SQLite is configured with a single writer connection to prevent "database is locked" errors during concurrent scans. Never open additional write connections.

### Module Interface

Every tool wrapper in `internal/modules/` implements:

```go
Name() string
Description() string
CheckInstalled() bool
Install() error
Run(ctx context.Context, target string) (string, error)
```

New tools must be registered in the module registry and will be auto-installed on startup if missing.

### Overlord (AI Agent)

Overlord is a separate Docker service running OpenCode with 15+ specialized agents (binary RE, APK analysis, web, etc.) plus 70+ tools (radare2, Frida, binwalk, angr, etc.). The Go app proxies `/api/overlord/*` requests and SSE streams to it. The `overlord/` directory contains the Dockerfile, agent definitions (`overlord/agents/`), and TypeScript tools (`overlord/tools/`).

### Embedded Assets

Web UI templates and static files are embedded into the Go binary via `//go:embed`. When modifying templates in `internal/ui/templates/` or static files, rebuild the binary to pick up changes.

### Notifications

`ScanManager` accepts `SetOnStart` / `SetOnStop` callbacks. Discord and Telegram bots hook into these. Credentials come from the `settings` DB table (configured via the Settings UI page).

## Docker Compose Services

| Service | Port | Purpose |
|---|---|---|
| `xpfarm` | 8888 | Main Go app |
| `overlord` | 3000 | OpenCode AI agent (binary/malware analysis) |
| `mobsf` | 8000 | Mobile Security Framework (optional profile) |

Persistent volumes: `data/`, `screenshots/`, `overlord/binaries/`, `overlord/output/`, `overlord/config/`

## Key Flags

- `-debug` — enables verbose logging and Gin debug mode
- `-up` — runs `projectdiscovery` tool updates on startup
