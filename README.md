# AI One Agent

Lightweight telemetry and management agent for the [AI One](https://aione.example.com) platform.

| Metric | Target |
|--------|--------|
| Binary size | ≤ 15 MB (stripped, CGO disabled) |
| Memory | 10–50 MB RSS |
| CPU | < 2% idle |
| Platforms | Linux, macOS, Windows (amd64 / arm64) |

---

## Architecture

```
cmd/agent/main.go
└─ internal/service.Agent          (orchestrator + kardianos/service)
   ├─ internal/registration        (install-token → mTLS cert issuance)
   ├─ internal/heartbeat           (30 s liveness pings)
   ├─ internal/transport           (mTLS HTTP client + WebSocket)
   ├─ internal/credentials         (cert/key lifecycle, 0600 on disk)
   ├─ internal/telemetry/
   │   ├─ snmp                     (SNMP v2c/v3 polling via gosnmp)
   │   ├─ syslog                   (UDP + TCP RFC 3164 receiver)
   │   ├─ wmi                      (Windows: PowerShell WQL queries)
   │   └─ api                      (REST endpoint scraping)
   ├─ internal/actions/
   │   ├─ validation               (HMAC-SHA256 + allowlist)
   │   └─ executor                 (run_command, restart_service, …)
   ├─ internal/buffer              (ring buffer, optional disk persistence)
   └─ internal/updater             (SHA-256 verified binary swap)
```

## Quick start

### Linux / macOS

```bash
curl -fsSL https://install.aione.example.com/agent | \
    AIONE_INSTALL_TOKEN=tok_xxx \
    AIONE_API_URL=https://api.aione.example.com \
    bash
```

### Windows (PowerShell, as Administrator)

```powershell
irm https://install.aione.example.com/agent.ps1 | iex
# Or with parameters:
.\scripts\install.ps1 -InstallToken "tok_xxx" -ApiUrl "https://api.aione.example.com"
```

### Docker

```bash
docker run -d \
  -v /etc/aione-agent:/etc/aione-agent:ro \
  -v /var/lib/aione-agent:/var/lib/aione-agent \
  shepherdtech/aione-agent:latest
```

---

## Configuration

Copy `configs/agent.yaml` to your config directory and edit:

```yaml
agent:
  install_token: "tok_xxx"   # one-time token — consumed at registration

api:
  base_url: "https://api.aione.example.com"
```

Environment variables are expanded with `${VAR}` syntax. The install token can
be supplied without touching the file:

```bash
AIONE_INSTALL_TOKEN=tok_xxx aione-agent -config /etc/aione-agent/agent.yaml
```

After the first successful registration the token is no longer needed — the
agent holds a short-lived mTLS certificate in `data_dir` instead.

---

## Building from source

```bash
git clone https://github.com/shepherdtech/aione-agent
cd aione-agent
go mod tidy
make build          # current platform
make build-all      # all platforms → dist/
make test
make lint           # requires golangci-lint
```

### Cross-compilation

```bash
GOOS=linux GOARCH=arm64 make build
```

---

## Service management

```bash
# Install as OS service (systemd / launchd / Windows SCM)
aione-agent -service install

# Control
aione-agent -service start
aione-agent -service stop
aione-agent -service status
aione-agent -service uninstall
```

---

## Telemetry collectors

| Collector | Protocol | Config key |
|-----------|----------|------------|
| SNMP | UDP 161 | `telemetry.snmp` |
| Syslog | UDP/TCP 514 | `telemetry.syslog` |
| WMI | PowerShell (Windows only) | `telemetry.wmi` |
| REST | HTTPS | `telemetry.api_collector` |

---

## Actions

The platform can push KAL actions via WebSocket. Each action is validated
with HMAC-SHA256 and checked against `actions.allowed_actions` before
execution.

| Type | Description | Required params |
|------|-------------|-----------------|
| `run_command` | Run a shell command | `command` |
| `restart_service` | Restart an OS service | `service` |
| `collect_diagnostics` | Gather system info | — |
| `apply_config` | Write a config file | `path`, `content` |

---

## Security model

- **Zero standing credentials**: the agent ships with no secrets. It registers
  once using a one-time install token and receives a short-lived mTLS
  certificate from the API.
- All API communication uses **TLS 1.3 + mutual authentication**.
- Action requests are validated with an **HMAC-SHA256** signature.
- The credential files are stored with **0600** permissions.
- The binary update is verified with **SHA-256** before the swap.

---

## Development

```bash
# Run interactively with pretty logs
AIONE_INSTALL_TOKEN=tok_xxx \
AIONE_API_URL=https://api.aione.example.com \
go run ./cmd/agent -config configs/agent.yaml
```

Set `log.pretty: true` in config for readable console output during development.

---

## License

Copyright © Shepherd Technology. All rights reserved.
