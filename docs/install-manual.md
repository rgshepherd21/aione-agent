# Installing the AI One agent — manual / advanced

**Most users should use the one-liner from the Roja chat UI's "Add host" card** — this document is the fallback for when the scripted installer isn't an option (air-gapped hosts, custom distros, troubleshooting).

---

## Primary path (scripted one-liner)

From the Roja chat UI, click **Add host**, pick your OS, copy the one-liner, paste into a root shell on the target.

```bash
# Linux / macOS
curl -sSL https://install.getroja.ai/install.sh | sudo bash -s -- --token=<tok>
```

```powershell
# Windows (admin PowerShell)
iex "& { $(irm https://install.getroja.ai/install.ps1) } -Token <tok>"
```

The scripts at [`install/install.sh`](../install/install.sh) and [`install/install.ps1`](../install/install.ps1) detect OS/arch, pull the right release binary from GitHub, verify SHA-256, write a config, install the system service, and start it. Takes ~15 seconds on a warm network.

---

## Manual install (fallback)

Use this if the scripted path fails or you need to audit every step before running.

### 1. Download + verify

Pick the release and binary for your OS/arch from <https://github.com/rgshepherd21/aione-agent/releases>. Each release ships four binaries:

| OS      | Arch     | File                                      |
|---------|----------|-------------------------------------------|
| Linux   | x86_64   | `aione-agent-vX.Y.Z-linux-amd64`          |
| Linux   | ARM64    | `aione-agent-vX.Y.Z-linux-arm64`          |
| Windows | x86_64   | `aione-agent-vX.Y.Z-windows-amd64.exe`    |
| macOS   | Apple Si | `aione-agent-vX.Y.Z-darwin-arm64`         |

Each binary has a matching `.sha256` file. **Verify before running.** Alpha binaries are not code-signed; SmartScreen may warn on first run.

### 2. Install to canonical paths

**Linux** (adjust for macOS: `/usr/local/opt`, `/usr/local/etc`, `/usr/local/var`):
```bash
sudo mkdir -p /opt/aione-agent /etc/aione-agent /var/lib/aione-agent
sudo mv aione-agent-* /opt/aione-agent/aione-agent
sudo chmod 755 /opt/aione-agent/aione-agent
```

**Windows**:
```powershell
New-Item -ItemType Directory "C:\Program Files\AIOne\Agent",
    "C:\ProgramData\AIOne\Agent\data" -Force
Move-Item aione-agent-*.exe "C:\Program Files\AIOne\Agent\aione-agent.exe"
```

### 3. Write config

At `/etc/aione-agent/agent.yaml` (Linux) or `C:\ProgramData\AIOne\Agent\agent.yaml` (Windows):

```yaml
agent:
  name: my-host-01                       # shows up in the chat UI
  install_token: "$AIONE_INSTALL_TOKEN"  # env-substituted at first run
  data_dir: /var/lib/aione-agent         # or C:\ProgramData\AIOne\Agent\data
  heartbeat: 30s

api:
  base_url: https://<your-backend-url>

transport:
  insecure_skip_verify: false

log:
  level: info
  pretty: false
```

### 4. Install as a system service

The agent binary has the service installer built in (uses `kardianos/service`):

```bash
# Linux / macOS
sudo AIONE_INSTALL_TOKEN="<your-token>" /opt/aione-agent/aione-agent \
  -service install -config /etc/aione-agent/agent.yaml
sudo systemctl daemon-reload
sudo systemctl enable --now aione-agent
```

```powershell
# Windows
$env:AIONE_INSTALL_TOKEN = "<your-token>"
& "C:\Program Files\AIOne\Agent\aione-agent.exe" `
    -service install -config "C:\ProgramData\AIOne\Agent\agent.yaml"
Start-Service aione-agent
```

### 5. Verify

```bash
sudo systemctl status aione-agent --no-pager
sudo journalctl -u aione-agent -n 30 --no-pager
```

Expected log lines, in order: `registering agent` → `registration successful agent_id=...` → `agent running` → `heartbeat sent pending_commands=0` (repeating every 30 s).

`ws dial (HTTP 403)` warnings are expected during alpha — the agent falls back to HTTP polling, commands still flow.

---

## Config reference

Required: `agent.name`, `agent.install_token`, `agent.data_dir`, `api.base_url`.

Optional:

| Field                          | Default | Notes                                             |
|--------------------------------|---------|---------------------------------------------------|
| `agent.heartbeat`              | `30s`   | Don't go below `15s`                              |
| `agent.tags`                   | `[]`    | String list for grouping in the UI                |
| `transport.insecure_skip_verify` | `false` | Only for dev against a self-signed backend        |
| `actions.hmac_secret`          | (empty) | Enables per-action HMAC verify if set             |
| `log.level`                    | `info`  | `debug` / `info` / `warn` / `error`               |
| `log.pretty`                   | `false` | Pretty-printed logs (dev only)                    |

---

## Troubleshooting

**`install_token required for first-time registration`**: the `AIONE_INSTALL_TOKEN` env var wasn't visible to the process that ran `-service install`. Either bake the token directly into `agent.yaml` (not recommended) or export it in the shell before re-running the install.

**Agent registers but no commands flow**: confirm outbound HTTPS to the backend works: `curl -v https://<backend>/health`. The WS 403 warnings are benign; the HTTP-poll heartbeat path delivers commands. If heartbeats succeed but `pending_commands` stays at 0, the issue is server-side (check with the Roja team).

**Windows SmartScreen blocks the binary**: click **More info** → **Run anyway**. If EDR/AV quarantines it, add `aione-agent.exe` to the allowlist. Authenticode signing lands in Phase B.

**Linux `ErrBothLinuxFlushersMissing`**: the DNS cache flush action needs one of `/usr/bin/resolvectl` or `/usr/bin/systemd-resolve`. Minimal container/NixOS installs lack these — `apt install systemd-resolved` on Debian/Ubuntu.

**Agent host doesn't appear in the chat UI**: the tenant ID in the install token must match the tenant you're viewing. Confirm with the tenant admin who minted the token.

---

## Uninstall

### Linux
```bash
sudo systemctl stop aione-agent
sudo /opt/aione-agent/aione-agent -service uninstall
sudo rm -rf /opt/aione-agent /etc/aione-agent /var/lib/aione-agent
```

### Windows
```powershell
Stop-Service aione-agent
& "C:\Program Files\AIOne\Agent\aione-agent.exe" -service uninstall
Remove-Item -Recurse "C:\Program Files\AIOne\Agent", "C:\ProgramData\AIOne\Agent"
```

### macOS
```bash
sudo launchctl unload /Library/LaunchDaemons/aione-agent.plist 2>/dev/null || true
sudo /usr/local/opt/aione-agent/aione-agent -service uninstall
sudo rm -rf /usr/local/opt/aione-agent /usr/local/etc/aione-agent
```

---

## Reporting issues

File at <https://github.com/rgshepherd21/aione-agent/issues> with:

- Agent version (`aione-agent -version`)
- OS + arch (`uname -a` or `systeminfo`)
- Last ~50 log lines (redact install tokens)
- Install method (scripted one-liner vs manual)

Security issues: email the maintainer directly — do not file publicly.
