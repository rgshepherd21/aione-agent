#!/usr/bin/env bash
# AI One Agent installer for Linux and macOS
# Usage:
#   curl -fsSL https://install.aione.example.com/agent | \
#       AIONE_INSTALL_TOKEN=<token> AIONE_API_URL=<url> bash
set -euo pipefail

AGENT_VERSION="${AIONE_AGENT_VERSION:-latest}"
INSTALL_TOKEN="${AIONE_INSTALL_TOKEN:?AIONE_INSTALL_TOKEN is required}"
API_URL="${AIONE_API_URL:?AIONE_API_URL is required}"
INSTALL_DIR="${AIONE_INSTALL_DIR:-/usr/local/bin}"
CONFIG_DIR="${AIONE_CONFIG_DIR:-/etc/aione-agent}"
DATA_DIR="${AIONE_DATA_DIR:-/var/lib/aione-agent}"
SERVICE_USER="${AIONE_SERVICE_USER:-aione-agent}"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64)  ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
    armv7l)  ARCH="arm"   ;;
    *)       echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

DOWNLOAD_URL="https://releases.aione.example.com/agent/${AGENT_VERSION}/aione-agent_${OS}_${ARCH}"

echo "==> Installing AI One Agent"
echo "    OS/arch:  ${OS}/${ARCH}"
echo "    Version:  ${AGENT_VERSION}"
echo "    API URL:  ${API_URL}"

# --- Download binary -------------------------------------------------------
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

echo "==> Downloading from ${DOWNLOAD_URL}"
curl -fsSL --retry 3 "${DOWNLOAD_URL}" -o "$TMP"
curl -fsSL --retry 3 "${DOWNLOAD_URL}.sha256" -o "${TMP}.sha256"

EXPECTED="$(awk '{print $1}' "${TMP}.sha256")"
ACTUAL="$(sha256sum "$TMP" | awk '{print $1}')"
if [ "$EXPECTED" != "$ACTUAL" ]; then
    echo "ERROR: checksum mismatch (expected $EXPECTED, got $ACTUAL)" >&2
    exit 1
fi

chmod 755 "$TMP"
install -m 755 "$TMP" "${INSTALL_DIR}/aione-agent"
echo "==> Binary installed to ${INSTALL_DIR}/aione-agent"

# --- Create service user ---------------------------------------------------
if ! id -u "$SERVICE_USER" &>/dev/null; then
    useradd --system --no-create-home --shell /sbin/nologin "$SERVICE_USER"
    echo "==> Created system user: ${SERVICE_USER}"
fi

# --- Directories -----------------------------------------------------------
install -d -m 750 -o "$SERVICE_USER" "$DATA_DIR"
install -d -m 755 "$CONFIG_DIR"

# --- Write config ----------------------------------------------------------
if [ ! -f "${CONFIG_DIR}/agent.yaml" ]; then
    cat > "${CONFIG_DIR}/agent.yaml" <<YAML
agent:
  name: "$(hostname -s)"
  install_token: "${INSTALL_TOKEN}"
  data_dir: ${DATA_DIR}
  heartbeat: 30s

api:
  base_url: "${API_URL}"
  timeout: 30s
  retry_max: 5
  retry_delay: 5s

transport:
  insecure_skip_verify: false

telemetry:
  syslog:
    enabled: false
  snmp:
    enabled: false
  wmi:
    enabled: false
  api_collector:
    enabled: false

actions:
  enabled: true
  max_concurrent: 5
  timeout: 5m
  allowed_actions:
    - run_command
    - restart_service
    - collect_diagnostics
    - apply_config

buffer:
  enabled: true
  max_size: 10000

updater:
  enabled: true
  channel: stable
  interval: 6h

log:
  level: info
YAML
    chmod 640 "${CONFIG_DIR}/agent.yaml"
    chown "$SERVICE_USER" "${CONFIG_DIR}/agent.yaml"
    echo "==> Config written to ${CONFIG_DIR}/agent.yaml"
fi

# --- systemd service -------------------------------------------------------
if command -v systemctl &>/dev/null; then
    cat > /etc/systemd/system/aione-agent.service <<UNIT
[Unit]
Description=AI One Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
ExecStart=${INSTALL_DIR}/aione-agent -config ${CONFIG_DIR}/agent.yaml
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
LimitNOFILE=65536

# Hardening
PrivateTmp=true
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=${DATA_DIR}

[Install]
WantedBy=multi-user.target
UNIT

    systemctl daemon-reload
    systemctl enable --now aione-agent
    echo "==> Service enabled and started"
    echo "    View logs: journalctl -u aione-agent -f"

elif command -v launchctl &>/dev/null; then
    # macOS launchd
    PLIST="/Library/LaunchDaemons/com.aione.agent.plist"
    cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>             <string>com.aione.agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>${INSTALL_DIR}/aione-agent</string>
    <string>-config</string>
    <string>${CONFIG_DIR}/agent.yaml</string>
  </array>
  <key>UserName</key>          <string>${SERVICE_USER}</string>
  <key>RunAtLoad</key>         <true/>
  <key>KeepAlive</key>         <true/>
  <key>StandardErrorPath</key> <string>/var/log/aione-agent.log</string>
  <key>StandardOutPath</key>   <string>/var/log/aione-agent.log</string>
</dict>
</plist>
PLIST
    launchctl load -w "$PLIST"
    echo "==> LaunchDaemon loaded"
else
    echo "WARNING: No service manager found. Run manually:"
    echo "  ${INSTALL_DIR}/aione-agent -config ${CONFIG_DIR}/agent.yaml"
fi

echo ""
echo "==> AI One Agent installation complete."
