#!/usr/bin/env bash
# install.sh — AI One agent installer (Linux + macOS)
#
# Usage:
#   curl -sSL https://install.getroja.ai/install.sh | sudo bash -s -- --token=<tok>
#
# Flags:
#   --token=<str>        REQUIRED. Install token from the Roja chat UI.
#   --version=<vX.Y.Z>   OPTIONAL. Defaults to the latest release.
#   --backend=<url>      OPTIONAL. Defaults to the baked-in production URL.
#   --name=<str>         OPTIONAL. Defaults to the machine hostname.
#   --no-start           OPTIONAL. Install the service but don't start it.
#
# Exits non-zero on any failure; safe to re-run (idempotent installs).

set -euo pipefail

# --- defaults ---------------------------------------------------------------
TOKEN=""
VERSION=""
BACKEND="https://aione-dev-api.icyground-7b27426e.centralus.azurecontainerapps.io"
NAME="$(hostname)"
NO_START=false
REPO="rgshepherd21/aione-agent"

# --- arg parsing ------------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        --token=*)   TOKEN="${1#*=}";   shift ;;
        --token)     TOKEN="$2";        shift 2 ;;
        --version=*) VERSION="${1#*=}"; shift ;;
        --version)   VERSION="$2";      shift 2 ;;
        --backend=*) BACKEND="${1#*=}"; shift ;;
        --backend)   BACKEND="$2";      shift 2 ;;
        --name=*)    NAME="${1#*=}";    shift ;;
        --name)      NAME="$2";         shift 2 ;;
        --no-start)  NO_START=true;     shift ;;
        -h|--help)
            sed -n '2,13p' "$0"; exit 0 ;;
        *)
            echo "ERROR: unknown argument: $1" >&2; exit 2 ;;
    esac
done

[ -n "$TOKEN" ]      || { echo "ERROR: --token is required" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo "ERROR: must run as root (use sudo)" >&2; exit 2; }

# --- OS + arch detection ----------------------------------------------------
case "$(uname -s)" in
    Linux)  OS="linux" ;;
    Darwin) OS="darwin" ;;
    *)      echo "ERROR: unsupported OS: $(uname -s)" >&2; exit 2 ;;
esac
case "$(uname -m)" in
    x86_64)          ARCH="amd64" ;;
    aarch64|arm64)   ARCH="arm64" ;;
    *)               echo "ERROR: unsupported arch: $(uname -m)" >&2; exit 2 ;;
esac

# --- resolve version --------------------------------------------------------
if [ -z "$VERSION" ]; then
    VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep '"tag_name":' | head -1 | cut -d'"' -f4)"
    [ -n "$VERSION" ] || { echo "ERROR: could not resolve latest version" >&2; exit 1; }
fi

echo ">>> Installing aione-agent ${VERSION} for ${OS}-${ARCH}"

# --- paths ------------------------------------------------------------------
if [ "$OS" = "linux" ]; then
    INSTALL_DIR="/opt/aione-agent"
    CONFIG_DIR="/etc/aione-agent"
    DATA_DIR="/var/lib/aione-agent"
else
    INSTALL_DIR="/usr/local/opt/aione-agent"
    CONFIG_DIR="/usr/local/etc/aione-agent"
    DATA_DIR="/usr/local/var/aione-agent"
fi

BINARY_NAME="aione-agent-${VERSION}-${OS}-${ARCH}"
BINARY_URL="https://github.com/${REPO}/releases/download/${VERSION}/${BINARY_NAME}"
CHECKSUM_URL="${BINARY_URL}.sha256"

# --- download + verify ------------------------------------------------------
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

echo ">>> Downloading ${BINARY_NAME}"
curl -fsSL -o "${TMPDIR}/agent" "$BINARY_URL"
curl -fsSL -o "${TMPDIR}/agent.sha256" "$CHECKSUM_URL"

EXPECTED="$(awk '{print $1}' "${TMPDIR}/agent.sha256")"
if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL="$(sha256sum "${TMPDIR}/agent" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
    ACTUAL="$(shasum -a 256 "${TMPDIR}/agent" | awk '{print $1}')"
else
    echo "ERROR: neither sha256sum nor shasum available" >&2; exit 1
fi
if [ "$EXPECTED" != "$ACTUAL" ]; then
    echo "ERROR: checksum mismatch" >&2
    echo "  expected: $EXPECTED" >&2
    echo "  actual:   $ACTUAL" >&2
    exit 1
fi
echo "    ✓ checksum verified"

# macOS quarantine clear (unsigned alpha binaries get flagged otherwise)
if [ "$OS" = "darwin" ]; then
    xattr -rd com.apple.quarantine "${TMPDIR}/agent" 2>/dev/null || true
fi

# --- install ---------------------------------------------------------------
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$DATA_DIR"
mv "${TMPDIR}/agent" "${INSTALL_DIR}/aione-agent"
chmod 755 "${INSTALL_DIR}/aione-agent"
chmod 755 "$DATA_DIR"

# Write config. install_token is env-substituted at first run; the systemd
# unit the agent writes via -service install captures env vars present at
# install time, so we export the token only for the install invocation.
cat > "${CONFIG_DIR}/agent.yaml" <<EOF
agent:
  name: "${NAME}"
  install_token: "\$AIONE_INSTALL_TOKEN"
  data_dir: "${DATA_DIR}"
  heartbeat: 30s

api:
  base_url: ${BACKEND}
  timeout: 30s
  retry_max: 5
  retry_delay: 5s

transport:
  insecure_skip_verify: false

log:
  level: info
  pretty: false
EOF
chmod 644 "${CONFIG_DIR}/agent.yaml"

# --- register as a system service ------------------------------------------
echo ">>> Installing system service"
AIONE_INSTALL_TOKEN="$TOKEN" \
    "${INSTALL_DIR}/aione-agent" \
    -service install \
    -config "${CONFIG_DIR}/agent.yaml"

if [ "$NO_START" = false ]; then
    if [ "$OS" = "linux" ]; then
        systemctl daemon-reload
        systemctl enable aione-agent >/dev/null
        systemctl start aione-agent
        sleep 2
        if systemctl is-active --quiet aione-agent; then
            echo "    ✓ service started"
        else
            echo "WARN: service did not reach active state; check journalctl -u aione-agent" >&2
        fi
    else
        echo "    (macOS: launchd unit installed; start with launchctl if needed)"
    fi
fi

cat <<EOF

✓ aione-agent ${VERSION} installed
  binary:  ${INSTALL_DIR}/aione-agent
  config:  ${CONFIG_DIR}/agent.yaml
  data:    ${DATA_DIR}

EOF

if [ "$NO_START" = false ]; then
    echo "Check the Roja chat UI — the new host should appear within 30 s."
else
    echo "Service installed but NOT started. Start with: sudo systemctl start aione-agent"
fi
