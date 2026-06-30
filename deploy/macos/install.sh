#!/bin/bash
# ═══════════════════════════════════════════════════════════════════
# AMOSKYS Enterprise Installer for macOS
# ═══════════════════════════════════════════════════════════════════
#
# Installs AMOSKYS as a system-level security service.
#
# Usage:
#   sudo bash install.sh                    # Interactive install
#   sudo bash install.sh --silent           # Silent (MDM-compatible)
#   sudo bash install.sh --uninstall        # Remove AMOSKYS
#
# Installs to:
#   /Library/Amoskys/                       # Engine, venv, config
#   /Library/LaunchDaemons/com.amoskys.*    # System-level services
#   /var/log/amoskys/                       # Logs
#   /var/lib/amoskys/                       # Data (telemetry, queues)
#
# Requirements:
#   - macOS 13+ (Ventura or later)
#   - Python 3.11+ (bundled or system)
#   - Root access (sudo)
#
# ═══════════════════════════════════════════════════════════════════

set -euo pipefail

# ── Configuration ──
INSTALL_DIR="/Library/Amoskys"
DATA_DIR="/var/lib/amoskys"
LOG_DIR="/var/log/amoskys"
VENV_DIR="$INSTALL_DIR/venv"
SRC_DIR="$INSTALL_DIR/src"
CERT_DIR="$INSTALL_DIR/certs"
CONFIG_DIR="$INSTALL_DIR/config"
SERVICE_USER="_amoskys"
SERVICE_GROUP="staff"
DAEMON_LABEL="com.amoskys.agent"
VERSION="0.9.1-beta"
SILENT=false
UNINSTALL=false
DEPLOY_TOKEN=""
AMOSKYS_SERVER=""
DOWNLOAD_ID=""

# ── Colors ──
RED='\033[91m'
GREEN='\033[92m'
YELLOW='\033[93m'
BLUE='\033[94m'
BOLD='\033[1m'
RESET='\033[0m'

log()  { echo -e "${GREEN}[AMOSKYS]${RESET} $*"; }
warn() { echo -e "${YELLOW}[WARN]${RESET} $*"; }
err()  { echo -e "${RED}[ERROR]${RESET} $*" >&2; }

# ── Parse Arguments ──
for arg in "$@"; do
    case "$arg" in
        --silent) SILENT=true ;;
        --uninstall) UNINSTALL=true ;;
        --token=*) DEPLOY_TOKEN="${arg#--token=}" ;;
        --server=*) AMOSKYS_SERVER="${arg#--server=}" ;;
        --download-id=*) DOWNLOAD_ID="${arg#--download-id=}" ;;
    esac
done

# ── Fetch config from server via download ID ──
# When downloaded from amoskys.com, the download_id maps to token + server.
if [[ -n "$DOWNLOAD_ID" && (-z "$DEPLOY_TOKEN" || -z "$AMOSKYS_SERVER") ]]; then
    CONFIG_URL="https://amoskys.com/dashboard/api/agents/deploy/config/${DOWNLOAD_ID}"
    log "Fetching config from server..."
    CONFIG_RESP=$(curl -fsSL --max-time 10 "$CONFIG_URL" 2>/dev/null || echo "")
    if [[ -n "$CONFIG_RESP" ]]; then
        while IFS='=' read -r key value; do
            case "$key" in
                token) [[ -z "$DEPLOY_TOKEN" ]] && DEPLOY_TOKEN="$value" ;;
                server) [[ -z "$AMOSKYS_SERVER" ]] && AMOSKYS_SERVER="$value" ;;
            esac
        done <<< "$CONFIG_RESP"
        log "Config received from server"
    else
        warn "Could not fetch config from server (download may have expired)"
    fi
fi

# ── Auto-discover .amoskys-config (from .zip download — fallback) ──
# When downloaded as a .zip, the config file sits next to the .pkg in ~/Downloads.
# The macOS installer runs postinstall as root, so we check the invoking user's Downloads.
if [[ -z "$DEPLOY_TOKEN" || -z "$AMOSKYS_SERVER" ]]; then
    # Find the real user (not root) who ran the installer
    REAL_USER="${SUDO_USER:-$(stat -f '%Su' /dev/console 2>/dev/null || echo '')}"
    REAL_HOME=$(eval echo "~${REAL_USER}" 2>/dev/null || echo "")

    # Search for .amoskys-config in likely locations
    for config_path in \
        "${REAL_HOME}/Downloads/.amoskys-config" \
        "${REAL_HOME}/Desktop/.amoskys-config" \
        "/tmp/.amoskys-config" \
        "${REAL_HOME}/.amoskys-config"; do
        if [[ -f "$config_path" ]]; then
            log "Found config: $config_path"
            # Read token and server from config (simple KEY=VALUE format)
            while IFS='=' read -r key value; do
                case "$key" in
                    token) [[ -z "$DEPLOY_TOKEN" ]] && DEPLOY_TOKEN="$value" ;;
                    server) [[ -z "$AMOSKYS_SERVER" ]] && AMOSKYS_SERVER="$value" ;;
                esac
            done < "$config_path"
            # Clean up the config file (one-time use)
            rm -f "$config_path"
            break
        fi
    done
fi

# ── Root Check ──
if [[ $EUID -ne 0 ]]; then
    err "This installer must be run as root (sudo)."
    exit 1
fi

# ── Uninstall ──
if $UNINSTALL; then
    log "Uninstalling AMOSKYS..."
    launchctl unload /Library/LaunchDaemons/${DAEMON_LABEL}.plist 2>/dev/null || true
    launchctl unload /Library/LaunchDaemons/com.amoskys.watchdog.plist 2>/dev/null || true
    rm -f /Library/LaunchDaemons/com.amoskys.*.plist
    rm -rf "$INSTALL_DIR"
    # Keep data and logs for forensic purposes
    log "Removed $INSTALL_DIR and LaunchDaemons"
    log "Data preserved at $DATA_DIR (remove manually if desired)"
    log "Logs preserved at $LOG_DIR"
    log "AMOSKYS uninstalled."
    exit 0
fi

# ── Pre-flight Checks ──
log "AMOSKYS Enterprise Installer v${VERSION}"
log "Target: $(sw_vers -productName) $(sw_vers -productVersion) ($(uname -m))"

# Check macOS version
MACOS_MAJOR=$(sw_vers -productVersion | cut -d. -f1)
if [[ "$MACOS_MAJOR" -lt 13 ]]; then
    err "macOS 13 (Ventura) or later required. Found: $(sw_vers -productVersion)"
    exit 1
fi

# Find Python 3.11+
PYTHON=""
for candidate in python3.13 python3.12 python3.11 python3; do
    if command -v "$candidate" &>/dev/null; then
        PY_VER=$("$candidate" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null)
        PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
        PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)
        if [[ "$PY_MAJOR" -ge 3 && "$PY_MINOR" -ge 11 ]]; then
            PYTHON=$(command -v "$candidate")
            break
        fi
    fi
done

if [[ -z "$PYTHON" ]]; then
    err "Python 3.11+ not found. Install via: brew install python@3.13"
    exit 1
fi
log "Python: $PYTHON ($PY_VER)"

# ── Detect Source ──
# Find the AMOSKYS source tree (where this script lives)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# Go up from deploy/macos/ to project root
if [[ -f "$SCRIPT_DIR/../../pyproject.toml" ]]; then
    SOURCE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
elif [[ -f "$SCRIPT_DIR/pyproject.toml" ]]; then
    SOURCE_DIR="$SCRIPT_DIR"
else
    err "Cannot find AMOSKYS source tree. Run from the project directory."
    exit 1
fi
log "Source: $SOURCE_DIR"

# ── Create Directory Structure ──
log "Creating directory structure..."
mkdir -p "$INSTALL_DIR"/{venv,config}
mkdir -p "$DATA_DIR"/{queue,intel/baselines,intel/models,geoip,heartbeats,pids}
mkdir -p "$LOG_DIR"
mkdir -p "$CERT_DIR"

# ── Copy Source ──
log "Installing AMOSKYS source..."
rsync -a --delete \
    --exclude='.venv' --exclude='__pycache__' --exclude='*.pyc' \
    --exclude='.git' --exclude='data' --exclude='logs' \
    --exclude='*.db' --exclude='kali' \
    "$SOURCE_DIR/src/" "$SRC_DIR/"

# Copy web app
rsync -a --delete \
    --exclude='__pycache__' --exclude='*.pyc' \
    "$SOURCE_DIR/web/" "$INSTALL_DIR/web/"

# Copy requirements and config
cp "$SOURCE_DIR/requirements.txt" "$INSTALL_DIR/"
cp "$SOURCE_DIR/pyproject.toml" "$INSTALL_DIR/"

# Copy GeoIP databases if available
if [[ -d "$SOURCE_DIR/data/geoip" ]]; then
    cp "$SOURCE_DIR/data/geoip/"*.mmdb "$DATA_DIR/geoip/" 2>/dev/null || true
fi

# Copy detection rules
if [[ -d "$SOURCE_DIR/src/amoskys/detection/rules" ]]; then
    mkdir -p "$SRC_DIR/amoskys/detection/rules"
    rsync -a "$SOURCE_DIR/src/amoskys/detection/rules/" "$SRC_DIR/amoskys/detection/rules/"
fi

# ── Create Virtual Environment ──
log "Creating Python virtual environment..."
"$PYTHON" -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --upgrade pip -q
log "Installing dependencies (this may take 2-3 minutes)..."
"$VENV_DIR/bin/pip" install -r "$INSTALL_DIR/requirements.txt" -q

# ── Generate Certificates ──
if [[ ! -f "$CERT_DIR/agent.ed25519" ]]; then
    log "Generating Ed25519 signing key..."
    "$VENV_DIR/bin/python3" -c "
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
key = Ed25519PrivateKey.generate()
private_bytes = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
public_bytes = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
open('$CERT_DIR/agent.ed25519', 'wb').write(private_bytes)
open('$CERT_DIR/agent.ed25519.pub', 'wb').write(public_bytes)
"
    chmod 600 "$CERT_DIR/agent.ed25519"
fi

# ── Generate Config ──
SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
cat > "$CONFIG_DIR/amoskys.env" << ENVEOF
# AMOSKYS Configuration
AMOSKYS_HOME=$INSTALL_DIR
AMOSKYS_DATA=$DATA_DIR
AMOSKYS_LOGS=$LOG_DIR
PYTHONPATH=$SRC_DIR
SECRET_KEY=$SECRET_KEY
LOGIN_DISABLED=true
FLASK_PORT=5003
FORCE_HTTPS=false
ENVEOF

# Append server + token if provided (enables fleet shipping)
if [[ -n "$AMOSKYS_SERVER" ]]; then
    echo "AMOSKYS_SERVER=$AMOSKYS_SERVER" >> "$CONFIG_DIR/amoskys.env"
    log "Fleet shipping enabled → $AMOSKYS_SERVER"
fi
if [[ -n "$DEPLOY_TOKEN" ]]; then
    echo "AMOSKYS_DEPLOY_TOKEN=$DEPLOY_TOKEN" >> "$CONFIG_DIR/amoskys.env"
    log "Deployment token configured"
fi

# ── Create Wrapper Script ──
cat > "$INSTALL_DIR/bin/amoskys-watchdog" << 'WDEOF'
#!/bin/bash
# AMOSKYS Watchdog Launcher
set -a
source /Library/Amoskys/config/amoskys.env
set +a
cd /var/lib/amoskys
exec /Library/Amoskys/venv/bin/python3 -m amoskys.watchdog "$@"
WDEOF
chmod +x "$INSTALL_DIR/bin/amoskys-watchdog"

mkdir -p "$INSTALL_DIR/bin"
cat > "$INSTALL_DIR/bin/amoskys" << 'CLIEOF'
#!/bin/bash
# AMOSKYS CLI
set -a
source /Library/Amoskys/config/amoskys.env
set +a
cd /var/lib/amoskys
exec /Library/Amoskys/venv/bin/python3 -m amoskys "$@"
CLIEOF
chmod +x "$INSTALL_DIR/bin/amoskys"

# Symlink to /usr/local/bin for PATH access
ln -sf "$INSTALL_DIR/bin/amoskys" /usr/local/bin/amoskys 2>/dev/null || true

# ── Create LaunchDaemon ──
log "Installing LaunchDaemon..."
cat > /Library/LaunchDaemons/com.amoskys.watchdog.plist << PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.amoskys.watchdog</string>

    <key>ProgramArguments</key>
    <array>
        <string>${INSTALL_DIR}/bin/amoskys-watchdog</string>
    </array>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>

    <key>ThrottleInterval</key>
    <integer>10</integer>

    <key>WorkingDirectory</key>
    <string>${DATA_DIR}</string>

    <key>EnvironmentVariables</key>
    <dict>
        <key>PYTHONPATH</key>
        <string>${SRC_DIR}</string>
        <key>AMOSKYS_HOME</key>
        <string>${INSTALL_DIR}</string>
        <key>AMOSKYS_DATA</key>
        <string>${DATA_DIR}</string>
        <key>PATH</key>
        <string>${INSTALL_DIR}/venv/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    </dict>

    <key>StandardOutPath</key>
    <string>${LOG_DIR}/watchdog.log</string>
    <key>StandardErrorPath</key>
    <string>${LOG_DIR}/watchdog.err.log</string>

    <key>SoftResourceLimits</key>
    <dict>
        <key>NumberOfFiles</key>
        <integer>8192</integer>
    </dict>

    <key>ExitTimeOut</key>
    <integer>30</integer>

    <key>ProcessType</key>
    <string>Standard</string>
</dict>
</plist>
PLISTEOF

# ── Set Permissions ──
log "Setting permissions..."
chown -R root:wheel "$INSTALL_DIR"
chown -R root:wheel "$DATA_DIR"
chown -R root:wheel "$LOG_DIR"
chmod -R 755 "$INSTALL_DIR"
chmod -R 755 "$DATA_DIR"
chmod -R 755 "$LOG_DIR"
chmod 600 "$CERT_DIR/agent.ed25519"
chmod 600 "$CONFIG_DIR/amoskys.env"

# ── Symlink data directories for the engine ──
# The engine expects data/ relative to CWD, which is now /var/lib/amoskys
ln -sf "$DATA_DIR" "$INSTALL_DIR/data" 2>/dev/null || true
ln -sf "$LOG_DIR" "$INSTALL_DIR/logs" 2>/dev/null || true
ln -sf "$CERT_DIR" "$DATA_DIR/certs" 2>/dev/null || true
# Also symlink certs from engine root (some agents look for certs/agent.ed25519)
ln -sf "$CERT_DIR" "$INSTALL_DIR/certs" 2>/dev/null || true

# ── Start Service ──
log "Starting AMOSKYS..."
launchctl load /Library/LaunchDaemons/com.amoskys.watchdog.plist 2>/dev/null || true
sleep 5

# ── Verify ──
log ""
log "═══════════════════════════════════════════════════"
log "  AMOSKYS v${VERSION} installed successfully"
log "═══════════════════════════════════════════════════"
log ""
log "  Install:    $INSTALL_DIR"
log "  Data:       $DATA_DIR"
log "  Logs:       $LOG_DIR"
log "  Config:     $CONFIG_DIR/amoskys.env"
log "  Dashboard:  http://localhost:5003/dashboard/"
log ""
log "  CLI:        amoskys status"
log "  Uninstall:  sudo bash $0 --uninstall"
log ""

# Check if watchdog started children
sleep 3
WATCHDOG_PID=$(pgrep -f "amoskys.watchdog" | head -1)
if [[ -n "$WATCHDOG_PID" ]]; then
    log "  Watchdog:   running (pid=$WATCHDOG_PID)"
else
    warn "  Watchdog:   not started (check $LOG_DIR/watchdog.err.log)"
fi

log ""
log "AMOSKYS is monitoring your Mac."
