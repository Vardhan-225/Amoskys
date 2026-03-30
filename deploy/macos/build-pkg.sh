#!/bin/bash
# ═══════════════════════════════════════════════════════════════════
# AMOSKYS .pkg Builder — Creates MDM-deployable macOS installer
# ═══════════════════════════════════════════════════════════════════
#
# Builds a .pkg that can be deployed via:
#   - Jamf Pro
#   - Microsoft Intune
#   - Kandji
#   - Mosyle
#   - Manual double-click
#
# Usage:
#   bash deploy/macos/build-pkg.sh
#   bash deploy/macos/build-pkg.sh --sign "Developer ID Installer: ..."
#
# Output:
#   dist/AMOSKYS-0.9.1-beta.pkg
#
# ═══════════════════════════════════════════════════════════════════

set -euo pipefail

VERSION="0.9.1-beta"
IDENTIFIER="com.amoskys.agent"
PKG_NAME="AMOSKYS-${VERSION}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/dist/pkg-build"
DIST_DIR="$PROJECT_ROOT/dist"
SIGN_IDENTITY=""

# Parse args
for arg in "$@"; do
    case "$arg" in
        --sign=*) SIGN_IDENTITY="${arg#--sign=}" ;;
        --sign) shift; SIGN_IDENTITY="$1" ;;
    esac
done

echo "═══════════════════════════════════════════════════"
echo "  AMOSKYS .pkg Builder v${VERSION}"
echo "═══════════════════════════════════════════════════"
echo ""

# ── Clean ──
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"/{root,scripts}
mkdir -p "$DIST_DIR"

# ── Build Payload ──
echo "Building payload..."

# Copy the installer script as postinstall
cat > "$BUILD_DIR/scripts/postinstall" << 'POSTEOF'
#!/bin/bash
# AMOSKYS Post-Install Script
# Runs after .pkg files are placed on disk

exec /Library/Amoskys/deploy/install-from-pkg.sh >> /var/log/amoskys/install.log 2>&1
POSTEOF
chmod +x "$BUILD_DIR/scripts/postinstall"

cat > "$BUILD_DIR/scripts/preinstall" << 'PREEOF'
#!/bin/bash
# Stop existing AMOSKYS if running
launchctl unload /Library/LaunchDaemons/com.amoskys.watchdog.plist 2>/dev/null || true
pkill -f "amoskys.watchdog" 2>/dev/null || true
pkill -f "amoskys.collector_main" 2>/dev/null || true
pkill -f "amoskys.analyzer_main" 2>/dev/null || true
sleep 2
exit 0
PREEOF
chmod +x "$BUILD_DIR/scripts/preinstall"

# Create the payload directory structure
PAYLOAD="$BUILD_DIR/root/Library/Amoskys"
mkdir -p "$PAYLOAD"/{src,web,config,certs,bin,deploy}
mkdir -p "$BUILD_DIR/root/var/lib/amoskys"/{queue,intel/baselines,intel/models,geoip,heartbeats,pids}
mkdir -p "$BUILD_DIR/root/var/log/amoskys"

# Copy source
echo "Copying source..."
rsync -a --exclude='__pycache__' --exclude='*.pyc' --exclude='.git' \
    "$PROJECT_ROOT/src/" "$PAYLOAD/src/"
rsync -a --exclude='__pycache__' --exclude='*.pyc' \
    "$PROJECT_ROOT/web/" "$PAYLOAD/web/"
cp "$PROJECT_ROOT/requirements.txt" "$PAYLOAD/"
cp "$PROJECT_ROOT/pyproject.toml" "$PAYLOAD/"

# Copy GeoIP databases
if [[ -d "$PROJECT_ROOT/data/geoip" ]]; then
    cp "$PROJECT_ROOT/data/geoip/"*.mmdb "$BUILD_DIR/root/var/lib/amoskys/geoip/" 2>/dev/null || true
fi

# Copy the full installer as post-install helper
cp "$SCRIPT_DIR/install.sh" "$PAYLOAD/deploy/install-from-pkg.sh"
chmod +x "$PAYLOAD/deploy/install-from-pkg.sh"

# Create the post-install wrapper that uses the already-placed files
cat > "$PAYLOAD/deploy/install-from-pkg.sh" << 'PKGINSTEOF'
#!/bin/bash
# AMOSKYS Post-PKG Install
# Files are already in /Library/Amoskys/ — just need venv + config + daemon

set -euo pipefail

INSTALL_DIR="/Library/Amoskys"
DATA_DIR="/var/lib/amoskys"
LOG_DIR="/var/log/amoskys"
VENV_DIR="$INSTALL_DIR/venv"
SRC_DIR="$INSTALL_DIR/src"
CERT_DIR="$INSTALL_DIR/certs"
CONFIG_DIR="$INSTALL_DIR/config"

echo "[AMOSKYS] Post-install starting..."

# Find Python
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
    echo "[ERROR] Python 3.11+ not found"
    exit 1
fi
echo "[AMOSKYS] Python: $PYTHON"

# Create venv if needed
if [[ ! -d "$VENV_DIR" ]]; then
    echo "[AMOSKYS] Creating virtual environment..."
    "$PYTHON" -m venv "$VENV_DIR"
fi

echo "[AMOSKYS] Installing dependencies..."
"$VENV_DIR/bin/pip" install --upgrade pip -q
"$VENV_DIR/bin/pip" install -r "$INSTALL_DIR/requirements.txt" -q

# Generate certs if needed
if [[ ! -f "$CERT_DIR/agent.ed25519" ]]; then
    echo "[AMOSKYS] Generating signing key..."
    "$VENV_DIR/bin/python3" -c "
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
key = Ed25519PrivateKey.generate()
open('$CERT_DIR/agent.ed25519', 'wb').write(key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()))
open('$CERT_DIR/agent.ed25519.pub', 'wb').write(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
"
    chmod 600 "$CERT_DIR/agent.ed25519"
fi

# Generate config
SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
cat > "$CONFIG_DIR/amoskys.env" << ENVEOF
AMOSKYS_HOME=$INSTALL_DIR
AMOSKYS_DATA=$DATA_DIR
AMOSKYS_LOGS=$LOG_DIR
PYTHONPATH=$SRC_DIR
SECRET_KEY=$SECRET_KEY
LOGIN_DISABLED=true
FLASK_PORT=5003
FORCE_HTTPS=false
ENVEOF
chmod 600 "$CONFIG_DIR/amoskys.env"

# Create wrapper scripts
mkdir -p "$INSTALL_DIR/bin"
cat > "$INSTALL_DIR/bin/amoskys-watchdog" << 'WD'
#!/bin/bash
set -a; source /Library/Amoskys/config/amoskys.env; set +a
cd /var/lib/amoskys
exec /Library/Amoskys/venv/bin/python3 -m amoskys.watchdog "$@"
WD
chmod +x "$INSTALL_DIR/bin/amoskys-watchdog"

cat > "$INSTALL_DIR/bin/amoskys" << 'CLI'
#!/bin/bash
set -a; source /Library/Amoskys/config/amoskys.env; set +a
cd /var/lib/amoskys
exec /Library/Amoskys/venv/bin/python3 -m amoskys "$@"
CLI
chmod +x "$INSTALL_DIR/bin/amoskys"
ln -sf "$INSTALL_DIR/bin/amoskys" /usr/local/bin/amoskys 2>/dev/null || true

# Symlinks
ln -sf "$DATA_DIR" "$INSTALL_DIR/data" 2>/dev/null || true
ln -sf "$LOG_DIR" "$INSTALL_DIR/logs" 2>/dev/null || true
ln -sf "$CERT_DIR" "$DATA_DIR/certs" 2>/dev/null || true
ln -sf "$CERT_DIR" "$INSTALL_DIR/certs" 2>/dev/null || true

# Set permissions
chown -R root:wheel "$INSTALL_DIR"
chown -R root:wheel "$DATA_DIR"
chown -R root:wheel "$LOG_DIR"

# Install LaunchDaemon
cat > /Library/LaunchDaemons/com.amoskys.watchdog.plist << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.amoskys.watchdog</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Library/Amoskys/bin/amoskys-watchdog</string>
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
    <string>/var/lib/amoskys</string>
    <key>StandardOutPath</key>
    <string>/var/log/amoskys/watchdog.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/amoskys/watchdog.err.log</string>
    <key>SoftResourceLimits</key>
    <dict>
        <key>NumberOfFiles</key>
        <integer>8192</integer>
    </dict>
    <key>ExitTimeOut</key>
    <integer>30</integer>
</dict>
</plist>
PLIST

# Start
echo "[AMOSKYS] Starting service..."
launchctl load /Library/LaunchDaemons/com.amoskys.watchdog.plist 2>/dev/null || true

echo "[AMOSKYS] Installation complete."
echo "[AMOSKYS] Dashboard: http://localhost:5003/dashboard/"
echo "[AMOSKYS] CLI: amoskys status"
PKGINSTEOF
chmod +x "$PAYLOAD/deploy/install-from-pkg.sh"

# ── Build Component Package ──
echo "Building component package..."
pkgbuild \
    --root "$BUILD_DIR/root" \
    --scripts "$BUILD_DIR/scripts" \
    --identifier "$IDENTIFIER" \
    --version "$VERSION" \
    --ownership recommended \
    "$BUILD_DIR/amoskys-component.pkg"

# ── Build Distribution Package ──
echo "Building distribution package..."

cat > "$BUILD_DIR/distribution.xml" << DISTEOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
    <title>AMOSKYS Security Platform</title>
    <organization>com.amoskys</organization>
    <domains enable_localSystem="true"/>
    <options customize="never" require-scripts="true" rootVolumeOnly="true"/>
    <volume-check>
        <allowed-os-versions>
            <os-version min="13.0"/>
        </allowed-os-versions>
    </volume-check>
    <welcome file="welcome.html"/>
    <conclusion file="conclusion.html"/>
    <choices-outline>
        <line choice="default">
            <line choice="com.amoskys.agent"/>
        </line>
    </choices-outline>
    <choice id="default"/>
    <choice id="com.amoskys.agent" visible="false">
        <pkg-ref id="com.amoskys.agent"/>
    </choice>
    <pkg-ref id="com.amoskys.agent" version="${VERSION}" onConclusion="none">amoskys-component.pkg</pkg-ref>
</installer-gui-script>
DISTEOF

# Create welcome/conclusion HTML
mkdir -p "$BUILD_DIR/resources"
cat > "$BUILD_DIR/resources/welcome.html" << 'WELEOF'
<html><body style="font-family: -apple-system, sans-serif; padding: 20px;">
<h1>AMOSKYS Security Platform</h1>
<p>This will install the AMOSKYS endpoint detection agent on your Mac.</p>
<p><strong>What gets installed:</strong></p>
<ul>
<li>Security monitoring agent (17 observatory agents)</li>
<li>Detection engine (56 Sigma rules, behavioral scoring)</li>
<li>Web dashboard (http://localhost:5003)</li>
</ul>
<p><strong>Requirements:</strong> Python 3.11+, macOS 13+</p>
</body></html>
WELEOF

cat > "$BUILD_DIR/resources/conclusion.html" << 'CONEOF'
<html><body style="font-family: -apple-system, sans-serif; padding: 20px;">
<h1>AMOSKYS Installed</h1>
<p>AMOSKYS is now monitoring your Mac.</p>
<p><strong>Dashboard:</strong> <a href="http://localhost:5003/dashboard/">http://localhost:5003/dashboard/</a></p>
<p><strong>CLI:</strong> Open Terminal and run <code>amoskys status</code></p>
<p><strong>Uninstall:</strong> <code>sudo /Library/Amoskys/deploy/install-from-pkg.sh --uninstall</code></p>
</body></html>
CONEOF

# Build the final .pkg
if [[ -n "$SIGN_IDENTITY" ]]; then
    echo "Signing with: $SIGN_IDENTITY"
    productbuild \
        --distribution "$BUILD_DIR/distribution.xml" \
        --resources "$BUILD_DIR/resources" \
        --package-path "$BUILD_DIR" \
        --sign "$SIGN_IDENTITY" \
        "$DIST_DIR/${PKG_NAME}.pkg"
else
    productbuild \
        --distribution "$BUILD_DIR/distribution.xml" \
        --resources "$BUILD_DIR/resources" \
        --package-path "$BUILD_DIR" \
        "$DIST_DIR/${PKG_NAME}.pkg"
    warn "Package is UNSIGNED. For MDM deployment, sign with: --sign 'Developer ID Installer: ...'"
fi

# ── Cleanup ──
rm -rf "$BUILD_DIR"

PKG_SIZE=$(du -h "$DIST_DIR/${PKG_NAME}.pkg" | awk '{print $1}')
echo ""
echo "═══════════════════════════════════════════════════"
echo "  Built: $DIST_DIR/${PKG_NAME}.pkg ($PKG_SIZE)"
echo "═══════════════════════════════════════════════════"
echo ""
echo "  Install:  sudo installer -pkg $DIST_DIR/${PKG_NAME}.pkg -target /"
echo "  MDM:      Upload to Jamf/Intune/Kandji"
echo ""
