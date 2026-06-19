#!/bin/bash
# Deploy the threat-intel fix to the live AMOSKYS agent.
# Root-gated steps only — code already deployed to /Library/Amoskys (user-owned).
#
#   sudo bash scripts/deploy_threat_intel.sh
#
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
DB_LIVE="/var/lib/amoskys/data/threat_intel.db"
INSTALL="/Library/Amoskys"
PLIST="/Library/LaunchDaemons/com.amoskys.threat-intel.plist"
WATCHDOG="/Library/LaunchDaemons/com.amoskys.watchdog.plist"

echo "==> 1/4  Placing populated indicator DB at $DB_LIVE"
install -d -m 755 /var/lib/amoskys/data
cp "/tmp/amoskys_threat_intel.db" "$DB_LIVE"
chown root:wheel "$DB_LIVE"; chmod 644 "$DB_LIVE"
N=$(/opt/homebrew/bin/python3.13 -c "import sqlite3;print(sqlite3.connect('$DB_LIVE').execute('SELECT COUNT(*) FROM indicators').fetchone()[0])")
echo "    indicators live: $N"

echo "==> 2/4  Installing self-contained auto-updater"
install -d -m 755 "$INSTALL/scripts"
cp "$REPO/scripts/threat_intel_autoupdate.py" "$INSTALL/scripts/threat_intel_autoupdate.py"

echo "==> 3/4  Installing + loading daily auto-update LaunchDaemon"
cp "$REPO/deploy/macos/com.amoskys.threat-intel.plist" "$PLIST"
chown root:wheel "$PLIST"; chmod 644 "$PLIST"
launchctl bootout system "$PLIST" 2>/dev/null || true
launchctl bootstrap system "$PLIST"

echo "==> 4/4  Reloading agent so analyzer re-opens the populated DB"
launchctl kickstart -k system/com.amoskys.watchdog

echo "DONE. Analyzer restarting with $N threat-intel indicators."
echo "Tail enrichment status:  sudo grep -i threat /var/log/amoskys/*.log | tail"
