#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# AMOSKYS Sentinel — install as a boot LaunchDaemon (run with sudo, once).
#   sudo ./install_sentinel.sh          # install + start (MONITOR mode)
#   sudo ./install_sentinel.sh remove   # stop + uninstall
#
# Prereqs already met on this Mac: signed AmoskysSentinel.app with embedded
# provisioning profile, and Full Disk Access granted to the inner binary.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

LABEL="com.amoskys.sentinel"
PLIST_SRC="$(cd "$(dirname "$0")/.." && pwd)/deploy/${LABEL}.plist"
PLIST_DST="/Library/LaunchDaemons/${LABEL}.plist"
BIN="/Users/athanneeru/Amoskys_recovered/macos-esf-shim/AmoskysSentinel.app/Contents/MacOS/amoskys-sentinel"

[[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }

if [[ "${1:-}" == "remove" ]]; then
  launchctl bootout system "$PLIST_DST" 2>/dev/null || true
  rm -f "$PLIST_DST"
  echo "✓ Sentinel LaunchDaemon removed (binary + bundle untouched)."
  exit 0
fi

# sanity: signature + entitlement still intact before installing at boot
codesign --verify --strict "$(dirname "$(dirname "$(dirname "$BIN")")")" \
  || { echo "✖ bundle signature invalid — re-run build_bundle.sh first"; exit 2; }

mkdir -p /var/log/amoskys

# root-owned copy, correct perms (launchd refuses group/world-writable plists)
install -m 0644 -o root -g wheel "$PLIST_SRC" "$PLIST_DST"

# (re)load
launchctl bootout system "$PLIST_DST" 2>/dev/null || true
launchctl bootstrap system "$PLIST_DST"
launchctl kickstart -k "system/${LABEL}"

sleep 1
echo "── status ───────────────────────────────────────────────"
launchctl print "system/${LABEL}" 2>/dev/null | grep -E "state|pid" | head -3
echo "── first log lines ──────────────────────────────────────"
tail -3 /var/log/amoskys/sentinel.log 2>/dev/null || echo "(log not written yet — check in a few seconds)"
cat <<EOF
─────────────────────────────────────────────────────────────
✓ Sentinel installed as a boot LaunchDaemon (MONITOR mode).
  watch verdicts : tail -f /var/log/amoskys/sentinel.log
  stop           : sudo launchctl bootout system $PLIST_DST
  enforce mode   : uncomment AMOSKYS_ENFORCE in the plist, reinstall
NOTE: if a foreground 'sudo …/amoskys-sentinel' is still running in a
terminal, Ctrl-C it — the daemon replaces it.
EOF
