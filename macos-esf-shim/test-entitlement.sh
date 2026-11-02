#!/bin/bash
# AMOSKYS Sentinel — ground-truth entitlement test.
# Run:  sudo /Users/athanneeru/Amoskys_recovered/macos-esf-shim/test-entitlement.sh
#
# This tells us the ONE thing we can't know without running: whether the OS
# HONORS the endpoint-security entitlement for this standalone signed binary,
# or demands a provisioning profile / System-Extension packaging.
#
# It starts the Sentinel in MONITOR mode (never denies), waits 3s, and reports
# what es_new_client returned. Then it stops. Nothing is enforced.
set -uo pipefail
cd "$(dirname "$0")"
BIN="./amoskys-sentinel"

if [ "$(id -u)" != "0" ]; then echo "must run as root — use: sudo $0"; exit 1; fi

echo "=== signature the OS will evaluate ==="
codesign -dv --verbose=2 "$BIN" 2>&1 | grep -E "TeamIdentifier|Authority=Developer ID|flags"
echo

echo "=== launching Sentinel (MONITOR, 3s) — watch the first line ==="
# MONITOR mode (default). Capture stderr; kill after 3s no matter what.
AMOSKYS_ENFORCE=0 "$BIN" 2>&1 &
pid=$!
sleep 3
kill "$pid" 2>/dev/null
wait "$pid" 2>/dev/null
rc=$?

echo
echo "=== VERDICT ==="
echo "If you saw 'guarding exec (mode=MONITOR ...)'  → ENTITLEMENT HONORED. We can block."
echo "If you saw 'missing ... entitlement'           → need a provisioning profile."
echo "If you saw 'needs Full Disk Access'            → grant Terminal FDA and retry."
echo "If you saw 'must run as root'                  → rerun with sudo."
