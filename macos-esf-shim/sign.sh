#!/bin/bash
# AMOSKYS Sentinel — clean Developer ID sign + verify.
# No --timestamp: the Apple timestamp server call hangs headless and is only
# needed for NOTARIZED DISTRIBUTION, not for locally running the daemon.
set -uo pipefail
cd "$(dirname "$0")"

IDENTITY="Developer ID Application: Akash Thanneeru (4Z5335ZWBH)"
BIN="amoskys-sentinel"
ENT="AmoskysAgent.entitlements"

echo "=== signing $BIN with: $IDENTITY ==="
codesign --force --options runtime \
  --sign "$IDENTITY" \
  --entitlements "$ENT" \
  "$BIN"
rc=$?
echo "codesign exit: $rc"
[ $rc -ne 0 ] && { echo "SIGN FAILED (rc=$rc)"; exit $rc; }

echo
echo "=== identity check (want TeamIdentifier=4Z5335ZWBH) ==="
codesign -dv --verbose=2 "$BIN" 2>&1 | grep -E "Identifier|TeamIdentifier|Authority|Signature|flags"
echo
echo "=== embedded entitlement (want endpoint-security.client) ==="
codesign -d --entitlements - --xml "$BIN" 2>/dev/null | grep -o "endpoint-security[a-z.]*" || echo "  (none embedded)"
echo
echo "=== validity ==="
codesign --verify --verbose=2 "$BIN" 2>&1 | tail -3
echo "DONE"
