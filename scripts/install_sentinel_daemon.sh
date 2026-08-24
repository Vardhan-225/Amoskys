#!/bin/bash
# Install the Sentinel as a LaunchDaemon so it survives reboot, sleep, crash —
# and so a code change needs one short command instead of a full re-invocation.
#
# WHY THIS EXISTS. The Sentinel has been run as a foreground `sudo` process, so
# every rebuild required retyping the whole path and a password, and any
# terminal closing killed the kernel witness silently. That is also why several
# fixes sat built-but-not-running for hours: the restart is easy to forget when
# it is a paragraph long.
#
# MONITOR ONLY. This installs with AMOSKYS_ENFORCE unset, so the Sentinel
# observes and blocks nothing. Persistence was deferred over ENFORCE risk, and
# that risk does not apply here — see the plist for the full reasoning.
set -euo pipefail
PLIST_SRC="$(cd "$(dirname "$0")/.." && pwd)/deploy/com.amoskys.sentinel.plist"
PLIST_DST="/Library/LaunchDaemons/com.amoskys.sentinel.plist"
LABEL="system/com.amoskys.sentinel"

[ "$(id -u)" -eq 0 ] || { echo "Run with sudo: sudo bash $0"; exit 1; }

echo "▸ installing $PLIST_DST"
install -m 0644 -o root -g wheel "$PLIST_SRC" "$PLIST_DST"

# Kill any foreground instance first. Two ES clients from the same binary is
# not fatal, but it doubles the stream and makes drop accounting meaningless.
pkill -f "MacOS/amoskys-sentinel" 2>/dev/null || true

launchctl bootout "$LABEL" 2>/dev/null || true

# ENABLE BEFORE BOOTSTRAP. Order matters and the failure is opaque:
# `launchctl bootstrap` returns "Input/output error" (EIO) when the label sits
# in launchd's persistent disabled-override list, which says nothing about the
# actual cause. This machine had four amoskys labels disabled — sentinel,
# threat-intel, watchdog, doctor — left over from the August shutdown when the
# disk filled. Calling enable AFTER bootstrap can never work, because bootstrap
# is the step that fails.
#
# The override list survives reboots and plist reinstalls, so a disabled label
# stays disabled no matter how many times the plist is copied into place.
launchctl enable "$LABEL" 2>/dev/null || true

if ! launchctl bootstrap system "$PLIST_DST" 2>/tmp/amoskys_bootstrap.err; then
  echo "▸ bootstrap failed: $(cat /tmp/amoskys_bootstrap.err)"
  echo "  currently disabled amoskys labels:"
  launchctl print-disabled system 2>/dev/null | grep -i amoskys | sed 's/^/    /'
  exit 1
fi
sleep 2

if launchctl print "$LABEL" >/dev/null 2>&1; then
  echo "▸ running. From now on, to pick up a rebuild:"
  echo "    sudo launchctl kickstart -k $LABEL"
else
  echo "▸ FAILED to start. Check: sudo launchctl print $LABEL"
  exit 1
fi
