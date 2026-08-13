#!/bin/bash
# Keeps the AMOSKYS device pipeline (collector + shipping analyzer) alive.
cd "$HOME/Amoskys_recovered" || exit 1
set -a; [ -f .env ] && . ./.env; set +a
export PYTHONPATH="src:$PWD/amoskys-venv/lib/python3.13/site-packages"
export AMOSKYS_DATA_DIR="$PWD/data" AMOSKYS_DATA="$PWD/data"
PY="$PWD/amoskys-venv/bin/python"
mkdir -p logs

# ── Log rotation ────────────────────────────────────────────────────────────
# Nothing in this tree rotated logs. Every process logs via
# logging.basicConfig() to stderr and the launches below append with `>>`, so
# each file grew without bound for as long as the pipeline ran:
# /Library/Amoskys/logs/analyzer.err.log reached 7.6GB and collector.err.log
# 1.3GB, ~8.9GB of the 10GB install. Together with the unpruned telemetry
# store that is what filled the disk to 99% and left macOS unable to write its
# hibernate image, panicking the kernel six times in a week.
#
# copytruncate semantics, NOT mv: the running processes already hold these
# files open via `>>`. Renaming the file leaves their fd pointing at the
# renamed inode and they keep writing to it, so the "rotated" log goes on
# growing and the new one stays empty forever. Copying and then truncating in
# place keeps the fd valid and actually resets the size.
#
# Note the append-mode caveat: O_APPEND writes always go to the current end of
# file, so truncation is safe here and does not leave a sparse gap.
LOG_MAX_BYTES=${AMOSKYS_LOG_MAX_BYTES:-52428800}   # 50MB per file

rotate_logs() {
  for f in logs/*.log; do
    [ -f "$f" ] || continue
    # stat -f%z is macOS/BSD; -c%s is GNU. Fall back so this works on both.
    sz=$(stat -f%z "$f" 2>/dev/null || stat -c%s "$f" 2>/dev/null || echo 0)
    if [ "$sz" -gt "$LOG_MAX_BYTES" ]; then
      cp -f "$f" "$f.1" 2>/dev/null && : > "$f"
    fi
  done
}

while true; do
  rotate_logs
  pgrep -f 'amoskys.collector_main' >/dev/null || nohup "$PY" -m amoskys.collector_main >> logs/collector.live.log 2>&1 &
  sleep 5
  pgrep -f 'amoskys.analyzer_main' >/dev/null || nohup "$PY" -m amoskys.analyzer_main >> logs/analyzer.live.log 2>&1 &
  sleep 5
  # The shipper is what makes this device part of a FLEET rather than a private
  # log. It was supervised by nothing — not this script, not launchd, not the
  # launcher — so once it exited it never came back. Its cursor showed the last
  # successful ship at 2026-08-12 20:46, which is exactly where the ops server's
  # newest flow_event stopped, while the Mac kept collecting normally. The
  # dashboard rendered that as "no network flows in the past 24 hours".
  #
  # Needs AMOSKYS_SERVER / AMOSKYS_API_KEY from .env (sourced above); if they
  # are absent the shipper exits immediately and this loop simply retries,
  # which is the correct behaviour for an unregistered device.
  pgrep -f 'amoskys.shipper' >/dev/null || nohup "$PY" -m amoskys.shipper >> logs/shipper.live.log 2>&1 &
  sleep 25
done
