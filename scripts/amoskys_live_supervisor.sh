#!/bin/bash
# Keeps the AMOSKYS device pipeline (collector + shipping analyzer) alive.
cd "$HOME/Amoskys_recovered" || exit 1
set -a; [ -f .env ] && . ./.env; set +a
export PYTHONPATH="src:$PWD/amoskys-venv/lib/python3.13/site-packages"
export AMOSKYS_DATA_DIR="$PWD/data" AMOSKYS_DATA="$PWD/data"
# Exported so the WEB health check can count the corpus. Without it
# _intel_corpus_size() returns None and the dashboard can only say
# "unverified" — it cannot distinguish an armed feed from a dead one.
export AMOSKYS_THREAT_INTEL_DB="$PWD/data/threat_intel.db"
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


# ── Threat-intel refresh ────────────────────────────────────────────────────
# Indicators carry a 72-HOUR expiry and the whole corpus shares one expires_at,
# so the feed does not decay gradually — it falls off a cliff, all 3,203 rows
# at the same instant. That already happened once: the corpus expired
# 2026-07-01 and nothing refreshed it for 52 days, during which every flow was
# stamped with a confident-looking threat_intel_match=False and the dashboard
# reported the feed HEALTHY.
#
# Refreshed every 12h — a 6x margin against the 72h expiry, so the feed
# survives three consecutive failed refreshes (laptop asleep, no network, feed
# outage) before it can go unarmed.
#
# This performs an OUTBOUND FETCH to abuse.ch, Emerging Threats and URLhaus.
# Set AMOSKYS_INTEL_AUTOREFRESH=0 to disable it and refresh by hand instead.
INTEL_REFRESH_EVERY_S=${AMOSKYS_INTEL_REFRESH_EVERY_S:-43200}
INTEL_STAMP="$PWD/data/.intel_refreshed"

refresh_threat_intel() {
  [ "${AMOSKYS_INTEL_AUTOREFRESH:-1}" = "1" ] || return 0
  local now age
  now=$(date +%s)
  if [ -f "$INTEL_STAMP" ]; then
    age=$(( now - $(stat -f %m "$INTEL_STAMP" 2>/dev/null || echo 0) ))
    [ "$age" -lt "$INTEL_REFRESH_EVERY_S" ] && return 0
  fi
  # Stamp BEFORE fetching, not after: a feed host that hangs or 500s must not
  # put this into a retry loop that hammers abuse.ch every 25 seconds.
  touch "$INTEL_STAMP"
  "$PY" scripts/update_threat_intel.py >> logs/intel_refresh.log 2>&1 \
    && echo "$(date -u +%FT%TZ) intel refresh ok" >> logs/intel_refresh.log \
    || echo "$(date -u +%FT%TZ) intel refresh FAILED (retry in ${INTEL_REFRESH_EVERY_S}s)" >> logs/intel_refresh.log
}


# ── Stale-code detection ────────────────────────────────────────────────────
# Three separate debugging sessions today ended at the same cause: a worker was
# running code older than the file on disk, and the only symptom was a table
# that stayed empty. Every time, the trail ran backwards from "why is nothing
# being produced" to "this process started before the change".
#
#   - the ESF collector ran 15h-old code and silently discarded every kernel
#     transition event
#   - the collector reported "All 18 sensors loaded" from a build that predated
#     three newly wired agents
#   - the Sentinel emitted boot-relative timestamps after they were fixed
#
# None of those raised an error. A process running stale code behaves
# perfectly — it just behaves like the old version, which is indistinguishable
# from a broken new one unless someone thinks to check.
#
# WARNS by default rather than restarting. An automatic restart on every source
# change would cycle the pipeline during editing, and losing the running state
# is a worse default than a loud line in the log. Set
# AMOSKYS_RESTART_ON_CHANGE=1 to opt in.
check_stale_code() {
  local newest worker pid started
  newest=$(find src -name '*.py' -newer "$STALE_STAMP" -print -quit 2>/dev/null)
  [ -z "$newest" ] && return 0

  for worker in amoskys.collector_main amoskys.analyzer_main amoskys.shipper amoskys.agents.os.macos.esf; do
    pid=$(pgrep -f "$worker" | head -1) || continue
    [ -z "$pid" ] && continue
    # Process start (epoch) vs the stamp we last refreshed after a restart.
    started=$(ps -o lstart= -p "$pid" 2>/dev/null | xargs -I{} date -j -f "%a %b %d %T %Y" {} +%s 2>/dev/null)
    [ -z "$started" ] && continue
    if [ "$started" -lt "$(stat -f %m "$STALE_STAMP" 2>/dev/null || echo 0)" ]; then
      echo "$(date -u +%FT%TZ) STALE CODE: $worker (pid $pid) started before the current source. It is running an older build and will behave like it — silently." >> logs/supervisor.log
      if [ "${AMOSKYS_RESTART_ON_CHANGE:-0}" = "1" ]; then
        echo "$(date -u +%FT%TZ)   AMOSKYS_RESTART_ON_CHANGE=1 -> restarting $worker" >> logs/supervisor.log
        pkill -f "$worker" 2>/dev/null
      fi
    fi
  done
  touch "$STALE_STAMP"
}
STALE_STAMP="$PWD/data/.code_stamp"
[ -f "$STALE_STAMP" ] || touch "$STALE_STAMP"

while true; do
  rotate_logs
  check_stale_code
  refresh_threat_intel
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
  # ESF collector. The Sentinel is the only sensor that sees a process BEFORE
  # it runs and the only one that reads cdhash and signing state as the kernel
  # saw them; until this was wired it wrote to a file nothing read. It needs
  # root and is therefore started separately (see scripts/esf_setup.sh) --
  # this side only tails what it writes, so the two lifecycles stay
  # independent: restarting the collector must never interrupt kernel
  # authorization.
  pgrep -f 'amoskys.agents.os.macos.esf' >/dev/null || nohup "$PY" -m amoskys.agents.os.macos.esf >> logs/esf_collector.live.log 2>&1 &
  sleep 25
done
