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
  # THE BOOTSTRAP PROBLEM, stated because it bit immediately.
  #
  # This function shipped inside the supervisor, and the supervisor that was
  # running had been started before it existed — so the stale-code detector was
  # itself stale, and never ran. Four separate times a component sat running
  # old code with an empty table as the only symptom, and the check written to
  # catch exactly that was among them.
  #
  # A self-check cannot detect its own staleness. The supervisor is therefore
  # checked FIRST and by a different mechanism: its own start time against the
  # script file on disk. That is the one comparison it can make about itself.
  local newest worker pid started sup_started script_mtime
  sup_started=$(ps -o lstart= -p $$ 2>/dev/null | xargs -I{} date -j -f "%a %b %d %T %Y" {} +%s 2>/dev/null || echo 0)
  script_mtime=$(stat -f %m "$0" 2>/dev/null || echo 0)
  if [ "${sup_started:-0}" -gt 0 ] && [ "$script_mtime" -gt "$sup_started" ]; then
    echo "$(date -u +%FT%TZ) STALE SUPERVISOR: this process started before the current $0. Its own checks are running an older build — restart it with: launchctl kickstart -k gui/\$(id -u)/com.amoskys.live" >> logs/supervisor.log
  fi

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


# ── Worker liveness ─────────────────────────────────────────────────────────
# pgrep -f matches ANY process whose command line contains the string — which
# includes a shell that merely mentioned it. That is not hypothetical: a
# diagnostic session left `amoskys.collector_main` in an interactive shell's
# argv, every guard below matched it, and the supervisor sat for 32 minutes
# believing all four workers were alive while the machine had NO sensors at
# all. The failure is silent by construction: a liveness check that returns
# "alive" costs nothing and logs nothing.
#
# So liveness is tracked by PID FILE and verified two ways: the pid must exist
# AND its own command line must contain the module. A stale pidfile whose pid
# was recycled by an unrelated process therefore fails the second test rather
# than passing the first.
PIDDIR="$PWD/data/pids"
mkdir -p "$PIDDIR"

worker_alive() {
  local module="$1" pf="$PIDDIR/${1//[^a-zA-Z0-9]/_}.pid" pid
  [ -f "$pf" ] || return 1
  pid=$(cat "$pf" 2>/dev/null) || return 1
  [ -n "$pid" ] || return 1
  ps -p "$pid" >/dev/null 2>&1 || return 1
  # The pid exists — but is it OURS, or a recycled number?
  ps -o command= -p "$pid" 2>/dev/null | grep -q "$module" || return 1
  return 0
}

start_worker() {
  local module="$1" logfile="$2" pf="$PIDDIR/${1//[^a-zA-Z0-9]/_}.pid"
  worker_alive "$module" && return 0
  nohup "$PY" -m "$module" >> "$logfile" 2>&1 &
  echo $! > "$pf"
  echo "$(date -u +%FT%TZ) started $module pid=$!" >> logs/supervisor.log
}

while true; do
  rotate_logs
  check_stale_code
  refresh_threat_intel
  start_worker amoskys.collector_main logs/collector.live.log
  sleep 5
  start_worker amoskys.analyzer_main logs/analyzer.live.log
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
  start_worker amoskys.shipper logs/shipper.live.log
  # ESF collector. The Sentinel is the only sensor that sees a process BEFORE
  # it runs and the only one that reads cdhash and signing state as the kernel
  # saw them; until this was wired it wrote to a file nothing read. It needs
  # root and is therefore started separately (see scripts/esf_setup.sh) --
  # this side only tails what it writes, so the two lifecycles stay
  # independent: restarting the collector must never interrupt kernel
  # authorization.
  start_worker amoskys.agents.os.macos.esf logs/esf_collector.live.log
  sleep 25
done
