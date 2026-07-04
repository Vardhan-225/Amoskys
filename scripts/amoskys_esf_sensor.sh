#!/bin/bash
# AMOSKYS ESF sensor — supervised, always-on runner.
#
# Runs the kernel-witness pipeline and keeps it alive like a real EDR sensor:
#
#   eslogger exec fork exit  →  amoskys-sensor (Rust: trust)  →  esf_bridge (→ Brain)
#
# MUST run as root (ESF requires it) AND the responsible process needs Full Disk
# Access. Interactive:   sudo ./scripts/amoskys_esf_sensor.sh
# As a boot service:     install deploy/com.amoskys.esf-sensor.plist (see BUILD notes).
#
# Robustness: if any stage dies (eslogger crash, broken pipe, bridge error) the
# whole chain is torn down and rebuilt after a capped exponential backoff, so a
# transient failure never leaves the sensor silently dead.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 1

SENSOR="$ROOT/sensor/target/release/amoskys-sensor"
PY="$ROOT/amoskys-venv/bin/python"
LOG_DIR="$ROOT/logs"
mkdir -p "$LOG_DIR"
LOG="$LOG_DIR/esf_sensor.log"

# Load shipping credentials/config (AMOSKYS_SERVER, AMOSKYS_API_KEY, …) from .env.
set -a; [ -f "$ROOT/.env" ] && . "$ROOT/.env"; set +a
export PYTHONPATH="$ROOT/src:${PYTHONPATH:-}"

# --dry-run unless AMOSKYS_SERVER is set (never silently no-op, never crash-ship).
MODE="--dry-run"
[ -n "${AMOSKYS_SERVER:-}" ] && MODE="--ship"

# Events to witness. exec = the verdict path; fork/exit = the process tree.
ES_EVENTS="${AMOSKYS_ES_EVENTS:-exec fork exit}"

log() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $*" | tee -a "$LOG" >&2; }

[ "$(id -u)" -eq 0 ] || { log "FATAL: must run as root (ESF requires it). Use: sudo $0"; exit 1; }
[ -x "$SENSOR" ] || { log "FATAL: sensor binary missing — run: (cd sensor && cargo build --release)"; exit 1; }
[ -x "$PY" ] || { log "FATAL: venv python missing at $PY"; exit 1; }

# Clean teardown on signal.
CHILDPGID=""
trap 'log "shutting down"; [ -n "$CHILDPGID" ] && kill -TERM -"$CHILDPGID" 2>/dev/null; exit 0' TERM INT

log "AMOSKYS ESF sensor starting — events=[$ES_EVENTS] mode=$MODE server=${AMOSKYS_SERVER:-<none>}"

backoff=1
while true; do
    start=$(date +%s)
    # Run the whole chain in its own process group so we can tear it down atomically.
    set -m
    ( eslogger $ES_EVENTS | "$SENSOR" | "$PY" -m amoskys.sensor.esf_bridge "$MODE" ) \
        >>"$LOG" 2>&1 &
    CHILDPGID=$!
    wait "$CHILDPGID"
    rc=$?
    ran=$(( $(date +%s) - start ))

    # A run that lasted a while is a transient failure → reset backoff.
    if [ "$ran" -ge 30 ]; then backoff=1; fi
    log "pipeline exited (rc=$rc, ran=${ran}s) — restarting in ${backoff}s"
    sleep "$backoff"
    backoff=$(( backoff < 30 ? backoff * 2 : 30 ))
done
