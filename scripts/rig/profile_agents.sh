#!/usr/bin/env bash
# filepath: /Users/athanneeru/Downloads/GitHub/Amoskys/scripts/rig/profile_agents.sh
# ────────────────────────────────────────────────────────────────────
# AMOSKYS Agent Resource Profiler — Phase 5 Operational Readiness
#
# Profiles CPU, RSS, open FDs, thread count for each Trinity agent
# over a configurable window. Outputs CSV + summary.
#
# Usage:
#   ./scripts/rig/profile_agents.sh              # 5-minute profile
#   ./scripts/rig/profile_agents.sh --duration 2  # 2-minute profile
#   ./scripts/rig/profile_agents.sh --sample 10   # Sample every 10s
# ────────────────────────────────────────────────────────────────────
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

DURATION_MINUTES=5
SAMPLE_INTERVAL=15

while [[ $# -gt 0 ]]; do
  case "$1" in
    --duration) DURATION_MINUTES="$2"; shift 2 ;;
    --sample)   SAMPLE_INTERVAL="$2";  shift 2 ;;
    *)          echo "Unknown option: $1"; exit 1 ;;
  esac
done

TOTAL_SECONDS=$((DURATION_MINUTES * 60))
NUM_SAMPLES=$((TOTAL_SECONDS / SAMPLE_INTERVAL + 1))
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_DIR="$ROOT/.amoskys_lab/profile_results/$TIMESTAMP"
mkdir -p "$RESULTS_DIR"

# ── Load env ──────────────────────────────────────────────────────
if [ -f "configs/trinity.local.env" ]; then
  source "configs/trinity.local.env"
else
  export AMOSKYS_DATA_ROOT="$ROOT/.amoskys_lab"
  export AMOSKYS_QUEUE_ROOT="$AMOSKYS_DATA_ROOT/queues"
  export AMOSKYS_LOG_ROOT="$AMOSKYS_DATA_ROOT/logs"
  export AMOSKYS_DEVICE_ID="mac-akash"
fi

mkdir -p "$AMOSKYS_QUEUE_ROOT"/{kernel_audit,protocol_collectors,device_discovery}
mkdir -p "$AMOSKYS_LOG_ROOT"

if [ -f "amoskys-venv/bin/activate" ]; then
  source amoskys-venv/bin/activate
fi
export PYTHONPATH=src

echo "╔════════════════════════════════════════════════════════════╗"
echo "║          AMOSKYS Agent Resource Profiler                  ║"
echo "╠════════════════════════════════════════════════════════════╣"
echo "║  Duration:     ${DURATION_MINUTES} minutes                              ║"
echo "║  Sample every: ${SAMPLE_INTERVAL}s (${NUM_SAMPLES} samples)                         ║"
echo "║  Results:      $RESULTS_DIR"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# ── Launch agents ─────────────────────────────────────────────────
KA_EXTRA_ARGS=""
[[ "$(uname -s)" == "Darwin" ]] && KA_EXTRA_ARGS="--audit-log-path=/dev/null"

python3 -m amoskys.agents.os.linux.kernel_audit.run_agent_v2 \
  --device-id="$AMOSKYS_DEVICE_ID" \
  --queue-path="$AMOSKYS_QUEUE_ROOT/kernel_audit" \
  --collection-interval=30 --metrics-interval=60 --log-level=INFO \
  $KA_EXTRA_ARGS \
  > "$AMOSKYS_LOG_ROOT/kernel_audit.log" 2>&1 &
KA_PID=$!

python3 -m amoskys.agents.os.macos.protocol_collectors.run_agent_v2 \
  --device-id="$AMOSKYS_DEVICE_ID" \
  --queue-path="$AMOSKYS_QUEUE_ROOT/protocol_collectors" \
  --collection-interval=30 --metrics-interval=60 --log-level=INFO \
  > "$AMOSKYS_LOG_ROOT/protocol_collectors.log" 2>&1 &
PC_PID=$!

python3 -m amoskys.agents.os.macos.discovery.run_agent_v2 \
  --device-id="$AMOSKYS_DEVICE_ID" \
  --queue-path="$AMOSKYS_QUEUE_ROOT/device_discovery" \
  --collection-interval=30 --metrics-interval=60 --log-level=INFO \
  > "$AMOSKYS_LOG_ROOT/device_discovery.log" 2>&1 &
DD_PID=$!

echo "Agents: KA=$KA_PID  PC=$PC_PID  DD=$DD_PID"
echo ""

cleanup() {
  echo ""
  echo "Stopping agents..."
  kill "$KA_PID" "$PC_PID" "$DD_PID" 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup INT TERM EXIT

# ── Profile function (macOS-compatible) ───────────────────────────
get_profile() {
  local pid=$1
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "DEAD,0,0,0,0"
    return
  fi
  local rss cpu fds threads
  rss=$(ps -o rss= -p "$pid" 2>/dev/null | tr -d ' ' || echo "0")
  cpu=$(ps -o %cpu= -p "$pid" 2>/dev/null | tr -d ' ' || echo "0")
  fds=$(lsof -p "$pid" 2>/dev/null | wc -l | tr -d ' ' || echo "0")
  if [[ "$(uname -s)" == "Darwin" ]]; then
    threads=$(ps -M -p "$pid" 2>/dev/null | tail -n +2 | wc -l | tr -d ' ' || echo "1")
  else
    threads=$(ls /proc/"$pid"/task 2>/dev/null | wc -l || echo "1")
  fi
  echo "ALIVE,$rss,$cpu,$fds,$threads"
}

# ── CSV files ─────────────────────────────────────────────────────
for agent in kernel_audit protocol_collectors device_discovery; do
  echo "elapsed_s,status,rss_kb,cpu_pct,open_fds,threads" > "$RESULTS_DIR/${agent}_profile.csv"
done

# ── Sample loop ──────────────────────────────────────────────────
echo "Profiling..."

for ((i=0; i<NUM_SAMPLES; i++)); do
  ELAPSED=$((i * SAMPLE_INTERVAL))
  MINS=$((ELAPSED / 60)); SECS=$((ELAPSED % 60))
  LINE=""

  for agent in kernel_audit protocol_collectors device_discovery; do
    case $agent in
      kernel_audit)        pid=$KA_PID ;;
      protocol_collectors) pid=$PC_PID ;;
      device_discovery)    pid=$DD_PID ;;
    esac
    profile=$(get_profile "$pid")
    echo "$ELAPSED,$profile" >> "$RESULTS_DIR/${agent}_profile.csv"
    rss=$(echo "$profile" | cut -d, -f2)
    cpu=$(echo "$profile" | cut -d, -f3)
    LINE="$LINE  ${agent:0:2}=${rss}KB/${cpu}%"
  done

  printf "  [%02d:%02d]%s\n" "$MINS" "$SECS" "$LINE"

  if [ $i -lt $((NUM_SAMPLES - 1)) ]; then
    sleep "$SAMPLE_INTERVAL"
  fi
done

echo ""

# ── Summary ──────────────────────────────────────────────────────
echo "═══════════════════════════════════════════════════════"
echo "  AGENT RESOURCE PROFILE SUMMARY"
echo "═══════════════════════════════════════════════════════"
echo ""

for agent in kernel_audit protocol_collectors device_discovery; do
  CSV="$RESULTS_DIR/${agent}_profile.csv"
  MAX_RSS=$(tail -n +2 "$CSV" | cut -d, -f3 | sort -n | tail -1)
  FIRST_RSS=$(tail -n +2 "$CSV" | head -1 | cut -d, -f3)
  LAST_RSS=$(tail -n +2 "$CSV" | tail -1 | cut -d, -f3)
  DELTA=$((LAST_RSS - FIRST_RSS))
  MAX_CPU=$(tail -n +2 "$CSV" | cut -d, -f4 | sort -n | tail -1)
  MAX_FDS=$(tail -n +2 "$CSV" | cut -d, -f5 | sort -n | tail -1)
  MAX_THREADS=$(tail -n +2 "$CSV" | cut -d, -f6 | sort -n | tail -1)

  echo "  $agent:"
  echo "    RSS:     ${FIRST_RSS} → ${LAST_RSS} KB (Δ ${DELTA} KB, max ${MAX_RSS} KB)"
  echo "    CPU:     max ${MAX_CPU}%"
  echo "    FDs:     max ${MAX_FDS}"
  echo "    Threads: max ${MAX_THREADS}"
  echo ""
done

echo "  CSVs saved to: $RESULTS_DIR/"
echo "═══════════════════════════════════════════════════════"
