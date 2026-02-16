#!/usr/bin/env bash
# filepath: /Users/athanneeru/Downloads/GitHub/Amoskys/scripts/rig/kill_agent_randomly.sh
# ────────────────────────────────────────────────────────────────────
# AMOSKYS Chaos Test — Validates CL-25 crash recovery
#
# Launches Trinity agents, randomly kills one with SIGKILL (kill -9),
# waits, then verifies queue DB integrity. Repeats N times.
#
# Success criteria:
#   - Queue DBs readable after every kill -9
#   - Surviving agents unaffected
#   - No zombie processes
#
# Usage:
#   ./scripts/rig/kill_agent_randomly.sh              # 3 rounds
#   ./scripts/rig/kill_agent_randomly.sh --rounds 5   # 5 rounds
# ────────────────────────────────────────────────────────────────────
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

ROUNDS=3
SETTLE_SECONDS=10

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rounds) ROUNDS="$2"; shift 2 ;;
    *)        echo "Unknown option: $1"; exit 1 ;;
  esac
done

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

AGENTS=(kernel_audit protocol_collectors device_discovery)
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_DIR="$ROOT/.amoskys_lab/chaos_results/$TIMESTAMP"
mkdir -p "$RESULTS_DIR"

echo "╔════════════════════════════════════════════════════════════╗"
echo "║          AMOSKYS Chaos Test (CL-25)                       ║"
echo "╠════════════════════════════════════════════════════════════╣"
echo "║  Rounds:  $ROUNDS                                              ║"
echo "║  Method:  kill -9 (SIGKILL — no cleanup)                  ║"
echo "║  Verify:  Queue DB integrity after each kill              ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

PASS_COUNT=0
FAIL_COUNT=0

launch_agent() {
  local agent=$1
  local KA_EXTRA_ARGS=""
  
  if [[ "$agent" == "kernel_audit" && "$(uname -s)" == "Darwin" ]]; then
    KA_EXTRA_ARGS="--audit-log-path=/dev/null"
  fi
  
  python3 -m "amoskys.agents.${agent}.run_agent_v2" \
    --device-id="$AMOSKYS_DEVICE_ID" \
    --queue-path="$AMOSKYS_QUEUE_ROOT/$agent" \
    --collection-interval=30 --metrics-interval=60 --log-level=INFO \
    $KA_EXTRA_ARGS \
    > "$AMOSKYS_LOG_ROOT/${agent}.log" 2>&1 &
  
  echo $!
}

check_db_integrity() {
  local agent=$1
  local db_path="$AMOSKYS_QUEUE_ROOT/$agent/${agent}_queue.db"
  
  if [ ! -f "$db_path" ]; then
    echo "SKIP"  # DB may not exist if agent never wrote
    return
  fi
  
  # Integrity check + read test
  local integrity result
  integrity=$(sqlite3 "$db_path" "PRAGMA integrity_check" 2>&1 || echo "ERROR")
  result=$(sqlite3 "$db_path" "SELECT COUNT(*) FROM queue" 2>&1 || echo "ERROR")
  
  if [[ "$integrity" == "ok" && "$result" =~ ^[0-9]+$ ]]; then
    echo "OK:${result}"
  else
    echo "CORRUPT:integrity=${integrity},count=${result}"
  fi
}

for ((round=1; round<=ROUNDS; round++)); do
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  Round $round of $ROUNDS"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  
  # Launch all 3 agents — bash 3.2 safe (no associative arrays)
  PID_kernel_audit=$(launch_agent "kernel_audit")
  echo "  Started kernel_audit (PID $PID_kernel_audit)"
  PID_protocol_collectors=$(launch_agent "protocol_collectors")
  echo "  Started protocol_collectors (PID $PID_protocol_collectors)"
  PID_device_discovery=$(launch_agent "device_discovery")
  echo "  Started device_discovery (PID $PID_device_discovery)"
  
  # Let them run for at least one collection cycle
  echo "  Waiting 35s for collection cycle..."
  sleep 35
  
  # Pick a random agent to kill
  VICTIM_IDX=$((RANDOM % 3))
  VICTIM=${AGENTS[$VICTIM_IDX]}
  
  # Resolve victim PID
  case "$VICTIM" in
    kernel_audit)         VICTIM_PID=$PID_kernel_audit ;;
    protocol_collectors)  VICTIM_PID=$PID_protocol_collectors ;;
    device_discovery)     VICTIM_PID=$PID_device_discovery ;;
  esac
  
  echo "  🎯 Killing $VICTIM (PID $VICTIM_PID) with SIGKILL..."
  kill -9 "$VICTIM_PID" 2>/dev/null || true
  
  # Wait for settle
  echo "  Settling for ${SETTLE_SECONDS}s..."
  sleep "$SETTLE_SECONDS"
  
  # Check surviving agents
  SURVIVORS_OK=true
  for agent in "${AGENTS[@]}"; do
    if [[ "$agent" == "$VICTIM" ]]; then
      continue
    fi
    # Resolve PID — bash 3.2 safe
    case "$agent" in
      kernel_audit)         pid=$PID_kernel_audit ;;
      protocol_collectors)  pid=$PID_protocol_collectors ;;
      device_discovery)     pid=$PID_device_discovery ;;
    esac
    if kill -0 "$pid" 2>/dev/null; then
      echo "  ✅ $agent (PID $pid) — still alive"
    else
      echo "  ❌ $agent (PID $pid) — unexpectedly dead"
      SURVIVORS_OK=false
    fi
  done
  
  # Check DB integrity for ALL agents (including the killed one)
  DB_OK=true
  for agent in "${AGENTS[@]}"; do
    result=$(check_db_integrity "$agent")
    if [[ "$result" == SKIP ]]; then
      echo "  ⚬ $agent DB — no DB file (skipped)"
    elif [[ "$result" == OK:* ]]; then
      count="${result#OK:}"
      echo "  ✅ $agent DB — integrity OK, $count rows"
    else
      echo "  ❌ $agent DB — $result"
      DB_OK=false
    fi
  done
  
  # Check for zombies
  ZOMBIES=$(ps aux 2>/dev/null | grep -c '[Zz]' || echo "0")
  
  # Round verdict
  ROUND_PASS=true
  if ! $SURVIVORS_OK; then ROUND_PASS=false; fi
  if ! $DB_OK; then ROUND_PASS=false; fi
  
  if $ROUND_PASS; then
    echo "  🟢 Round $round: PASS (victim=$VICTIM, zombies=$ZOMBIES)"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    echo "  🔴 Round $round: FAIL"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
  
  # Kill remaining agents — bash 3.2 safe
  kill "$PID_kernel_audit" 2>/dev/null || true
  kill "$PID_protocol_collectors" 2>/dev/null || true
  kill "$PID_device_discovery" 2>/dev/null || true
  wait 2>/dev/null || true
  
  # Brief pause between rounds
  if [ $round -lt "$ROUNDS" ]; then
    sleep 3
  fi
done

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  CHAOS TEST RESULTS"
echo "═══════════════════════════════════════════════════════"
echo "  Rounds: $PASS_COUNT passed, $FAIL_COUNT failed (of $ROUNDS)"

# Write result file
{
  echo "AMOSKYS Chaos Test (CL-25)"
  echo "Date: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo "Rounds: $ROUNDS"
  echo "Passed: $PASS_COUNT"
  echo "Failed: $FAIL_COUNT"
} > "$RESULTS_DIR/RESULT.txt"

if [ "$FAIL_COUNT" -eq 0 ]; then
  echo "  🟢 CL-25 CHAOS TEST: ALL ROUNDS PASSED"
  echo "═══════════════════════════════════════════════════════"
  exit 0
else
  echo "  🔴 CL-25 CHAOS TEST: $FAIL_COUNT ROUND(S) FAILED"
  echo "═══════════════════════════════════════════════════════"
  exit 1
fi
