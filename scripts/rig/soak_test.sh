#!/usr/bin/env bash
# filepath: /Users/athanneeru/Downloads/GitHub/Amoskys/scripts/rig/soak_test.sh
# ────────────────────────────────────────────────────────────────────
# AMOSKYS CL-23 Soak Test — 10-minute Trinity agent RSS monitoring
#
# Purpose: Prove 3 Trinity agents run concurrently for 10+ minutes
#          on macOS without memory leak or crash.
#
# Success criteria:
#   - All 3 agents alive at end of soak window
#   - RSS growth < 10 MB per agent over soak duration
#   - 0 crashes / 0 Python tracebacks in logs
#   - Queue DBs remain readable (no corruption)
#
# Usage:
#   ./scripts/rig/soak_test.sh              # 10-minute soak (default)
#   ./scripts/rig/soak_test.sh --duration 5 # 5-minute soak
#   ./scripts/rig/soak_test.sh --sample 30  # Sample RSS every 30s
# ────────────────────────────────────────────────────────────────────
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# ── Defaults ──────────────────────────────────────────────────────
DURATION_MINUTES=10
SAMPLE_INTERVAL=60   # seconds between RSS samples
RESULTS_DIR="$ROOT/.amoskys_lab/soak_results"

# ── Parse CLI ─────────────────────────────────────────────────────
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
RUN_DIR="$RESULTS_DIR/$TIMESTAMP"
mkdir -p "$RUN_DIR"

# ── Load env ──────────────────────────────────────────────────────
if [ -f "configs/trinity.local.env" ]; then
  source "configs/trinity.local.env"
else
  export AMOSKYS_DATA_ROOT="$ROOT/.amoskys_lab"
  export AMOSKYS_QUEUE_ROOT="$AMOSKYS_DATA_ROOT/queues"
  export AMOSKYS_LOG_ROOT="$AMOSKYS_DATA_ROOT/logs"
  export AMOSKYS_DEVICE_ID="mac-akash"
fi

# Fresh log dir for this soak run
SOAK_LOG_DIR="$RUN_DIR/logs"
mkdir -p "$SOAK_LOG_DIR"
mkdir -p "$AMOSKYS_QUEUE_ROOT"/{kernel_audit,protocol_collectors,device_discovery}

# ── Activate venv ─────────────────────────────────────────────────
if [ -f "amoskys-venv/bin/activate" ]; then
  source amoskys-venv/bin/activate
fi
export PYTHONPATH=src

echo "╔════════════════════════════════════════════════════════════╗"
echo "║          AMOSKYS CL-23 SOAK TEST                         ║"
echo "╠════════════════════════════════════════════════════════════╣"
echo "║  Duration:     ${DURATION_MINUTES} minutes                              ║"
echo "║  Sample every: ${SAMPLE_INTERVAL}s (${NUM_SAMPLES} samples)                         ║"
echo "║  Results:      $RUN_DIR"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# ── Launch Trinity agents ─────────────────────────────────────────
KA_EXTRA_ARGS=""
if [[ "$(uname -s)" == "Darwin" ]]; then
  KA_EXTRA_ARGS="--audit-log-path=/dev/null"
fi

python3 -m amoskys.agents.kernel_audit.run_agent_v2 \
  --device-id="$AMOSKYS_DEVICE_ID" \
  --queue-path="$AMOSKYS_QUEUE_ROOT/kernel_audit" \
  --collection-interval=30 --metrics-interval=60 --log-level=INFO \
  $KA_EXTRA_ARGS \
  > "$SOAK_LOG_DIR/kernel_audit.log" 2>&1 &
KA_PID=$!

python3 -m amoskys.agents.protocol_collectors.run_agent_v2 \
  --device-id="$AMOSKYS_DEVICE_ID" \
  --queue-path="$AMOSKYS_QUEUE_ROOT/protocol_collectors" \
  --collection-interval=30 --metrics-interval=60 --log-level=INFO \
  > "$SOAK_LOG_DIR/protocol_collectors.log" 2>&1 &
PC_PID=$!

python3 -m amoskys.agents.device_discovery.run_agent_v2 \
  --device-id="$AMOSKYS_DEVICE_ID" \
  --queue-path="$AMOSKYS_QUEUE_ROOT/device_discovery" \
  --collection-interval=30 --metrics-interval=60 --log-level=INFO \
  > "$SOAK_LOG_DIR/device_discovery.log" 2>&1 &
DD_PID=$!

# Initial RSS (set on first sample)
KA_INIT_RSS=0; PC_INIT_RSS=0; DD_INIT_RSS=0

echo "Agents launched:"
echo "  KernelAudit PID:        $KA_PID"
echo "  ProtocolCollectors PID: $PC_PID"
echo "  DeviceDiscovery PID:    $DD_PID"
echo ""

# ── RSS sampling function ─────────────────────────────────────────
get_rss_kb() {
  # macOS ps reports RSS in KB
  local pid=$1
  if kill -0 "$pid" 2>/dev/null; then
    ps -o rss= -p "$pid" 2>/dev/null | tr -d ' ' || echo "0"
  else
    echo "DEAD"
  fi
}

# ── CSV header ────────────────────────────────────────────────────
RSS_CSV="$RUN_DIR/rss_samples.csv"
echo "elapsed_s,kernel_audit_rss_kb,protocol_collectors_rss_kb,device_discovery_rss_kb" > "$RSS_CSV"

# ── Cleanup handler ──────────────────────────────────────────────
cleanup() {
  echo ""
  echo "Stopping agents..."
  kill "$KA_PID" "$PC_PID" "$DD_PID" 2>/dev/null || true
  wait 2>/dev/null || true
  echo "Agents stopped."
}
trap cleanup INT TERM EXIT

# ── Track dead agents ────────────────────────────────────────────
KA_DEAD=false; PC_DEAD=false; DD_DEAD=false
DEAD_COUNT=0

# ── Sample loop ──────────────────────────────────────────────────
echo "Sampling RSS every ${SAMPLE_INTERVAL}s for ${DURATION_MINUTES} minutes..."
echo ""

START_TIME=$(date +%s)

for ((i=0; i<NUM_SAMPLES; i++)); do
  ELAPSED=$((i * SAMPLE_INTERVAL))
  
  KA_RSS=$(get_rss_kb "$KA_PID")
  PC_RSS=$(get_rss_kb "$PC_PID")
  DD_RSS=$(get_rss_kb "$DD_PID")
  
  # Record post-warmup RSS for delta calculation (skip first 2 samples for startup)
  WARMUP_SAMPLES=2
  if [ $i -eq $WARMUP_SAMPLES ]; then
    KA_INIT_RSS=$KA_RSS; PC_INIT_RSS=$PC_RSS; DD_INIT_RSS=$DD_RSS
  fi
  
  # Check for dead agents
  if [[ "$KA_RSS" == "DEAD" && "$KA_DEAD" == "false" ]]; then
    KA_DEAD=true; DEAD_COUNT=$((DEAD_COUNT + 1))
    echo "  ⚠️  kernel_audit (PID $KA_PID) DIED at ${ELAPSED}s!"
  fi
  if [[ "$PC_RSS" == "DEAD" && "$PC_DEAD" == "false" ]]; then
    PC_DEAD=true; DEAD_COUNT=$((DEAD_COUNT + 1))
    echo "  ⚠️  protocol_collectors (PID $PC_PID) DIED at ${ELAPSED}s!"
  fi
  if [[ "$DD_RSS" == "DEAD" && "$DD_DEAD" == "false" ]]; then
    DD_DEAD=true; DEAD_COUNT=$((DEAD_COUNT + 1))
    echo "  ⚠️  device_discovery (PID $DD_PID) DIED at ${ELAPSED}s!"
  fi
  
  echo "$ELAPSED,$KA_RSS,$PC_RSS,$DD_RSS" >> "$RSS_CSV"
  
  # Progress display
  MINS=$((ELAPSED / 60))
  SECS=$((ELAPSED % 60))
  printf "  [%02d:%02d] KA=%s KB  PC=%s KB  DD=%s KB\n" \
    "$MINS" "$SECS" "$KA_RSS" "$PC_RSS" "$DD_RSS"
  
  # Don't sleep after the last sample
  if [ $i -lt $((NUM_SAMPLES - 1)) ]; then
    sleep "$SAMPLE_INTERVAL"
  fi
done

END_TIME=$(date +%s)
ACTUAL_DURATION=$((END_TIME - START_TIME))

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  SOAK TEST RESULTS"
echo "═══════════════════════════════════════════════════════"
echo ""

# ── Check for crashes (tracebacks in logs) ────────────────────────
TRACEBACK_COUNT=0
for logfile in "$SOAK_LOG_DIR"/*.log; do
  [ -f "$logfile" ] || continue
  tb=$(grep -c "Traceback" "$logfile" 2>/dev/null || true)
  # Sanitize: strip whitespace, default to 0
  tb=$(echo "$tb" | tr -d '[:space:]')
  tb=${tb:-0}
  if [ "$tb" -gt 0 ] 2>/dev/null; then
    echo "  ❌ $(basename "$logfile"): $tb traceback(s) found"
    TRACEBACK_COUNT=$((TRACEBACK_COUNT + tb))
  fi
done

# ── Check queue DB integrity ─────────────────────────────────────
DB_ERRORS=0
for agent_name in kernel_audit protocol_collectors device_discovery; do
  db_path="$AMOSKYS_QUEUE_ROOT/$agent_name/${agent_name}_queue.db"
  if [ -f "$db_path" ]; then
    result=$(sqlite3 "$db_path" "SELECT COUNT(*) FROM queue" 2>&1) || true
    if [[ "$result" =~ ^[0-9]+$ ]]; then
      echo "  ✅ $agent_name queue: $result rows, DB readable"
    else
      echo "  ❌ $agent_name queue: DB corrupt — $result"
      DB_ERRORS=$((DB_ERRORS + 1))
    fi
  else
    echo "  ⚠️  $agent_name queue: DB not found at $db_path"
  fi
done

echo ""

# ── RSS delta analysis ────────────────────────────────────────────
FINAL_KA_RSS=$(tail -1 "$RSS_CSV" | cut -d, -f2)
FINAL_PC_RSS=$(tail -1 "$RSS_CSV" | cut -d, -f3)
FINAL_DD_RSS=$(tail -1 "$RSS_CSV" | cut -d, -f4)

RSS_PASS=true

check_rss() {
  local name=$1 init=$2 final=$3
  if [[ "$init" == "DEAD" || "$final" == "DEAD" ]]; then
    echo "  ❌ $name: Agent died during soak"
    RSS_PASS=false
    return
  fi
  local delta=$((final - init))
  local delta_mb=$((delta / 1024))
  if [ "$delta" -lt 10240 ]; then
    echo "  ✅ $name: RSS Δ = ${delta} KB (${delta_mb} MB) — within 10 MB limit"
  else
    echo "  ❌ $name: RSS Δ = ${delta} KB (${delta_mb} MB) — EXCEEDS 10 MB limit"
    RSS_PASS=false
  fi
}

check_rss "kernel_audit"        "$KA_INIT_RSS" "$FINAL_KA_RSS"
check_rss "protocol_collectors" "$PC_INIT_RSS" "$FINAL_PC_RSS"
check_rss "device_discovery"    "$DD_INIT_RSS" "$FINAL_DD_RSS"

echo ""

# ── Summary ──────────────────────────────────────────────────────
PASS_COUNT=0
FAIL_COUNT=0

# Check 1: All agents survived
if [ "$DEAD_COUNT" -eq 0 ]; then
  echo "  ✅ CHECK 1: All 3 agents alive at end of soak"
  PASS_COUNT=$((PASS_COUNT + 1))
else
  echo "  ❌ CHECK 1: $DEAD_COUNT agent(s) died"
  FAIL_COUNT=$((FAIL_COUNT + 1))
fi

# Check 2: RSS within bounds
if $RSS_PASS; then
  echo "  ✅ CHECK 2: RSS growth < 10 MB for all agents"
  PASS_COUNT=$((PASS_COUNT + 1))
else
  echo "  ❌ CHECK 2: RSS growth exceeded 10 MB limit"
  FAIL_COUNT=$((FAIL_COUNT + 1))
fi

# Check 3: No tracebacks
if [ "$TRACEBACK_COUNT" -eq 0 ]; then
  echo "  ✅ CHECK 3: 0 Python tracebacks in logs"
  PASS_COUNT=$((PASS_COUNT + 1))
else
  echo "  ❌ CHECK 3: $TRACEBACK_COUNT traceback(s) found in logs"
  FAIL_COUNT=$((FAIL_COUNT + 1))
fi

# Check 4: Queue DBs readable
if [ "$DB_ERRORS" -eq 0 ]; then
  echo "  ✅ CHECK 4: All queue DBs readable (no corruption)"
  PASS_COUNT=$((PASS_COUNT + 1))
else
  echo "  ❌ CHECK 4: $DB_ERRORS queue DB(s) corrupt"
  FAIL_COUNT=$((FAIL_COUNT + 1))
fi

echo ""
echo "═══════════════════════════════════════════════════════"

# ── Write result file ─────────────────────────────────────────────
RESULT_FILE="$RUN_DIR/RESULT.txt"
{
  echo "AMOSKYS CL-23 Soak Test"
  echo "Date: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo "Duration: ${ACTUAL_DURATION}s (target: ${TOTAL_SECONDS}s)"
  echo "Samples: $NUM_SAMPLES at ${SAMPLE_INTERVAL}s intervals"
  echo "Platform: $(uname -srm)"
  echo "Python: $(python3 --version 2>&1)"
  echo ""
  echo "Checks: $PASS_COUNT PASSED, $FAIL_COUNT FAILED (of 4)"
  echo ""
  echo "Dead agents: $DEAD_COUNT"
  echo "Tracebacks: $TRACEBACK_COUNT"
  echo "DB errors: $DB_ERRORS"
  echo ""
  echo "RSS CSV: $RSS_CSV"
  echo "Agent logs: $SOAK_LOG_DIR/"
} > "$RESULT_FILE"

if [ "$FAIL_COUNT" -eq 0 ]; then
  echo "  🟢 CL-23 SOAK TEST: ALL 4 CHECKS PASSED"
  echo "═══════════════════════════════════════════════════════"
  echo ""
  echo "Results saved to: $RUN_DIR/"
  exit 0
else
  echo "  🔴 CL-23 SOAK TEST: $FAIL_COUNT CHECK(S) FAILED"
  echo "═══════════════════════════════════════════════════════"
  echo ""
  echo "Results saved to: $RUN_DIR/"
  exit 1
fi
