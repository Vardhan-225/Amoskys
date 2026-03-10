#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Load local env if present
if [ -f "configs/trinity.local.env" ]; then
  # shellcheck source=/dev/null
  source "configs/trinity.local.env"
else
  export AMOSKYS_DATA_ROOT="$ROOT/.amoskys_lab"
  export AMOSKYS_QUEUE_ROOT="$AMOSKYS_DATA_ROOT/queues"
  export AMOSKYS_LOG_ROOT="$AMOSKYS_DATA_ROOT/logs"
  export AMOSKYS_DRAIN_ROOT="$AMOSKYS_DATA_ROOT/drained"
  export AMOSKYS_DEVICE_ID="mac-akash"
fi

# Ensure directories exist
mkdir -p "$AMOSKYS_QUEUE_ROOT"/{kernel_audit,protocol_collectors,device_discovery}
mkdir -p "$AMOSKYS_LOG_ROOT"
if [ -n "${AMOSKYS_DRAIN_ROOT:-}" ]; then
  mkdir -p "$AMOSKYS_DRAIN_ROOT"
fi

echo "╔════════════════════════════════════════════════════╗"
echo "║           AMOSKYS MAC LAB - TRINITY LAUNCH        ║"
echo "╚════════════════════════════════════════════════════╝"
echo "  Repo Root:        $ROOT"
echo "  Device ID:        $AMOSKYS_DEVICE_ID"
echo "  Queue Root:       $AMOSKYS_QUEUE_ROOT"
echo "  Log Root:         $AMOSKYS_LOG_ROOT"
echo "  Drain Root:       ${AMOSKYS_DRAIN_ROOT:-<not set>}"
echo ""

# Activate venv if present
if [ -f "amoskys-venv/bin/activate" ]; then
  # shellcheck source=/dev/null
  source amoskys-venv/bin/activate
else
  echo "⚠️  Warning: amoskys-venv not found, using system python"
fi

export PYTHONPATH=src

# Detect OS — macOS agents use stub collectors (no auditd, no /proc)
IS_MAC=false
if [[ "$(uname -s)" == "Darwin" ]]; then
  IS_MAC=true
  echo "  Platform:         macOS (stub collectors enabled)"
else
  echo "  Platform:         $(uname -s)"
fi
echo ""

echo "Starting Trinity agents..."
echo ""

# Run as modules (-m) to avoid types.py shadowing stdlib types module.
# When run as a script, Python adds the script's directory to sys.path,
# and kernel_audit/types.py or protocol_collectors/agent_types.py shadows
# the stdlib 'types' module, crashing the import chain.

# Kernel audit — on macOS, audit log doesn't exist but collector handles gracefully
KA_EXTRA_ARGS=""
if $IS_MAC; then
  KA_EXTRA_ARGS="--audit-log-path=/dev/null"
fi
python3 -m amoskys.agents.os.linux.kernel_audit.run_agent_v2 \
  --device-id="$AMOSKYS_DEVICE_ID" \
  --queue-path="$AMOSKYS_QUEUE_ROOT/kernel_audit" \
  --collection-interval=30 \
  --metrics-interval=60 \
  --log-level=INFO \
  $KA_EXTRA_ARGS \
  > "$AMOSKYS_LOG_ROOT/kernel_audit.log" 2>&1 &

KA_PID=$!

# Protocol collectors — use_stub=True is set in launcher for mac lab
python3 -m amoskys.agents.shared.protocol_collectors.run_agent_v2 \
  --device-id="$AMOSKYS_DEVICE_ID" \
  --queue-path="$AMOSKYS_QUEUE_ROOT/protocol_collectors" \
  --collection-interval=30 \
  --metrics-interval=60 \
  --log-level=INFO \
  > "$AMOSKYS_LOG_ROOT/protocol_collectors.log" 2>&1 &

PC_PID=$!

# Device discovery — ARP probes fail gracefully on macOS (no ip neigh, no /proc)
python3 -m amoskys.agents.shared.device_discovery.run_agent_v2 \
  --device-id="$AMOSKYS_DEVICE_ID" \
  --queue-path="$AMOSKYS_QUEUE_ROOT/device_discovery" \
  --collection-interval=30 \
  --metrics-interval=60 \
  --log-level=INFO \
  > "$AMOSKYS_LOG_ROOT/device_discovery.log" 2>&1 &

DD_PID=$!

echo "KernelAudit PID:        $KA_PID"
echo "ProtocolCollectors PID: $PC_PID"
echo "DeviceDiscovery PID:    $DD_PID"
echo ""
echo "Logs:"
echo "  $AMOSKYS_LOG_ROOT/kernel_audit.log"
echo "  $AMOSKYS_LOG_ROOT/protocol_collectors.log"
echo "  $AMOSKYS_LOG_ROOT/device_discovery.log"
echo ""
echo "Use Ctrl+C to stop all agents."

cleanup() {
  echo ""
  echo "Stopping agents..."
  kill "$KA_PID" "$PC_PID" "$DD_PID" 2>/dev/null || true
  wait || true
  echo "Agents stopped."
  exit 0
}

trap cleanup INT TERM

# Wait for all children
wait
