#!/usr/bin/env bash
# AMOSKYS Mac Lab Gate Check
# Run this before ANY production deploy. All checks must pass.
# Usage: ./scripts/lab_check.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PASS=0
FAIL=0
TOTAL=0

check() {
  local label="$1"
  shift
  TOTAL=$((TOTAL + 1))
  echo -n "  [$TOTAL] $label ... "
  if "$@" > /dev/null 2>&1; then
    echo "✅"
    PASS=$((PASS + 1))
  else
    echo "❌"
    FAIL=$((FAIL + 1))
  fi
}

echo "╔════════════════════════════════════════════════════╗"
echo "║       AMOSKYS MAC LAB — PRE-DEPLOY GATE CHECK     ║"
echo "╚════════════════════════════════════════════════════╝"
echo ""

# Activate venv
if [ -f "amoskys-venv/bin/activate" ]; then
  # shellcheck source=/dev/null
  source amoskys-venv/bin/activate
else
  echo "❌ amoskys-venv not found. Run: python3 -m venv amoskys-venv"
  exit 1
fi

export PYTHONPATH=src

# ── 1. Code-level sanity ──────────────────────────────────────────
echo "── Step 1: Code Sanity ──"

check "Proto imports" \
  python -c "from amoskys.proto import messaging_schema_pb2, universal_telemetry_pb2"

check "Entry point: amoskys-procagent" \
  python -c "from amoskys.agents.shared.process.agent_v3 import main"

check "Entry point: amoskys-authguard" \
  python -c "from amoskys.agents.shared.auth.agent_v2 import main"

check "Entry point: amoskys-eventbus" \
  python -c "from amoskys.eventbus.server import serve"

# ── 2. Agent selftest ─────────────────────────────────────────────
echo ""
echo "── Step 2: Agent Selftest ──"

if [ -f "scripts/selftest.py" ]; then
  check "Selftest: Trinity agents" \
    python scripts/selftest.py --trinity
else
  echo "  ⚠️  scripts/selftest.py not found, skipping"
fi

# ── 3. Unit tests (critical modules) ─────────────────────────────
echo ""
echo "── Step 3: Unit Tests (P1 critical) ──"

check "HardenedAgentBase tests" \
  python -m pytest tests/unit/agents/common/test_hardened_base.py -q --tb=no

check "Threat detection tests" \
  python -m pytest tests/unit/agents/common/test_threat_detection.py -q --tb=no

check "EventBus core tests" \
  python -m pytest tests/unit/eventbus/test_eventbus_core.py -q --tb=no

# ── 4. Full unit test suite ───────────────────────────────────────
echo ""
echo "── Step 4: Full Unit + Agent Tests ──"

check "All unit tests" \
  python -m pytest tests/unit/ -q --tb=no

check "All agent tests" \
  python -m pytest tests/agents/ -q --tb=no -k "not test_flow_probes"

# ── 5. Queue validation (if lab data exists) ──────────────────────
echo ""
echo "── Step 5: Lab Queue Validation ──"

LAB_QUEUE_ROOT="$ROOT/.amoskys_lab/queues"
if [ -d "$LAB_QUEUE_ROOT" ] && find "$LAB_QUEUE_ROOT" -name "*.db" 2>/dev/null | grep -q .; then
  check "Queue data validates" \
    python scripts/validate_queue_data.py --queue-root "$LAB_QUEUE_ROOT" --samples 3
else
  echo "  ℹ️  No lab queue data found (run run_trinity_local.sh first)"
fi

# ── Summary ───────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════════"
if [ "$FAIL" -eq 0 ]; then
  echo "  ✅ ALL $PASS/$TOTAL CHECKS PASSED"
  echo "  → Safe to deploy to production."
  echo "══════════════════════════════════════════════════════"
  exit 0
else
  echo "  ❌ $FAIL/$TOTAL CHECKS FAILED ($PASS passed)"
  echo "  → DO NOT deploy to production."
  echo "══════════════════════════════════════════════════════"
  exit 1
fi
