#!/bin/bash
#
# AMOSKYS Full-Stack Dev Launcher
# Starts: EventBus -> WAL Processor -> All 10 Agents -> Flask Dashboard
# Usage:  bash scripts/dev_fullstack.sh
# Stop:   Ctrl+C (kills all child processes)
#

set -euo pipefail

# ── Resolve project root ──────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

# ── Environment ───────────────────────────────────────────────
export PYTHONPATH="$PROJECT_ROOT/src:${PYTHONPATH:-}"
export FLASK_DEBUG=true
export FLASK_ENV=development
export LOG_LEVEL=INFO
export SECRET_KEY="${SECRET_KEY:-dev-only-not-for-production-key-$(date +%s)-amoskys}"

# ── Colors ────────────────────────────────────────────────────
C_CYAN='\033[0;36m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[0;33m'
C_RED='\033[0;31m'
C_BOLD='\033[1m'
C_RESET='\033[0m'

info()  { echo -e "${C_CYAN}[INFO]${C_RESET}  $*"; }
ok()    { echo -e "${C_GREEN}[OK]${C_RESET}    $*"; }
warn()  { echo -e "${C_YELLOW}[WARN]${C_RESET}  $*"; }
fail()  { echo -e "${C_RED}[FAIL]${C_RESET}  $*"; }

# ── Ensure directories ────────────────────────────────────────
mkdir -p data data/wal data/queue logs

# ── Track child PIDs for cleanup ──────────────────────────────
PIDS=()

cleanup() {
    echo ""
    info "Shutting down AMOSKYS stack..."
    for pid in "${PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    # Wait briefly, then force-kill stragglers
    sleep 1
    for pid in "${PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null || true
        fi
    done
    ok "All services stopped."
}

trap cleanup EXIT INT TERM

# ── Banner ────────────────────────────────────────────────────
echo ""
echo -e "${C_BOLD}${C_CYAN}============================================${C_RESET}"
echo -e "${C_BOLD}${C_CYAN}  AMOSKYS Full-Stack Dev Launcher${C_RESET}"
echo -e "${C_BOLD}${C_CYAN}============================================${C_RESET}"
echo ""
echo -e "  Project root: ${C_BOLD}$PROJECT_ROOT${C_RESET}"
echo -e "  Python:       ${C_BOLD}$(python3 --version 2>&1)${C_RESET}"
echo ""

# ── 1. Kill any existing services ─────────────────────────────
info "Checking for stale services..."
pkill -f "eventbus/server.py" 2>/dev/null && warn "Killed stale EventBus" || true
pkill -f "wal_processor" 2>/dev/null && warn "Killed stale WAL Processor" || true
pkill -f "amoskys.agents.shared.process" 2>/dev/null && warn "Killed stale ProcAgent" || true
pkill -f "amoskys.agents.shared.auth" 2>/dev/null && warn "Killed stale AuthAgent" || true
pkill -f "amoskys.agents.shared.dns" 2>/dev/null && warn "Killed stale DNSAgent" || true
pkill -f "amoskys.agents.shared.filesystem" 2>/dev/null && warn "Killed stale FIMAgent" || true
pkill -f "amoskys.agents.shared.network" 2>/dev/null && warn "Killed stale FlowAgent" || true
pkill -f "amoskys.agents.shared.persistence" 2>/dev/null && warn "Killed stale PersistenceAgent" || true
pkill -f "amoskys.agents.shared.peripheral" 2>/dev/null && warn "Killed stale PeripheralAgent" || true
pkill -f "kernel_audit/run_agent_v2" 2>/dev/null && warn "Killed stale KernelAuditAgent" || true
pkill -f "device_discovery/run_agent_v2" 2>/dev/null && warn "Killed stale DeviceDiscovery" || true
pkill -f "protocol_collectors/run_agent_v2" 2>/dev/null && warn "Killed stale ProtocolCollectors" || true
pkill -f "wsgi:app" 2>/dev/null && warn "Killed stale Dashboard" || true
pkill -f "wsgi.py --dev" 2>/dev/null && warn "Killed stale Dashboard (dev)" || true
sleep 1

# ── 2. Start EventBus ─────────────────────────────────────────
info "Starting EventBus (gRPC :50051)..."
python3 src/amoskys/eventbus/server.py > logs/eventbus.log 2>&1 &
EVENTBUS_PID=$!
PIDS+=($EVENTBUS_PID)
sleep 2

if kill -0 "$EVENTBUS_PID" 2>/dev/null; then
    ok "EventBus running (PID $EVENTBUS_PID)"
else
    fail "EventBus failed to start. Check logs/eventbus.log"
    tail -5 logs/eventbus.log 2>/dev/null || true
    exit 1
fi

# ── 3. Start WAL Processor ────────────────────────────────────
info "Starting WAL Processor..."
python3 -m amoskys.storage.wal_processor > logs/wal_processor.log 2>&1 &
WAL_PID=$!
PIDS+=($WAL_PID)
sleep 1

if kill -0 "$WAL_PID" 2>/dev/null; then
    ok "WAL Processor running (PID $WAL_PID)"
else
    warn "WAL Processor failed to start (non-fatal). Check logs/wal_processor.log"
fi

# ── 4. Seed initial data (single collection cycle) ────────────
info "Seeding initial telemetry (single collection cycle)..."
python3 -m amoskys.agents.shared.process --interval 1 --once --no-heartbeat --log-level WARNING > logs/proc_seed.log 2>&1 || warn "Proc seed had issues (non-fatal)"
python3 -m amoskys.agents.shared.auth --interval 1 --once --no-heartbeat --log-level WARNING > logs/auth_seed.log 2>&1 || warn "Auth seed had issues (non-fatal)"
python3 -m amoskys.agents.shared.filesystem --interval 1 --once --no-heartbeat --log-level WARNING > logs/fim_seed.log 2>&1 || warn "FIM seed had issues (non-fatal)"
ok "Initial telemetry seeded"

# ── 5. Start all 10 agents (continuous) ───────────────────────

# --- Standard agents (7) ---
info "Starting Proc Agent (15s interval)..."
python3 -m amoskys.agents.shared.process --interval 15 --no-heartbeat --log-level INFO > logs/proc_agent.log 2>&1 &
PROC_PID=$!
PIDS+=($PROC_PID)
ok "Proc Agent (PID $PROC_PID)"

info "Starting Auth Agent (15s interval)..."
python3 -m amoskys.agents.shared.auth --interval 15 --no-heartbeat --log-level INFO > logs/auth_agent.log 2>&1 &
AUTH_PID=$!
PIDS+=($AUTH_PID)
ok "Auth Agent (PID $AUTH_PID)"

info "Starting DNS Agent (20s interval)..."
python3 -m amoskys.agents.shared.dns --interval 20 --no-heartbeat --log-level INFO > logs/dns_agent.log 2>&1 &
DNS_PID=$!
PIDS+=($DNS_PID)
ok "DNS Agent (PID $DNS_PID)"

info "Starting FIM Agent (20s interval)..."
python3 -m amoskys.agents.shared.filesystem --interval 20 --no-heartbeat --log-level INFO > logs/fim_agent.log 2>&1 &
FIM_PID=$!
PIDS+=($FIM_PID)
ok "FIM Agent (PID $FIM_PID)"

info "Starting Flow Agent (20s interval)..."
python3 -m amoskys.agents.shared.network --interval 20 --no-heartbeat --log-level INFO > logs/flow_agent.log 2>&1 &
FLOW_PID=$!
PIDS+=($FLOW_PID)
ok "Flow Agent (PID $FLOW_PID)"

info "Starting Persistence Agent (20s interval)..."
python3 -m amoskys.agents.shared.persistence --interval 20 --no-heartbeat --log-level INFO > logs/persistence_agent.log 2>&1 &
PERSIST_PID=$!
PIDS+=($PERSIST_PID)
ok "Persistence Agent (PID $PERSIST_PID)"

info "Starting Peripheral Agent (20s interval)..."
python3 -m amoskys.agents.shared.peripheral --interval 20 --no-heartbeat --log-level INFO > logs/peripheral_agent.log 2>&1 &
PERIPH_PID=$!
PIDS+=($PERIPH_PID)
ok "Peripheral Agent (PID $PERIPH_PID)"

# --- Remaining agents (3) — same canonical pattern ---
info "Starting Kernel Audit Agent (30s interval)..."
python3 -m amoskys.agents.os.linux.kernel_audit --interval 30 --no-heartbeat --log-level INFO > logs/kernel_audit_agent.log 2>&1 &
KAUDIT_PID=$!
PIDS+=($KAUDIT_PID)
ok "Kernel Audit Agent (PID $KAUDIT_PID)"

info "Starting Device Discovery Agent (60s interval)..."
python3 -m amoskys.agents.shared.device_discovery --interval 60 --no-heartbeat --log-level INFO > logs/device_discovery_agent.log 2>&1 &
DISCO_PID=$!
PIDS+=($DISCO_PID)
ok "Device Discovery Agent (PID $DISCO_PID)"

info "Starting Protocol Collectors Agent (30s interval)..."
python3 -m amoskys.agents.shared.protocol_collectors --interval 30 --no-heartbeat --log-level INFO > logs/protocol_collectors_agent.log 2>&1 &
PROTO_PID=$!
PIDS+=($PROTO_PID)
ok "Protocol Collectors Agent (PID $PROTO_PID)"

sleep 1

# ── 6. Start Flask Dashboard (foreground) ─────────────────────
echo ""
echo -e "${C_BOLD}${C_GREEN}============================================${C_RESET}"
echo -e "${C_BOLD}${C_GREEN}  AMOSKYS Stack Ready  (10 agents)${C_RESET}"
echo -e "${C_BOLD}${C_GREEN}============================================${C_RESET}"
echo ""
echo -e "  ${C_BOLD}Dashboard:${C_RESET}          ${C_CYAN}http://localhost:5001/dashboard/cortex${C_RESET}"
echo -e "  ${C_BOLD}Agents Page:${C_RESET}        ${C_CYAN}http://localhost:5001/dashboard/agents${C_RESET}"
echo -e "  ${C_BOLD}Agent Monitor:${C_RESET}      ${C_CYAN}http://localhost:5001/dashboard/agent-monitor${C_RESET}"
echo -e "  ${C_BOLD}SOC Operations:${C_RESET}     ${C_CYAN}http://localhost:5001/dashboard/soc${C_RESET}"
echo -e "  ${C_BOLD}Threat Feed:${C_RESET}        ${C_CYAN}http://localhost:5001/dashboard/threat-feed${C_RESET}"
echo ""
echo -e "  ${C_BOLD}Infrastructure:${C_RESET}"
echo -e "    EventBus         PID $EVENTBUS_PID  (gRPC :50051)"
echo -e "    WAL Processor    PID $WAL_PID"
echo ""
echo -e "  ${C_BOLD}Agents (10):${C_RESET}"
echo -e "    Proc             PID $PROC_PID      (15s)"
echo -e "    Auth             PID $AUTH_PID      (15s)"
echo -e "    DNS              PID $DNS_PID      (20s)"
echo -e "    FIM              PID $FIM_PID      (20s)"
echo -e "    Flow             PID $FLOW_PID      (20s)"
echo -e "    Persistence      PID $PERSIST_PID      (20s)"
echo -e "    Peripheral       PID $PERIPH_PID      (20s)"
echo -e "    Kernel Audit     PID $KAUDIT_PID      (30s)"
echo -e "    Device Discovery PID $DISCO_PID      (60s)"
echo -e "    Protocol Coll.   PID $PROTO_PID      (30s)"
echo ""
echo -e "  ${C_BOLD}Logs:${C_RESET} logs/*.log"
echo ""
echo -e "  ${C_YELLOW}Press Ctrl+C to stop all services${C_RESET}"
echo ""
echo -e "${C_CYAN}────────────────────────────────────────────${C_RESET}"
echo ""

# Run dashboard in foreground so user sees Flask output + Ctrl+C works
cd "$PROJECT_ROOT/web"
exec python3 wsgi.py --dev
