#!/bin/bash
# AMOSKYS Daemon Installer
# Creates directories, verifies dependencies, optionally installs LaunchDaemon
set -euo pipefail
cd "$(dirname "$0")"

GREEN='\033[92m'
YELLOW='\033[93m'
RED='\033[91m'
CYAN='\033[96m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

echo ""
echo -e "${BOLD}${CYAN}  AMOSKYS Daemon Installer${RESET}"
echo -e "${DIM}  ─────────────────────────${RESET}"
echo ""

# 1. Verify Python environment
echo -e "${CYAN}[1/5] Checking Python environment...${RESET}"
if [ -f .venv/bin/python ]; then
    PYTHON=.venv/bin/python
    echo -e "  ${GREEN}[OK]${RESET} Using .venv/bin/python"
else
    PYTHON=$(which python3)
    echo -e "  ${YELLOW}[WARN]${RESET} No .venv found, using system python: $PYTHON"
fi
$PYTHON -c "import amoskys" 2>/dev/null && echo -e "  ${GREEN}[OK]${RESET} amoskys package importable" || {
    echo -e "  ${YELLOW}[WARN]${RESET} amoskys not importable — will use PYTHONPATH"
}

# 2. Create directories
echo ""
echo -e "${CYAN}[2/5] Creating directories...${RESET}"
mkdir -p data logs data/intel/models data/benchmarks
echo -e "  ${GREEN}[OK]${RESET} data/, logs/, data/intel/models/"

# 3. Verify daemon module
echo ""
echo -e "${CYAN}[3/5] Verifying daemon module...${RESET}"
PYTHONPATH=src $PYTHON -c "from amoskys.daemon import AmoskysDaemon; print('  [OK] daemon.py loadable')" 2>&1 || {
    echo -e "  ${RED}[FAIL]${RESET} Cannot import amoskys.daemon"
    exit 1
}

# 4. Verify probes
echo ""
echo -e "${CYAN}[4/5] Verifying probe inventory...${RESET}"
PYTHONPATH=src $PYTHON -c "
from amoskys.agents.os.macos.infostealer_guard.probes import create_infostealer_guard_probes
from amoskys.agents.os.macos.process.probes import create_process_probes
from amoskys.agents.os.macos.network.probes import create_network_probes
from amoskys.agents.os.macos.auth.probes import create_auth_probes
total = (len(create_infostealer_guard_probes()) + len(create_process_probes()) +
         len(create_network_probes()) + len(create_auth_probes()))
print(f'  [OK] {total} probes across 4 agents')
" 2>&1

# 5. Print usage
echo ""
echo -e "${CYAN}[5/5] Installation complete${RESET}"
echo ""
echo -e "${BOLD}  Quick Start:${RESET}"
echo ""
echo -e "  ${GREEN}# Terminal 1 — Start AMOSKYS daemon:${RESET}"
echo -e "  ${DIM}PYTHONPATH=src python -m amoskys.daemon --interval 10 --respond${RESET}"
echo ""
echo -e "  ${GREEN}# Terminal 2 — Run attacks:${RESET}"
echo -e "  ${DIM}bash scripts/live_demo.sh attack${RESET}"
echo ""
echo -e "  ${GREEN}# After demo — clean up:${RESET}"
echo -e "  ${DIM}bash scripts/live_demo.sh cleanup${RESET}"
echo ""
echo -e "${BOLD}  LaunchDaemon Install (optional, auto-start on boot):${RESET}"
echo ""
echo -e "  ${DIM}PYTHONPATH=src python -m amoskys.launcher install${RESET}"
echo -e "  ${DIM}launchctl load ~/Library/LaunchAgents/com.amoskys.*.plist${RESET}"
echo ""
