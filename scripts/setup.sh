#!/usr/bin/env bash
# ============================================================
# AMOSKYS v0.9.0-beta.1 — macOS Setup Script
# ============================================================
# First-time setup for a fresh macOS machine.
#
# Usage:
#   git clone https://github.com/Vardhan-225/Amoskys.git
#   cd Amoskys
#   bash scripts/setup.sh
#
# Requirements:
#   - macOS 13+ (Ventura or later)
#   - Python 3.11+ (brew install python@3.12)
#   - Xcode Command Line Tools (xcode-select --install)
# ============================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${CYAN}[AMOSKYS]${NC} $1"; }
ok()   { echo -e "${GREEN}[  OK  ]${NC} $1"; }
warn() { echo -e "${YELLOW}[ WARN ]${NC} $1"; }
fail() { echo -e "${RED}[FAIL  ]${NC} $1"; exit 1; }

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

# ── Pre-flight checks ──────────────────────────────────────

log "AMOSKYS v0.9.0-beta.1 — macOS Setup"
echo ""

# Check macOS
if [[ "$(uname)" != "Darwin" ]]; then
    fail "AMOSKYS macOS Observatory requires macOS. Detected: $(uname)"
fi
ok "Platform: macOS $(sw_vers -productVersion)"

# Check Python
PYTHON=""
for candidate in python3.13 python3.12 python3.11 python3; do
    if command -v "$candidate" &>/dev/null; then
        version=$("$candidate" --version 2>&1 | awk '{print $2}')
        major=$(echo "$version" | cut -d. -f1)
        minor=$(echo "$version" | cut -d. -f2)
        if [[ "$major" -ge 3 && "$minor" -ge 11 ]]; then
            PYTHON="$candidate"
            break
        fi
    fi
done

if [[ -z "$PYTHON" ]]; then
    fail "Python 3.11+ required. Install via: brew install python@3.12"
fi
ok "Python: $($PYTHON --version)"

# ── Create virtual environment ─────────────────────────────

VENV_DIR=".venv"
if [[ -d "$VENV_DIR" ]]; then
    warn "Virtual environment exists at $VENV_DIR — reusing"
else
    log "Creating virtual environment..."
    $PYTHON -m venv "$VENV_DIR"
    ok "Virtual environment created"
fi

# Activate
source "$VENV_DIR/bin/activate"
ok "Activated: $(which python)"

# ── Install dependencies ───────────────────────────────────

log "Installing production dependencies..."
pip install --upgrade pip setuptools wheel -q
pip install -r requirements.txt -q
ok "Production dependencies installed"

log "Installing AMOSKYS in editable mode..."
pip install -e . -q
ok "AMOSKYS package installed"

# ── Generate proto stubs (if needed) ───────────────────────

if [[ ! -f "src/amoskys/proto/universal_telemetry_pb2.py" ]]; then
    log "Generating protobuf stubs..."
    if [[ -f "proto/Makefile" ]]; then
        make -C proto generate
        ok "Proto stubs generated"
    else
        warn "Proto stubs missing and no Makefile found — run manually"
    fi
else
    ok "Proto stubs present"
fi

# ── Create runtime directories ─────────────────────────────

mkdir -p data/queue data/wal data/baselines logs certs/agents
ok "Runtime directories created"

# ── Generate agent signing key (if missing) ────────────────

KEY_PATH="certs/agents/agent.ed25519"
if [[ ! -f "$KEY_PATH" ]]; then
    log "Generating Ed25519 agent signing key..."
    python -c "
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
key = Ed25519PrivateKey.generate()
pem = key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption()
)
with open('$KEY_PATH', 'wb') as f:
    f.write(pem)
print('  Key written to $KEY_PATH')
"
    ok "Agent signing key generated"
else
    ok "Agent signing key exists"
fi

# ── Verify installation ────────────────────────────────────

log "Verifying AMOSKYS installation..."

python -c "
from amoskys.agents import AGENT_REGISTRY, get_available_agents
darwin_agents = get_available_agents('darwin')
print(f'  Agent Registry: {len(AGENT_REGISTRY)} total, {len(darwin_agents)} macOS')

from amoskys.detection import SigmaEngine
print(f'  SigmaEngine: loaded')

from amoskys.agents.common.base import HardenedAgentBase
from amoskys.agents.common.probes import MicroProbe
print(f'  Base classes: HardenedAgentBase, MicroProbe')

print('  All imports OK')
" || fail "Import verification failed"

ok "AMOSKYS verified"

# ── Summary ────────────────────────────────────────────────

echo ""
echo "============================================================"
echo "  AMOSKYS v0.9.0-beta.1 — Setup Complete"
echo "============================================================"
echo ""
echo "  Quick start:"
echo "    source .venv/bin/activate"
echo "    PYTHONPATH=src python scripts/live_demo.py"
echo ""
echo "  Run all agents:"
echo "    PYTHONPATH=src python scripts/collect_and_store.py"
echo ""
echo "  Dashboard:"
echo "    FLASK_PORT=5002 LOGIN_DISABLED=true python -m web.app"
echo ""
echo "  Production services:"
echo "    bash scripts/deploy.sh start"
echo ""
echo "  Tests:"
echo "    pip install -r requirements-dev.txt"
echo "    pytest tests/ -x"
echo ""
echo "============================================================"
