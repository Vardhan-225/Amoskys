#!/bin/bash
# AMOSKYS Installer — one command to set up endpoint detection.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Vardhan-225/Amoskys/main/install.sh | bash
#
# What it does:
#   1. Checks prerequisites (Python 3.11+, git)
#   2. Clones AMOSKYS to ~/.amoskys/engine/
#   3. Creates a virtual environment
#   4. Installs dependencies
#   5. Runs amoskys setup (dirs, keys, LaunchAgent)
#   6. Starts the detection engine
#
# Requirements:
#   - macOS 13+ (Ventura or later)
#   - Python 3.11+
#   - git

set -euo pipefail

REPO="https://github.com/Vardhan-225/Amoskys.git"
INSTALL_DIR="${AMOSKYS_HOME:-$HOME/.amoskys}"
ENGINE_DIR="${INSTALL_DIR}/engine"
BRANCH="${AMOSKYS_BRANCH:-main}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${BLUE}==>${NC} $*"; }
ok()    { echo -e "${GREEN}  ✓${NC} $*"; }
warn()  { echo -e "${YELLOW}  !${NC} $*"; }
fail()  { echo -e "${RED}  ✗${NC} $*"; exit 1; }

echo ""
echo -e "${BLUE}  AMOSKYS${NC} — Endpoint Detection Platform"
echo "  To securing the Cyberspace."
echo ""

# ── Prerequisites ──

info "Checking prerequisites..."

# Python 3.11+
PYTHON=""
for py in python3.13 python3.12 python3.11 python3; do
    if command -v "$py" &>/dev/null; then
        ver=$("$py" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        major=$(echo "$ver" | cut -d. -f1)
        minor=$(echo "$ver" | cut -d. -f2)
        if [ "$major" -ge 3 ] && [ "$minor" -ge 11 ]; then
            PYTHON=$(command -v "$py")
            break
        fi
    fi
done

if [ -z "$PYTHON" ]; then
    fail "Python 3.11+ required. Install from https://python.org or: brew install python@3.13"
fi
ok "Python: $PYTHON ($($PYTHON --version))"

# git
if ! command -v git &>/dev/null; then
    fail "git required. Install from: xcode-select --install"
fi
ok "git: $(git --version)"

# macOS check
if [ "$(uname -s)" != "Darwin" ]; then
    warn "AMOSKYS is optimized for macOS. Linux/Windows support is experimental."
fi

# ── Clone or update ──

if [ -d "$ENGINE_DIR/.git" ]; then
    info "Updating existing installation..."
    cd "$ENGINE_DIR"
    git pull origin "$BRANCH" --quiet
    ok "Updated to latest"
else
    info "Cloning AMOSKYS..."
    mkdir -p "$INSTALL_DIR"
    git clone --depth 1 --branch "$BRANCH" "$REPO" "$ENGINE_DIR" 2>&1 | tail -1
    ok "Cloned to $ENGINE_DIR"
fi

cd "$ENGINE_DIR"

# ── Virtual environment ──

VENV_DIR="${ENGINE_DIR}/amoskys-venv"
if [ ! -d "$VENV_DIR" ]; then
    info "Creating virtual environment..."
    "$PYTHON" -m venv "$VENV_DIR"
    ok "venv created"
else
    ok "venv exists"
fi

# Activate
source "${VENV_DIR}/bin/activate"

# ── Dependencies ──

info "Installing dependencies..."
pip install --upgrade pip -q 2>/dev/null
pip install -r requirements.txt -q 2>&1 | tail -1
ok "Dependencies installed"

# ── Setup ──

info "Running setup..."
PYTHONPATH="${ENGINE_DIR}/src" python -m amoskys setup
ok "Setup complete"

# ── Shell alias ──

ALIAS_LINE="alias amoskys='PYTHONPATH=${ENGINE_DIR}/src ${VENV_DIR}/bin/python -m amoskys'"
SHELL_RC=""

if [ -f "$HOME/.zshrc" ]; then
    SHELL_RC="$HOME/.zshrc"
elif [ -f "$HOME/.bashrc" ]; then
    SHELL_RC="$HOME/.bashrc"
fi

if [ -n "$SHELL_RC" ]; then
    if ! grep -q "alias amoskys=" "$SHELL_RC" 2>/dev/null; then
        echo "" >> "$SHELL_RC"
        echo "# AMOSKYS endpoint detection" >> "$SHELL_RC"
        echo "$ALIAS_LINE" >> "$SHELL_RC"
        ok "Added 'amoskys' alias to $SHELL_RC"
    else
        ok "Alias already exists in $SHELL_RC"
    fi
fi

echo ""
echo -e "${GREEN}AMOSKYS installed successfully!${NC}"
echo ""
echo "  Start:    amoskys start"
echo "  Status:   amoskys status"
echo "  Shell:    amoskys"
echo "  Upgrade:  amoskys upgrade"
echo ""
echo "  For auto-start at login:"
echo "    amoskys setup --enable-launchd"
echo ""

# If this is a fresh shell, source the alias
if [ -n "$SHELL_RC" ]; then
    echo "  Restart your terminal or run:"
    echo "    source $SHELL_RC"
fi
echo ""
