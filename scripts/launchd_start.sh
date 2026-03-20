#!/bin/bash
# AMOSKYS LaunchAgent wrapper — invoked by launchd at login.
# Uses /bin/bash (always permitted by macOS) to activate the venv
# and run AMOSKYS in foreground mode.

set -euo pipefail

PROJECT_DIR="/Volumes/Akash_Lab/Amoskys"
VENV_DIR="${PROJECT_DIR}/amoskys-venv"

cd "${PROJECT_DIR}"
export PYTHONPATH="${PROJECT_DIR}/src"

# Activate venv
source "${VENV_DIR}/bin/activate"

# Run in foreground (launchd manages the lifecycle)
exec python -m amoskys start --foreground --no-dashboard
