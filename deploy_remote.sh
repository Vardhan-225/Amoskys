#!/usr/bin/env bash
set -euo pipefail

echo "🧠 AMOSKYS remote deploy starting..."

APP_DIR="/opt/amoskys"
VENV_DIR="$APP_DIR/venv"
BRANCH="main"

cd "$APP_DIR"

echo "1) Fetching latest code..."
git fetch origin "$BRANCH"
git reset --hard "origin/$BRANCH"

echo "2) Ensuring virtualenv exists..."
if [ ! -d "$VENV_DIR" ]; then
  echo "   → Creating venv at $VENV_DIR"
  python3 -m venv "$VENV_DIR"
fi

echo "3) Installing dependencies (.[all])..."
source "$VENV_DIR/bin/activate"
pip install --upgrade pip
pip install -e ".[all]"

echo "4) Running smoke tests..."
# Keep this fast – unit/integration tests run in CI already
pytest tests/web/test_dashboard.py -q || {
  echo "❌ Smoke tests failed, aborting deploy."
  exit 1
}

echo "5) Restarting AMOSKYS systemd service..."
sudo systemctl restart amoskys

echo "6) Checking service status..."
sleep 5
sudo systemctl is-active --quiet amoskys && echo "✅ amoskys.service is active" || {
  echo "❌ amoskys.service is not active!"
  sudo systemctl status amoskys --no-pager || true
  exit 1
}

echo "7) Touching deployment marker..."
mkdir -p "$APP_DIR/web/app/static"
echo "CI/CD Pipeline Active - $(date -u)" > "$APP_DIR/web/app/static/deploy_marker.txt"

echo "✅ AMOSKYS remote deploy completed successfully."
