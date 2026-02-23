#!/usr/bin/env bash
# =============================================================================
# AMOSKYS VPS Deployment Script
# =============================================================================
# This script is executed on the VPS to deploy new versions of AMOSKYS.
# It handles: git pull, dependencies, smoke tests, service restart, health check
#
# Usage:
#   GIT_REF=<commit_sha> bash deploy_remote.sh
#   or just: bash deploy_remote.sh (defaults to origin/main)
#
# Environment variables:
#   GIT_REF     - Git reference to deploy (commit SHA, branch, tag)
#   SKIP_TESTS  - Set to "true" to skip smoke tests (not recommended)
# =============================================================================

set -euo pipefail

# Configuration
APP_DIR="/opt/amoskys"
VENV_DIR="$APP_DIR/venv"
BRANCH="${GIT_REF:-main}"
DEPLOY_MARKER="$APP_DIR/.last_deploy"
HEALTH_URL="http://127.0.0.1:5001/api/v1/health/ping"
HEALTH_SYSTEM_URL="http://127.0.0.1:5001/api/v1/health/system"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

echo "🧠 =============================================="
echo "🧠 AMOSKYS Neural Security Platform - Deploying"
echo "🧠 =============================================="
echo ""

cd "$APP_DIR"

# Pre-flight: Check disk space
log_info "Pre-flight: Checking disk space..."
DISK_USAGE=$(df -h / | awk 'NR==2 {gsub("%",""); print $5}')
if [ "$DISK_USAGE" -gt 90 ]; then
    log_error "Disk usage is at ${DISK_USAGE}%! Attempting cleanup..."
    # Clean up old logs
    find /var/log/amoskys -type f -name "*.log.*" -mtime +1 -delete 2>/dev/null || true
    find "$APP_DIR/logs" -type f -name "*.log.*" -mtime +1 -delete 2>/dev/null || true
    # Force log rotation
    sudo logrotate -f /etc/logrotate.d/amoskys 2>/dev/null || true
    # Re-check disk space
    DISK_USAGE=$(df -h / | awk 'NR==2 {gsub("%",""); print $5}')
    if [ "$DISK_USAGE" -gt 95 ]; then
        log_error "Disk usage still critical at ${DISK_USAGE}%! Manual intervention required."
        exit 1
    fi
    log_warn "Disk cleaned up, now at ${DISK_USAGE}%"
else
    log_info "  Disk usage: ${DISK_USAGE}% ✓"
fi

# Step 1: Fetch and checkout code
log_info "Step 1/8: Fetching latest code..."
git fetch --all --prune

if [[ "$BRANCH" == "main" ]]; then
    git reset --hard "origin/main"
else
    # For specific commits/refs
    git checkout "$BRANCH" 2>/dev/null || git reset --hard "$BRANCH"
fi

DEPLOYED_COMMIT=$(git rev-parse HEAD)
DEPLOYED_REF=$(git describe --tags --always 2>/dev/null || echo "$DEPLOYED_COMMIT")
log_info "Deploying: $DEPLOYED_REF ($DEPLOYED_COMMIT)"

# Step 2: Ensure virtualenv exists
log_info "Step 2/8: Ensuring virtualenv exists..."
if [ ! -d "$VENV_DIR" ]; then
    log_warn "Creating new venv at $VENV_DIR"
    python3 -m venv "$VENV_DIR"
fi

# Step 3: Install dependencies
log_info "Step 3/8: Installing dependencies..."
source "$VENV_DIR/bin/activate"
pip install --upgrade pip --quiet
pip install -e ".[all]" --quiet

# Ensure log rotation is configured
if [ -f "$APP_DIR/deploy/logrotate/amoskys" ]; then
    sudo cp "$APP_DIR/deploy/logrotate/amoskys" /etc/logrotate.d/amoskys 2>/dev/null || true
fi

# Ensure systemd service files are up to date
if [ -f "$APP_DIR/deploy/systemd/amoskys-web.service" ]; then
    sudo cp "$APP_DIR/deploy/systemd/amoskys-web.service" /etc/systemd/system/amoskys-web.service 2>/dev/null || true
fi

# Step 4: Run smoke tests
if [ "${SKIP_TESTS:-false}" != "true" ]; then
    log_info "Step 4/8: Running smoke tests..."
    pytest tests/integration/test_smoke_deploy.py -m smoke -q --tb=short || {
        log_error "Smoke tests failed! Aborting deploy."
        exit 1
    }
    log_info "✅ Smoke tests passed"
else
    log_warn "Step 4/8: Skipping smoke tests (SKIP_TESTS=true)"
fi

# Step 5: Stop existing service gracefully
log_info "Step 5/8: Stopping AMOSKYS services..."
sudo systemctl stop amoskys-web 2>/dev/null || true
sudo systemctl stop amoskys 2>/dev/null || true
sleep 2

# Step 6: Start service
log_info "Step 6/8: Starting AMOSKYS services..."
# Reload systemd in case service files changed
sudo systemctl daemon-reload
# Start the web service (agents can be started separately if needed)
sudo systemctl start amoskys-web

# Step 7: Health check with retries
log_info "Step 7/8: Running health checks..."
HEALTH_RETRIES=5
HEALTH_DELAY=3
HEALTH_OK=false

for i in $(seq 1 $HEALTH_RETRIES); do
    sleep $HEALTH_DELAY
    log_info "  Health check attempt $i/$HEALTH_RETRIES..."
    
    if curl -fsS --max-time 5 "$HEALTH_URL" > /dev/null 2>&1; then
        HEALTH_OK=true
        break
    fi
done

if [ "$HEALTH_OK" = true ]; then
    log_info "✅ Health ping OK"
    
    # Get detailed health status
    HEALTH_RESPONSE=$(curl -fsS --max-time 10 "$HEALTH_SYSTEM_URL" 2>/dev/null || echo "{}")
    HEALTH_SCORE=$(echo "$HEALTH_RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('health_score', 'N/A'))" 2>/dev/null || echo "N/A")
    THREAT_LEVEL=$(echo "$HEALTH_RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('threat_level', 'N/A'))" 2>/dev/null || echo "N/A")
    
    log_info "  Health Score: $HEALTH_SCORE/100"
    log_info "  Threat Level: $THREAT_LEVEL"
else
    log_error "Health check failed after $HEALTH_RETRIES attempts!"
    log_error "Service may have failed to start. Check logs:"
    sudo journalctl -u amoskys-web --no-pager -n 30 || true
    exit 1
fi

# Step 8: Write deployment marker
log_info "Step 8/8: Writing deployment marker..."
cat > "$DEPLOY_MARKER" << EOF
{
    "commit": "$DEPLOYED_COMMIT",
    "ref": "$DEPLOYED_REF",
    "deployed_at_utc": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
    "deployed_by": "${GITHUB_ACTOR:-manual}",
    "health_score": "$HEALTH_SCORE",
    "threat_level": "$THREAT_LEVEL"
}
EOF

# Also update static marker for web access
mkdir -p "$APP_DIR/web/app/static"
echo "Deployed: $DEPLOYED_REF @ $(date -u +"%Y-%m-%dT%H:%M:%SZ") | Health: $HEALTH_SCORE/100" > "$APP_DIR/web/app/static/deploy_marker.txt"

echo ""
echo "🧠 =============================================="
echo "🧠 AMOSKYS Deploy Complete!"
echo "🧠 =============================================="
echo "   Commit:       $DEPLOYED_COMMIT"
echo "   Ref:          $DEPLOYED_REF"
echo "   Health Score: $HEALTH_SCORE/100"
echo "   Threat Level: $THREAT_LEVEL"
echo "🧠 =============================================="
