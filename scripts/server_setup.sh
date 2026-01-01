#!/bin/bash
# =============================================================================
# AMOSKYS Production Server Setup Script
# =============================================================================
# Run this script on your EC2/VPS server to set up and start AMOSKYS
#
# Usage: 
#   scp scripts/server_setup.sh ubuntu@<your-server-ip>:~/
#   ssh ubuntu@<your-server-ip>
#   chmod +x server_setup.sh && sudo ./server_setup.sh
# =============================================================================

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${BLUE}[$(date +'%H:%M:%S')]${NC} $1"; }
success() { echo -e "${GREEN}✅ $1${NC}"; }
warn() { echo -e "${YELLOW}⚠️  $1${NC}"; }
error() { echo -e "${RED}❌ $1${NC}"; exit 1; }

echo ""
echo -e "${GREEN}🧠 ═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}🧠  AMOSKYS Neural Security Command Platform - Server Setup${NC}"
echo -e "${GREEN}🧠 ═══════════════════════════════════════════════════════════${NC}"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root (use sudo)"
fi

APP_DIR="/opt/amoskys"
VENV_DIR="$APP_DIR/venv"
LOG_DIR="/var/log/amoskys"
DATA_DIR="$APP_DIR/data"
WEB_DATA_DIR="$APP_DIR/web/data"

# Step 1: Create directories
log "Step 1/8: Creating directories..."
mkdir -p "$LOG_DIR" "$DATA_DIR" "$WEB_DATA_DIR"
chown -R amoskys:amoskys "$LOG_DIR" 2>/dev/null || chown -R ubuntu:ubuntu "$LOG_DIR"
success "Directories created"

# Step 2: Check if app exists
log "Step 2/8: Checking application..."
if [ ! -d "$APP_DIR" ]; then
    error "Application not found at $APP_DIR. Please clone the repository first."
fi
cd "$APP_DIR"
success "Application found at $APP_DIR"

# Step 3: Set up Python virtual environment
log "Step 3/8: Setting up Python environment..."
if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
    success "Created new virtual environment"
else
    success "Virtual environment already exists"
fi

source "$VENV_DIR/bin/activate"
pip install --upgrade pip --quiet
pip install -e ".[all]" --quiet 2>/dev/null || pip install -e . --quiet
success "Dependencies installed"

# Step 4: Create/update systemd service for web app
log "Step 4/8: Setting up systemd services..."

cat > /etc/systemd/system/amoskys-web.service << 'EOF'
[Unit]
Description=AMOSKYS Neural Security Command Platform - Web Interface
After=network.target

[Service]
Type=simple
User=ubuntu
Group=ubuntu
WorkingDirectory=/opt/amoskys
Environment=FLASK_ENV=production
Environment=PYTHONPATH=/opt/amoskys
Environment=PYTHONUNBUFFERED=1
ExecStart=/opt/amoskys/venv/bin/gunicorn --bind 127.0.0.1:5001 --workers 2 --timeout 120 --access-logfile /var/log/amoskys/access.log --error-logfile /var/log/amoskys/error.log web.wsgi:app
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Create EventBus service
cat > /etc/systemd/system/amoskys-eventbus.service << 'EOF'
[Unit]
Description=AMOSKYS EventBus (gRPC Neural Hub)
After=network.target

[Service]
Type=simple
User=ubuntu
Group=ubuntu
WorkingDirectory=/opt/amoskys
Environment=PYTHONPATH=/opt/amoskys
Environment=PYTHONUNBUFFERED=1
ExecStart=/opt/amoskys/venv/bin/python -m amoskys.eventbus.server
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
success "Systemd services configured"

# Step 5: Update nginx config
log "Step 5/8: Updating nginx configuration..."
if [ -f "$APP_DIR/deploy/nginx/amoskys.conf" ]; then
    cp "$APP_DIR/deploy/nginx/amoskys.conf" /etc/nginx/sites-available/amoskys.conf
    
    # Create symlink if not exists
    if [ ! -L "/etc/nginx/sites-enabled/amoskys.conf" ]; then
        ln -sf /etc/nginx/sites-available/amoskys.conf /etc/nginx/sites-enabled/amoskys.conf
    fi
    
    # Remove default site if exists
    rm -f /etc/nginx/sites-enabled/default
    
    # Copy error pages
    mkdir -p "$APP_DIR/web/app/static/errors"
    if [ -d "$APP_DIR/deploy/nginx/error_pages" ]; then
        cp "$APP_DIR/deploy/nginx/error_pages/"*.html "$APP_DIR/web/app/static/errors/" 2>/dev/null || true
    fi
    
    # Test and reload nginx
    nginx -t && systemctl reload nginx
    success "Nginx configured and reloaded"
else
    warn "Nginx config not found, skipping..."
fi

# Step 6: Set permissions
log "Step 6/8: Setting permissions..."
chown -R ubuntu:ubuntu "$APP_DIR"
chmod -R 755 "$APP_DIR"
chmod 700 "$APP_DIR/certs" 2>/dev/null || true
success "Permissions set"

# Step 7: Enable and start services
log "Step 7/8: Starting services..."
systemctl enable amoskys-web
systemctl enable amoskys-eventbus

systemctl restart amoskys-eventbus
sleep 2
systemctl restart amoskys-web
success "Services started"

# Step 8: Health check
log "Step 8/8: Running health checks..."
sleep 3

# Check service status
echo ""
echo "Service Status:"
echo "---------------"
systemctl is-active amoskys-web && success "amoskys-web is running" || warn "amoskys-web is not running"
systemctl is-active amoskys-eventbus && success "amoskys-eventbus is running" || warn "amoskys-eventbus is not running"
systemctl is-active nginx && success "nginx is running" || warn "nginx is not running"

# Test local endpoint
echo ""
echo "Testing local endpoint..."
if curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:5001/ | grep -q "200\|302"; then
    success "Web app responding on port 5001"
else
    warn "Web app not responding yet (may still be starting)"
fi

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  AMOSKYS Setup Complete!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo "Useful commands:"
echo "  sudo systemctl status amoskys-web      # Check web service status"
echo "  sudo systemctl status amoskys-eventbus # Check eventbus status"
echo "  sudo journalctl -u amoskys-web -f      # View web logs"
echo "  sudo journalctl -u amoskys-eventbus -f # View eventbus logs"
echo "  sudo tail -f /var/log/amoskys/*.log    # View app logs"
echo ""
