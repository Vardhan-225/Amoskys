#!/bin/bash

# AMOSKYS Neural Security Command Platform
# Production Deployment Script for VPS
# Usage: ./deploy_web.sh

set -euo pipefail

# Configuration
DEPLOY_USER="www-data"
DEPLOY_PATH="/opt/amoskys"
WEB_PATH="$DEPLOY_PATH/web"
CERT_PATH="$DEPLOY_PATH/certs"
LOG_PATH="/var/log/amoskys"
BACKUP_PATH="/opt/amoskys/backups/$(date +%Y%m%d_%H%M%S)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

success() {
    echo -e "${GREEN}✅ $1${NC}"
}

warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

error() {
    echo -e "${RED}❌ $1${NC}"
    exit 1
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root (use sudo)"
fi

log "🧠🛡️ AMOSKYS Neural Security Command Platform Deployment"
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# 1. Create directory structure
log "📁 Creating directory structure..."
mkdir -p "$DEPLOY_PATH"/{web,certs,backups,data}
mkdir -p "$LOG_PATH"

# 2. Set up Python environment
log "🐍 Setting up Python virtual environment..."
cd "$DEPLOY_PATH"
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip

# Install requirements if they exist
if [[ -f "requirements/requirements-amoskys-web.txt" ]]; then
    pip install -r requirements/requirements-amoskys-web.txt
elif [[ -f "web/requirements.txt" ]]; then
    pip install -r web/requirements.txt
else
    warning "No requirements file found, installing basic dependencies..."
    pip install flask==3.0.0 gunicorn==21.2.0 werkzeug==3.0.1
fi

# 3. Set ownership and permissions
log "🔐 Setting ownership and permissions..."
chown -R "$DEPLOY_USER:$DEPLOY_USER" "$DEPLOY_PATH"
chown -R "$DEPLOY_USER:$DEPLOY_USER" "$LOG_PATH"
chmod -R 755 "$DEPLOY_PATH"
chmod -R 644 "$WEB_PATH"/*.py "$WEB_PATH"/*.txt 2>/dev/null || true
chmod +x "$WEB_PATH"/*.py 2>/dev/null || true

# 4. Certificate setup (if certificates exist)
log "🔒 Checking SSL certificates..."
if [[ -f "amoskys.com.pem" && -f "amoskys.com.key" ]]; then
    log "Installing SSL certificates..."
    cp amoskys.com.pem amoskys.com.key "$CERT_PATH/"
    chown root:root "$CERT_PATH"/*
    chmod 644 "$CERT_PATH"/amoskys.com.pem
    chmod 600 "$CERT_PATH"/amoskys.com.key
    success "SSL certificates installed"
else
    warning "SSL certificates not found in current directory"
    warning "Please place amoskys.com.pem and amoskys.com.key in $CERT_PATH/"
fi

# 5. NGINX configuration
log "🌐 Configuring NGINX..."
if [[ -f "nginx/amoskys.conf" ]]; then
    cp nginx/amoskys.conf /etc/nginx/sites-available/
    
    # Enable site
    if [[ ! -L "/etc/nginx/sites-enabled/amoskys.conf" ]]; then
        ln -s /etc/nginx/sites-available/amoskys.conf /etc/nginx/sites-enabled/
    fi
    
    # Test NGINX configuration
    if nginx -t; then
        success "NGINX configuration valid"
        systemctl reload nginx
        success "NGINX reloaded"
    else
        error "NGINX configuration test failed"
    fi
else
    warning "NGINX configuration not found"
fi

# 6. Systemd service setup
log "⚙️  Installing systemd service..."
if [[ -f "deploy/systemd/amoskys-web.service" ]]; then
    cp deploy/systemd/amoskys-web.service /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable amoskys-web
    success "Systemd service installed and enabled"
else
    warning "Systemd service file not found"
fi

# 7. Start the service
log "🚀 Starting AMOSKYS web service..."
if systemctl start amoskys-web; then
    success "AMOSKYS web service started"
    
    # Wait a moment and check status
    sleep 3
    if systemctl is-active --quiet amoskys-web; then
        success "Service is running successfully"
    else
        warning "Service may have issues, checking logs..."
        journalctl -u amoskys-web --no-pager -n 10
    fi
else
    error "Failed to start AMOSKYS web service"
fi

# 8. Verification
log "🔍 Running deployment verification..."

# Check if port 8000 is listening
if netstat -tulpn | grep -q ":8000"; then
    success "Gunicorn is listening on port 8000"
else
    warning "Gunicorn may not be listening on port 8000"
fi

# Test local endpoint
if curl -s http://localhost:8000/health >/dev/null; then
    success "Health endpoint responding"
else
    warning "Health endpoint not responding"
fi

# 9. Display status
log "📊 Deployment Status:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🧠 AMOSKYS Web Interface: $(systemctl is-active amoskys-web)"
echo "🌐 NGINX: $(systemctl is-active nginx)"
echo "🔒 SSL Certificates: $([ -f "$CERT_PATH/amoskys.com.pem" ] && echo "✅ Installed" || echo "❌ Missing")"
echo "📂 Web Path: $WEB_PATH"
echo "📝 Logs: $LOG_PATH"
echo "🔧 Service: systemctl status amoskys-web"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

success "🧠🛡️ AMOSKYS deployment completed!"

log "Next steps:"
echo "  1. Place SSL certificates in $CERT_PATH/"
echo "  2. Test: curl -k https://amoskys.com/health"
echo "  3. Monitor: journalctl -u amoskys-web -f"
echo "  4. Manage: systemctl {start|stop|restart|status} amoskys-web"
