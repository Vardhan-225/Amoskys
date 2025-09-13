#!/bin/bash

# AMOSKYS Neural Security Command Platform
# One-Command Production Deployment Script
# Usage: curl -sSL https://raw.githubusercontent.com/your-repo/amoskys/main/scripts/quick_deploy.sh | sudo bash

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

# ASCII Art Banner
cat << 'EOF'
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║     🧠🛡️  AMOSKYS NEURAL SECURITY COMMAND PLATFORM           ║
║                                                               ║
║        Neural Security Orchestration That Evolves            ║
║                                                               ║
║                    One-Command Deployment                     ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
EOF

echo -e "${PURPLE}Phase 2.2 - Production VPS Deployment${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

log() {
    echo -e "${BLUE}[$(date +'%H:%M:%S')]${NC} $1"
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
    error "This script must be run as root. Use: curl -sSL [script-url] | sudo bash"
fi

# Configuration
DEPLOY_DIR="/opt/amoskys"
DOMAIN="amoskys.com"
REPO_URL="https://github.com/your-username/amoskys.git"  # Update this!

log "🚀 Starting AMOSKYS Neural Security Platform deployment..."

# Step 1: System Updates
log "📦 Updating system packages..."
apt update -qq && apt upgrade -y -qq

# Step 2: Install Dependencies
log "🔧 Installing required packages..."
apt install -y -qq python3 python3-venv python3-pip nginx curl git ufw fail2ban

# Step 3: Security Setup
log "🛡️ Configuring basic security..."
ufw --force enable
ufw allow ssh
ufw allow http
ufw allow https

# Configure fail2ban
systemctl enable fail2ban
systemctl start fail2ban

# Step 4: Clone Repository
log "📁 Cloning AMOSKYS repository..."
if [[ -d "$DEPLOY_DIR" ]]; then
    rm -rf "$DEPLOY_DIR"
fi

git clone "$REPO_URL" "$DEPLOY_DIR"
cd "$DEPLOY_DIR"

# Step 5: Set Permissions
log "🔐 Setting file permissions..."
chown -R www-data:www-data "$DEPLOY_DIR"
chmod +x scripts/*.sh

# Step 6: Python Environment
log "🐍 Setting up Python environment..."
cd "$DEPLOY_DIR"
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements/requirements-amoskys-web.txt

# Step 7: SSL Certificate Setup
log "🔒 SSL Certificate configuration..."
mkdir -p "$DEPLOY_DIR/certs"

echo ""
echo -e "${YELLOW}SSL Certificate Setup Required:${NC}"
echo "1. You need to provide SSL certificates for $DOMAIN"
echo "2. Place your certificates in: $DEPLOY_DIR/certs/"
echo "   - Certificate file: ${DOMAIN}.pem"
echo "   - Private key file: ${DOMAIN}.key"
echo ""
echo "Options:"
echo "  a) Use Cloudflare Origin Certificate (recommended)"
echo "  b) Use Let's Encrypt: certbot --nginx -d $DOMAIN"
echo "  c) Upload existing certificates"
echo ""
read -p "Do you want to continue with SSL setup now? (y/n): " ssl_setup

if [[ "$ssl_setup" =~ ^[Yy]$ ]]; then
    ./scripts/ssl_setup.sh
else
    warning "SSL setup skipped. You must configure SSL before production use."
    # Create self-signed cert for testing
    openssl req -x509 -nodes -days 30 -newkey rsa:2048 \
        -keyout "$DEPLOY_DIR/certs/${DOMAIN}.key" \
        -out "$DEPLOY_DIR/certs/${DOMAIN}.pem" \
        -subj "/C=US/ST=State/L=City/O=AMOSKYS/OU=Neural/CN=${DOMAIN}"
fi

# Step 8: NGINX Configuration
log "🌐 Configuring NGINX..."
cp nginx/amoskys.conf /etc/nginx/sites-available/
ln -sf /etc/nginx/sites-available/amoskys.conf /etc/nginx/sites-enabled/

# Remove default site
rm -f /etc/nginx/sites-enabled/default

# Test NGINX configuration
if nginx -t; then
    success "NGINX configuration valid"
else
    error "NGINX configuration failed"
fi

# Step 9: Systemd Service
log "⚙️ Installing systemd service..."
cp deploy/systemd/amoskys-web.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable amoskys-web

# Step 10: Create Log Directory
log "📝 Setting up logging..."
mkdir -p /var/log/amoskys
chown www-data:www-data /var/log/amoskys
chmod 755 /var/log/amoskys

# Step 11: Start Services
log "🚀 Starting AMOSKYS services..."
systemctl start amoskys-web
systemctl reload nginx

# Wait for services to start
sleep 3

# Step 12: Health Checks
log "🔍 Running health checks..."

# Check if services are running
if systemctl is-active --quiet amoskys-web; then
    success "AMOSKYS web service is running"
else
    error "AMOSKYS web service failed to start"
fi

if systemctl is-active --quiet nginx; then
    success "NGINX is running"
else
    error "NGINX failed to start"
fi

# Test local endpoints
if curl -s http://localhost:8000/health | grep -q "healthy"; then
    success "Health endpoint responding"
else
    warning "Health endpoint not responding locally"
fi

# Step 13: Display Results
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}🧠🛡️ AMOSKYS DEPLOYMENT COMPLETED SUCCESSFULLY!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${BLUE}📊 Deployment Summary:${NC}"
echo "🌐 Domain: https://$DOMAIN"
echo "📁 Installation: $DEPLOY_DIR"
echo "🔧 Service: amoskys-web"
echo "📝 Logs: /var/log/amoskys/"
echo ""
echo -e "${BLUE}🔍 Quick Tests:${NC}"
echo "curl http://localhost:8000/health"
echo "curl https://$DOMAIN/health"
echo "systemctl status amoskys-web"
echo ""
echo -e "${BLUE}⚙️ Management Commands:${NC}"
echo "sudo systemctl {start|stop|restart|status} amoskys-web"
echo "sudo systemctl {reload|restart} nginx"
echo "sudo journalctl -u amoskys-web -f"
echo ""
echo -e "${YELLOW}📋 Next Steps:${NC}"
echo "1. Configure DNS: $DOMAIN → $(curl -s ifconfig.me 2>/dev/null || echo 'YOUR_VPS_IP')"
echo "2. Set up proper SSL certificates (if not done)"
echo "3. Configure Cloudflare (see docs/CLOUDFLARE_SETUP.md)"
echo "4. Test from external network: https://$DOMAIN"
echo "5. Monitor logs: sudo tail -f /var/log/nginx/amoskys.access.log"
echo ""
echo -e "${PURPLE}🧠 AMOSKYS Neural Security Command Platform v1.0.0${NC}"
echo -e "${PURPLE}Neural Security Orchestration That Evolves${NC}"
echo ""
success "Phase 2.2 deployment complete! The neural network is live! 🧠⚡"
