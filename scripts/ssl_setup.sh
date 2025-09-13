#!/bin/bash

# AMOSKYS Neural Security Command Platform
# SSL Certificate Management Script for Cloudflare Origin Certificates
# Usage: ./scripts/ssl_setup.sh

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

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

log "🧠🛡️ AMOSKYS SSL Certificate Setup"
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root (use sudo)"
fi

CERT_DIR="/opt/amoskys/certs"
DOMAIN="amoskys.com"

# Create certificate directory
log "📁 Creating certificate directory..."
mkdir -p "$CERT_DIR"

echo ""
log "🔒 SSL Certificate Setup Options:"
echo "  1. Use existing Cloudflare Origin Certificate (recommended for production)"
echo "  2. Generate self-signed certificate (development only)"
echo "  3. Use Let's Encrypt certificate (alternative production option)"
echo ""

read -p "Choose option (1-3): " choice

case $choice in
    1)
        log "📋 Cloudflare Origin Certificate Setup"
        echo ""
        echo "Instructions:"
        echo "1. Go to Cloudflare Dashboard → SSL/TLS → Origin Server"
        echo "2. Click 'Create Certificate'"
        echo "3. Select 'Let Cloudflare generate a private key and a CSR'"
        echo "4. Add hostnames: amoskys.com, *.amoskys.com"
        echo "5. Set certificate validity (15 years recommended)"
        echo "6. Copy the certificate and private key"
        echo ""
        
        # Create temporary files for pasting certificates
        TEMP_CERT="/tmp/amoskys_cert.pem"
        TEMP_KEY="/tmp/amoskys_key.pem"
        
        echo "Paste the Origin Certificate (including -----BEGIN CERTIFICATE----- and -----END CERTIFICATE-----)"
        echo "Press Ctrl+D when done:"
        cat > "$TEMP_CERT"
        
        echo ""
        echo "Paste the Private Key (including -----BEGIN PRIVATE KEY----- and -----END PRIVATE KEY-----)"
        echo "Press Ctrl+D when done:"
        cat > "$TEMP_KEY"
        
        # Validate certificates
        if openssl x509 -in "$TEMP_CERT" -noout 2>/dev/null; then
            success "Certificate format validated"
        else
            error "Invalid certificate format"
        fi
        
        if openssl rsa -in "$TEMP_KEY" -check -noout 2>/dev/null; then
            success "Private key format validated"
        else
            error "Invalid private key format"
        fi
        
        # Install certificates
        cp "$TEMP_CERT" "$CERT_DIR/${DOMAIN}.pem"
        cp "$TEMP_KEY" "$CERT_DIR/${DOMAIN}.key"
        
        # Clean up temp files
        rm -f "$TEMP_CERT" "$TEMP_KEY"
        ;;
        
    2)
        log "🔧 Generating self-signed certificate for development..."
        
        # Generate self-signed certificate
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "$CERT_DIR/${DOMAIN}.key" \
            -out "$CERT_DIR/${DOMAIN}.pem" \
            -subj "/C=US/ST=State/L=City/O=AMOSKYS/OU=Neural Security/CN=${DOMAIN}" \
            -addext "subjectAltName=DNS:${DOMAIN},DNS:*.${DOMAIN}"
        
        warning "Self-signed certificate generated - browsers will show security warnings"
        ;;
        
    3)
        log "🔐 Let's Encrypt certificate setup..."
        
        # Install certbot if not present
        if ! command -v certbot &> /dev/null; then
            log "Installing certbot..."
            apt update
            apt install -y certbot python3-certbot-nginx
        fi
        
        # Generate Let's Encrypt certificate
        certbot --nginx -d "$DOMAIN" -d "www.${DOMAIN}" --non-interactive --agree-tos \
            --email "admin@${DOMAIN}" --redirect
        
        # Copy certificates to our directory
        cp "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" "$CERT_DIR/${DOMAIN}.pem"
        cp "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" "$CERT_DIR/${DOMAIN}.key"
        
        success "Let's Encrypt certificate installed"
        ;;
        
    *)
        error "Invalid option selected"
        ;;
esac

# Set proper permissions
chown root:root "$CERT_DIR"/*
chmod 644 "$CERT_DIR/${DOMAIN}.pem"
chmod 600 "$CERT_DIR/${DOMAIN}.key"

# Verify certificate installation
log "🔍 Verifying certificate installation..."

if [[ -f "$CERT_DIR/${DOMAIN}.pem" && -f "$CERT_DIR/${DOMAIN}.key" ]]; then
    success "Certificate files installed successfully"
    
    # Display certificate info
    echo ""
    log "📋 Certificate Information:"
    openssl x509 -in "$CERT_DIR/${DOMAIN}.pem" -noout -subject -dates -issuer
    
    # Verify private key matches certificate
    CERT_HASH=$(openssl x509 -noout -modulus -in "$CERT_DIR/${DOMAIN}.pem" | openssl md5)
    KEY_HASH=$(openssl rsa -noout -modulus -in "$CERT_DIR/${DOMAIN}.key" | openssl md5)
    
    if [[ "$CERT_HASH" == "$KEY_HASH" ]]; then
        success "Certificate and private key match"
    else
        error "Certificate and private key do not match"
    fi
    
else
    error "Certificate installation failed"
fi

echo ""
log "📊 Next Steps:"
echo "  1. Run: sudo ./scripts/deploy_web.sh"
echo "  2. Configure DNS: amoskys.com → Your VPS IP"
echo "  3. Test: curl https://amoskys.com/health"
echo "  4. Verify: https://www.ssllabs.com/ssltest/"

success "🧠🛡️ SSL setup completed successfully!"
