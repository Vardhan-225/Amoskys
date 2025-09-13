#!/bin/bash

# AMOSKYS SSL Certificate Management Script
# Handles Cloudflare Origin Certificate installation and management

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

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

# Configuration
CERT_PATH="/opt/amoskys/certs"
DOMAIN="amoskys.com"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root (use sudo)"
fi

log "🔒 AMOSKYS SSL Certificate Management"
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Function to validate certificate files
validate_cert_files() {
    local cert_file="$1"
    local key_file="$2"
    
    # Check if files exist
    if [[ ! -f "$cert_file" ]]; then
        error "Certificate file not found: $cert_file"
    fi
    
    if [[ ! -f "$key_file" ]]; then
        error "Private key file not found: $key_file"
    fi
    
    # Validate certificate format
    if openssl x509 -in "$cert_file" -noout -text >/dev/null 2>&1; then
        success "Certificate file format valid"
    else
        error "Invalid certificate file format"
    fi
    
    # Validate private key format
    if openssl rsa -in "$key_file" -check -noout >/dev/null 2>&1; then
        success "Private key file format valid"
    else
        error "Invalid private key file format"
    fi
    
    # Check if certificate and key match
    cert_modulus=$(openssl x509 -noout -modulus -in "$cert_file" | openssl md5)
    key_modulus=$(openssl rsa -noout -modulus -in "$key_file" | openssl md5)
    
    if [[ "$cert_modulus" == "$key_modulus" ]]; then
        success "Certificate and private key match"
    else
        error "Certificate and private key do not match"
    fi
    
    # Display certificate info
    log "📋 Certificate Information:"
    openssl x509 -in "$cert_file" -noout -subject -issuer -dates
}

# Function to install certificates
install_certificates() {
    local cert_file="$1"
    local key_file="$2"
    
    log "📂 Creating certificate directory..."
    mkdir -p "$CERT_PATH"
    
    log "📋 Installing certificates..."
    cp "$cert_file" "$CERT_PATH/${DOMAIN}.pem"
    cp "$key_file" "$CERT_PATH/${DOMAIN}.key"
    
    # Set proper ownership and permissions
    chown root:root "$CERT_PATH"/*
    chmod 644 "$CERT_PATH/${DOMAIN}.pem"
    chmod 600 "$CERT_PATH/${DOMAIN}.key"
    
    success "Certificates installed to $CERT_PATH"
}

# Function to test NGINX configuration with new certificates
test_nginx_config() {
    if command -v nginx &> /dev/null; then
        log "🌐 Testing NGINX configuration..."
        if nginx -t; then
            success "NGINX configuration test passed"
            
            log "🔄 Reloading NGINX..."
            systemctl reload nginx
            success "NGINX reloaded"
        else
            error "NGINX configuration test failed"
        fi
    else
        warning "NGINX not found, skipping configuration test"
    fi
}

# Function to check certificate expiry
check_cert_expiry() {
    local cert_file="$CERT_PATH/${DOMAIN}.pem"
    
    if [[ -f "$cert_file" ]]; then
        log "📅 Checking certificate expiry..."
        
        expiry_date=$(openssl x509 -in "$cert_file" -noout -enddate | cut -d= -f2)
        expiry_epoch=$(date -d "$expiry_date" +%s)
        current_epoch=$(date +%s)
        days_until_expiry=$(( (expiry_epoch - current_epoch) / 86400 ))
        
        echo "Certificate expires: $expiry_date"
        echo "Days until expiry: $days_until_expiry"
        
        if [[ $days_until_expiry -lt 30 ]]; then
            warning "Certificate expires in less than 30 days!"
        elif [[ $days_until_expiry -lt 90 ]]; then
            warning "Certificate expires in less than 90 days"
        else
            success "Certificate expiry is okay ($days_until_expiry days)"
        fi
    else
        warning "No certificate found to check"
    fi
}

# Function to backup existing certificates
backup_certificates() {
    if [[ -d "$CERT_PATH" ]]; then
        backup_dir="/opt/amoskys/backups/certs_$(date +%Y%m%d_%H%M%S)"
        log "💾 Backing up existing certificates to $backup_dir"
        mkdir -p "$backup_dir"
        cp -r "$CERT_PATH"/* "$backup_dir/" 2>/dev/null || true
        success "Certificates backed up"
    fi
}

# Main script logic
case "${1:-help}" in
    "install")
        if [[ $# -ne 3 ]]; then
            error "Usage: $0 install <certificate_file> <private_key_file>"
        fi
        
        cert_file="$2"
        key_file="$3"
        
        log "Installing SSL certificates for $DOMAIN"
        validate_cert_files "$cert_file" "$key_file"
        backup_certificates
        install_certificates "$cert_file" "$key_file"
        test_nginx_config
        success "SSL certificate installation completed"
        ;;
        
    "check")
        log "Checking existing SSL certificates"
        check_cert_expiry
        
        if [[ -f "$CERT_PATH/${DOMAIN}.pem" && -f "$CERT_PATH/${DOMAIN}.key" ]]; then
            validate_cert_files "$CERT_PATH/${DOMAIN}.pem" "$CERT_PATH/${DOMAIN}.key"
        else
            warning "No certificates found in $CERT_PATH"
        fi
        ;;
        
    "renew")
        warning "Certificate renewal must be done through Cloudflare Dashboard"
        echo "Steps to renew Cloudflare Origin Certificate:"
        echo "1. Log into Cloudflare Dashboard"
        echo "2. Go to SSL/TLS > Origin Server"
        echo "3. Create new Origin Certificate"
        echo "4. Download new certificate files"
        echo "5. Run: $0 install <new_cert.pem> <new_key.key>"
        ;;
        
    "status")
        log "🔒 SSL Certificate Status for $DOMAIN"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        
        if [[ -f "$CERT_PATH/${DOMAIN}.pem" ]]; then
            echo "Certificate: ✅ Installed"
            check_cert_expiry
        else
            echo "Certificate: ❌ Not found"
        fi
        
        if [[ -f "$CERT_PATH/${DOMAIN}.key" ]]; then
            echo "Private Key: ✅ Installed"
        else
            echo "Private Key: ❌ Not found"
        fi
        
        # Test if HTTPS is working
        if command -v curl &> /dev/null; then
            if curl -s -k "https://$DOMAIN/health" >/dev/null 2>&1; then
                echo "HTTPS Endpoint: ✅ Responding"
            else
                echo "HTTPS Endpoint: ❌ Not responding"
            fi
        fi
        ;;
        
    "help"|*)
        echo "🔒 AMOSKYS SSL Certificate Management"
        echo ""
        echo "Usage: $0 <command> [options]"
        echo ""
        echo "Commands:"
        echo "  install <cert.pem> <key.key>  Install new SSL certificates"
        echo "  check                         Check existing certificates"
        echo "  status                        Show certificate status"
        echo "  renew                         Show renewal instructions"
        echo "  help                          Show this help"
        echo ""
        echo "Examples:"
        echo "  $0 install amoskys.com.pem amoskys.com.key"
        echo "  $0 check"
        echo "  $0 status"
        ;;
esac
