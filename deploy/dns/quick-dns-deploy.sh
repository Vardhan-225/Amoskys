#!/bin/bash
#
# AMOSKYS - Quick DNS Deployment Script
# Interactive script to guide through DNS deployment
#
# Usage:
#   ./quick-dns-deploy.sh
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

print_header() {
    echo -e "\n${CYAN}=============================================="
    echo -e "  $1"
    echo -e "==============================================${NC}\n"
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_step() {
    echo -e "\n${GREEN}━━━ Step $1 ━━━${NC}"
    echo -e "${CYAN}$2${NC}\n"
}

# Configuration
ZONE_NAME="amoskys.com"
ZONE_ID="3f214ea5270b99e93c2a1460000e7a00"
ACCOUNT_ID="a65accb1674b8138917103c0c334a981"

main() {
    print_header "AMOSKYS - DNS Deployment Assistant"
    
    echo "This script will guide you through deploying AMOSKYS to amoskys.com"
    echo "with Cloudflare DNS and SSL/TLS configuration."
    echo ""
    echo "Current domain status:"
    echo "  Domain: $ZONE_NAME"
    echo "  Zone ID: $ZONE_ID"
    echo "  Account ID: $ACCOUNT_ID"
    echo ""
    
    read -p "Press Enter to continue..."
    
    # Step 1: Check Prerequisites
    print_step "1/7" "Checking Prerequisites"
    check_prerequisites
    
    # Step 2: Gather Information
    print_step "2/7" "Gathering Deployment Information"
    gather_info
    
    # Step 3: DNS Configuration
    print_step "3/7" "DNS Configuration Options"
    dns_configuration
    
    # Step 4: SSL/TLS Setup
    print_step "4/7" "SSL/TLS Configuration"
    ssl_setup
    
    # Step 5: VPS Instructions
    print_step "5/7" "VPS Deployment Instructions"
    vps_instructions
    
    # Step 6: Firewall Configuration
    print_step "6/7" "Firewall Configuration"
    firewall_instructions
    
    # Step 7: Verification
    print_step "7/7" "Verification Steps"
    verification_steps
    
    # Summary
    deployment_summary
}

check_prerequisites() {
    print_info "Checking required tools..."
    
    local all_good=true
    
    # Check for dig
    if command -v dig &> /dev/null; then
        print_success "dig found (DNS testing)"
    else
        print_warning "dig not found (optional, for DNS testing)"
    fi
    
    # Check for curl
    if command -v curl &> /dev/null; then
        print_success "curl found (testing endpoints)"
    else
        print_error "curl not found (required)"
        all_good=false
    fi
    
    # Check for openssl
    if command -v openssl &> /dev/null; then
        print_success "openssl found (SSL testing)"
    else
        print_warning "openssl not found (optional, for SSL testing)"
    fi
    
    # Check for jq (for API method)
    if command -v jq &> /dev/null; then
        print_success "jq found (API automation available)"
    else
        print_warning "jq not found (API automation unavailable, manual DNS setup required)"
    fi
    
    if [ "$all_good" = false ]; then
        print_error "Please install missing required tools"
        exit 1
    fi
    
    echo ""
    print_success "Prerequisites check complete"
}

gather_info() {
    print_info "Please provide the following information:"
    echo ""
    
    # Get VPS IP
    read -p "Enter your VPS IP address: " VPS_IP
    
    # Validate IP
    if ! echo "$VPS_IP" | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' > /dev/null; then
        print_error "Invalid IP address format"
        exit 1
    fi
    
    print_success "VPS IP: $VPS_IP"
    
    # Export for use by other scripts
    export VPS_IP
    
    echo ""
    print_info "Do you have a Cloudflare API token?"
    echo "  (Required for automated DNS setup)"
    echo "  Get it from: https://dash.cloudflare.com/profile/api-tokens"
    echo ""
    read -p "Enter API token (or press Enter to skip): " CF_TOKEN
    
    if [ -n "$CF_TOKEN" ]; then
        export CLOUDFLARE_API_TOKEN="$CF_TOKEN"
        print_success "API token configured"
    else
        print_warning "No API token provided - will use manual DNS setup"
    fi
}

dns_configuration() {
    if [ -n "$CLOUDFLARE_API_TOKEN" ] && command -v jq &> /dev/null; then
        print_info "Automated DNS configuration available"
        echo ""
        echo "Would you like to:"
        echo "  1) Automatically configure DNS via API (recommended)"
        echo "  2) Show manual DNS configuration instructions"
        echo ""
        read -p "Choose option (1 or 2): " dns_option
        
        case $dns_option in
            1)
                print_info "Running automated DNS configuration..."
                if [ -x "deploy/dns/setup-cloudflare-dns.sh" ]; then
                    ./deploy/dns/setup-cloudflare-dns.sh
                    print_success "Automated DNS configuration complete"
                else
                    print_error "DNS setup script not found or not executable"
                    show_manual_dns
                fi
                ;;
            2)
                show_manual_dns
                ;;
            *)
                print_warning "Invalid option, showing manual instructions"
                show_manual_dns
                ;;
        esac
    else
        show_manual_dns
    fi
}

show_manual_dns() {
    print_info "Manual DNS Configuration Steps:"
    echo ""
    echo "1. Go to: https://dash.cloudflare.com"
    echo "2. Select domain: $ZONE_NAME"
    echo "3. Navigate to: DNS → Records"
    echo "4. Add the following DNS records:"
    echo ""
    echo "   Type   | Name   | Content     | Proxy  "
    echo "   -------|--------|-------------|--------"
    echo "   A      | @      | $VPS_IP     | ✅ Yes "
    echo "   A      | www    | $VPS_IP     | ✅ Yes "
    echo "   CNAME  | app    | $ZONE_NAME  | ✅ Yes "
    echo "   CNAME  | api    | $ZONE_NAME  | ✅ Yes "
    echo "   CNAME  | docs   | $ZONE_NAME  | ✅ Yes "
    echo ""
    echo "5. Save all records"
    echo ""
    read -p "Press Enter when DNS records are configured..."
    print_success "DNS configuration noted"
}

ssl_setup() {
    print_info "SSL/TLS Configuration Steps:"
    echo ""
    echo "You need to generate a Cloudflare Origin Certificate:"
    echo ""
    echo "1. Go to: https://dash.cloudflare.com"
    echo "2. Select: $ZONE_NAME"
    echo "3. Navigate to: SSL/TLS → Origin Server"
    echo "4. Click: 'Create Certificate'"
    echo "5. Configure:"
    echo "   - Hostnames: $ZONE_NAME, *.$ZONE_NAME"
    echo "   - Validity: 15 years"
    echo "6. Download:"
    echo "   - Origin Certificate (save as amoskys.com.pem)"
    echo "   - Private Key (save as amoskys.com.key)"
    echo ""
    echo "7. Set SSL/TLS mode:"
    echo "   - Go to: SSL/TLS → Overview"
    echo "   - Select: 'Full (strict)'"
    echo ""
    echo "8. Enable HSTS:"
    echo "   - Go to: SSL/TLS → Edge Certificates"
    echo "   - Enable HSTS (12 months, include subdomains)"
    echo ""
    read -p "Press Enter when SSL/TLS is configured and certificates are downloaded..."
    print_success "SSL/TLS configuration noted"
}

vps_instructions() {
    print_info "VPS Deployment Instructions:"
    echo ""
    echo "Run these commands on your VPS:"
    echo ""
    
    cat << 'EOF'
# 1. Clone repository
sudo mkdir -p /opt/amoskys
cd /opt/amoskys
sudo git clone https://github.com/Vardhan-225/Amoskys.git .

# 2. Transfer SSL certificates to VPS
# (On local machine, run:)
# scp amoskys.com.pem user@YOUR_VPS:/tmp/
# scp amoskys.com.key user@YOUR_VPS:/tmp/

# 3. Install certificates
sudo mkdir -p /opt/amoskys/certs
sudo mv /tmp/amoskys.com.pem /opt/amoskys/certs/
sudo mv /tmp/amoskys.com.key /opt/amoskys/certs/
sudo chmod 644 /opt/amoskys/certs/amoskys.com.pem
sudo chmod 600 /opt/amoskys/certs/amoskys.com.key

# 4. Install dependencies
cd /opt/amoskys
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[web]

# 5. Configure NGINX
sudo cp deploy/nginx/amoskys.conf /etc/nginx/sites-available/
sudo ln -sf /etc/nginx/sites-available/amoskys.conf /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx

# 6. Install and start service
sudo cp deploy/systemd/amoskys-web.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable amoskys-web
sudo systemctl start amoskys-web

# 7. Check status
sudo systemctl status amoskys-web
EOF
    
    echo ""
    read -p "Press Enter when VPS deployment is complete..."
    print_success "VPS deployment noted"
}

firewall_instructions() {
    print_info "VPS Firewall Configuration:"
    echo ""
    echo "For security, configure your VPS firewall to only accept"
    echo "HTTP/HTTPS traffic from Cloudflare IP ranges."
    echo ""
    echo "On your VPS, run:"
    echo ""
    echo "  cd /opt/amoskys/deploy/dns"
    echo "  sudo chmod +x configure-vps-firewall.sh"
    echo "  sudo ./configure-vps-firewall.sh"
    echo ""
    echo "This will configure your firewall (UFW/firewalld/iptables)"
    echo "to only allow Cloudflare IPs."
    echo ""
    read -p "Press Enter when firewall is configured..."
    print_success "Firewall configuration noted"
}

verification_steps() {
    print_info "Let's verify your deployment..."
    echo ""
    
    # Test DNS
    print_info "Testing DNS resolution..."
    if command -v dig &> /dev/null; then
        echo ""
        echo "Main domain:"
        dig +short "$ZONE_NAME" | head -n 2
        echo ""
        echo "WWW subdomain:"
        dig +short "www.$ZONE_NAME" | head -n 2
        echo ""
    else
        print_warning "dig not available, skipping DNS test"
    fi
    
    # Test HTTPS
    print_info "Testing HTTPS access..."
    echo ""
    
    sleep 2  # Give DNS time to propagate
    
    if curl -I -s -f "https://$ZONE_NAME/health" > /dev/null 2>&1; then
        print_success "Main domain is accessible via HTTPS"
    else
        print_warning "Cannot reach https://$ZONE_NAME/health yet (DNS may still be propagating)"
    fi
    
    if curl -I -s -f "https://www.$ZONE_NAME/health" > /dev/null 2>&1; then
        print_success "WWW subdomain is accessible"
    else
        print_warning "Cannot reach https://www.$ZONE_NAME/health yet"
    fi
    
    echo ""
    print_info "Manual verification steps:"
    echo ""
    echo "1. Test all endpoints:"
    echo "   curl https://$ZONE_NAME/health"
    echo "   curl https://www.$ZONE_NAME/health"
    echo "   curl https://app.$ZONE_NAME/health"
    echo "   curl https://api.$ZONE_NAME/health"
    echo ""
    echo "2. Check SSL grade:"
    echo "   https://www.ssllabs.com/ssltest/analyze.html?d=$ZONE_NAME"
    echo ""
    echo "3. Check DNS propagation:"
    echo "   https://www.whatsmydns.net/#A/$ZONE_NAME"
    echo ""
    echo "4. Monitor Cloudflare dashboard:"
    echo "   https://dash.cloudflare.com"
    echo ""
}

deployment_summary() {
    print_header "Deployment Summary"
    
    echo "Configuration Details:"
    echo "  Domain: $ZONE_NAME"
    echo "  VPS IP: $VPS_IP"
    echo "  Zone ID: $ZONE_ID"
    echo ""
    echo "Next Steps:"
    echo "  1. Monitor Cloudflare analytics"
    echo "  2. Set up Cloudflare alerts"
    echo "  3. Review application logs"
    echo "  4. Test all endpoints"
    echo ""
    echo "Documentation:"
    echo "  - Complete Guide: docs/DNS_DEPLOYMENT_GUIDE.md"
    echo "  - Deployment Checklist: docs/DNS_DEPLOYMENT_CHECKLIST.md"
    echo "  - Cloudflare Setup: docs/CLOUDFLARE_SETUP.md"
    echo "  - VPS Guide: docs/VPS_DEPLOYMENT_GUIDE.md"
    echo ""
    echo "Support:"
    echo "  - Cloudflare Dashboard: https://dash.cloudflare.com"
    echo "  - Repository: https://github.com/Vardhan-225/Amoskys"
    echo ""
    
    print_success "Deployment guide complete!"
    echo ""
    echo "🧠🛡️ AMOSKYS Neural Security Command Platform"
    echo "   DNS Deployment Assistant - Complete"
    echo ""
}

# Run main function
main
