#!/bin/bash
#
# AMOSKYS - VPS Firewall Configuration for Cloudflare
# Configures firewall to allow only Cloudflare IP ranges
#
# This script should be run on your VPS after deploying the application
# It ensures that all traffic comes through Cloudflare's proxy
#
# Usage:
#   sudo ./configure-vps-firewall.sh
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    print_error "This script must be run as root (use sudo)"
    exit 1
fi

# Detect firewall system
detect_firewall() {
    if command -v ufw &> /dev/null; then
        echo "ufw"
    elif command -v firewall-cmd &> /dev/null; then
        echo "firewalld"
    elif command -v iptables &> /dev/null; then
        echo "iptables"
    else
        echo "none"
    fi
}

FIREWALL=$(detect_firewall)

print_info "Detected firewall: $FIREWALL"

if [ "$FIREWALL" = "none" ]; then
    print_error "No supported firewall found (ufw, firewalld, or iptables)"
    exit 1
fi

# Cloudflare IPv4 ranges
CF_IPV4=(
    "173.245.48.0/20"
    "103.21.244.0/22"
    "103.22.200.0/22"
    "103.31.4.0/22"
    "141.101.64.0/18"
    "108.162.192.0/18"
    "190.93.240.0/20"
    "188.114.96.0/20"
    "197.234.240.0/22"
    "198.41.128.0/17"
    "162.158.0.0/15"
    "104.16.0.0/13"
    "104.24.0.0/14"
    "172.64.0.0/13"
    "131.0.72.0/22"
)

# Cloudflare IPv6 ranges
CF_IPV6=(
    "2400:cb00::/32"
    "2606:4700::/32"
    "2803:f800::/32"
    "2405:b500::/32"
    "2405:8100::/32"
    "2a06:98c0::/29"
    "2c0f:f248::/32"
)

configure_ufw() {
    print_info "Configuring UFW firewall..."
    
    # Enable UFW if not already enabled
    if ! ufw status | grep -q "Status: active"; then
        print_info "Enabling UFW..."
        ufw --force enable
    fi
    
    # Set default policies
    print_info "Setting default policies (deny incoming, allow outgoing)..."
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH (important!)
    print_warning "Ensuring SSH access is allowed..."
    ufw allow 22/tcp comment 'SSH access'
    
    # Delete old Cloudflare rules if they exist
    print_info "Cleaning up old Cloudflare rules..."
    ufw --force delete allow from 173.245.48.0/20 2>/dev/null || true
    
    # Allow HTTP/HTTPS from Cloudflare IPs only
    print_info "Adding Cloudflare IPv4 ranges..."
    for ip in "${CF_IPV4[@]}"; do
        ufw allow from "$ip" to any port 80 proto tcp comment 'Cloudflare HTTP'
        ufw allow from "$ip" to any port 443 proto tcp comment 'Cloudflare HTTPS'
    done
    
    print_info "Adding Cloudflare IPv6 ranges..."
    for ip in "${CF_IPV6[@]}"; do
        ufw allow from "$ip" to any port 80 proto tcp comment 'Cloudflare HTTP IPv6'
        ufw allow from "$ip" to any port 443 proto tcp comment 'Cloudflare HTTPS IPv6'
    done
    
    # Reload UFW
    ufw --force reload
    
    print_success "UFW configured successfully"
    echo ""
    print_info "Current UFW status:"
    ufw status numbered | head -n 30
}

configure_firewalld() {
    print_info "Configuring firewalld..."
    
    # Start and enable firewalld
    systemctl start firewalld
    systemctl enable firewalld
    
    # Create Cloudflare zone if it doesn't exist
    if ! firewall-cmd --get-zones | grep -q cloudflare; then
        print_info "Creating Cloudflare zone..."
        firewall-cmd --permanent --new-zone=cloudflare
    fi
    
    # Configure Cloudflare zone
    print_info "Adding Cloudflare IP ranges to zone..."
    for ip in "${CF_IPV4[@]}"; do
        firewall-cmd --permanent --zone=cloudflare --add-source="$ip"
    done
    
    for ip in "${CF_IPV6[@]}"; do
        firewall-cmd --permanent --zone=cloudflare --add-source="$ip"
    done
    
    # Allow HTTP/HTTPS in Cloudflare zone
    firewall-cmd --permanent --zone=cloudflare --add-service=http
    firewall-cmd --permanent --zone=cloudflare --add-service=https
    
    # Ensure SSH is allowed in public zone
    firewall-cmd --permanent --zone=public --add-service=ssh
    
    # Reload firewalld
    firewall-cmd --reload
    
    print_success "firewalld configured successfully"
    echo ""
    print_info "Current firewalld zones:"
    firewall-cmd --list-all-zones | grep -A 10 "cloudflare"
}

configure_iptables() {
    print_info "Configuring iptables..."
    
    print_warning "Note: iptables rules are not persistent by default"
    print_info "Consider installing iptables-persistent package"
    
    # Flush existing rules (careful!)
    read -p "Do you want to flush existing iptables rules? (yes/no) " -r
    if [[ $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        iptables -F
        iptables -X
    fi
    
    # Set default policies
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    
    # Allow loopback
    iptables -A INPUT -i lo -j ACCEPT
    
    # Allow established connections
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # Allow SSH
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    
    # Allow HTTP/HTTPS from Cloudflare IPs
    for ip in "${CF_IPV4[@]}"; do
        iptables -A INPUT -p tcp -s "$ip" --dport 80 -j ACCEPT
        iptables -A INPUT -p tcp -s "$ip" --dport 443 -j ACCEPT
    done
    
    # Save rules
    if command -v iptables-save &> /dev/null; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || \
        iptables-save > /etc/iptables.rules 2>/dev/null || \
        print_warning "Could not save iptables rules. Install iptables-persistent."
    fi
    
    print_success "iptables configured successfully"
    echo ""
    print_info "Current iptables rules:"
    iptables -L -n -v | head -n 30
}

# Main execution
main() {
    echo ""
    echo "=============================================="
    echo "  AMOSKYS - VPS Firewall Configuration"
    echo "  for Cloudflare Protection"
    echo "=============================================="
    echo ""
    
    print_warning "This will configure your firewall to ONLY accept HTTP/HTTPS traffic from Cloudflare"
    print_warning "Make sure:"
    print_warning "  1. Your domain is proxied through Cloudflare (orange cloud)"
    print_warning "  2. You have SSH access (port 22 will remain open)"
    print_warning "  3. You have a backup way to access your server"
    echo ""
    
    read -p "Do you want to continue? (yes/no) " -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        print_warning "Operation cancelled by user"
        exit 0
    fi
    
    case $FIREWALL in
        ufw)
            configure_ufw
            ;;
        firewalld)
            configure_firewalld
            ;;
        iptables)
            configure_iptables
            ;;
        *)
            print_error "Unsupported firewall: $FIREWALL"
            exit 1
            ;;
    esac
    
    echo ""
    echo "=============================================="
    print_success "Firewall Configuration Complete!"
    echo "=============================================="
    echo ""
    echo "Your VPS now only accepts HTTP/HTTPS traffic from Cloudflare IP ranges."
    echo ""
    echo "Testing:"
    echo "  - Access your site: https://amoskys.com"
    echo "  - Direct IP access should be blocked (if Cloudflare is proxying)"
    echo "  - SSH access should still work on port 22"
    echo ""
    echo "To update Cloudflare IP ranges in the future:"
    echo "  - Get latest ranges: https://www.cloudflare.com/ips/"
    echo "  - Re-run this script"
    echo ""
}

main
