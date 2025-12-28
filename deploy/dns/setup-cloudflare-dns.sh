#!/bin/bash
#
# AMOSKYS - Cloudflare DNS Setup Script
# Automates DNS record creation for amoskys.com
#
# Prerequisites:
# - Cloudflare API token with DNS edit permissions
# - jq installed (for JSON parsing)
#
# Usage:
#   export CLOUDFLARE_API_TOKEN="your_token_here"
#   export VPS_IP="your.vps.ip.address"
#   ./setup-cloudflare-dns.sh
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
ZONE_NAME="amoskys.com"
ZONE_ID="3f214ea5270b99e93c2a1460000e7a00"
CLOUDFLARE_API="https://api.cloudflare.com/client/v4"

# Function to print colored output
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

# Function to check prerequisites
check_prerequisites() {
    print_info "Checking prerequisites..."
    
    # Check for jq
    if ! command -v jq &> /dev/null; then
        print_error "jq is not installed. Please install it first."
        echo "  Ubuntu/Debian: sudo apt-get install jq"
        echo "  macOS: brew install jq"
        exit 1
    fi
    
    # Check for API token
    if [ -z "$CLOUDFLARE_API_TOKEN" ]; then
        print_error "CLOUDFLARE_API_TOKEN environment variable is not set"
        echo "Get your API token from: https://dash.cloudflare.com/profile/api-tokens"
        exit 1
    fi
    
    # Check for VPS IP
    if [ -z "$VPS_IP" ]; then
        print_error "VPS_IP environment variable is not set"
        echo "Usage: export VPS_IP=\"your.vps.ip.address\""
        exit 1
    fi
    
    # Validate IP format
    if ! echo "$VPS_IP" | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' > /dev/null; then
        print_error "Invalid IP address format: $VPS_IP"
        exit 1
    fi
    
    print_success "All prerequisites met"
}

# Function to verify API token
verify_api_token() {
    print_info "Verifying Cloudflare API token..."
    
    response=$(curl -s -X GET "$CLOUDFLARE_API/user/tokens/verify" \
        -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
        -H "Content-Type: application/json")
    
    if echo "$response" | jq -e '.success == true' > /dev/null; then
        print_success "API token verified"
    else
        print_error "API token verification failed"
        echo "$response" | jq '.'
        exit 1
    fi
}

# Function to list existing DNS records
list_dns_records() {
    print_info "Listing existing DNS records for $ZONE_NAME..."
    
    response=$(curl -s -X GET "$CLOUDFLARE_API/zones/$ZONE_ID/dns_records" \
        -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
        -H "Content-Type: application/json")
    
    if echo "$response" | jq -e '.success == true' > /dev/null; then
        echo "$response" | jq -r '.result[] | "\(.type)\t\(.name)\t\(.content)\t\(.proxied)"'
    else
        print_warning "Could not list existing DNS records"
    fi
}

# Function to create or update DNS record
create_or_update_dns_record() {
    local record_type=$1
    local record_name=$2
    local record_content=$3
    local proxied=$4
    local comment=$5
    
    local full_name="$record_name"
    if [ "$record_name" = "@" ]; then
        full_name="$ZONE_NAME"
    else
        full_name="$record_name.$ZONE_NAME"
    fi
    
    print_info "Processing: $record_type $full_name -> $record_content"
    
    # Check if record exists
    existing_record=$(curl -s -X GET "$CLOUDFLARE_API/zones/$ZONE_ID/dns_records?type=$record_type&name=$full_name" \
        -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
        -H "Content-Type: application/json")
    
    record_id=$(echo "$existing_record" | jq -r '.result[0].id // empty')
    
    # Prepare JSON payload
    payload=$(jq -n \
        --arg type "$record_type" \
        --arg name "$full_name" \
        --arg content "$record_content" \
        --argjson proxied "$proxied" \
        --arg comment "$comment" \
        '{
            type: $type,
            name: $name,
            content: $content,
            proxied: $proxied,
            comment: $comment,
            ttl: 1
        }')
    
    if [ -n "$record_id" ] && [ "$record_id" != "null" ]; then
        # Update existing record
        response=$(curl -s -X PUT "$CLOUDFLARE_API/zones/$ZONE_ID/dns_records/$record_id" \
            -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
            -H "Content-Type: application/json" \
            -d "$payload")
        
        if echo "$response" | jq -e '.success == true' > /dev/null; then
            print_success "Updated: $record_type $full_name"
        else
            print_error "Failed to update: $record_type $full_name"
            echo "$response" | jq '.errors'
        fi
    else
        # Create new record
        response=$(curl -s -X POST "$CLOUDFLARE_API/zones/$ZONE_ID/dns_records" \
            -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
            -H "Content-Type: application/json" \
            -d "$payload")
        
        if echo "$response" | jq -e '.success == true' > /dev/null; then
            print_success "Created: $record_type $full_name"
        else
            print_error "Failed to create: $record_type $full_name"
            echo "$response" | jq '.errors'
        fi
    fi
}

# Function to configure DNS records
configure_dns_records() {
    print_info "Configuring DNS records for amoskys.com..."
    echo ""
    
    # Primary A records
    create_or_update_dns_record "A" "@" "$VPS_IP" true "Main domain - points to VPS running NGINX"
    create_or_update_dns_record "A" "www" "$VPS_IP" true "WWW subdomain - points to VPS"
    
    # CNAME records for subdomains
    create_or_update_dns_record "CNAME" "app" "$ZONE_NAME" true "Application dashboard subdomain"
    create_or_update_dns_record "CNAME" "api" "$ZONE_NAME" true "API endpoints subdomain"
    create_or_update_dns_record "CNAME" "docs" "$ZONE_NAME" true "Documentation subdomain"
    
    # Optional future records
    create_or_update_dns_record "CNAME" "status" "$ZONE_NAME" true "Status page subdomain (future)"
    create_or_update_dns_record "CNAME" "metrics" "$ZONE_NAME" true "Metrics dashboard subdomain (future)"
    
    # SPF record
    create_or_update_dns_record "TXT" "@" "v=spf1 -all" false "SPF record - no mail servers authorized"
    
    echo ""
    print_success "DNS records configuration complete"
}

# Function to verify DNS propagation
verify_dns_propagation() {
    print_info "Verifying DNS propagation..."
    echo ""
    
    sleep 2  # Wait a bit for DNS to update
    
    records=("$ZONE_NAME" "www.$ZONE_NAME" "app.$ZONE_NAME" "api.$ZONE_NAME")
    
    for record in "${records[@]}"; do
        print_info "Checking $record..."
        if command -v dig &> /dev/null; then
            dig +short "$record" | head -n 3
        else
            nslookup "$record" | grep -A 1 "Name:" || echo "  (DNS lookup tool not available)"
        fi
    done
    
    echo ""
    print_info "Note: Full DNS propagation may take 1-5 minutes globally"
}

# Main execution
main() {
    echo ""
    echo "=============================================="
    echo "  AMOSKYS - Cloudflare DNS Setup"
    echo "=============================================="
    echo ""
    echo "Zone: $ZONE_NAME"
    echo "Zone ID: $ZONE_ID"
    echo "VPS IP: $VPS_IP"
    echo ""
    
    check_prerequisites
    verify_api_token
    
    echo ""
    print_info "Current DNS records:"
    list_dns_records
    echo ""
    
    read -p "Do you want to proceed with DNS configuration? (yes/no) " -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        print_warning "Operation cancelled by user"
        exit 0
    fi
    
    configure_dns_records
    verify_dns_propagation
    
    echo ""
    echo "=============================================="
    print_success "DNS Setup Complete!"
    echo "=============================================="
    echo ""
    echo "Next steps:"
    echo "1. Verify DNS propagation: https://www.whatsmydns.net/#A/$ZONE_NAME"
    echo "2. Test HTTPS access: https://$ZONE_NAME/health"
    echo "3. Check SSL rating: https://www.ssllabs.com/ssltest/analyze.html?d=$ZONE_NAME"
    echo "4. Monitor Cloudflare dashboard: https://dash.cloudflare.com"
    echo ""
}

# Run main function
main
