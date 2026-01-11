#!/bin/bash
##############################################################################
# AMOSKYS KernelAudit - Local Deployment Script
##############################################################################
#
# Purpose: Deploy KernelAuditGuardV2 from local Mac to production server
#
# Usage:
#   ./deploy_to_server.sh
#
# This script (run on local Mac) will:
#   1. Transfer deployment package to server
#   2. Transfer AMOSKYS source code to server
#   3. SSH into server and run server_setup.sh
#   4. Display monitoring commands
#
##############################################################################

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Server Configuration
SERVER_USER="ubuntu"
SERVER_HOST="3.147.175.238"
SERVER_NAME="amoskys-vps"
SERVER_PRIVATE_IP="172.31.39.9"
SSH_KEY="${HOME}/.ssh/amoskys-key.pem"  # Adjust if your key is different

# Local paths
LOCAL_REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEPLOYMENT_DIR="${LOCAL_REPO_ROOT}/deployments/kernel_audit"

# Remote paths
REMOTE_HOME="/home/${SERVER_USER}"
REMOTE_AMOSKYS_SRC="${REMOTE_HOME}/amoskys-src"
REMOTE_DEPLOYMENT="${REMOTE_HOME}/kernel_audit"

##############################################################################
# Helper Functions
##############################################################################

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

##############################################################################
# Pre-flight Checks
##############################################################################

check_ssh_key() {
    log_info "Checking SSH key..."

    if [ ! -f "$SSH_KEY" ]; then
        log_error "SSH key not found: $SSH_KEY"
        log_info "Searching for SSH keys in ~/.ssh..."

        # Search for possible keys
        POSSIBLE_KEYS=(
            "${HOME}/.ssh/amoskys-key"
            "${HOME}/.ssh/amoskys-key.pem"
            "${HOME}/.ssh/id_rsa"
            "${HOME}/.ssh/id_ed25519"
        )

        for key in "${POSSIBLE_KEYS[@]}"; do
            if [ -f "$key" ]; then
                log_warn "Found alternative key: $key"
                read -p "Use this key? (y/n): " -n 1 -r
                echo
                if [[ $REPLY =~ ^[Yy]$ ]]; then
                    SSH_KEY="$key"
                    log_success "Using key: $SSH_KEY"
                    return 0
                fi
            fi
        done

        log_error "No valid SSH key found. Please update SSH_KEY in this script."
        exit 1
    fi

    log_success "SSH key OK: $SSH_KEY"
}

test_ssh_connection() {
    log_info "Testing SSH connection to ${SERVER_HOST}..."

    if ssh -i "$SSH_KEY" -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
        "${SERVER_USER}@${SERVER_HOST}" "echo 'SSH OK'" > /dev/null 2>&1; then
        log_success "SSH connection successful"
        return 0
    else
        log_error "Cannot connect to ${SERVER_HOST}"
        log_error "Troubleshooting:"
        log_error "  1. Check SSH key permissions: chmod 400 ${SSH_KEY}"
        log_error "  2. Check AWS security group allows SSH from your IP"
        log_error "  3. Check instance is running"
        exit 1
    fi
}

check_local_files() {
    log_info "Checking local files..."

    if [ ! -d "${LOCAL_REPO_ROOT}/src/amoskys" ]; then
        log_error "AMOSKYS source not found: ${LOCAL_REPO_ROOT}/src/amoskys"
        exit 1
    fi

    if [ ! -f "${DEPLOYMENT_DIR}/install.sh" ]; then
        log_error "install.sh not found in deployment directory"
        exit 1
    fi

    log_success "Local files OK"
}

##############################################################################
# Step 1: Transfer Files to Server
##############################################################################

transfer_files() {
    log_info "Transferring files to server..."

    # Transfer AMOSKYS source code
    log_info "  → Transferring AMOSKYS source (src/amoskys)..."
    ssh -i "$SSH_KEY" "${SERVER_USER}@${SERVER_HOST}" "mkdir -p ${REMOTE_AMOSKYS_SRC}"

    rsync -av -e "ssh -i $SSH_KEY" \
        --exclude='.git' \
        --exclude='*.pyc' \
        --exclude='__pycache__' \
        --exclude='.DS_Store' \
        --exclude='venv' \
        --exclude='.venv' \
        --exclude='*.egg-info' \
        --exclude='build' \
        --exclude='dist' \
        --exclude='.pytest_cache' \
        --exclude='.mypy_cache' \
        "${LOCAL_REPO_ROOT}/src/amoskys/" \
        "${SERVER_USER}@${SERVER_HOST}:${REMOTE_AMOSKYS_SRC}/amoskys/" \
        | grep -v "^building\|^sending\|^sent\|^total" || true

    # Transfer deployment package
    log_info "  → Transferring deployment package..."
    rsync -av -e "ssh -i $SSH_KEY" \
        --exclude='*.pyc' \
        --exclude='__pycache__' \
        --exclude='.DS_Store' \
        "${DEPLOYMENT_DIR}/" \
        "${SERVER_USER}@${SERVER_HOST}:${REMOTE_DEPLOYMENT}/" \
        | grep -v "^building\|^sending\|^sent\|^total" || true

    log_success "Files transferred successfully"
}

##############################################################################
# Step 2: Run Remote Setup Script
##############################################################################

run_remote_setup() {
    log_info "Running setup script on server..."
    echo ""

    ssh -i "$SSH_KEY" -t "${SERVER_USER}@${SERVER_HOST}" bash <<'ENDSSH'
cd ~/kernel_audit
chmod +x server_setup.sh
./server_setup.sh
ENDSSH

    echo ""
    log_success "Remote setup completed"
}

##############################################################################
# Step 3: Display Monitoring Info
##############################################################################

display_monitoring_info() {
    echo ""
    echo "=========================================="
    echo "✅ Deployment Complete!"
    echo "=========================================="
    echo ""
    log_success "KernelAudit Guard v2 is running on ${SERVER_NAME}"
    echo ""
    log_info "Server Details:"
    echo "  • Name: ${SERVER_NAME}"
    echo "  • Public IP: ${SERVER_HOST}"
    echo "  • Private IP: ${SERVER_PRIVATE_IP}"
    echo ""
    log_info "Quick Monitoring Commands:"
    echo ""
    echo "  # SSH to server"
    echo "  ssh -i ${SSH_KEY} ${SERVER_USER}@${SERVER_HOST}"
    echo ""
    echo "  # Real-time logs"
    echo "  ssh -i ${SSH_KEY} ${SERVER_USER}@${SERVER_HOST} 'sudo journalctl -u amoskys-kernel-audit -f'"
    echo ""
    echo "  # Check metrics (after 5 minutes)"
    echo "  ssh -i ${SSH_KEY} ${SERVER_USER}@${SERVER_HOST} 'sudo journalctl -u amoskys-kernel-audit | grep \"emitted metrics\"'"
    echo ""
    echo "  # Service status"
    echo "  ssh -i ${SSH_KEY} ${SERVER_USER}@${SERVER_HOST} 'sudo systemctl status amoskys-kernel-audit'"
    echo ""
    log_info "Next Steps:"
    echo "  1. Monitor logs for 10-15 minutes"
    echo "  2. Verify metrics show success_rate >99%"
    echo "  3. Check SOMA dashboard for KERNEL_AUDIT events"
    echo "  4. Proceed to Phase 2 after 24h validation"
    echo ""
}

##############################################################################
# Main Execution
##############################################################################

main() {
    echo ""
    echo "=========================================="
    echo "AMOSKYS KernelAudit Deployment"
    echo "=========================================="
    echo ""
    echo "Target: ${SERVER_NAME} (${SERVER_HOST})"
    echo "Source: ${LOCAL_REPO_ROOT}"
    echo ""

    # Pre-flight checks
    check_ssh_key
    check_local_files
    test_ssh_connection

    echo ""
    read -p "Ready to deploy? (y/n): " -n 1 -r
    echo ""

    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_warn "Deployment cancelled"
        exit 0
    fi

    echo ""

    # Execute deployment
    transfer_files
    run_remote_setup
    display_monitoring_info
}

main "$@"
