#!/bin/bash
##############################################################################
# AMOSKYS KernelAudit Guard v2 - Installation Script
##############################################################################
#
# Purpose: Automated installation of KernelAuditGuardV2 agent
#
# Usage:
#   sudo ./install.sh [--device-id DEVICE_ID] [--skip-audit-rules]
#
# What this script does:
#   1. Create amoskys service account and directories
#   2. Install audit rules configuration
#   3. Install systemd service
#   4. Configure permissions
#   5. Enable and start service
#
# Requirements:
#   - Linux with systemd
#   - auditd installed and running
#   - Python 3.8+ with amoskys package installed
#
##############################################################################

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
AMOSKYS_USER="amoskys"
AMOSKYS_GROUP="amoskys"
AMOSKYS_HOME="/var/lib/amoskys"
QUEUE_DIR="$AMOSKYS_HOME/queues/kernel_audit"
AUDIT_LOG="/var/log/audit/audit.log"

# Installation paths
AUDIT_RULES_SRC="./audit_rules.conf"
AUDIT_RULES_DST="/etc/audit/rules.d/amoskys-kernel.rules"
SYSTEMD_SERVICE_SRC="./amoskys-kernel-audit.service"
SYSTEMD_SERVICE_DST="/etc/systemd/system/amoskys-kernel-audit.service"
AGENT_SCRIPT_SRC="./run_agent_v2.py"
AGENT_SCRIPT_DST="/usr/local/bin/amoskys-kernel-audit-agent"

# Arguments
DEVICE_ID=""
SKIP_AUDIT_RULES=0

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

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root"
        echo "Usage: sudo $0"
        exit 1
    fi
}

check_command() {
    if ! command -v "$1" &> /dev/null; then
        log_error "Required command not found: $1"
        return 1
    fi
    return 0
}

##############################################################################
# Pre-flight Checks
##############################################################################

preflight_checks() {
    log_info "Running pre-flight checks..."

    # Check if running as root
    check_root

    # Check required commands
    local required_commands=("systemctl" "auditctl" "python3" "useradd" "getfacl" "setfacl")
    local missing_commands=()

    for cmd in "${required_commands[@]}"; do
        if ! check_command "$cmd"; then
            missing_commands+=("$cmd")
        fi
    done

    if [ ${#missing_commands[@]} -gt 0 ]; then
        log_error "Missing required commands: ${missing_commands[*]}"
        log_error "Install missing packages:"
        log_error "  Debian/Ubuntu: apt-get install auditd acl python3"
        log_error "  RHEL/CentOS: yum install audit acl python3"
        exit 1
    fi

    # Check if auditd is running
    if ! systemctl is-active --quiet auditd; then
        log_warn "auditd service is not running"
        log_info "Starting auditd..."
        systemctl start auditd || {
            log_error "Failed to start auditd"
            exit 1
        }
    fi

    # Check if Python module is importable
    if ! python3 -c "from amoskys.agents.kernel_audit import KernelAuditAgentV2" 2>/dev/null; then
        log_error "Cannot import amoskys.agents.kernel_audit.KernelAuditAgentV2"
        log_error "Ensure AMOSKYS is installed:"
        log_error "  cd /path/to/amoskys"
        log_error "  pip3 install -e ."
        exit 1
    fi

    log_success "Pre-flight checks passed"
}

##############################################################################
# Step 1: Create Service Account
##############################################################################

create_service_account() {
    log_info "Creating service account..."

    # Create group if it doesn't exist
    if ! getent group "$AMOSKYS_GROUP" > /dev/null; then
        groupadd -r "$AMOSKYS_GROUP"
        log_success "Created group: $AMOSKYS_GROUP"
    else
        log_info "Group already exists: $AMOSKYS_GROUP"
    fi

    # Create user if it doesn't exist
    if ! id "$AMOSKYS_USER" &>/dev/null; then
        useradd -r -g "$AMOSKYS_GROUP" -d "$AMOSKYS_HOME" -s /bin/false "$AMOSKYS_USER"
        log_success "Created user: $AMOSKYS_USER"
    else
        log_info "User already exists: $AMOSKYS_USER"
    fi

    # Create directories
    mkdir -p "$AMOSKYS_HOME"
    mkdir -p "$QUEUE_DIR"
    chown -R "$AMOSKYS_USER:$AMOSKYS_GROUP" "$AMOSKYS_HOME"

    log_success "Created directories: $AMOSKYS_HOME, $QUEUE_DIR"
}

##############################################################################
# Step 2: Configure Permissions
##############################################################################

configure_permissions() {
    log_info "Configuring permissions..."

    # Grant read access to audit log
    if [ -f "$AUDIT_LOG" ]; then
        # Try ACL first (more fine-grained)
        if setfacl -m "u:$AMOSKYS_USER:r" "$AUDIT_LOG" 2>/dev/null; then
            log_success "Granted ACL read permission on $AUDIT_LOG"
        else
            # Fallback: add to adm group (Debian/Ubuntu)
            if getent group adm > /dev/null; then
                usermod -a -G adm "$AMOSKYS_USER"
                log_success "Added $AMOSKYS_USER to adm group"
            else
                log_warn "Could not grant read permission on $AUDIT_LOG"
                log_warn "Manual step required: sudo setfacl -m u:$AMOSKYS_USER:r $AUDIT_LOG"
            fi
        fi
    else
        log_warn "Audit log not found at $AUDIT_LOG"
    fi

    # Set queue directory permissions
    chown -R "$AMOSKYS_USER:$AMOSKYS_GROUP" "$QUEUE_DIR"
    chmod 755 "$QUEUE_DIR"

    log_success "Configured permissions"
}

##############################################################################
# Step 3: Install Audit Rules
##############################################################################

install_audit_rules() {
    if [ "$SKIP_AUDIT_RULES" -eq 1 ]; then
        log_info "Skipping audit rules installation (--skip-audit-rules)"
        return 0
    fi

    log_info "Installing audit rules..."

    if [ ! -f "$AUDIT_RULES_SRC" ]; then
        log_error "Audit rules file not found: $AUDIT_RULES_SRC"
        exit 1
    fi

    # Backup existing rules if present
    if [ -f "$AUDIT_RULES_DST" ]; then
        cp "$AUDIT_RULES_DST" "${AUDIT_RULES_DST}.backup.$(date +%s)"
        log_info "Backed up existing rules to ${AUDIT_RULES_DST}.backup.*"
    fi

    # Copy rules
    cp "$AUDIT_RULES_SRC" "$AUDIT_RULES_DST"
    log_success "Installed audit rules to $AUDIT_RULES_DST"

    # Load rules
    log_info "Loading audit rules..."
    if augenrules --load; then
        log_success "Loaded audit rules"
    else
        log_warn "Failed to load audit rules automatically"
        log_warn "Manual step: sudo augenrules --load"
    fi

    # Restart auditd
    log_info "Restarting auditd..."
    systemctl restart auditd

    # Verify rules
    local rule_count=$(auditctl -l | grep -c "amoskys" || echo "0")
    if [ "$rule_count" -gt 0 ]; then
        log_success "Verified $rule_count AMOSKYS audit rules loaded"
    else
        log_warn "No AMOSKYS audit rules found. Check: sudo auditctl -l"
    fi
}

##############################################################################
# Step 4: Install Agent Binary
##############################################################################

install_agent_binary() {
    log_info "Installing agent binary..."

    if [ ! -f "$AGENT_SCRIPT_SRC" ]; then
        log_error "Agent script not found: $AGENT_SCRIPT_SRC"
        exit 1
    fi

    # Copy agent script
    cp "$AGENT_SCRIPT_SRC" "$AGENT_SCRIPT_DST"
    chmod +x "$AGENT_SCRIPT_DST"

    log_success "Installed agent binary to $AGENT_SCRIPT_DST"

    # Test agent import
    if python3 "$AGENT_SCRIPT_DST" --help &>/dev/null; then
        log_success "Agent binary is executable"
    else
        log_warn "Agent binary may have issues. Test manually:"
        log_warn "  $AGENT_SCRIPT_DST --help"
    fi
}

##############################################################################
# Step 5: Install Systemd Service
##############################################################################

install_systemd_service() {
    log_info "Installing systemd service..."

    if [ ! -f "$SYSTEMD_SERVICE_SRC" ]; then
        log_error "Systemd service file not found: $SYSTEMD_SERVICE_SRC"
        exit 1
    fi

    # Backup existing service if present
    if [ -f "$SYSTEMD_SERVICE_DST" ]; then
        cp "$SYSTEMD_SERVICE_DST" "${SYSTEMD_SERVICE_DST}.backup.$(date +%s)"
        log_info "Backed up existing service to ${SYSTEMD_SERVICE_DST}.backup.*"
    fi

    # Copy service file
    cp "$SYSTEMD_SERVICE_SRC" "$SYSTEMD_SERVICE_DST"

    # Update device ID if provided
    if [ -n "$DEVICE_ID" ]; then
        log_info "Setting device ID: $DEVICE_ID"
        sed -i "s/%H/$DEVICE_ID/g" "$SYSTEMD_SERVICE_DST"
    fi

    # Reload systemd
    systemctl daemon-reload

    log_success "Installed systemd service to $SYSTEMD_SERVICE_DST"
}

##############################################################################
# Step 6: Enable and Start Service
##############################################################################

enable_and_start_service() {
    log_info "Enabling and starting service..."

    # Enable service
    systemctl enable amoskys-kernel-audit.service
    log_success "Enabled service"

    # Start service
    if systemctl start amoskys-kernel-audit.service; then
        log_success "Started service"
    else
        log_error "Failed to start service"
        log_error "Check logs: journalctl -u amoskys-kernel-audit -n 50"
        exit 1
    fi

    # Wait for service to stabilize
    sleep 2

    # Check status
    if systemctl is-active --quiet amoskys-kernel-audit; then
        log_success "Service is running"

        # Show status
        echo ""
        log_info "Service Status:"
        systemctl status amoskys-kernel-audit --no-pager | head -20
    else
        log_error "Service is not running"
        log_error "Check logs: journalctl -u amoskys-kernel-audit -n 50"
        exit 1
    fi
}

##############################################################################
# Main Installation Flow
##############################################################################

main() {
    echo ""
    echo "=========================================="
    echo "AMOSKYS KernelAudit Guard v2 Installation"
    echo "=========================================="
    echo ""

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --device-id=*)
                DEVICE_ID="${1#*=}"
                shift
                ;;
            --device-id)
                DEVICE_ID="$2"
                shift 2
                ;;
            --skip-audit-rules)
                SKIP_AUDIT_RULES=1
                shift
                ;;
            --help|-h)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --device-id ID         Set device identifier (use --device-id=ID or --device-id ID)"
                echo "  --skip-audit-rules     Skip audit rules installation"
                echo ""
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done

    # Run installation steps
    preflight_checks
    create_service_account
    configure_permissions
    install_audit_rules
    install_agent_binary
    install_systemd_service
    enable_and_start_service

    # Success summary
    echo ""
    echo "=========================================="
    echo "Installation Complete!"
    echo "=========================================="
    echo ""
    log_success "KernelAudit Guard v2 is now running"
    echo ""
    log_info "Next Steps:"
    log_info "1. Run smoke test: sudo ./smoke_test.sh"
    log_info "2. Check metrics: journalctl -u amoskys-kernel-audit | grep metrics"
    log_info "3. Verify SOMA sees events (protocol=KERNEL_AUDIT)"
    echo ""
    log_info "Useful Commands:"
    log_info "  Status:  systemctl status amoskys-kernel-audit"
    log_info "  Logs:    journalctl -u amoskys-kernel-audit -f"
    log_info "  Stop:    systemctl stop amoskys-kernel-audit"
    log_info "  Restart: systemctl restart amoskys-kernel-audit"
    echo ""
}

main "$@"
