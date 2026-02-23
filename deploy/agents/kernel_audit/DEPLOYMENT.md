# KernelAuditGuardV2 - Production Deployment Guide

## Overview

KernelAuditGuardV2 is a syscall-plane threat detection agent that monitors Linux kernel audit events for:
- Privilege escalation attempts (T1068, T1548)
- Process injection via ptrace (T1055)
- Kernel module/rootkit loading (T1014, T1547.006)
- File permission tampering (T1222)
- Audit subsystem tampering (T1562, T1070)

This guide covers installation, configuration, and operational verification.

---

## Prerequisites

### System Requirements

- **OS**: Linux (kernel 3.10+)
- **Architecture**: x86_64 (arm64 support planned)
- **Memory**: 512MB dedicated to agent
- **Disk**: 1GB for queue storage
- **CPU**: <5% on average, bursts to 50% during high audit volume

### Required Packages

```bash
# Debian/Ubuntu
sudo apt-get install -y auditd audispd-plugins python3 python3-pip

# RHEL/CentOS
sudo yum install -y audit audit-libs python3 python3-pip

# Arch
sudo pacman -S audit python python-pip
```

### Python Dependencies

```bash
pip3 install protobuf>=4.0
```

---

## Installation

### Step 1: Create Service Account

```bash
# Create amoskys user and group
sudo useradd -r -s /bin/false -d /var/lib/amoskys amoskys

# Create required directories
sudo mkdir -p /var/lib/amoskys/queues/kernel_audit
sudo chown -R amoskys:amoskys /var/lib/amoskys

# Grant read access to audit logs
sudo usermod -a -G adm amoskys  # For Debian/Ubuntu
# OR
sudo setfacl -m u:amoskys:r /var/log/audit/audit.log  # Direct ACL
```

### Step 2: Install Audit Rules

```bash
# Copy audit rules to system directory
sudo cp audit_rules.conf /etc/audit/rules.d/amoskys-kernel.rules

# Load rules
sudo augenrules --load

# Restart auditd
sudo systemctl restart auditd

# Verify rules loaded
sudo auditctl -l | grep amoskys
```

**Expected Output:**
```
-a always,exit -F arch=b64 -S execve -F key=amoskys_exec
-a always,exit -F arch=b64 -S setuid,seteuid,setreuid,setresuid -F key=amoskys_privesc
...
```

### Step 3: Install Agent

```bash
# Option A: Install from source
cd /path/to/amoskys
sudo python3 setup.py install

# Option B: Install via pip (future)
# sudo pip3 install amoskys-agent

# Verify installation
python3 -c "from amoskys.agents.kernel_audit import KernelAuditAgentV2; print('OK')"
```

### Step 4: Install Systemd Service

```bash
# Copy service file
sudo cp amoskys-kernel-audit.service /etc/systemd/system/

# Reload systemd
sudo systemctl daemon-reload

# Enable service
sudo systemctl enable amoskys-kernel-audit.service

# Start service
sudo systemctl start amoskys-kernel-audit.service

# Verify status
sudo systemctl status amoskys-kernel-audit.service
```

**Expected Status:**
```
● amoskys-kernel-audit.service - AMOSKYS KernelAudit Guard v2
   Loaded: loaded (/etc/systemd/system/amoskys-kernel-audit.service; enabled)
   Active: active (running) since ...
   Main PID: 12345 (python3)
   ...
```

---

## Configuration

### Agent Configuration

Create `/etc/amoskys/kernel_audit.yaml`:

```yaml
kernel_audit:
  # Audit log source
  audit_log: "/var/log/audit/audit.log"

  # Collection interval (seconds)
  collection_interval: 5

  # Metrics emission interval (seconds)
  metrics_interval: 60

  # Queue configuration
  queue:
    path: "/var/lib/amoskys/queues/kernel_audit"
    max_size_mb: 100
    flush_interval: 10

  # Probe-specific tuning
  probes:
    execve_high_risk:
      enabled: true
      high_risk_paths:
        - "/tmp"
        - "/dev/shm"
        - "/var/tmp"

    privesc_syscall:
      enabled: true
      severity_override: CRITICAL

    kernel_module_load:
      enabled: true
      suspicious_paths:
        - "/tmp"
        - "/dev/shm"
        - "/home"

    ptrace_abuse:
      enabled: true
      protected_processes:
        - "sshd"
        - "systemd"
        - "auditd"

    file_permission_tamper:
      enabled: true
      sensitive_files:
        - "/etc/shadow"
        - "/etc/sudoers"
        - "/etc/passwd"

    audit_tamper:
      enabled: true

    syscall_flood:
      enabled: true
      threshold: 100
      window_seconds: 5
```

### Environment Variables

```bash
# Set in /etc/default/amoskys-kernel-audit
AMOSKYS_DEVICE_ID="host-prod-01"
AMOSKYS_LOG_LEVEL="INFO"
AMOSKYS_QUEUE_PATH="/var/lib/amoskys/queues/kernel_audit"
```

---

## Verification

### Smoke Test

Run the comprehensive smoke test suite:

```bash
# Make executable
chmod +x smoke_test.sh

# Run as root (required for most tests)
sudo ./smoke_test.sh
```

**Expected Output:**
```
==========================================
AMOSKYS KernelAudit Smoke Test Suite
==========================================

[INFO] Pre-flight checks...
[PASS] auditd is running and logging to /var/log/audit/audit.log
[INFO] Running as root - all tests enabled

========================================
TEST: ExecveHighRiskProbe - Execution from /tmp
========================================
[INFO] Executing: /tmp/amoskys-smoke-test-12345/malware.sh
[INFO] Waiting for audit event with key=amoskys_exec
[PASS] Found audit event with key=amoskys_exec
[PASS] ExecveHighRiskProbe should detect execution from /tmp
...
```

### Manual Trigger Tests

**Test 1: Execute from /tmp**
```bash
echo '#!/bin/bash
echo "test"' > /tmp/test.sh
chmod +x /tmp/test.sh
/tmp/test.sh
```

Check agent logs:
```bash
sudo journalctl -u amoskys-kernel-audit -f
```

Expected log entry:
```
Detected 1 threats from 15 audit events
kernel_execve_high_risk: MEDIUM - Process executed from high-risk location: /tmp/test.sh
```

**Test 2: Privilege Escalation (as root)**
```bash
sudo python3 -c "import os; os.setuid(1000); os.setuid(0)"
```

Expected detection:
```
kernel_privesc_syscall: CRITICAL - Privilege escalation: UID 1000 gained EUID 0
```

---

## Monitoring

### Agent Health Metrics

Query agent metrics via systemd:

```bash
# View recent metrics
sudo journalctl -u amoskys-kernel-audit | grep "emitted metrics"
```

**Example Output:**
```
Agent kernel_audit_v2 emitted metrics telemetry: loops=1234/1234, events=456, probes=37
```

### Agent Metrics Endpoint

Enable optional HTTP metrics endpoint (for Prometheus scraping):

```python
# In agent startup code
agent.start_metrics_http_server(host="127.0.0.1", port=9100)
```

Query metrics:
```bash
curl http://localhost:9100/metrics
```

**Response:**
```json
{
  "loops_started": 1234,
  "loops_succeeded": 1233,
  "loops_failed": 1,
  "events_emitted": 456,
  "probe_events_emitted": 37,
  "probe_errors": 0,
  "success_rate": 0.999,
  "last_success_ns": 1735901234567890000
}
```

### SOMA Integration

Query threat events in SOMA:

```sql
-- KernelAudit threats in last hour
SELECT
    timestamp,
    event_type,
    severity,
    attributes->>'reason' as reason,
    attributes->>'exe' as exe,
    attributes->>'uid' as uid
FROM telemetry_events
WHERE
    protocol = 'KERNEL_AUDIT'
    AND timestamp > NOW() - INTERVAL '1 hour'
ORDER BY timestamp DESC;
```

### Grafana Dashboards

Import dashboard: `dashboards/kernel_audit_health.json`

**Panels:**
- Loop success rate (target: >99%)
- Threat events detected (rate)
- Top 5 event types (by volume)
- Probe error rate (target: 0%)
- Audit events processed (rate)

---

## Troubleshooting

### Agent Won't Start

**Symptom:** Service fails to start
```bash
sudo systemctl status amoskys-kernel-audit
# Output: Failed to start...
```

**Diagnosis:**
```bash
# Check permissions
ls -la /var/log/audit/audit.log
# Output: -rw------- 1 root root ... /var/log/audit/audit.log

# Check if amoskys user can read
sudo -u amoskys cat /var/log/audit/audit.log
# Output: Permission denied
```

**Fix:**
```bash
# Add amoskys to adm group (Debian/Ubuntu)
sudo usermod -a -G adm amoskys

# OR set ACL
sudo setfacl -m u:amoskys:r /var/log/audit/audit.log

# Restart service
sudo systemctl restart amoskys-kernel-audit
```

### No Events Detected

**Symptom:** Agent running but no threat events

**Diagnosis:**
```bash
# Check audit rules loaded
sudo auditctl -l | grep amoskys

# Check audit log has recent entries
sudo tail -f /var/log/audit/audit.log

# Check agent metrics
sudo journalctl -u amoskys-kernel-audit | grep "audit events"
```

**Fix:**
- If no audit rules: Reload rules (`sudo augenrules --load`)
- If no audit log activity: Generate test event (see smoke test)
- If agent sees 0 audit events: Check collector offset/permissions

### High CPU Usage

**Symptom:** Agent using >50% CPU continuously

**Diagnosis:**
```bash
# Check audit event volume
sudo journalctl -u amoskys-kernel-audit | grep "Collected.*audit events"
# Output: Collected 5000 kernel audit events

# Check probe execution time
sudo journalctl -u amoskys-kernel-audit | grep "scan.*duration"
```

**Tuning:**
```bash
# Reduce audit rule scope (edit /etc/audit/rules.d/amoskys-kernel.rules)
# Example: Only track execve from /tmp instead of all execve
-a always,exit -F arch=b64 -S execve -F dir=/tmp -k amoskys_exec_tmp

# Increase collection interval (edit systemd service)
ExecStart=/usr/local/bin/amoskys-kernel-audit-agent ... --collection-interval=10

# Reload and restart
sudo augenrules --load
sudo systemctl restart amoskys-kernel-audit
```

### Queue Filling Up

**Symptom:** Disk space consumed by queue

**Diagnosis:**
```bash
du -sh /var/lib/amoskys/queues/kernel_audit
# Output: 500M /var/lib/amoskys/queues/kernel_audit
```

**Fix:**
- Check if SOMA/EventBus is reachable (agent will queue offline)
- Reduce event volume via audit rule tuning
- Increase queue flush frequency

---

## Performance Tuning

### Audit Rule Optimization

**High-Volume Systems:**
```bash
# Replace broad syscall monitoring with targeted paths
# Instead of: -a always,exit -S execve
# Use: -a always,exit -S execve -F dir=/tmp
```

**Production Systems (lower overhead):**
```bash
# Monitor only security-critical events
# Disable SyscallFloodProbe (set enabled: false in config)
# Reduce execve monitoring to high-risk paths only
```

### Collection Interval

- **Development/Testing:** 5 seconds (default)
- **Production (normal):** 10 seconds
- **Production (high-load):** 30 seconds

### Batch Size

Adjust collector max batch size:
```python
collector = AuditdLogCollector(
    source="/var/log/audit/audit.log",
    max_batch_size=512  # Reduce from 1024 for lower latency
)
```

---

## Security Considerations

### Audit Log Rotation

Ensure audit logs rotate properly:

```bash
# /etc/audit/auditd.conf
max_log_file = 100
num_logs = 10
```

The agent detects rotation automatically via inode tracking.

### Agent Permissions

**Principle of Least Privilege:**
- Agent runs as `amoskys` user (non-root)
- Only requires `CAP_DAC_READ_SEARCH` for audit log access
- No write permissions to system directories

**File ACLs:**
```bash
# Audit log read-only
sudo setfacl -m u:amoskys:r /var/log/audit/audit.log

# Queue directory read-write
sudo chown amoskys:amoskys /var/lib/amoskys/queues/kernel_audit
```

### Systemd Hardening

The provided systemd service includes:
- `PrivateTmp=yes` - Isolated /tmp
- `ProtectSystem=strict` - Read-only system directories
- `NoNewPrivileges=yes` - Cannot gain privileges
- `CapabilityBoundingSet=CAP_DAC_READ_SEARCH` - Limited capabilities

---

## Upgrade Path

### v1 → v2 Migration

1. **Run v1 and v2 in parallel** (different queue paths)
2. **Compare detection coverage** (v2 should match or exceed v1)
3. **Switch traffic** (disable v1 service, enable v2)
4. **Monitor for 48 hours**
5. **Decommission v1**

### Rolling Updates

```bash
# Update agent binary
sudo pip3 install --upgrade amoskys-agent

# Reload service
sudo systemctl restart amoskys-kernel-audit

# Verify health
sudo systemctl status amoskys-kernel-audit
sudo journalctl -u amoskys-kernel-audit -n 50
```

---

## Support

**Logs:**
```bash
# Agent logs
sudo journalctl -u amoskys-kernel-audit -f

# Audit system logs
sudo journalctl -u auditd -f
```

**Health Check:**
```bash
# Quick status
sudo systemctl is-active amoskys-kernel-audit

# Detailed metrics
curl http://localhost:9100/metrics 2>/dev/null | jq .
```

**Issue Reporting:**
Include the following in bug reports:
- Agent version (`python3 -c "import amoskys; print(amoskys.__version__)"`)
- OS/kernel version (`uname -a`)
- Audit rules (`sudo auditctl -l`)
- Recent logs (`sudo journalctl -u amoskys-kernel-audit -n 100`)
- Agent metrics (if HTTP endpoint enabled)

---

## References

- [Linux Audit Documentation](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/chap-system_auditing)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [AMOSKYS Architecture Docs](../../docs/AGENTS.md)
- [Agent Health Metrics](../../docs/METRICS.md)
