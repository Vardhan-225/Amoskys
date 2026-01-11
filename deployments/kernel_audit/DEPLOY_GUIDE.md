# KernelAuditGuardV2 - Quick Deployment Guide

## Production Server Deployment (One Command)

### From Your Local Mac:

```bash
cd /Users/athanneeru/Downloads/GitHub/Amoskys/deployments/kernel_audit
./deploy_to_server.sh
```

This will:
1. ✅ Transfer deployment package to server
2. ✅ Transfer AMOSKYS source code to server
3. ✅ Run installation on server
4. ✅ Execute smoke tests
5. ✅ Display monitoring commands

### What Happens Behind the Scenes:

**On Local Machine (`deploy_to_server.sh`):**
- Verifies SSH key and connection
- Transfers `src/amoskys` → `ubuntu@server:~/amoskys-src/amoskys`
- Transfers `deployments/kernel_audit` → `ubuntu@server:~/kernel_audit`
- SSH into server and runs `server_setup.sh`

**On Server (`server_setup.sh`):**
- Installs Python deps (pip, protobuf, psutil)
- Verifies AMOSKYS imports work
- Runs `install.sh --device-id=$(hostname)`
- Installs systemd service
- Runs smoke tests
- Displays service status

**Final Result:**
- Service running: `systemd` service `amoskys-kernel-audit`
- Agent binary: `/usr/local/bin/amoskys-kernel-audit-agent`
- Queue directory: `/var/lib/amoskys/queues/kernel_audit`
- Audit rules: `/etc/audit/rules.d/amoskys-kernel.rules`

---

## Server Details

**Production Server:**
- Name: `amoskys-vps`
- Public IP: `3.147.175.238`
- Private IP: `172.31.39.9`
- Hostname: `ip-172-31-39-9.us-east-2.compute.internal`
- OS: Ubuntu 24.04.3 LTS
- Instance: AWS EC2 t3.micro
- SSH Key: `~/.ssh/amoskys-key.pem`

---

## Prerequisites (Already Installed ✅)

- ✅ `git`
- ✅ `auditd` (running)
- ✅ `acl`
- ✅ `python3`
- ✅ `python3-venv`

---

## Post-Deployment Monitoring

### 1. Real-time Logs

```bash
ssh -i ~/.ssh/amoskys-key.pem ubuntu@3.147.175.238 \
  'sudo journalctl -u amoskys-kernel-audit -f'
```

**Expected Output (after 5-10 seconds):**
```
Jan 11 12:00:15 ip-172-31-39-9 amoskys-kernel-audit-agent[1234]: Loop completed successfully
Jan 11 12:00:15 ip-172-31-39-9 amoskys-kernel-audit-agent[1234]: Collected 47 audit events
Jan 11 12:00:15 ip-172-31-39-9 amoskys-kernel-audit-agent[1234]: Detected 2 threats: kernel_execve_high_risk=1, kernel_privesc_syscall=1
Jan 11 12:00:15 ip-172-31-39-9 amoskys-kernel-audit-agent[1234]: Enqueued 2 events to local queue
```

### 2. Check Metrics (after 60 seconds)

```bash
ssh -i ~/.ssh/amoskys-key.pem ubuntu@3.147.175.238 \
  'sudo journalctl -u amoskys-kernel-audit | grep "emitted metrics"'
```

**Expected Output:**
```
Jan 11 12:01:00 ip-172-31-39-9 amoskys-kernel-audit-agent[1234]: Agent emitted metrics: loops_started=12, loops_succeeded=12, success_rate=100.0%, events_emitted=24
```

**Key Metrics:**
- `success_rate`: Should be **>99%**
- `loops_succeeded`: Should be close to `loops_started`
- `events_emitted`: Number of threat events detected

### 3. Service Status

```bash
ssh -i ~/.ssh/amoskys-key.pem ubuntu@3.147.175.238 \
  'sudo systemctl status amoskys-kernel-audit'
```

**Expected Output:**
```
● amoskys-kernel-audit.service - AMOSKYS KernelAudit Guard v2
     Loaded: loaded (/etc/systemd/system/amoskys-kernel-audit.service; enabled; preset: enabled)
     Active: active (running) since ...
```

### 4. Check Audit Rules

```bash
ssh -i ~/.ssh/amoskys-key.pem ubuntu@3.147.175.238 \
  'sudo auditctl -l | grep amoskys'
```

**Expected Output:**
```
-a always,exit -F arch=b64 -S execve -F key=amoskys_execve
-a always,exit -F arch=b64 -S setuid,seteuid -F key=amoskys_privesc
-a always,exit -F arch=b64 -S init_module,finit_module -F key=amoskys_module
...
```

---

## Troubleshooting

### Issue: SSH Connection Failed

```bash
# Check SSH key permissions
chmod 400 ~/.ssh/amoskys-key.pem

# Check security group allows SSH from your IP
# AWS Console → EC2 → Security Groups → Check port 22 inbound rule
```

### Issue: "Cannot import amoskys.agents.kernel_audit"

**On Server:**
```bash
# Verify file structure
ls -la ~/amoskys-src/amoskys/agents/kernel_audit/

# Should show:
# __init__.py
# kernel_audit_agent_v2.py
# probes.py
# collector.py
# types.py
```

### Issue: Service Not Running

```bash
# Check logs for errors
ssh -i ~/.ssh/amoskys-key.pem ubuntu@3.147.175.238 \
  'sudo journalctl -u amoskys-kernel-audit -n 50'

# Check permissions on audit log
ssh -i ~/.ssh/amoskys-key.pem ubuntu@3.147.175.238 \
  'sudo getfacl /var/log/audit/audit.log'

# Should show: user:amoskys:r--
```

### Issue: No Threats Detected

```bash
# Trigger a test event (high-risk execution)
ssh -i ~/.ssh/amoskys-key.pem ubuntu@3.147.175.238 \
  'echo "#!/bin/bash\necho test" > /tmp/test.sh && chmod +x /tmp/test.sh && /tmp/test.sh'

# Check logs for detection
ssh -i ~/.ssh/amoskys-key.pem ubuntu@3.147.175.238 \
  'sudo journalctl -u amoskys-kernel-audit | grep kernel_execve_high_risk'
```

---

## Manual Deployment (If Script Fails)

If `deploy_to_server.sh` fails, run these commands manually:

### 1. Transfer Files

```bash
cd /Users/athanneeru/Downloads/GitHub/Amoskys

# Transfer source code
rsync -av -e "ssh -i ~/.ssh/amoskys-key.pem" \
  --exclude='.git' --exclude='__pycache__' --exclude='*.pyc' \
  src/amoskys/ \
  ubuntu@3.147.175.238:~/amoskys-src/amoskys/

# Transfer deployment package
rsync -av -e "ssh -i ~/.ssh/amoskys-key.pem" \
  --exclude='__pycache__' --exclude='*.pyc' \
  deployments/kernel_audit/ \
  ubuntu@3.147.175.238:~/kernel_audit/
```

### 2. Run Installation on Server

```bash
ssh -i ~/.ssh/amoskys-key.pem ubuntu@3.147.175.238

# On server
cd ~/kernel_audit
chmod +x server_setup.sh
./server_setup.sh
```

---

## Success Criteria

After deployment, verify:

- ✅ Service status: **active (running)**
- ✅ Smoke tests: **7/7 passed**
- ✅ Metrics success_rate: **>99%**
- ✅ Audit rules loaded: **7 rules** (`auditctl -l | grep amoskys | wc -l`)
- ✅ Queue directory writable: `/var/lib/amoskys/queues/kernel_audit`
- ✅ Agent binary executable: `/usr/local/bin/amoskys-kernel-audit-agent`

---

## Next Steps After Deployment

1. **Monitor for 10 minutes** - Watch real-time logs to ensure stability
2. **Check metrics** - Verify success_rate >99%
3. **Test threat detection** - Run smoke tests or trigger manual events
4. **Verify SOMA integration** - Check if events appear in SOMA dashboard
5. **24-hour validation** - Monitor overnight before proceeding to Phase 2

---

## Phase 2: Remaining Agents (After 24h Validation)

Once KernelAudit is stable:
- SNMPAgentV2 (6 probes, 2-3 hours)
- ProtocolCollectorsV2 (10 probes, 3-4 hours)
- DeviceDiscoveryV2 (6 probes, 3-4 hours)

---

## Quick Reference Commands

```bash
# Deploy from local Mac
cd /Users/athanneeru/Downloads/GitHub/Amoskys/deployments/kernel_audit
./deploy_to_server.sh

# SSH to server
ssh -i ~/.ssh/amoskys-key.pem ubuntu@3.147.175.238

# Service management
sudo systemctl status amoskys-kernel-audit
sudo systemctl restart amoskys-kernel-audit
sudo systemctl stop amoskys-kernel-audit

# Logs
sudo journalctl -u amoskys-kernel-audit -f         # Real-time
sudo journalctl -u amoskys-kernel-audit -n 100     # Last 100 lines
sudo journalctl -u amoskys-kernel-audit --since "5 min ago"

# Queue inspection
ls -lh /var/lib/amoskys/queues/kernel_audit/
sqlite3 /var/lib/amoskys/queues/kernel_audit/events.db "SELECT COUNT(*) FROM events;"
```
