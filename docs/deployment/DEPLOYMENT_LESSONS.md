# Deployment Lessons - KernelAuditGuardV2 Production Rollout

## What Actually Worked (Jan 11, 2026)

### TL;DR: The Golden Path

```bash
# On Mac
rsync source code → ubuntu@server:~/amoskys-src/amoskys/
rsync deployment → ubuntu@server:~/agent_dir/

# On Server
pip install -e ~/amoskys-src
sudo systemctl daemon-reload && systemctl start amoskys-<agent>
```

**Result:** Service running, probes active, queue persisting. No crashes.

---

## Three Critical Bugs (And Fixes)

### Bug 1: systemd 203/EXEC

**Symptom:**
```
Main process exited, code=exited, status=203/EXEC
```

**Root Cause:**
- Wrong Python path in ExecStart
- Or missing interpreter
- Or bad permissions

**Fix:**
```ini
# ❌ WRONG
ExecStart=/usr/bin/python3 /home/ubuntu/...

# ✅ CORRECT
ExecStart=/home/ubuntu/amoskys-venv/bin/python3 /home/ubuntu/kernel_audit/run_agent_v2.py
```

**Lesson:** Always use full venv path. Don't rely on system Python or $PATH.

---

### Bug 2: LocalQueueAdapter Init Mismatch

**Symptom:**
```
TypeError: LocalQueueAdapter.__init__() missing 1 required positional argument: 'agent_name'
```

**Root Cause:**
- Deployed run_agent_v2.py was out of sync with library signature
- LocalQueueAdapter signature changed to require `agent_name`

**Fix:**
```python
# ❌ WRONG (old signature)
queue_adapter = LocalQueueAdapter(
    queue_path=args.queue_path,
    device_id=args.device_id,
)

# ✅ CORRECT (new signature)
queue_db_path = os.path.join(args.queue_path, "kernel_audit_queue.db")
queue_adapter = LocalQueueAdapter(
    queue_path=queue_db_path,    # File path, not directory!
    agent_name="kernel_audit_v2", # Required parameter
    device_id=args.device_id,
)
```

**Lesson:** Keep deployment scripts in sync with library changes. Use `agent_name` parameter.

---

### Bug 3: SQLite "unable to open database file"

**Symptom:**
```
Failed to initialize queue adapter: unable to open database file
```

**Root Cause:**
- Queue directory doesn't exist
- No write permissions for service user
- Passed directory instead of file path

**Fix:**
```bash
# Create queue directory with correct permissions
sudo mkdir -p /var/lib/amoskys/queues/kernel_audit
sudo chown -R ubuntu:ubuntu /var/lib/amoskys
```

```python
# Form file path from directory in code
queue_db_path = os.path.join(args.queue_path, "kernel_audit_queue.db")
```

**Lesson:**
- Queue path argument should be directory (for flexibility)
- Code should form file path internally
- Ensure directories exist and are writable before starting service

---

## Working Configuration

### systemd Service (Minimal, Working)

**File:** `/etc/systemd/system/amoskys-kernel-audit.service`

```ini
[Unit]
Description=AMOSKYS KernelAudit Guard v2 - Syscall-Plane Threat Detection
After=network-online.target auditd.service
Wants=network-online.target

[Service]
Type=simple
User=ubuntu
Group=ubuntu
WorkingDirectory=/home/ubuntu/kernel_audit
Environment="PYTHONUNBUFFERED=1"

ExecStart=/home/ubuntu/amoskys-venv/bin/python3 \
  /home/ubuntu/kernel_audit/run_agent_v2.py \
  --device-id=%H \
  --queue-path=/var/lib/amoskys/queues/kernel_audit \
  --audit-log=/var/log/audit/audit.log \
  --collection-interval=5 \
  --metrics-interval=60

Restart=on-failure
RestartSec=10
TimeoutStartSec=120

MemoryMax=512M
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
```

**What's Missing (Intentionally for Now):**
- No `ProtectSystem=strict` (caused 203/EXEC initially)
- No `ProtectHome=true` (needs home directory access)
- No complex capability restrictions

**Add Later:** After 24-48h validation, reintroduce hardening incrementally.

---

### run_agent_v2.py (Key Sections)

```python
# Critical: Form file path from directory argument
def main():
    args = parse_args()

    # args.queue_path is a directory
    queue_db_path = os.path.join(args.queue_path, "kernel_audit_queue.db")

    queue_adapter = LocalQueueAdapter(
        queue_path=queue_db_path,           # File path
        agent_name="kernel_audit_v2",       # Required!
        device_id=args.device_id,
    )

    agent = KernelAuditAgentV2(
        device_id=args.device_id,
        agent_name="kernel_audit_v2",
        collection_interval=args.collection_interval,
        queue_adapter=queue_adapter,
        metrics_interval=args.metrics_interval,
    )

    agent.run()
```

---

## Deployment Checklist (Copy-Paste for Next Agent)

### Pre-Deployment

- [ ] Agent code implemented and tested locally
- [ ] All probes have passing unit tests
- [ ] `run_agent_v2.py` uses template from AGENT_TEMPLATE.md
- [ ] systemd service file created from template

### Transfer Files

```bash
# On Mac
cd /Users/athanneeru/Downloads/GitHub/Amoskys

# Transfer source
rsync -av -e "ssh -i ~/.ssh/amoskys-key.pem" \
  --exclude='.git' --exclude='__pycache__' \
  src/amoskys/ \
  ubuntu@3.147.175.238:~/amoskys-src/amoskys/

# Transfer deployment
rsync -av -e "ssh -i ~/.ssh/amoskys-key.pem" \
  deployments/<agent_dir>/ \
  ubuntu@3.147.175.238:~/<agent_dir>/
```

### Install on Server

```bash
# SSH to server
ssh -i ~/.ssh/amoskys-key.pem ubuntu@3.147.175.238

# Install in venv
source ~/amoskys-venv/bin/activate
cd ~/amoskys-src
pip install -e .

# Verify imports
python3 -c "from amoskys.agents.<agent_name> import <Agent>V2; print('OK')"

# Create queue directory
sudo mkdir -p /var/lib/amoskys/queues/<agent_name>
sudo chown -R ubuntu:ubuntu /var/lib/amoskys

# Install systemd service
sudo cp ~/<agent_dir>/amoskys-<agent_name>.service \
  /etc/systemd/system/
sudo systemctl daemon-reload

# Start service
sudo systemctl enable amoskys-<agent_name>
sudo systemctl start amoskys-<agent_name>
```

### Validation

```bash
# Check service status
sudo systemctl status amoskys-<agent_name> --no-pager

# Watch logs
sudo journalctl -u amoskys-<agent_name> -f

# Expected output within 30 seconds:
# - "Registered X default <agent_name> probes"
# - "Probe <probe_name> initialized" (for each probe)
# - "Initialized X/X probes"
# - "<agent_name>_v2 setup complete: X probes active"
# - "Loop completed successfully"

# Check queue database created
ls -lh /var/lib/amoskys/queues/<agent_name>/
# Expected: *_queue.db, *-shm, *-wal files

# Check metrics after 60 seconds
sudo journalctl -u amoskys-<agent_name> | grep "emitted metrics"
# Expected: success_rate close to 100%
```

### Success Criteria

- [ ] Service status: **active (running)**
- [ ] All probes initialized (X/X)
- [ ] Queue database files created
- [ ] No restart loops (check journalctl)
- [ ] Metrics showing success_rate >99%
- [ ] Memory usage reasonable (<512M)

---

## File Structure Reference

```
Server Filesystem After Deployment:

/home/ubuntu/
├── amoskys-src/                    # Shared source (all agents)
│   └── amoskys/
│       ├── agents/
│       │   ├── kernel_audit/
│       │   ├── snmp/
│       │   ├── protocol_collectors/
│       │   └── device_discovery/
│       └── common/
│
├── amoskys-venv/                   # Shared venv (all agents)
│   ├── bin/python3
│   └── lib/python3.12/site-packages/
│
├── kernel_audit/                   # Deployment package per agent
│   ├── run_agent_v2.py
│   ├── install.sh
│   ├── smoke_test.sh
│   └── requirements-minimal.txt
│
└── /var/lib/amoskys/
    └── queues/
        ├── kernel_audit/
        │   ├── kernel_audit_queue.db      # SQLite database
        │   ├── kernel_audit_queue.db-shm  # Shared memory
        │   └── kernel_audit_queue.db-wal  # Write-ahead log
        ├── snmp/
        ├── protocol_collectors/
        └── device_discovery/
```

---

## Troubleshooting Quick Reference

### Service Won't Start (203/EXEC)

```bash
# Check ExecStart path
sudo systemctl cat amoskys-<agent_name> | grep ExecStart

# Verify Python exists at that path
ls -la /home/ubuntu/amoskys-venv/bin/python3

# Check script exists
ls -la /home/ubuntu/<agent_dir>/run_agent_v2.py

# Check script is executable (shouldn't matter for python3 <script>, but check anyway)
chmod +x /home/ubuntu/<agent_dir>/run_agent_v2.py
```

### Import Errors

```bash
# Test import manually
source ~/amoskys-venv/bin/activate
python3 -c "from amoskys.agents.<agent_name> import <Agent>V2"

# If fails, check source structure
ls -la ~/amoskys-src/amoskys/agents/<agent_name>/

# Reinstall in venv
cd ~/amoskys-src
pip install -e . --force-reinstall
```

### Queue Database Errors

```bash
# Check directory exists and is writable
ls -la /var/lib/amoskys/queues/<agent_name>/
sudo chown -R ubuntu:ubuntu /var/lib/amoskys

# Check for stale lock files
rm /var/lib/amoskys/queues/<agent_name>/*.db-shm
rm /var/lib/amoskys/queues/<agent_name>/*.db-wal
```

### Service Crashing

```bash
# Watch logs in real-time
sudo journalctl -u amoskys-<agent_name> -f

# Check last 100 lines
sudo journalctl -u amoskys-<agent_name> -n 100 --no-pager

# Check for Python exceptions
sudo journalctl -u amoskys-<agent_name> | grep -A10 "Traceback"

# Restart with fresh queue
sudo systemctl stop amoskys-<agent_name>
rm /var/lib/amoskys/queues/<agent_name>/*.db*
sudo systemctl start amoskys-<agent_name>
```

---

## What We Learned

1. **Start Simple:** Deploy with minimal systemd restrictions. Add hardening incrementally after validation.

2. **Full Paths:** Always use absolute paths in systemd ExecStart. No assumptions about $PATH.

3. **Sync Code:** Keep deployment scripts in sync with library signatures. Version mismatches cause runtime errors.

4. **Directory vs File:** Be clear about queue_path semantics:
   - CLI argument: directory
   - LocalQueueAdapter parameter: file path
   - Code forms file path from directory

5. **Permissions Matter:** Create directories with correct ownership before starting service.

6. **Shared Venv:** One venv for all agents is simpler than per-agent venvs.

7. **Validation Steps:** Have a checklist. Check service status, logs, queue files, metrics - in that order.

---

## Next Steps

Now that KernelAuditGuardV2 is proven stable:

1. **Commit Working State**
   - Updated run_agent_v2.py with agent_name parameter
   - Simplified systemd service (add to repo as .simple.service)
   - requirements-minimal.txt

2. **Replicate for Next 3 Agents**
   - SNMPAgentV2 (6 probes)
   - ProtocolCollectorsV2 (10 probes)
   - DeviceDiscoveryV2 (6 probes)

3. **24h Monitoring**
   - Watch KernelAudit metrics
   - Verify SOMA integration
   - Check for any memory/CPU issues

4. **Harden After Validation**
   - Add ProtectSystem/ProtectHome
   - Enable SystemCallFilter
   - Add capability restrictions

---

**Status:** Pattern validated. Template ready. Next agent deploy time: ~30 minutes.
