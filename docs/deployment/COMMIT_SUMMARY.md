# Commit Summary - KernelAuditGuardV2 Production Deployment

## What Changed

### Files Modified

1. **deployments/kernel_audit/run_agent_v2.py**
   - Fixed LocalQueueAdapter initialization to include required `agent_name` parameter
   - Changed queue_path handling: now forms file path from directory argument
   - Added multiple Python path resolution for local dev + server deployment

2. **deployments/kernel_audit/install.sh**
   - Fixed argument parsing to handle both `--device-id=VALUE` and `--device-id VALUE` formats
   - Bug: `--device-id=$(hostname)` was failing with "Unknown option"

3. **deployments/kernel_audit/server_setup.sh**
   - Updated to use virtual environment (`~/amoskys-venv`)
   - Added proper Python package installation in venv
   - Improved verification steps

### Files Created

1. **deployments/AGENT_TEMPLATE.md**
   - Canonical deployment pattern for all V2 agents
   - Includes systemd service template, run_agent_v2.py template
   - Deployment steps and validation checklist

2. **deployments/DEPLOYMENT_LESSONS.md**
   - Lessons learned from KernelAuditGuardV2 production rollout
   - Three critical bugs and fixes
   - Troubleshooting quick reference

3. **deployments/kernel_audit/deploy_to_server.sh**
   - Local Mac script to deploy to production server
   - Automates rsync transfers and SSH installation

4. **deployments/kernel_audit/DEPLOY_GUIDE.md**
   - Complete deployment guide with monitoring commands
   - Server details and validation steps

5. **deployments/kernel_audit/requirements-minimal.txt**
   - Minimal dependencies for KernelAudit (no TensorFlow/ML)

6. **deployments/COMMIT_SUMMARY.md** (this file)

### Files Previously Created (Context)

- docs/SYSTEM_ARCHITECTURE.md (785 lines)
- docs/LOGIN_ROUTING_ISSUE.md
- All KernelAuditGuardV2 implementation files (already committed)

---

## Why These Changes

### Problem 1: LocalQueueAdapter Signature Mismatch

**Before:**
```python
queue_adapter = LocalQueueAdapter(
    queue_path=args.queue_path,
    device_id=args.device_id,
)
```

**After:**
```python
queue_db_path = os.path.join(args.queue_path, "kernel_audit_queue.db")
queue_adapter = LocalQueueAdapter(
    queue_path=queue_db_path,
    agent_name="kernel_audit_v2",  # Required parameter
    device_id=args.device_id,
)
```

**Reason:** LocalQueueAdapter signature changed to require `agent_name`. Old deployment script was out of sync.

### Problem 2: install.sh Argument Parsing

**Before:**
```bash
case $1 in
    --device-id)
        DEVICE_ID="$2"
        shift 2
        ;;
```

**After:**
```bash
case $1 in
    --device-id=*)
        DEVICE_ID="${1#*=}"
        shift
        ;;
    --device-id)
        DEVICE_ID="$2"
        shift 2
        ;;
```

**Reason:** `--device-id=$(hostname)` expands to `--device-id=ip-172-31-39-9`, which wasn't handled by original parser.

### Problem 3: systemd Service Complexity

**Before:** Complex service with extensive hardening (ProtectSystem, ProtectHome, capabilities)

**After:** Simplified service that works first, harden later

**Reason:** Complex restrictions caused 203/EXEC errors. Start simple, add hardening incrementally.

---

## Commit Messages

### Commit 1: Core Fixes

```
fix(kernel_audit): Fix production deployment issues

- Fix LocalQueueAdapter init to include required agent_name parameter
- Fix queue_path handling: form file path from directory argument
- Fix install.sh to handle --device-id=VALUE format
- Add Python path resolution for server deployment

Fixes three critical bugs that prevented service from starting:
1. TypeError: missing required positional argument 'agent_name'
2. SQLite unable to open database file (directory vs file path)
3. install.sh --device-id=$(hostname) parsing failure

Tested on production server (ip-172-31-39-9.us-east-2.compute.internal)
Service now running stable with all 7 probes active.
```

### Commit 2: Documentation

```
docs(deployment): Add production deployment templates and lessons

- Add AGENT_TEMPLATE.md: canonical pattern for all V2 agents
- Add DEPLOYMENT_LESSONS.md: lessons from KernelAudit rollout
- Add deploy_to_server.sh: automated deployment script
- Add DEPLOY_GUIDE.md: complete deployment guide
- Add requirements-minimal.txt: minimal deps for agents

These templates capture the proven working pattern from
KernelAuditGuardV2 production deployment and can be reused
for SNMP, ProtocolCollectors, and DeviceDiscovery agents.

Estimated time to deploy next agent using templates: 30 minutes.
```

### Commit 3: Production Config

```
chore(kernel_audit): Update server_setup.sh for venv deployment

- Use shared virtual environment at ~/amoskys-venv
- Install amoskys package in venv with pip install -e
- Add verification steps for imports and service status
- Improve error messages and status output

This aligns with the actual working deployment on production server.
```

---

## Test Plan (Before Committing)

1. **Local Tests (Mac):**
   ```bash
   cd /Users/athanneeru/Downloads/GitHub/Amoskys

   # Verify install.sh parses arguments correctly
   cd deployments/kernel_audit
   ./install.sh --help
   ./install.sh --device-id=test-device  # Should not error

   # Verify run_agent_v2.py imports work
   python3 run_agent_v2.py --help
   ```

2. **Production Validation (Server):**
   ```bash
   # Service is running
   sudo systemctl status amoskys-kernel-audit
   # Expected: active (running)

   # Queue database exists
   ls -lh /var/lib/amoskys/queues/kernel_audit/
   # Expected: kernel_audit_queue.db with -shm and -wal files

   # Probes are active
   sudo journalctl -u amoskys-kernel-audit | grep "Initialized.*probes"
   # Expected: Initialized 7/7 probes

   # No crashes
   sudo journalctl -u amoskys-kernel-audit -n 100 | grep -i error
   # Expected: No recent errors
   ```

3. **Template Validation:**
   - Review AGENT_TEMPLATE.md for completeness
   - Verify systemd service template has correct placeholders
   - Verify run_agent_v2.py template has all required sections

---

## Git Commands

```bash
cd /Users/athanneeru/Downloads/GitHub/Amoskys

# Check current status
git status

# Stage modified files
git add deployments/kernel_audit/run_agent_v2.py
git add deployments/kernel_audit/install.sh
git add deployments/kernel_audit/server_setup.sh

# Stage new files
git add deployments/AGENT_TEMPLATE.md
git add deployments/DEPLOYMENT_LESSONS.md
git add deployments/COMMIT_SUMMARY.md
git add deployments/kernel_audit/deploy_to_server.sh
git add deployments/kernel_audit/DEPLOY_GUIDE.md
git add deployments/kernel_audit/requirements-minimal.txt

# Commit with detailed message
git commit -F deployments/COMMIT_SUMMARY.md

# Or commit in batches
git commit -m "fix(kernel_audit): Fix production deployment issues

- Fix LocalQueueAdapter init to include required agent_name parameter
- Fix queue_path handling: form file path from directory argument
- Fix install.sh to handle --device-id=VALUE format
- Add Python path resolution for server deployment

Fixes three critical bugs that prevented service from starting.
Tested on production server with all 7 probes active."

git commit -m "docs(deployment): Add production deployment templates

Add canonical templates and lessons learned from KernelAudit rollout.
Reusable for SNMP, ProtocolCollectors, DeviceDiscovery agents."

# Push to remote
git push origin main
```

---

## What's Next

1. **Monitor KernelAudit for 24h**
   - Check metrics: `sudo journalctl -u amoskys-kernel-audit | grep "emitted metrics"`
   - Verify stability: No restart loops, memory stays under 512M

2. **Deploy Next Agent (SNMP)**
   - Use AGENT_TEMPLATE.md as guide
   - Should take ~30 minutes with templates
   - Validate same checklist

3. **SOMA Integration**
   - Once agents are stable, wire up EventBus → SOMA
   - Verify events flow from agent → queue → SOMA → Cortex

4. **Security Hardening**
   - After 24-48h stability, add systemd restrictions incrementally
   - Test after each addition

---

## Production Status

**Server:** amoskys-vps (3.147.175.238)
**Deployed Agent:** KernelAuditGuardV2
**Status:** ✅ Active (running)
**Probes:** 7/7 initialized
**Queue:** SQLite database created and persisting
**Memory:** 22.3M / 512M limit
**Uptime:** Since Jan 11, 2026 15:36 UTC

**Next Deployment:** SNMPAgentV2 (after 24h validation)

---

## Files Ready to Commit

```
M  deployments/kernel_audit/run_agent_v2.py
M  deployments/kernel_audit/install.sh
M  deployments/kernel_audit/server_setup.sh
A  deployments/AGENT_TEMPLATE.md
A  deployments/DEPLOYMENT_LESSONS.md
A  deployments/COMMIT_SUMMARY.md
A  deployments/kernel_audit/deploy_to_server.sh
A  deployments/kernel_audit/DEPLOY_GUIDE.md
A  deployments/kernel_audit/requirements-minimal.txt
```

**Total:** 6 new files, 3 modified files
**Lines Added:** ~2,500
**Lines Modified:** ~50

**Ready to commit:** Yes ✅
