# ProtocolCollectorsV2 - Deploy Now (Copy-Paste Commands)

**Estimated time:** 30 minutes
**Pattern:** Proven from KernelAudit deployment

---

## Step 1: Transfer Files (Mac → Server) [5 min]

```bash
cd /Users/athanneeru/Downloads/GitHub/Amoskys

# Transfer source code
rsync -av -e "ssh -i ~/.ssh/amoskys-deploy" \
  --exclude='.git' --exclude='__pycache__' \
  src/amoskys/ \
  ubuntu@3.147.175.238:~/amoskys-src/amoskys/

# Transfer deployment package
rsync -av -e "ssh -i ~/.ssh/amoskys-deploy" \
  deployments/protocol_collectors/ \
  ubuntu@3.147.175.238:~/protocol_collectors/
```

✅ **Expected:** Files transferred without errors

---

## Step 2: Install on Server [10 min]

```bash
# SSH to server
ssh -i ~/.ssh/amoskys-deploy ubuntu@3.147.175.238

# Activate venv and install amoskys
source ~/amoskys-venv/bin/activate
cd ~/amoskys-src
pip install -e .

# Verify imports work
python3 -c "from amoskys.agents.protocol_collectors.protocol_collectors_v2 import ProtocolCollectorsV2; print('✅ ProtocolCollectorsV2 import OK')"
```

✅ **Expected:** `✅ ProtocolCollectorsV2 import OK`

---

## Step 3: Create Queue & Install Service [5 min]

```bash
# Create queue directory
sudo mkdir -p /var/lib/amoskys/queues/protocol_collectors
sudo chown -R ubuntu:ubuntu /var/lib/amoskys

# Install systemd service
sudo cp ~/protocol_collectors/amoskys-protocol_collectors.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable amoskys-protocol_collectors
sudo systemctl start amoskys-protocol_collectors
```

✅ **Expected:** Service enabled and started

---

## Step 4: Validate Deployment [10 min]

```bash
# Check service status
sudo systemctl status amoskys-protocol_collectors --no-pager

# Watch logs (Ctrl+C to exit)
sudo journalctl -u amoskys-protocol_collectors -f
```

✅ **Expected within 30 seconds:**
```
Registered 10 default protocol_collectors probes
Probe <probe_name> initialized (×10)
Initialized 10/10 probes
protocol_collectors_v2 setup complete: 10 probes active
```

---

## Step 5: Generate Test Traffic [5 min]

```bash
# HTTP
curl http://example.com

# HTTPS
curl https://example.com

# DNS
dig google.com +short

# SSH
ssh localhost -p 22 || true

# Check for detections
sudo journalctl -u amoskys-protocol_collectors | tail -50
```

✅ **Expected:** Protocol events detected in logs

---

## Step 6: Check Queue Database [2 min]

```bash
ls -lh /var/lib/amoskys/queues/protocol_collectors/
```

✅ **Expected:**
```
protocol_collectors_queue.db
protocol_collectors_queue.db-shm
protocol_collectors_queue.db-wal
```

---

## Step 7: Verify Metrics [2 min]

Wait 60 seconds after starting, then:

```bash
sudo journalctl -u amoskys-protocol_collectors | grep "emitted metrics"
```

✅ **Expected:**
```
Agent emitted metrics: loops_started=X, loops_succeeded=X, success_rate=100.0%
```

---

## ✅ Success Criteria

- [ ] Service status: **active (running)**
- [ ] Probes: **10/10 initialized**
- [ ] Queue files: **DB + WAL + SHM created**
- [ ] No restart loops
- [ ] Metrics: **success_rate close to 100%**
- [ ] Test traffic generates protocol events

---

## 📊 Monitoring Commands

```bash
# Real-time logs
sudo journalctl -u amoskys-protocol_collectors -f

# Service status
sudo systemctl status amoskys-protocol_collectors

# Recent errors (should be none)
sudo journalctl -u amoskys-protocol_collectors -n 50 | grep -i error

# Queue size
ls -lh /var/lib/amoskys/queues/protocol_collectors/
```

---

## 🔧 Troubleshooting

### Issue: Import Error

```bash
# Re-install amoskys package
source ~/amoskys-venv/bin/activate
cd ~/amoskys-src
pip install -e . --force-reinstall

# Test import
python3 -c "from amoskys.agents.protocol_collectors.protocol_collectors_v2 import ProtocolCollectorsV2"
```

### Issue: Service Crashing

```bash
# Check detailed logs
sudo journalctl -u amoskys-protocol_collectors -n 100 --no-pager

# Check for Python traceback
sudo journalctl -u amoskys-protocol_collectors | grep "Traceback" -A10
```

### Issue: Queue Permissions

```bash
sudo chown -R ubuntu:ubuntu /var/lib/amoskys
ls -la /var/lib/amoskys/queues/protocol_collectors/
```

---

## 🎯 After Successful Deployment

Once ProtocolCollectors is stable (running for 10-15 minutes):

1. **Check both agents are running:**
   ```bash
   systemctl is-active amoskys-kernel-audit
   systemctl is-active amoskys-protocol_collectors
   ```

2. **Compare queue growth:**
   ```bash
   ls -lh /var/lib/amoskys/queues/*/
   ```

3. **Ready for DeviceDiscoveryV2** (next agent, 6 probes)

---

## 📈 Current Deployment Status

| Agent | Status | Probes | Memory | Queue |
|-------|--------|--------|--------|-------|
| **KernelAuditGuardV2** | ✅ Running | 7/7 | 22.7M | WAL 403K |
| **ProtocolCollectorsV2** | ⏳ Deploying | 10/10 | - | - |
| DeviceDiscoveryV2 | 📋 Next | 6 | - | - |
| SNMPAgentV2 | 📋 Queued | 6 | - | - |

**Total Progress:** 1/4 agents → 2/4 agents (50%)
**Total Probes:** 7/29 (24%) → 17/29 (59%)

---

**Time to deploy:** ~30 minutes
**Pattern:** Same as KernelAudit (proven working)
