# DeviceDiscoveryV2 - Deploy Now (Copy-Paste Commands)

**Estimated time:** 30 minutes
**Pattern:** Proven from KernelAudit + ProtocolCollectors
**Deploy after:** ProtocolCollectors is stable

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
  deployments/device_discovery/ \
  ubuntu@3.147.175.238:~/device_discovery/
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
python3 -c "from amoskys.agents.device_discovery.device_discovery_v2 import DeviceDiscoveryV2; print('✅ DeviceDiscoveryV2 import OK')"
```

✅ **Expected:** `✅ DeviceDiscoveryV2 import OK`

---

## Step 3: Create Queue & Install Service [5 min]

```bash
# Create queue directory
sudo mkdir -p /var/lib/amoskys/queues/device_discovery
sudo chown -R ubuntu:ubuntu /var/lib/amoskys

# Install systemd service
sudo cp ~/device_discovery/amoskys-device_discovery.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable amoskys-device_discovery
sudo systemctl start amoskys-device_discovery
```

✅ **Expected:** Service enabled and started

---

## Step 4: Validate Deployment [10 min]

```bash
# Check service status
sudo systemctl status amoskys-device_discovery --no-pager

# Watch logs (Ctrl+C to exit)
sudo journalctl -u amoskys-device_discovery -f
```

✅ **Expected within 30 seconds:**
```
Registered 6 default device_discovery probes
Probe new_mac_seen initialized
Probe new_ip_seen initialized
Probe device_role_change initialized
Probe suspicious_device_fingerprint initialized
Probe rapid_device_churn initialized
Probe rogue_dhcp_server initialized
Initialized 6/6 probes
device_discovery_v2 setup complete: 6 probes active
```

---

## Step 5: Generate Discovery Events [5 min]

```bash
# Check current network state
ip addr show
arp -a

# Optional: scan local subnet to trigger discovery
# sudo nmap -sn 192.168.1.0/24 || true

# Check for discoveries
sudo journalctl -u amoskys-device_discovery | tail -50
```

✅ **Expected:** Discovery events for existing devices in logs

---

## Step 6: Check Queue Database [2 min]

```bash
ls -lh /var/lib/amoskys/queues/device_discovery/
```

✅ **Expected:**
```
device_discovery_queue.db
device_discovery_queue.db-shm
device_discovery_queue.db-wal
```

---

## Step 7: Verify Metrics [2 min]

Wait 60 seconds after starting, then:

```bash
sudo journalctl -u amoskys-device_discovery | grep "emitted metrics"
```

✅ **Expected:**
```
Agent emitted metrics: loops_started=2, loops_succeeded=2, success_rate=100.0%
```

Note: Discovery cycles every 30 seconds (slower than other agents)

---

## ✅ Success Criteria

- [ ] Service status: **active (running)**
- [ ] Probes: **6/6 initialized**
- [ ] Queue files: **DB + WAL + SHM created**
- [ ] No restart loops
- [ ] Metrics: **success_rate close to 100%**
- [ ] Discovery events for existing network devices

---

## 📊 Check All Three Agents

Once DeviceDiscovery is deployed, verify all agents:

```bash
# All services running
systemctl is-active amoskys-kernel-audit
systemctl is-active amoskys-protocol_collectors
systemctl is-active amoskys-device_discovery

# All queue databases
ls -lh /var/lib/amoskys/queues/*/
```

✅ **Expected:** 3 agents active, 3 queue databases with WAL files

---

## 📈 Complete Trinity Status

| Agent | Status | Probes | Queue WAL Size |
|-------|--------|--------|----------------|
| **KernelAudit** | ✅ Running | 7/7 | Growing |
| **ProtocolCollectors** | ✅ Running | 10/10 | Growing |
| **DeviceDiscovery** | ✅ Running | 6/6 | Growing |

**Total Coverage:**
- **Agents:** 3/4 (75%)
- **Probes:** 23/29 (79%)
- **Planes:** Kernel + Protocol + Discovery

---

## 🔧 Troubleshooting

### Issue: Import Error

```bash
# Re-install amoskys package
source ~/amoskys-venv/bin/activate
cd ~/amoskys-src
pip install -e . --force-reinstall

# Test import
python3 -c "from amoskys.agents.device_discovery.device_discovery_v2 import DeviceDiscoveryV2"
```

### Issue: Service Crashing

```bash
# Check detailed logs
sudo journalctl -u amoskys-device_discovery -n 100 --no-pager

# Check for Python traceback
sudo journalctl -u amoskys-device_discovery | grep "Traceback" -A10
```

### Issue: No Discovery Events

```bash
# Discovery happens every 30s (slower than other agents)
# Wait at least 2 minutes, then check logs again
sleep 120
sudo journalctl -u amoskys-device_discovery | tail -50

# Check if collector is running
sudo journalctl -u amoskys-device_discovery | grep "Collected"
```

---

## 🎯 After Successful Deployment

You now have **the trinity** running:

### Kernel Plane (KernelAudit)
- Syscall monitoring
- Privilege escalation
- Rootkit detection
- Process injection

### Protocol Plane (ProtocolCollectors)
- HTTP/HTTPS analysis
- DNS tunneling
- SSH brute force
- SQL injection
- Protocol anomalies

### Discovery Plane (DeviceDiscovery)
- Asset inventory
- New device detection
- Device role changes
- Rogue DHCP detection

**Combined View:** "Device X appeared at 10:00, speaks HTTP+SSH, executes suspicious syscalls from /tmp"

---

## 🚀 Next: SNMP (Optional)

SNMPAgentV2 adds infrastructure enrichment (6 probes):
- Switch/router monitoring
- Interface statistics
- SNMP trap detection
- Infrastructure alerts

Deploy when ready for infrastructure-plane visibility.

---

**Time to deploy:** ~30 minutes
**Pattern:** Same as KernelAudit + ProtocolCollectors
**Result:** Complete multi-plane visibility on single host
