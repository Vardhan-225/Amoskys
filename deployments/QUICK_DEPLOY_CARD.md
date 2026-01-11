# AMOSKYS V2 Agent - Quick Deploy Card

**Copy-paste commands for deploying next agent (SNMP, ProtocolCollectors, DeviceDiscovery)**

---

## 🚀 Deploy Checklist (30 minutes)

### 1. Prepare Files (5 min)

```bash
cd /Users/athanneeru/Downloads/GitHub/Amoskys

# Copy template and customize
cp deployments/kernel_audit/run_agent_v2.py deployments/<new_agent>/
# Replace in file:
#   kernel_audit → <agent_name>
#   KernelAuditAgentV2 → <Agent>V2
#   kernel_audit_v2 → <agent_name>_v2

# Create systemd service
cat > deployments/<new_agent>/amoskys-<agent_name>.service <<'EOF'
[Unit]
Description=AMOSKYS <Agent> v2 - <Plane> Threat Detection
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ubuntu
Group=ubuntu
WorkingDirectory=/home/ubuntu/<agent_dir>
Environment="PYTHONUNBUFFERED=1"

ExecStart=/home/ubuntu/amoskys-venv/bin/python3 \
  /home/ubuntu/<agent_dir>/run_agent_v2.py \
  --device-id=%H \
  --queue-path=/var/lib/amoskys/queues/<agent_name> \
  --collection-interval=5 \
  --metrics-interval=60

Restart=on-failure
RestartSec=10
TimeoutStartSec=120
MemoryMax=512M
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
EOF
```

---

### 2. Transfer to Server (5 min)

```bash
# Transfer source code
rsync -av -e "ssh -i ~/.ssh/amoskys-key.pem" \
  --exclude='.git' --exclude='__pycache__' \
  src/amoskys/ \
  ubuntu@3.147.175.238:~/amoskys-src/amoskys/

# Transfer deployment
rsync -av -e "ssh -i ~/.ssh/amoskys-key.pem" \
  deployments/<agent_dir>/ \
  ubuntu@3.147.175.238:~/<agent_dir>/
```

---

### 3. Install on Server (10 min)

```bash
ssh -i ~/.ssh/amoskys-key.pem ubuntu@3.147.175.238

# Install in venv
source ~/amoskys-venv/bin/activate
cd ~/amoskys-src
pip install -e .

# Verify imports
python3 -c "from amoskys.agents.<agent_name> import <Agent>V2; print('✅ OK')"

# Create queue directory
sudo mkdir -p /var/lib/amoskys/queues/<agent_name>
sudo chown -R ubuntu:ubuntu /var/lib/amoskys

# Install service
sudo cp ~/<agent_dir>/amoskys-<agent_name>.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable amoskys-<agent_name>
sudo systemctl start amoskys-<agent_name>
```

---

### 4. Validate (10 min)

```bash
# Check status (should be "active (running)")
sudo systemctl status amoskys-<agent_name> --no-pager

# Watch logs (should see probes initialize)
sudo journalctl -u amoskys-<agent_name> -f

# Expected within 30 seconds:
# ✅ "Registered X default <agent_name> probes"
# ✅ "Probe <probe_name> initialized" (for each)
# ✅ "Initialized X/X probes"
# ✅ "Loop completed successfully"

# Check queue database (after 60 seconds)
ls -lh /var/lib/amoskys/queues/<agent_name>/
# Expected: <agent>_queue.db, *-shm, *-wal

# Check metrics (after 60 seconds)
sudo journalctl -u amoskys-<agent_name> | grep "emitted metrics"
# Expected: success_rate close to 100%
```

---

## 🔍 Troubleshooting

### Service Won't Start (203/EXEC)
```bash
# Check paths
sudo systemctl cat amoskys-<agent_name> | grep ExecStart
ls -la /home/ubuntu/amoskys-venv/bin/python3
ls -la /home/ubuntu/<agent_dir>/run_agent_v2.py
```

### Import Errors
```bash
source ~/amoskys-venv/bin/activate
python3 -c "from amoskys.agents.<agent_name> import <Agent>V2"
cd ~/amoskys-src && pip install -e . --force-reinstall
```

### Queue Database Errors
```bash
sudo chown -R ubuntu:ubuntu /var/lib/amoskys
ls -la /var/lib/amoskys/queues/<agent_name>/
```

### Restart Loop
```bash
# Watch for errors
sudo journalctl -u amoskys-<agent_name> -n 50 | grep -i error
sudo journalctl -u amoskys-<agent_name> | grep "Traceback" -A10
```

---

## ✅ Success Criteria

- [ ] `systemctl status` shows **active (running)**
- [ ] All probes initialized (X/X)
- [ ] Queue .db files exist in `/var/lib/amoskys/queues/<agent_name>/`
- [ ] No restart loops (check journalctl -n 50)
- [ ] Metrics show success_rate >99%
- [ ] Memory <512M

---

## 📊 Monitoring Commands

```bash
# Real-time logs
sudo journalctl -u amoskys-<agent_name> -f

# Service status
sudo systemctl status amoskys-<agent_name> --no-pager

# Recent errors
sudo journalctl -u amoskys-<agent_name> -n 50 | grep -i error

# Metrics
sudo journalctl -u amoskys-<agent_name> | grep "emitted metrics"

# Restart if needed
sudo systemctl restart amoskys-<agent_name>
```

---

## 🎯 Next 3 Agents

### SNMPAgentV2
- **Probes:** 6
- **Plane:** Network Management
- **Replace:** `<agent_name>` → `snmp`

### ProtocolCollectorsV2
- **Probes:** 10
- **Plane:** Protocol
- **Replace:** `<agent_name>` → `protocol_collectors`

### DeviceDiscoveryV2
- **Probes:** 6
- **Plane:** Discovery
- **Replace:** `<agent_name>` → `device_discovery`

---

## 📁 File Locations (Server)

```
/home/ubuntu/
├── amoskys-src/amoskys/            # Source code (shared)
├── amoskys-venv/                   # Virtual env (shared)
├── <agent_dir>/                    # Deployment package
│   └── run_agent_v2.py
└── /var/lib/amoskys/queues/
    └── <agent_name>/               # Queue directory
        └── <agent>_queue.db        # SQLite database
```

---

## 🔐 Server Details

- **IP:** 3.147.175.238
- **Hostname:** ip-172-31-39-9.us-east-2.compute.internal
- **User:** ubuntu
- **SSH Key:** ~/.ssh/amoskys-key.pem
- **OS:** Ubuntu 24.04.3 LTS

---

## 📚 Full Documentation

- **Templates:** `deployments/AGENT_TEMPLATE.md`
- **Lessons:** `deployments/DEPLOYMENT_LESSONS.md`
- **Commit Guide:** `deployments/COMMIT_SUMMARY.md`

---

**Current Status:** KernelAuditGuardV2 ✅ Production (7/7 probes active)
**Next:** SNMPAgentV2 → ProtocolCollectorsV2 → DeviceDiscoveryV2
**ETA per agent:** 30 minutes
