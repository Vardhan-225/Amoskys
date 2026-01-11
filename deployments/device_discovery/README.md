# DeviceDiscoveryV2 - Deployment Package

Production-ready deployment artifacts for DeviceDiscoveryV2 discovery-plane asset mapping agent.

## 📦 Package Contents

```
deployments/device_discovery/
├── README.md                                    # This file
├── run_agent_v2.py                             # Agent CLI entry point
├── amoskys-device_discovery.service            # Systemd service definition
└── requirements-minimal.txt                    # Python dependencies
```

## 🚀 Quick Start

### 1. Prerequisites

- **OS:** Linux (Ubuntu 24.04 LTS recommended)
- **Packages:** `python3`, `python3-venv`, `systemd`
- **AMOSKYS:** Source code at `~/amoskys-src`
- **Venv:** Shared venv at `~/amoskys-venv`

### 2. Deploy from Mac

```bash
cd /Users/athanneeru/Downloads/GitHub/Amoskys

# Transfer source code (if updated)
rsync -av -e "ssh -i ~/.ssh/amoskys-deploy" \
  --exclude='.git' --exclude='__pycache__' \
  src/amoskys/ \
  ubuntu@3.147.175.238:~/amoskys-src/amoskys/

# Transfer deployment package
rsync -av -e "ssh -i ~/.ssh/amoskys-deploy" \
  deployments/device_discovery/ \
  ubuntu@3.147.175.238:~/device_discovery/
```

### 3. Install on Server

```bash
ssh -i ~/.ssh/amoskys-deploy ubuntu@3.147.175.238

# Activate venv and install/update amoskys
source ~/amoskys-venv/bin/activate
cd ~/amoskys-src
pip install -e .

# Verify imports
python3 -c "from amoskys.agents.device_discovery.device_discovery_v2 import DeviceDiscoveryV2; print('✅ OK')"

# Create queue directory
sudo mkdir -p /var/lib/amoskys/queues/device_discovery
sudo chown -R ubuntu:ubuntu /var/lib/amoskys

# Install systemd service
sudo cp ~/device_discovery/amoskys-device_discovery.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable amoskys-device_discovery
sudo systemctl start amoskys-device_discovery

# Check status
sudo systemctl status amoskys-device_discovery --no-pager
sudo journalctl -u amoskys-device_discovery -f
```

## 📋 What Gets Monitored

DeviceDiscoveryV2 maps assets and detects discovery-plane anomalies across 6 categories:

| Threat | MITRE | Severity | Example |
|--------|-------|----------|---------|
| New MAC address seen | T1590 | INFO | Unknown device on network |
| New IP address seen | T1590.005 | INFO | New host appeared |
| Device role change | T1590 | MEDIUM | Server → Client behavior |
| Suspicious device fingerprint | T1040, T1590 | MEDIUM | Spoofed MAC/vendor |
| Rapid device churn | T1498 | HIGH | Many devices appearing/disappearing |
| Rogue DHCP server | T1557.002 | **CRITICAL** | Man-in-the-middle attack |

## ✅ Validation Checklist

After deployment, verify:

```bash
# Service is running
sudo systemctl status amoskys-device_discovery
# Expected: active (running)

# Probes initialized
sudo journalctl -u amoskys-device_discovery | grep "Registered.*probes"
# Expected: Registered 6 default device_discovery probes

# Queue database created
ls -lh /var/lib/amoskys/queues/device_discovery/
# Expected: device_discovery_queue.db, *-shm, *-wal files

# No restart loops
sudo journalctl -u amoskys-device_discovery -n 50
# Expected: No repeating errors

# Metrics after 60 seconds
sudo journalctl -u amoskys-device_discovery | grep "emitted metrics"
# Expected: loops_started=X, success_rate=100%
```

## 🧪 Trigger Discovery Events

Generate discovery activity:

```bash
# Check current network state
ip addr show
arp -a

# Scan local subnet (triggers discovery)
sudo nmap -sn 192.168.1.0/24 || true

# Check for discoveries
sudo journalctl -u amoskys-device_discovery | tail -50
```

## 📊 Monitoring

### Real-time Logs

```bash
sudo journalctl -u amoskys-device_discovery -f
```

### Check Metrics (after 60 seconds)

```bash
sudo journalctl -u amoskys-device_discovery | grep "emitted metrics"
```

**Expected Output:**
```
Agent emitted metrics: loops_started=2, loops_succeeded=2, success_rate=100.0%, events_emitted=X
```

Note: Discovery cycles every 30 seconds (vs 5s for other agents)

### Service Status

```bash
sudo systemctl status amoskys-device_discovery
```

### Queue Growth

```bash
ls -lh /var/lib/amoskys/queues/device_discovery/
```

## 🔍 Troubleshooting

### Service Won't Start

```bash
# Check logs
sudo journalctl -u amoskys-device_discovery -n 50

# Common issues:
# 1. Import error - verify: python3 -c "from amoskys.agents.device_discovery.device_discovery_v2 import DeviceDiscoveryV2"
# 2. Queue permissions - fix: sudo chown -R ubuntu:ubuntu /var/lib/amoskys
# 3. Config validation - ensure: ~/amoskys-src/config/amoskys.yaml exists
```

### No Discovery Events

```bash
# Generate network activity (see "Trigger Discovery Events" above)

# Check if collector is running
sudo journalctl -u amoskys-device_discovery | grep "Collected.*discovery events"

# Check probe status
sudo journalctl -u amoskys-device_discovery | grep "Probe.*initialized"
```

### High CPU/Memory Usage

```bash
# Check resource usage
sudo systemctl status amoskys-device_discovery

# Increase collection interval if needed (discovery is already slower at 30s)
sudo systemctl edit amoskys-device_discovery
# Add: --collection-interval=60 (instead of 30)

sudo systemctl daemon-reload
sudo systemctl restart amoskys-device_discovery
```

## 🔐 Security Notes

- **Runs as non-root:** `ubuntu` service account
- **Passive discovery:** ARP table / neighbor cache monitoring
- **Systemd hardening:** `NoNewPrivileges`, resource limits
- **Resource limits:** Memory/CPU quotas prevent DoS

## 📞 Quick Reference Commands

```bash
# Service management
sudo systemctl start amoskys-device_discovery
sudo systemctl stop amoskys-device_discovery
sudo systemctl restart amoskys-device_discovery
sudo systemctl status amoskys-device_discovery

# Logs
sudo journalctl -u amoskys-device_discovery -f         # Real-time
sudo journalctl -u amoskys-device_discovery -n 100     # Last 100 lines
sudo journalctl -u amoskys-device_discovery --since "5 min ago"

# Queue inspection
ls -lh /var/lib/amoskys/queues/device_discovery/
sqlite3 /var/lib/amoskys/queues/device_discovery/device_discovery_queue.db "SELECT COUNT(*) FROM events;"
```

## 🚀 Next Steps

After successful deployment:

1. **Monitor for 10-15 minutes** to establish device baseline
2. **Generate network activity** to validate detection
3. **Check metrics** for success_rate >99%
4. **Complete the trinity:** Kernel + Protocol + Discovery all running

---

## 🎯 The Complete View

With all three agents deployed:

| Agent | Plane | What It Sees | Probes |
|-------|-------|--------------|--------|
| **KernelAudit** | Syscall | Process behavior, privilege escalation | 7 |
| **ProtocolCollectors** | Protocol | Network traffic, C2, tunneling | 10 |
| **DeviceDiscovery** | Discovery | Asset inventory, new devices | 6 |

**Combined:** "Device X appeared at time T, speaks protocols P1-Pn, executes suspicious syscalls"

---

**DeviceDiscoveryV2** - Discovery-plane asset mapping for the AMOSKYS defense mesh.

For architecture details, see [../../docs/AGENTS.md](../../docs/AGENTS.md).
