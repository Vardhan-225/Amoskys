# ProtocolCollectorsV2 - Deployment Package

Production-ready deployment artifacts for ProtocolCollectorsV2 protocol-plane threat detection agent.

## 📦 Package Contents

```
deployments/protocol_collectors/
├── README.md                                    # This file
├── run_agent_v2.py                             # Agent CLI entry point
├── amoskys-protocol_collectors.service         # Systemd service definition
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
  deployments/protocol_collectors/ \
  ubuntu@3.147.175.238:~/protocol_collectors/
```

### 3. Install on Server

```bash
ssh -i ~/.ssh/amoskys-deploy ubuntu@3.147.175.238

# Activate venv and install/update amoskys
source ~/amoskys-venv/bin/activate
cd ~/amoskys-src
pip install -e .

# Verify imports
python3 -c "from amoskys.agents.protocol_collectors.protocol_collectors_v2 import ProtocolCollectorsV2; print('✅ OK')"

# Create queue directory
sudo mkdir -p /var/lib/amoskys/queues/protocol_collectors
sudo chown -R ubuntu:ubuntu /var/lib/amoskys

# Install systemd service
sudo cp ~/protocol_collectors/amoskys-protocol_collectors.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable amoskys-protocol_collectors
sudo systemctl start amoskys-protocol_collectors

# Check status
sudo systemctl status amoskys-protocol_collectors --no-pager
sudo journalctl -u amoskys-protocol_collectors -f
```

## 📋 What Gets Monitored

ProtocolCollectorsV2 detects protocol-level threats across 10 categories:

| Threat | MITRE | Severity | Example |
|--------|-------|----------|------------|
| HTTP suspicious headers | T1071.001 | MEDIUM | User-Agent: sqlmap |
| TLS/SSL anomalies | T1573.002 | HIGH | Self-signed certs, weak ciphers |
| SSH brute force patterns | T1110, T1021.004 | HIGH | Rapid connection attempts |
| DNS tunneling | T1048.003, T1071.004 | CRITICAL | Large TXT records |
| SQL injection in traffic | T1190 | **CRITICAL** | `'; DROP TABLE--` |
| RDP suspicious activity | T1021.001 | MEDIUM | Off-hours access |
| FTP cleartext credentials | T1552.001 | HIGH | Plaintext user/pass |
| SMTP spam/phish patterns | T1566.001 | MEDIUM | Mass mailing |
| IRC/P2P C2 protocols | T1071.001 | HIGH | Known C2 signatures |
| Protocol anomalies | T1205 | MEDIUM | Malformed packets |

## ✅ Validation Checklist

After deployment, verify:

```bash
# Service is running
sudo systemctl status amoskys-protocol_collectors
# Expected: active (running)

# Probes initialized
sudo journalctl -u amoskys-protocol_collectors | grep "Registered.*probes"
# Expected: Registered 10 default protocol_collectors probes

# Queue database created
ls -lh /var/lib/amoskys/queues/protocol_collectors/
# Expected: protocol_collectors_queue.db, *-shm, *-wal files

# No restart loops
sudo journalctl -u amoskys-protocol_collectors -n 50
# Expected: No repeating errors

# Metrics after 60 seconds
sudo journalctl -u amoskys-protocol_collectors | grep "emitted metrics"
# Expected: loops_started=X, success_rate=100%
```

## 🧪 Generate Test Traffic

Trigger protocol detections:

```bash
# HTTP traffic
curl http://example.com

# HTTPS/TLS
curl https://example.com

# DNS queries
dig google.com +short
dig microsoft.com +short

# SSH connection attempt
ssh localhost -p 22 || true

# Check for detections
sudo journalctl -u amoskys-protocol_collectors | tail -50
```

## 📊 Monitoring

### Real-time Logs

```bash
sudo journalctl -u amoskys-protocol_collectors -f
```

### Check Metrics (after 60 seconds)

```bash
sudo journalctl -u amoskys-protocol_collectors | grep "emitted metrics"
```

**Expected Output:**
```
Agent emitted metrics: loops_started=12, loops_succeeded=12, success_rate=100.0%, events_emitted=XX
```

### Service Status

```bash
sudo systemctl status amoskys-protocol_collectors
```

### Queue Growth

```bash
ls -lh /var/lib/amoskys/queues/protocol_collectors/
```

## 🔍 Troubleshooting

### Service Won't Start

```bash
# Check logs
sudo journalctl -u amoskys-protocol_collectors -n 50

# Common issues:
# 1. Import error - verify: python3 -c "from amoskys.agents.protocol_collectors.protocol_collectors_v2 import ProtocolCollectorsV2"
# 2. Queue permissions - fix: sudo chown -R ubuntu:ubuntu /var/lib/amoskys
# 3. Config validation - ensure: ~/amoskys-src/config/amoskys.yaml exists
```

### No Protocol Detections

```bash
# Generate test traffic (see "Generate Test Traffic" above)

# Check if collector is running
sudo journalctl -u amoskys-protocol_collectors | grep "Collected.*protocol events"

# Check probe status
sudo journalctl -u amoskys-protocol_collectors | grep "Probe.*initialized"
```

### High CPU/Memory Usage

```bash
# Check resource usage
sudo systemctl status amoskys-protocol_collectors

# Increase collection interval if needed
sudo systemctl edit amoskys-protocol_collectors
# Add: --collection-interval=10 (instead of 5)

sudo systemctl daemon-reload
sudo systemctl restart amoskys-protocol_collectors
```

## 🔐 Security Notes

- **Runs as non-root:** `ubuntu` service account
- **Read-only network access:** Passive monitoring
- **Systemd hardening:** `NoNewPrivileges`, resource limits
- **Resource limits:** Memory/CPU quotas prevent DoS

## 📞 Quick Reference Commands

```bash
# Service management
sudo systemctl start amoskys-protocol_collectors
sudo systemctl stop amoskys-protocol_collectors
sudo systemctl restart amoskys-protocol_collectors
sudo systemctl status amoskys-protocol_collectors

# Logs
sudo journalctl -u amoskys-protocol_collectors -f         # Real-time
sudo journalctl -u amoskys-protocol_collectors -n 100     # Last 100 lines
sudo journalctl -u amoskys-protocol_collectors --since "5 min ago"

# Queue inspection
ls -lh /var/lib/amoskys/queues/protocol_collectors/
sqlite3 /var/lib/amoskys/queues/protocol_collectors/protocol_collectors_queue.db "SELECT COUNT(*) FROM events;"
```

## 🚀 Next Steps

After successful deployment:

1. **Monitor for 10-15 minutes** to establish baseline
2. **Generate test traffic** to validate detection
3. **Check metrics** for success_rate >99%
4. **Proceed to DeviceDiscoveryV2** deployment

---

**ProtocolCollectorsV2** - Protocol-plane threat detection for the AMOSKYS defense mesh.

For architecture details, see [../../docs/AGENTS.md](../../docs/AGENTS.md).
