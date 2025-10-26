# AMOSKYS Multi-Agent System - Activation & Testing Guide

## Overview

This guide walks you through activating and testing the complete multi-agent telemetry system with:
- ✅ Enhanced SNMP metrics collection (40+ metrics available)
- ✅ Process monitoring agent (ProcAgent)
- ✅ Multi-agent correlation engine (ScoreJunction)
- ✅ EventBus integration with WAL storage
- ✅ Real-time threat detection

---

## 🚀 Quick Start

### Step 1: Verify Prerequisites

```bash
# Check that SNMP is installed
which snmpwalk
# If not installed:
# macOS: brew install net-snmp
# Ubuntu: sudo apt-get install snmp snmp-mibs-downloader

# Check Python dependencies
pip list | grep -E "(psutil|pysnmp|grpcio)"

# If missing, install:
pip install psutil pysnmp grpcio grpcio-tools
```

### Step 2: Enable Expanded SNMP Metrics

Edit `config/snmp_metrics_config.yaml`:

```yaml
metrics:
  system_info:
    enabled: true  # Already enabled
    
  cpu:
    enabled: true  # ← Change from false to true
    
  memory:
    enabled: true  # ← Change from false to true
    
  disk:
    enabled: true  # ← Change from false to true
    
  network_interfaces:
    enabled: true  # ← Change from false to true
    
  processes:
    enabled: false  # Can enable for process table via SNMP
    
  system_load:
    enabled: true  # ← Change from false to true
```

**Alternative:** Use a predefined profile by editing `scripts/activate_multiagent.py`:
```python
# Line 52: Change profile from 'standard' to 'full'
self.snmp_config.apply_profile('full')  # Enables ALL metrics
```

### Step 3: Start the System

**Terminal 1: Start EventBus**
```bash
cd ~/Downloads/GitHub/Amoskys
python -m amoskys.eventbus.server
```

**Terminal 2: Start Multi-Agent System**
```bash
cd ~/Downloads/GitHub/Amoskys
python scripts/activate_multiagent.py
```

**Terminal 3: Start Dashboard (optional)**
```bash
cd ~/Downloads/GitHub/Amoskys/web/app
python main.py
# Visit: http://localhost:5000
```

---

## 📊 What You'll See

### Console Output

```
╔═══════════════════════════════════════════════════════════╗
║      AMOSKYS Multi-Agent Telemetry System v2.0           ║
║                Agent Harmony Architecture                 ║
╚═══════════════════════════════════════════════════════════╝

2025-01-15 10:00:00 - MultiAgent - INFO - Initializing multi-agent system...
2025-01-15 10:00:00 - MultiAgent - INFO - SNMP: Enabled 25/40 metrics
2025-01-15 10:00:00 - MultiAgent - INFO - SNMP Categories: ['system_info', 'cpu', 'memory', 'network_interfaces']
2025-01-15 10:00:00 - MultiAgent - INFO - ✓ All agents initialized
2025-01-15 10:00:00 - MultiAgent - INFO - ✓ Connected to EventBus at localhost:50051

============================================================
Collection Iteration #1
============================================================
2025-01-15 10:00:01 - MultiAgent - INFO - SNMP: Collected 25 metrics
2025-01-15 10:00:01 - MultiAgent - INFO - ProcAgent: Generated 12 telemetry events
2025-01-15 10:00:01 - MultiAgent - INFO - ScoreJunction: 37 events, 0 threats detected
```

### Threat Detection Example

When anomalies are detected:
```
⚠ Threat detected: MEDIUM (score: 65.00, confidence: 0.85)
   Correlation: high_cpu_suspicious_process
   - Event 1: CPU usage at 92% (device: localhost)
   - Event 2: Suspicious process 'cryptominer' detected
```

---

## 🔍 Verification Commands

### 1. Check EventBus WAL Storage

```bash
# Open the WAL database
sqlite3 data/wal/flowagent.db

# Count total events
SELECT COUNT(*) FROM wal;

# View recent events
SELECT id, idem, datetime(ts_ns/1e9, 'unixepoch') as timestamp, 
       length(bytes) as size_bytes 
FROM wal 
ORDER BY id DESC 
LIMIT 10;
```

### 2. Query Dashboard API

```bash
# Get overall stats
curl http://localhost:5000/api/snmp/stats | jq

# Get recent events
curl http://localhost:5000/api/snmp/recent | jq

# Get device status
curl http://localhost:5000/api/snmp/devices | jq
```

### 3. Test SNMP Metrics Directly

```bash
# Test system info (should work)
snmpget -v2c -c public localhost 1.3.6.1.2.1.1.1.0

# Test CPU (if enabled)
snmpwalk -v2c -c public localhost 1.3.6.1.2.1.25.3.3.1.2

# Test memory
snmpwalk -v2c -c public localhost 1.3.6.1.2.1.25.2.3.1

# Test network interfaces
snmpwalk -v2c -c public localhost 1.3.6.1.2.1.2.2.1
```

---

## 📈 Expected Metrics

### Current (Minimal Profile)
- System description
- System uptime
- System contact
- System name
- System location

**Total: 5 metrics**

### Standard Profile (Recommended)
- All system info metrics (5)
- CPU load per processor (1-8 metrics)
- Memory usage (2-4 metrics)
- Network interface stats (8-16 metrics per interface)
- System load averages (3 metrics)

**Total: ~25-30 metrics**

### Full Profile
- All standard metrics
- Disk I/O statistics
- Process table (100+ processes)
- Extended network stats
- Vendor-specific OIDs

**Total: 40+ metrics + tables**

---

## 🎯 Testing Plan

### Phase 1: Verify Basic Collection (5 minutes)

```bash
# Start EventBus
python -m amoskys.eventbus.server &

# Run single collection cycle
python scripts/activate_multiagent.py

# Press Ctrl+C after 1-2 cycles

# Verify events in database
sqlite3 data/wal/flowagent.db "SELECT COUNT(*) FROM wal;"
# Should see increase in event count
```

### Phase 2: Enable Expanded Metrics (10 minutes)

```bash
# Edit config
vim config/snmp_metrics_config.yaml
# Set cpu.enabled = true
# Set memory.enabled = true

# Or apply 'full' profile in activate_multiagent.py

# Restart collection
python scripts/activate_multiagent.py

# Should see: "SNMP: Enabled 25/40 metrics" (or more)
```

### Phase 3: Test Process Monitoring (5 minutes)

```bash
# ProcAgent automatically starts with activate_multiagent.py

# In another terminal, start some processes:
python -c "import time; time.sleep(600)" &
python -c "import time; time.sleep(600)" &

# Watch logs for:
# "ProcAgent: Generated N telemetry events"
# "PROCESS_START event detected"
```

### Phase 4: Trigger Correlation (15 minutes)

```bash
# Generate CPU load
yes > /dev/null &  # High CPU process
yes > /dev/null &

# Watch for correlation:
# "⚠ Threat detected: MEDIUM"
# "Correlation: high_cpu_suspicious_process"

# Kill the processes
killall yes
```

### Phase 5: Dashboard Visualization (10 minutes)

```bash
# Start dashboard
cd web/app
python main.py

# Open browser: http://localhost:5000

# You should see:
# - Device status (online/offline)
# - Metric counts
# - Recent events
# - Event timeline
```

---

## 🔧 Troubleshooting

### Issue: "SNMP: Collected 0 metrics"

**Solution:**
```bash
# Check if SNMP daemon is running
ps aux | grep snmp

# macOS: Start SNMP daemon
sudo launchctl load -w /System/Library/LaunchDaemons/org.net-snmp.snmpd.plist

# Ubuntu: Start SNMP daemon
sudo systemctl start snmpd

# Test manually
snmpwalk -v2c -c public localhost 1.3.6.1.2.1.1
```

### Issue: "Failed to connect to EventBus"

**Solution:**
```bash
# Check if EventBus is running
ps aux | grep eventbus

# Check port
lsof -i :50051

# Restart EventBus
python -m amoskys.eventbus.server
```

### Issue: "ProcAgent: Permission denied"

**Solution:**
```bash
# Run with elevated privileges (for some process info)
sudo python scripts/activate_multiagent.py

# Or adjust permissions for current user
```

### Issue: "No threats detected"

**Expected behavior** - Most of the time, the system should be quiet. To test correlation:

```bash
# Generate load
stress-ng --cpu 4 --timeout 60s  # If installed

# Or manually:
dd if=/dev/zero of=/dev/null &  # CPU load
dd if=/dev/zero of=/dev/null &
```

---

## 📚 Next Steps

### 1. Add More Devices

Edit `scripts/activate_multiagent.py`:
```python
# Add multiple SNMP devices
devices = [
    ('localhost', 'public'),
    ('192.168.1.1', 'public'),  # Router
    ('192.168.1.10', 'private'), # Switch
]

for host, community in devices:
    results = await self.snmp_collector.collect_all(host, community)
```

### 2. Customize Correlation Rules

Edit `src/amoskys/intelligence/score_junction.py`:
```python
# Add new correlation rule
{
    'name': 'disk_full_high_writes',
    'description': 'Disk almost full + high write activity',
    'conditions': [
        ('disk_usage', '>', 90),  # >90% full
        ('disk_writes', '>', 10000),  # High writes
    ],
    'threat_level': 'HIGH',
    'base_score': 75
}
```

### 3. Build Custom Dashboard

Create `web/app/templates/multiagent_dashboard.html`:
- Real-time metric charts
- Threat timeline
- Agent health status
- Correlation event log

### 4. Deploy Additional Agents

```python
# FlowAgent (network flows)
from amoskys.agents.flowagent.flow_agent import FlowAgent

# SyscallAgent (eBPF syscall tracing)
from amoskys.agents.syscall.syscall_agent import SyscallAgent

# LogAgent (log file monitoring)
from amoskys.agents.log.log_agent import LogAgent
```

---

## 🎉 Success Criteria

You'll know the system is working when:

✅ EventBus shows increasing event count
✅ Console shows metrics being collected from both SNMP and ProcAgent
✅ WAL database has events from multiple agents
✅ Dashboard API returns data
✅ ScoreJunction detects and reports anomalies
✅ No error messages in logs

---

## 📊 Performance Benchmarks

Expected performance (localhost, 30-second intervals):

| Component | Metrics/Cycle | Time (ms) | Events/Min |
|-----------|---------------|-----------|------------|
| SNMP (minimal) | 5 | 50-100 | 10 |
| SNMP (standard) | 25 | 200-400 | 50 |
| SNMP (full) | 40+ | 500-1000 | 80+ |
| ProcAgent | 10-15 | 100-200 | 20-30 |
| ScoreJunction | N/A | 10-50 | N/A |
| **Total** | **30-55** | **300-1200** | **60-110** |

---

## 🔗 Reference Documentation

- [SNMP_DATA_COLLECTION_SUMMARY.md](./SNMP_DATA_COLLECTION_SUMMARY.md) - Current metrics and API
- [AGENT_HARMONY_ARCHITECTURE.md](./AGENT_HARMONY_ARCHITECTURE.md) - System architecture
- [config/snmp_metrics_config.yaml](../config/snmp_metrics_config.yaml) - Metric definitions

---

**Last Updated:** January 15, 2025
**Version:** 2.0
**Status:** Ready for Production Testing 🚀
