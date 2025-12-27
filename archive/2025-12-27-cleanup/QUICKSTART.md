# 🚀 AMOSKYS Multi-Agent System - Quick Start

## What's New in v2.0

Your AMOSKYS system has been upgraded from a single-agent SNMP collector to a **multi-agent distributed intelligence platform**:

### ✨ New Capabilities

1. **Enhanced SNMP Collection** (40+ metrics available)
   - CPU usage per processor
   - Memory and storage statistics
   - Network interface traffic and errors
   - Disk I/O statistics
   - System load averages
   - Process tables

2. **Process Monitoring Agent** (ProcAgent)
   - Real-time process scanning
   - Resource usage tracking
   - Process lifecycle detection
   - Suspicious process alerting

3. **Multi-Agent Correlation Engine** (ScoreJunction)
   - Correlates events from multiple agents
   - Pattern-based threat detection
   - Automatic threat scoring
   - Configurable correlation rules

4. **Unified Data Pipeline**
   - All agents → EventBus → WAL database
   - Real-time API access
   - Ed25519 signing for authenticity
   - Idempotency for reliability

---

## 🎯 30-Second Quick Start

```bash
# 1. Test all components
cd ~/Downloads/GitHub/Amoskys
python scripts/test_components.py --all

# 2. Enable more metrics (optional)
python scripts/configure_metrics.py --profile full

# 3. Start EventBus (Terminal 1)
python -m amoskys.eventbus.server

# 4. Start multi-agent system (Terminal 2)
python scripts/activate_multiagent.py

# 5. View dashboard (Terminal 3)
cd web/app && python main.py
# Open: http://localhost:5000
```

---

## 📊 What You'll Get

### Before (v1.0)
```
SNMP Agent → EventBus → WAL
     ↓
5 basic metrics from localhost
```

### After (v2.0)
```
SNMP Agent ─────┐
                ├──→ EventBus → WAL → Dashboard
ProcAgent ──────┤         ↓
                └──→ ScoreJunction → Threat Detection

40+ metrics + process monitoring + correlation
```

---

## 🛠️ Available Scripts

### 1. Component Testing
```bash
# Test everything
python scripts/test_components.py --all

# Test specific components
python scripts/test_components.py --snmp
python scripts/test_components.py --proc
python scripts/test_components.py --correlation
```

**Expected output:**
```
✓ snmp_config: PASS
✓ snmp_collection: PASS
✓ proc_agent: PASS
✓ score_junction: PASS
✓ eventbus: PASS
✓ wal_database: PASS

🎉 All tests passed! System is ready.
```

### 2. Metrics Configuration
```bash
# Show current status
python scripts/configure_metrics.py --show

# Apply predefined profiles
python scripts/configure_metrics.py --profile minimal   # 5 metrics
python scripts/configure_metrics.py --profile standard  # 25 metrics
python scripts/configure_metrics.py --profile full      # 40+ metrics

# Enable specific categories
python scripts/configure_metrics.py --enable cpu memory network

# Disable categories
python scripts/configure_metrics.py --disable processes disk
```

### 3. Multi-Agent System
```bash
# Start all agents
python scripts/activate_multiagent.py

# What it does:
# - Loads SNMP metrics config
# - Starts ProcAgent for process monitoring
# - Starts ScoreJunction for correlation
# - Collects every 30 seconds
# - Sends telemetry to EventBus
# - Detects and reports threats
```

---

## 📈 Metrics Overview

### System Information (Always Enabled)
- `sysDescr` - System description and OS
- `sysUpTime` - System uptime
- `sysContact` - Admin contact
- `sysName` - Hostname
- `sysLocation` - Physical location

### CPU Metrics (Enable with `--profile standard`)
- `hrProcessorLoad` - CPU load per processor
- Supports multi-CPU systems
- Per-core statistics

### Memory Metrics
- `hrMemorySize` - Total physical memory
- `hrStorageUsed` - Used storage
- `hrStorageSize` - Total storage
- Per-partition statistics

### Network Metrics
- `ifInOctets` - Incoming bytes
- `ifOutOctets` - Outgoing bytes
- `ifInErrors` - Input errors
- `ifOutErrors` - Output errors
- Per-interface statistics

### System Load
- `laLoad1` - 1-minute load average
- `laLoad5` - 5-minute load average
- `laLoad15` - 15-minute load average

### Process Monitoring (ProcAgent)
- Process count and list
- CPU usage per process
- Memory usage per process
- Process lifecycle events
- Suspicious process detection

---

## 🎨 Profiles Explained

### Minimal (Current Default)
- **Metrics:** 5
- **Use Case:** Basic system identification
- **Collection Time:** ~50ms
- **Categories:** `system_info`

### Standard (Recommended)
- **Metrics:** 25-30
- **Use Case:** Production monitoring
- **Collection Time:** ~200-400ms
- **Categories:** `system_info`, `cpu`, `memory`, `network_interfaces`, `system_load`

### Full (Maximum Coverage)
- **Metrics:** 40+
- **Use Case:** Deep analysis, troubleshooting
- **Collection Time:** ~500-1000ms
- **Categories:** All categories enabled

### Network Focus
- **Metrics:** 15-20
- **Use Case:** Network device monitoring (routers, switches)
- **Categories:** `system_info`, `network_interfaces`

### Performance
- **Metrics:** 20-25
- **Use Case:** Resource monitoring
- **Categories:** `system_info`, `cpu`, `memory`, `system_load`

---

## 🔍 Verification Commands

### Check EventBus is Running
```bash
ps aux | grep eventbus
lsof -i :50051
```

### Check WAL Database
```bash
sqlite3 data/wal/flowagent.db "SELECT COUNT(*) FROM wal;"
sqlite3 data/wal/flowagent.db "SELECT * FROM wal ORDER BY id DESC LIMIT 1;"
```

### Test SNMP Manually
```bash
# Basic system info
snmpget -v2c -c public localhost 1.3.6.1.2.1.1.1.0

# CPU load (if enabled)
snmpwalk -v2c -c public localhost 1.3.6.1.2.1.25.3.3.1.2

# Network interfaces
snmpwalk -v2c -c public localhost 1.3.6.1.2.1.2.2.1
```

### Query Dashboard API
```bash
# Statistics
curl http://localhost:5000/api/snmp/stats | jq

# Recent events
curl http://localhost:5000/api/snmp/recent | jq

# Device status
curl http://localhost:5000/api/snmp/devices | jq
```

---

## 🚨 Troubleshooting

### Issue: SNMP daemon not running

**macOS:**
```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.net-snmp.snmpd.plist
```

**Ubuntu/Debian:**
```bash
sudo apt-get install snmpd
sudo systemctl start snmpd
sudo systemctl enable snmpd
```

**Verify:**
```bash
snmpwalk -v2c -c public localhost 1.3.6.1.2.1.1
```

### Issue: EventBus not starting

**Check port:**
```bash
lsof -i :50051
```

**Kill existing process:**
```bash
pkill -f eventbus
```

**Restart:**
```bash
python -m amoskys.eventbus.server
```

### Issue: No metrics collected

**Check SNMP config:**
```bash
python scripts/configure_metrics.py --show
```

**Test SNMP directly:**
```bash
snmpget -v2c -c public localhost 1.3.6.1.2.1.1.1.0
```

**Enable metrics:**
```bash
python scripts/configure_metrics.py --profile standard
```

### Issue: Dashboard not showing data

**Check WAL database:**
```bash
sqlite3 data/wal/flowagent.db "SELECT COUNT(*) FROM wal;"
```

**Restart Flask app:**
```bash
cd web/app
python main.py
```

**Check API manually:**
```bash
curl http://localhost:5000/api/snmp/stats
```

---

## 📚 Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                   AMOSKYS v2.0                          │
│              Agent Harmony Architecture                 │
└─────────────────────────────────────────────────────────┘

┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│ SNMP Agent   │  │  ProcAgent   │  │ Flow Agent   │
│              │  │              │  │              │
│ 40+ metrics  │  │ Process Mon  │  │ NetFlow      │
└──────┬───────┘  └──────┬───────┘  └──────┬───────┘
       │                 │                 │
       └─────────────────┼─────────────────┘
                         ↓
                  ┌──────────────┐
                  │  EventBus    │
                  │  (gRPC)      │
                  └──────┬───────┘
                         ↓
           ┌─────────────┴─────────────┐
           ↓                           ↓
    ┌──────────────┐           ┌──────────────┐
    │ WAL Database │           │ ScoreJunction│
    │ (SQLite)     │           │ Correlation  │
    └──────┬───────┘           └──────┬───────┘
           ↓                           ↓
    ┌──────────────┐           ┌──────────────┐
    │  Dashboard   │           │   Threat     │
    │  (Flask)     │           │  Detection   │
    └──────────────┘           └──────────────┘
```

---

## 🎯 Next Steps

### Immediate (Next 15 minutes)
1. ✅ Run component tests: `python scripts/test_components.py --all`
2. ✅ Enable more metrics: `python scripts/configure_metrics.py --profile standard`
3. ✅ Start multi-agent system: `python scripts/activate_multiagent.py`
4. ✅ Verify data in dashboard

### Short-term (Next hour)
1. Add more SNMP devices (routers, switches)
2. Customize correlation rules
3. Test threat detection with CPU load
4. Build custom dashboard widgets

### Long-term (Next week)
1. Deploy SyscallAgent for eBPF tracing
2. Add LogAgent for log file monitoring
3. Implement ML-based anomaly detection
4. Create automated response actions

---

## 📖 Documentation

- **[ACTIVATION_GUIDE.md](./ACTIVATION_GUIDE.md)** - Complete activation and testing guide
- **[AGENT_HARMONY_ARCHITECTURE.md](./AGENT_HARMONY_ARCHITECTURE.md)** - System architecture and design
- **[SNMP_DATA_COLLECTION_SUMMARY.md](./SNMP_DATA_COLLECTION_SUMMARY.md)** - Current metrics and API
- **[config/snmp_metrics_config.yaml](./config/snmp_metrics_config.yaml)** - Metric definitions

---

## 💡 Tips

### For Development
- Use `minimal` profile for fast testing
- Use `standard` profile for normal operation
- Use `full` profile for troubleshooting

### For Production
- Start with `standard` profile
- Monitor EventBus memory usage
- Set up log rotation for WAL database
- Use systemd/launchd for auto-restart

### For Debugging
- Check component tests first
- Verify SNMP daemon is running
- Look for errors in EventBus logs
- Query WAL database directly

---

## 🎉 Success Checklist

- [ ] All component tests pass
- [ ] Metrics configuration applied
- [ ] EventBus running on port 50051
- [ ] Multi-agent system collecting data
- [ ] Events appearing in WAL database
- [ ] Dashboard showing device status
- [ ] No error messages in logs

When all items are checked, you're ready for production! 🚀

---

**Version:** 2.0
**Last Updated:** January 15, 2025
**Status:** Production Ready ✨
