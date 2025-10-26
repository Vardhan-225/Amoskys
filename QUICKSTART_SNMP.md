# 🚀 AMOSKYS Quick Start - SNMP Agent

## ⚡ Start Everything

```bash
cd /Users/athanneeru/Downloads/GitHub/Amoskys

# 1. Start EventBus
make run-eventbus &

# 2. Start SNMP Agent  
make run-snmp-agent &

# 3. Start Dashboard (optional)
make run-web &
```

## 📊 Check Status

```bash
# View SNMP agent metrics
curl http://localhost:8001/metrics | grep snmp

# View EventBus metrics  
curl http://localhost:9090/metrics

# Check running processes
ps aux | grep amoskys
```

## 🔍 View Logs

```bash
# SNMP Agent logs (real-time)
tail -f /tmp/snmp_agent.log

# EventBus WAL
ls -lh data/wal/

# View latest events
cat data/wal/*.log | tail -20
```

## 🎯 Test Collection

```bash
# One-time test
python tests/manual/test_snmp_real.py

# Continuous monitoring
python tests/manual/test_snmp_continuous.py
```

## 🔧 Configuration

Edit devices:
```bash
nano config/snmp_agent.yaml
```

Add device:
```yaml
devices:
  - name: "my-router"
    host: "192.168.1.1"
    community: "public"
    enabled: true
```

Restart agent:
```bash
pkill -f snmp-agent
make run-snmp-agent
```

## 📈 Success Indicators

✅ Agent logs show: `✅ Published telemetry: localhost`  
✅ Metrics endpoint responds: `curl localhost:8001/metrics`  
✅ EventBus receives data: Check WAL files  
✅ No errors in logs

## 🆘 Troubleshooting

### No SNMP data
```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.net-snmp.snmpd.plist
ps aux | grep snmpd
```

### Connection refused
```bash
# Check EventBus running
ps aux | grep eventbus

# Start if needed
make run-eventbus
```

### Port in use
```bash
# Find what's using port 8001
lsof -i :8001
kill <PID>
```

## 📚 Documentation

- **SNMP_AGENT_SUCCESS.md** - Full achievement details
- **SESSION_SUMMARY_OCT25.md** - Today's work
- **FIRST_STEPS_GUIDE.md** - Complete tutorial
- **QUICK_COMMANDS.md** - Command reference

## 🎯 Next Steps

1. Add your router to `config/snmp_agent.yaml`
2. View metrics in dashboard: `http://localhost:5000`
3. Enable threat correlator
4. Configure alerts

---

**You're now monitoring real devices!** 🧠⚡
