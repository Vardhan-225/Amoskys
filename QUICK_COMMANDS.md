# 🚀 Quick Commands - AMOSKYS SNMP Collection

## ✅ Test Once
```bash
cd /Users/athanneeru/Downloads/GitHub/Amoskys
source .venv/bin/activate
python tests/manual/test_snmp_real.py
```

## 🔄 Continuous Collection
```bash
python tests/manual/test_snmp_continuous.py
# Press Ctrl+C to stop
```

## 🔧 Enable SNMP on Mac
```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.net-snmp.snmpd.plist
```

## 🔍 Verify SNMP Works
```bash
ps aux | grep snmpd
snmpget -v2c -c public localhost SNMPv2-MIB::sysDescr.0
```

## 📦 Rebuild Protocol Buffers
```bash
make proto
```

## 🧪 Run All Tests
```bash
make test
```

## 📚 View Documentation
- **FIRST_STEPS_GUIDE.md** - 60-minute tutorial
- **FIRST_DATA_COLLECTION_MILESTONE.md** - What we just did
- **SYSTEM_ANALYSIS_AND_ROADMAP.md** - Full plan

## 🎯 What's Working
- ✅ SNMP data collection from localhost
- ✅ 5 metrics collected every 60 seconds
- ✅ DeviceTelemetry protobuf serialization
- ✅ Continuous monitoring with statistics
- ✅ Graceful shutdown

## 📈 Next: Connect to EventBus
See **FIRST_STEPS_GUIDE.md Step 5** for instructions.
