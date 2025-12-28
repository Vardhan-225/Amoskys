# AMOSKYS End-to-End Validation Guide

This guide walks you through validating the complete AMOSKYS Intelligence pipeline on your Mac.

## Prerequisites

✅ All 16 fusion rule tests passing (verified)
✅ Intelligence modules import successfully (verified)
✅ Data directories created (verified)

## Quick Start (Automated)

### Option 1: Run Everything Automatically

```bash
# Start all components
./scripts/run_e2e_validation.sh

# Check status
./scripts/check_e2e_status.sh

# Stop all components when done
./scripts/stop_e2e_validation.sh
```

### Option 2: Manual Step-by-Step

See "Manual Validation Process" section below.

---

## Automated Validation Workflow

### Step 1: Start the Pipeline

```bash
./scripts/run_e2e_validation.sh
```

This starts:
- **AuthGuardAgent** → Monitors SSH/sudo events → `data/queue/auth_agent.db`
- **PersistenceGuardAgent** → Monitors LaunchAgents/Daemons → `data/queue/persistence_agent.db`
- **TelemetryIngestor** → Polls agent databases → Feeds FusionEngine
- **FusionEngine** → Correlates events → Creates incidents → `data/intel/fusion_live.db`

**Logs:**
```bash
tail -f logs/auth_agent.log
tail -f logs/persistence_agent.log
tail -f logs/ingest.log
tail -f logs/fusion_engine.log
```

---

### Step 2: Trigger Safe Scenario

This scenario triggers the `persistence_after_auth` correlation rule (CRITICAL severity).

**Action 1: Generate sudo event**
```bash
sudo ls /tmp
```

**Action 2: Create harmless LaunchAgent**
```bash
cat << 'EOF' > ~/Library/LaunchAgents/com.amoskys.test.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" \
 "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>com.amoskys.test</string>
    <key>ProgramArguments</key>
    <array>
      <string>/bin/echo</string>
      <string>amoskys-test</string>
    </array>
    <key>RunAtLoad</key>
    <false/>
  </dict>
</plist>
EOF
```

**Wait 10-15 seconds** for:
1. AuthGuard to capture sudo event
2. PersistenceGuard to detect LaunchAgent creation
3. TelemetryIngestor to poll databases
4. FusionEngine to correlate events

---

### Step 3: Verify Detection

**Check for incidents:**
```bash
PYTHONPATH=src python -m amoskys.intel.fusion_engine \
  --db data/intel/fusion_live.db \
  --list-incidents --limit 5
```

**Expected output:**
```
🔴 [CRITICAL] persistence_after_auth
   Device: <your-mac-hostname>
   Summary: New LAUNCH_AGENT created 120s after SSH login or sudo
   Tactics: TA0003, TA0004
   Techniques: T1543.001, T1548.003
   Time: 2025-12-28 15:XX:XX
```

**Check device risk:**
```bash
PYTHONPATH=src python -m amoskys.intel.fusion_engine \
  --db data/intel/fusion_live.db \
  --risk "$(hostname)"
```

**Expected output:**
```
Device Risk: <your-mac-hostname>
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Risk Score: 75
Risk Level: HIGH
Last Activity: 2025-12-28 15:XX:XX
Total Events: 2
Total Incidents: 1
```

---

### Step 4: Monitor Real-Time

**Watch fusion engine logs for structured output:**
```bash
tail -f logs/fusion_engine.log
```

Look for:
```
INCIDENT_CREATED | device_id=<hostname> | incident_id=<uuid> | rule=persistence_after_auth | severity=CRITICAL | tactics=TA0003,TA0004 | techniques=T1543.001,T1548.003
```

**Check system status:**
```bash
./scripts/check_e2e_status.sh
```

---

### Step 5: Cleanup

**Remove test LaunchAgent:**
```bash
rm ~/Library/LaunchAgents/com.amoskys.test.plist
```

**Stop all components:**
```bash
./scripts/stop_e2e_validation.sh
```

---

## Manual Validation Process

If you prefer manual control over each component:

### Terminal 1: AuthGuardAgent
```bash
PYTHONPATH=src python -m amoskys.agents.auth.auth_agent \
  --device-id "$(hostname)" \
  --queue-db data/queue/auth_agent.db
```

### Terminal 2: PersistenceGuardAgent
```bash
PYTHONPATH=src python -m amoskys.agents.persistence.persistence_agent \
  --device-id "$(hostname)" \
  --queue-db data/queue/persistence_agent.db
```

### Terminal 3: TelemetryIngestor
```bash
PYTHONPATH=src python -m amoskys.intel.ingest \
  --poll-interval 5 \
  --fusion-db data/intel/fusion_live.db \
  --fusion-window 30
```

### Terminal 4: FusionEngine
```bash
PYTHONPATH=src python -m amoskys.intel.fusion_engine \
  --db data/intel/fusion_live.db \
  --window 30 \
  --interval 60
```

Then follow Steps 2-5 from the automated workflow.

---

## Troubleshooting

### No incidents created

**Check agent databases:**
```bash
sqlite3 data/queue/auth_agent.db "SELECT COUNT(*) FROM queue"
sqlite3 data/queue/persistence_agent.db "SELECT COUNT(*) FROM queue"
```

**Check ingest logs:**
```bash
grep "Processing" logs/ingest.log
```

**Check fusion logs:**
```bash
grep "INCIDENT_CREATED" logs/fusion_engine.log
```

### Agents not capturing events

**Verify AuthGuard is monitoring sudo:**
```bash
tail -f logs/auth_agent.log
# Then run: sudo ls /tmp
# Should see: "Captured sudo event" or similar
```

**Verify PersistenceGuard is monitoring LaunchAgents:**
```bash
tail -f logs/persistence_agent.log
# Then create test plist
# Should see: "Detected LAUNCH_AGENT creation" or similar
```

### Correlation not working

**Check timing:** Ensure actions happen within correlation window (10 minutes for persistence_after_auth)

**Check rule evaluation:**
```bash
grep "evaluate_all_devices" logs/fusion_engine.log
```

**Manually inspect fusion DB:**
```bash
sqlite3 data/intel/fusion_live.db << EOF
SELECT device_id, event_type, timestamp FROM device_events ORDER BY timestamp DESC LIMIT 10;
SELECT incident_id, rule_name, severity, summary FROM incidents;
EOF
```

---

## Success Criteria

✅ All 4 components start without errors
✅ Agents capture events (visible in logs/databases)
✅ TelemetryIngestor polls and forwards events
✅ FusionEngine evaluates and creates incident
✅ CLI tools show incident with CRITICAL severity
✅ Device risk increases to HIGH or CRITICAL
✅ Structured logs contain INCIDENT_CREATED entries

---

## What's Being Validated

### Architecture
```
AuthGuard (sudo)           ─┐
PersistenceGuard (plist)   ─┤
                            ├─→ TelemetryIngestor → FusionEngine → Incidents
FlowAgent (network)        ─┤
ProcAgent (processes)      ─┘
```

### Correlation Rule: persistence_after_auth
- **Pattern:** SSH/sudo → persistence creation (10min window)
- **Techniques:** T1543.001 (Launch Agent), T1548.003 (Sudo)
- **Tactics:** TA0003 (Persistence), TA0004 (Privilege Escalation)
- **Severity:** CRITICAL (user directory), HIGH (system directory)

### Risk Scoring
- Base: 10 points
- Sudo command: +30 (suspicious patterns)
- LaunchAgent in ~/Library: +25
- CRITICAL incident: +40
- **Expected final score:** 65-75 (HIGH to CRITICAL)

---

## Next Steps After Validation

Once you've verified the safe scenario works:

1. **Try other scenarios:**
   - Multiple sudo commands (should increase risk)
   - Edit /etc/sudoers (triggers suspicious_sudo rule)
   - Run process from /tmp with network connection (triggers multi_tactic_attack)

2. **Iterate on detections:**
   - Tune correlation windows
   - Adjust risk scoring weights
   - Add new correlation rules

3. **Expand coverage:**
   - Add FlowAgent for network correlation
   - Add ProcAgent for process tree analysis
   - Implement next 3 rules from MITRE roadmap

---

## Reference

- **Tests:** `pytest tests/intel/test_fusion_rules.py -v`
- **MITRE Coverage:** [docs/MITRE_COVERAGE.md](docs/MITRE_COVERAGE.md)
- **Rules Implementation:** [src/amoskys/intel/rules.py](../src/amoskys/intel/rules.py)
- **Fusion Engine:** [src/amoskys/intel/fusion_engine.py](../src/amoskys/intel/fusion_engine.py)

---

**Last Updated:** 2025-12-28
**Status:** Ready for validation
