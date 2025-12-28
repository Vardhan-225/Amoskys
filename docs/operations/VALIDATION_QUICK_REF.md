# E2E Validation Quick Reference

## One-Command Start
```bash
./scripts/run_e2e_validation.sh
```

## Safe Scenario (Copy-Paste Ready)

### Step 1: Generate sudo event
```bash
sudo ls /tmp
```

### Step 2: Create test LaunchAgent
```bash
cat << 'EOF' > ~/Library/LaunchAgents/com.amoskys.test.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
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

### Step 3: Wait 15 seconds, then check

```bash
# Check for incidents
PYTHONPATH=src python -m amoskys.intel.fusion_engine --db data/intel/fusion_live.db --list-incidents --limit 5

# Check device risk
PYTHONPATH=src python -m amoskys.intel.fusion_engine --db data/intel/fusion_live.db --risk "$(hostname)"
```

## Expected Output
```
🔴 [CRITICAL] persistence_after_auth
   Device: <hostname>
   Summary: New LAUNCH_AGENT created 120s after SSH login or sudo
   Tactics: TA0003, TA0004
   Techniques: T1543.001, T1548.003
```

## Monitoring Commands

```bash
# Status check
./scripts/check_e2e_status.sh

# Watch fusion logs
tail -f logs/fusion_engine.log | grep INCIDENT_CREATED

# Check agent databases
sqlite3 data/queue/auth_agent.db "SELECT COUNT(*) FROM queue"
sqlite3 data/queue/persistence_agent.db "SELECT COUNT(*) FROM queue"
```

## Cleanup

```bash
# Remove test plist
rm ~/Library/LaunchAgents/com.amoskys.test.plist

# Stop all components
./scripts/stop_e2e_validation.sh
```

## Troubleshooting

**No incident created?**
- Check logs: `tail logs/*.log`
- Check databases: `sqlite3 data/queue/auth_agent.db "SELECT * FROM queue"`
- Verify timing: Actions must be within 10 minutes

**Components not starting?**
- Check PYTHONPATH: `echo $PYTHONPATH`
- Verify modules: `PYTHONPATH=src python -c "from amoskys.intel import FusionEngine"`

**Need manual control?**
- See `E2E_VALIDATION_GUIDE.md` for step-by-step manual process
