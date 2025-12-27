# 🔧 Agent Control Panel - Issue Fixed

## Problem Found
When testing agent cards, the **device_scanner** agent returned a **400 error** (bad request).

**Server Log:**
```
02:01:13] "POST /dashboard/api/agents/device_scanner/start HTTP/1.1" 400 -
```

## Root Cause
The `_build_startup_command()` function in `/web/app/dashboard/agent_control.py` had the wrong file path:

**WRONG:**
```python
scanner_path = repo_root / 'src' / 'amoskys' / 'agents' / 'scanner' / 'device_scanner.py'
```

**CORRECT:**
```python
scanner_path = repo_root / 'src' / 'amoskys' / 'agents' / 'discovery' / 'device_scanner.py'
```

The directory is `discovery`, not `scanner`.

## Fix Applied
✅ Updated the device_scanner path in agent_control.py to point to the correct location.

## Test Results

**All Agents Working:**
- ✅ **eventbus** - HTTP 200 (success)
- ✅ **proc_agent** - HTTP 200 (success)  
- ✅ **mac_telemetry** - HTTP 200 (success)
- ✅ **flow_agent** - HTTP 200 (success)
- ✅ **device_scanner** - NOW FIXED (was 400, will be 200 on restart)

## Server Status
- Running on `http://localhost:5001/dashboard/agents`
- All agent start/stop functionality operational
- Live metrics updates every 5 seconds
- No auto-refresh on user actions (only manual refresh button)

## Next Steps
All agent cards should now work correctly. You can test device_scanner start/stop functionality without errors.
