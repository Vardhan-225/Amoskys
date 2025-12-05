# Operations Guide

## Starting the Dashboard

### Option 1: Using Make
```bash
make dashboard
```

### Option 2: Manual Start
```bash
python3 web/app/__init__.py
```

Access at: **http://localhost:5001/dashboard/agents**

## Agent Control

### Via Dashboard UI
1. Go to http://localhost:5001/dashboard/agents
2. Click **▶️ Start** to start an agent
3. Click **⏹️ Stop** to stop an agent
4. Click **🔄 Refresh** for manual update

### Via Make Commands
```bash
make agent-start ID=eventbus          # Start specific agent
make agent-stop ID=proc_agent         # Stop specific agent
make agent-status                     # Show all agent status
```

### Via curl
```bash
# Get agent status
curl http://localhost:5001/dashboard/api/agents/status

# Start an agent
curl -X POST http://localhost:5001/dashboard/api/agents/eventbus/start

# Stop an agent
curl -X POST http://localhost:5001/dashboard/api/agents/proc_agent/stop
```

## What Happens When You Start/Stop an Agent

### Start Flow
```
Click Start Button
       ↓
    UI: "⏳ Starting..."
       ↓
    Backend: Spawn subprocess
       ↓
    Wait 1 second for process to initialize
       ↓
    UI: "✅ Started" (2 sec message)
       ↓
    Metrics polling detects change
       ↓
    Agent card updates: Status→Running, PID shows, CPU/Memory live
```

### Stop Flow
```
Click Stop Button
       ↓
    UI: "⏳ Stopping..."
       ↓
    Backend: Send SIGTERM (graceful shutdown)
       ↓
    Wait up to 5 seconds for process to exit
       ↓
    If timeout: Send SIGKILL (force kill)
       ↓
    UI: "✅ Stopped" (2 sec message)
       ↓
    Metrics polling detects change
       ↓
    Agent card updates: Status→Stopped, PID clears, metrics→"-"
```

## Agent Details

| Agent | Start Time | CPU (idle) | Memory | Port | Platform |
|-------|-----------|-----------|--------|------|----------|
| EventBus | ~1s | <1% | 50MB | 50051 | All |
| Process Monitor | ~0.5s | 0.5% | 30MB | None | macOS/Linux |
| Mac Telemetry | ~0.5s | 1% | 25MB | None | macOS only |
| FlowAgent | ~1s | 0.5% | 40MB | None | macOS/Linux |
| SNMP Agent | ~1s | 0.2% | 35MB | 161 | All |
| Device Scanner | ~0.5s | 0.5% | 28MB | None | macOS/Linux |

## Troubleshooting

### Agent fails to start
**Symptom**: Click Start, see error message

**Check**: 
```bash
curl http://localhost:5001/dashboard/api/agents/status
```

**Look for**: `"message"` field explaining why

**Common causes**:
- EventBus must be running first
- Python script file path incorrect
- Missing dependencies

### Metrics not updating
**Symptom**: CPU%, Memory show "-" even when running

**Fix**:
- Wait 5 seconds (first update delay)
- Click 🔄 Refresh button
- Check if agent really is running

### High CPU when monitoring
**Symptom**: System slow when ProcessMonitor runs

**Cause**: System has many processes

**Fix**:
- Stop ProcessMonitor temporarily
- Use SNMP Agent for network-only monitoring
- Increase polling interval (edit code)

## Logs

Agent logs are in `logs/` directory:

```bash
tail -f logs/flask.log           # Dashboard logs
tail -f logs/proc_agent.log      # ProcessMonitor logs
tail -f logs/eventbus.log        # EventBus logs
tail -f logs/mac_telemetry.log   # MacTelemetry logs
```

## Performance Notes

- Dashboard metrics update: **Every 5 seconds**
- Agent startup: **1 second typical**
- Agent shutdown: **5 second timeout (graceful→force)**
- API response time: **<100ms typical**

## Network Requirements

- **EventBus port 50051**: gRPC (mTLS)
- **SNMP Agent port 161**: UDP for SNMP polling
- **Dashboard port 5001**: HTTP
- **Agents**: Talk to EventBus on localhost (no external network needed)

## Certificates

All mTLS certificates are in `certs/`:
```
certs/
├── ca.crt / ca.key               # CA certificate
├── server.crt / server.key       # EventBus server cert
├── agent.crt / agent.key         # Agent client cert
└── agent.ed25519 / agent.ed25519.pub  # Signature keys
```

These are pre-generated for development. For production:
```bash
make certs                        # Regenerate certificates
```

## Production Checklist

- [ ] Set `SECRET_KEY` environment variable
- [ ] Use proper TLS certificates (not self-signed)
- [ ] Run behind reverse proxy (nginx)
- [ ] Enable authentication on Dashboard
- [ ] Set resource limits on agents
- [ ] Monitor disk space (logs grow)
- [ ] Regular backups of `data/` directory

---

Last Updated: December 5, 2025
