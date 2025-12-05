# 🚀 AMOSKYS Dashboard Quick Start - Active Session

## 🟢 Server Status: RUNNING

**Server URL**: http://127.0.0.1:5001  
**Process ID**: 23305  
**Mode**: Development with SocketIO  
**Status**: ✅ All systems operational

---

## 📊 Dashboard URLs

Open these in your browser:

| Dashboard | URL | Purpose |
|-----------|-----|---------|
| 🛡️ SOC Operations | http://127.0.0.1:5001/dashboard/soc | Live threat monitoring |
| 🖥️ System Health | http://127.0.0.1:5001/dashboard/system | CPU, memory, disk metrics |
| 🤖 Agent Network | http://127.0.0.1:5001/dashboard/agents | Agent status & health |
| 🧠 Cortex Command | http://127.0.0.1:5001/dashboard/cortex | Command center |
| 🔮 Neural Insights | http://127.0.0.1:5001/dashboard/neural | AI detection insights |

---

## 📝 Current Test Data

### Events Loaded
- **Total**: 10 security events
- **Severities**: 2 Critical, 2 High, 1 Medium, 5 Low
- **Threat Types**: suspicious_connection, malware_detection, unauthorized_access, brute_force_attempt, data_exfiltration, privilege_escalation
- **Time Range**: Last few minutes (live updates)

### Agents
- **test-agent-1**: Active
- **test-agent-2**: Active  
- **test-agent-3**: Active

---

## 🔐 API Authentication

### Get a Token
```bash
curl -X POST http://127.0.0.1:5001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "flowagent-001", "secret": "amoskys-neural-flow-secure-key-2025"}'
```

### Use the Token
```bash
TOKEN="<paste_token_here>"

# Submit an event
curl -X POST http://127.0.0.1:5001/api/events/submit \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "event_type": "malware_detection",
    "severity": "critical",
    "source_ip": "192.168.1.100",
    "destination_ip": "192.168.1.1",
    "description": "Detected suspicious malware signature"
  }'
```

---

## 🧪 Generate More Test Data

```bash
python populate_test_data.py
```

This will:
1. Authenticate with the API
2. Register 3 new test agents
3. Submit 10 security events with mixed severities
4. Print summary statistics

---

## ⚙️ API Endpoints (All Working)

### Authentication
- `POST /api/auth/login` → Get JWT token

### Events
- `POST /api/events/submit` → Submit security event
- `GET /api/events/list` → List all events

### Dashboard (Real-time)
- `GET /dashboard/api/live/threats` → Live threat feed (10 events)
- `GET /dashboard/api/live/agents` → Agent status
- `GET /dashboard/api/live/metrics` → System metrics
- `GET /dashboard/api/live/threat-score` → Threat level

### System
- `GET /api/system/stats` → Health statistics
- `GET /api/system/processes` → Top processes
- `GET /api/system/disk` → Disk usage

---

## 🔧 Configuration

### Server Port
Default: **5001**

To use a different port:
```bash
FLASK_PORT=5002 python web/wsgi.py --dev
```

### Rate Limiting
- **Status**: Active
- **Localhost**: Exempt (127.0.0.1, ::1)
- **External**: 100 requests/minute per IP

---

## 🐛 Troubleshooting

### Dashboard shows no data
```bash
python populate_test_data.py
```

### API returns 401 Unauthorized
Get a new token:
```bash
curl -X POST http://127.0.0.1:5001/api/auth/login \
  -d '{"agent_id": "flowagent-001", "secret": "amoskys-neural-flow-secure-key-2025"}'
```

### Port already in use
Find and kill the process:
```bash
lsof -i :5001
kill -9 <PID>
```

Or use a different port:
```bash
FLASK_PORT=5002 python web/wsgi.py --dev
```

### Server won't start
Check logs:
```bash
ps aux | grep wsgi
tail -50 /tmp/flask_server.log
```

---

## 📈 What's Working

✅ **Dashboards**
- Live event feed with filtering
- Real-time threat level display
- Event timeline with time range selection
- Agent health monitoring
- System resource monitoring
- Severity distribution charts

✅ **APIs**
- JWT authentication
- Event submission
- Real-time data retrieval
- Rate limiting (localhost exempt)
- System metrics

✅ **Features**
- Memory leak fixes (canvas)
- Error handling with retry buttons
- Data freshness timestamps
- Color-coded severity indicators
- Socket.IO real-time updates

---

## 🎯 Quick Actions

### Watch live threats
Open: http://127.0.0.1:5001/dashboard/soc

### Monitor system health
Open: http://127.0.0.1:5001/dashboard/system

### Add new threat events
```bash
python populate_test_data.py
```

### Check API status
```bash
curl http://127.0.0.1:5001/dashboard/api/live/threats | python3 -m json.tool
```

---

## 📚 Documentation

For detailed information, see:
- `DASHBOARD_STATUS_COMPLETE.md` - Full status report
- `PRODUCTION_HARDENING_CHECKLIST.md` - Phase 1.5 completion
- `PHASE_1_5_COMPLETE.md` - Implementation details

---

**Last Updated**: December 4, 2025  
**Server Status**: 🟢 RUNNING  
**All Systems**: ✅ OPERATIONAL
