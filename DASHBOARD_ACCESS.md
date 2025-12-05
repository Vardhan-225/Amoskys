# AMOSKYS Neural Security Platform - Dashboard Access Guide

## 🚀 Quick Start

### Starting the Server
```bash
./start_amoskys.sh
```

### Stopping the Server
```bash
./stop_amoskys.sh
```

### Checking Server Status
```bash
cat logs/flask.pid   # View PID
lsof -i :5000        # Check port 5000
tail -f logs/flask.log   # Monitor logs
```

---

## 📍 Dashboard Access URLs

### Main Dashboard
- **Home Page**: http://127.0.0.1:5000/
- **Cortex Command Center**: http://127.0.0.1:5000/dashboard/cortex

### Security Monitoring Dashboards
| Dashboard | URL | Description |
|-----------|-----|-------------|
| 🧠 **Cortex Center** | http://127.0.0.1:5000/dashboard/cortex | Main command center with real-time metrics |
| 🛡️ **SOC Operations** | http://127.0.0.1:5000/dashboard/soc | Security Operations Center - Live threat monitoring |
| 📊 **System Health** | http://127.0.0.1:5000/dashboard/system | System performance & health recommendations |
| 🔬 **Process Telemetry** | http://127.0.0.1:5000/dashboard/processes | Mac process monitoring & analysis |
| 🤖 **Agent Management** | http://127.0.0.1:5000/dashboard/agents | Agent deployment & status |
| 🧠 **Neural Insights** | http://127.0.0.1:5000/dashboard/neural | AI-powered detection visualization |

---

## 🔌 API Endpoints

### API Documentation
- **Swagger UI**: http://127.0.0.1:5000/api/docs
- **OpenAPI Spec**: http://127.0.0.1:5000/api/docs/openapi.json

### Real-time Dashboard APIs
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/dashboard/api/live/threats` | GET | Real-time threat feed (last 24h) |
| `/dashboard/api/live/agents` | GET | Agent status and health |
| `/dashboard/api/live/metrics` | GET | System performance metrics |
| `/dashboard/api/live/threat-score` | GET | Current threat score calculation |
| `/dashboard/api/available-agents` | GET | List of deployable agents |

### Process Telemetry API
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/process-telemetry/recent` | GET | Recent process events |
| `/api/process-telemetry/stats` | GET | Aggregated process statistics |
| `/api/process-telemetry/top-executables` | GET | Most frequently seen executables |
| `/api/process-telemetry/user-distribution` | GET | Process distribution by user type |

### Agent Management API
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/agents/register` | POST | Register a new agent |
| `/api/agents/{agent_id}/heartbeat` | POST | Send agent heartbeat |
| `/api/agents/list` | GET | List all registered agents |

### Event Ingestion API
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/events/ingest` | POST | Ingest security events |
| `/api/events/query` | GET | Query security events |

### SNMP Telemetry API
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/snmp/metrics` | GET | Get SNMP device metrics |

---

## 🎯 Features

### ✅ Implemented Features
- [x] Real-time system metrics (CPU, Memory, Disk, Network)
- [x] Process telemetry visualization with distribution charts
- [x] Rate limiting (100 requests/60s, bypasses localhost)
- [x] WebSocket support for live updates
- [x] System health recommendations
- [x] Agent management dashboard
- [x] Process classification (system, application, daemon, third-party)
- [x] Top executables tracking
- [x] User type distribution (root, system, user)
- [x] Interactive charts with Chart.js
- [x] Neural-themed dark UI
- [x] Single-port server automation

### 🔧 Server Features
- **Port Management**: Always runs on port 5000
- **Single Instance**: Automatically kills duplicate servers
- **Health Checks**: Verifies server responds before confirming startup
- **PID Management**: Tracks server PID in `logs/flask.pid`
- **Auto-Cleanup**: Removes stale processes before starting
- **Error Recovery**: Validates environment and app structure

---

## 📊 Current Statistics

**From Latest Data (as of deployment)**:
- **Total Process Events**: 491,501
- **Collection Period**: 7.2 hours
- **Unique PIDs**: Monitored
- **Process Classes**:
  - System: 262,225 events
  - Daemon: 140,722 events
  - Application: 52,760 events
  - Other: 32,945 events
  - Third-party: 2,849 events

**Top Executables**:
1. `distnoted` - 17,040 events
2. `com.apple.WebKit.WebContent` - 11,980 events
3. `Google Chrome Helper (Renderer)` - 10,246 events
4. `zsh` - 8,567 events

---

## 🛡️ Security Features

### Rate Limiting
- **Default**: 100 requests per 60 seconds
- **Localhost Bypass**: Development requests bypass rate limiting
- **Blocked IPs**: Temporarily blocked for 1 minute on limit exceed
- **Headers**: Returns `429 Too Many Requests` with retry-after

### Authentication (Planned)
- API key authentication for external agents
- JWT tokens for dashboard access
- Role-based access control (RBAC)

---

## 🔄 Service Management

### Start Server (Recommended Method)
```bash
./start_amoskys.sh
```

**What it does**:
1. Kills existing Flask instances
2. Verifies Python environment
3. Validates application structure
4. Starts Flask on port 5000
5. Performs health check
6. Shows access URLs

### Stop Server
```bash
./stop_amoskys.sh
```

**What it does**:
1. Stops Flask by PID
2. Force kills if necessary
3. Cleans up stray processes
4. Frees port 5000

### Manual Start (Alternative)
```bash
cd web
PYTHONPATH=../src FLASK_APP=wsgi:app FLASK_DEBUG=True python -m flask run --port 5000
```

---

## 📝 Logs

### Log Locations
- **Flask**: `logs/flask.log`
- **EventBus**: `logs/eventbus.log`
- **Process Agent**: `logs/proc_agent.log`
- **Mac Telemetry**: `logs/mac_telemetry.log`

### Monitor Logs
```bash
# Flask server logs
tail -f logs/flask.log

# All logs
tail -f logs/*.log

# Search for errors
grep -i error logs/flask.log
```

---

## 🎨 Dashboard Themes

**Neural Dark Theme** (Default)
- Background: `#0a0a0f` (Deep space black)
- Primary: `#00ff88` (Neural green)
- Secondary: `#0088ff` (Neural blue)
- Warning: `#ffaa00` (Alert amber)
- Critical: `#ff3366` (Danger red)

---

## 🧪 Testing Endpoints

### Quick Health Check
```bash
# Server health
curl http://127.0.0.1:5000/

# System metrics
curl http://127.0.0.1:5000/dashboard/api/live/metrics

# Process stats
curl http://127.0.0.1:5000/api/process-telemetry/stats

# Agent status
curl http://127.0.0.1:5000/dashboard/api/live/agents
```

### Browser Testing
1. Open http://127.0.0.1:5000/dashboard/cortex
2. Watch real-time metrics update every 5 seconds
3. Navigate between dashboards using the menu
4. Check browser console for WebSocket connections

---

## 📞 Support

**Server Issues**:
- Check logs: `tail -f logs/flask.log`
- Verify PID: `cat logs/flask.pid`
- Check port: `lsof -i :5000`
- Restart: `./stop_amoskys.sh && ./start_amoskys.sh`

**Dashboard Issues**:
- Clear browser cache
- Check browser console (F12)
- Verify API endpoints are responding
- Check rate limiting (should bypass for localhost)

---

## 🎯 Next Steps

1. **Deploy Agents**: Start process and SNMP agents to populate data
2. **Configure Alerts**: Set up thresholds for system health alerts
3. **Enable Auth**: Implement API key authentication for production
4. **Add Integrations**: Connect to SIEM, logging, and alerting systems
5. **Scale**: Deploy agents across infrastructure

---

**Generated**: 2025-12-04
**Version**: AMOSKYS Neural Security Platform v2.4
**Port**: 5000 (Fixed)
**PID**: Check `logs/flask.pid`
