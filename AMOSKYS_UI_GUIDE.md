# AMOSKYS UI/UX Guide - Developer Reference

**Version**: 1.0  
**Status**: Production-Ready  
**Last Updated**: December 4, 2025  

---

## 📋 Quick Navigation

### For Users
- **[Getting Started](#getting-started)**: First-time setup
- **[Dashboard Overview](#dashboards)**: What each dashboard shows
- **[Features](#features)**: Available features and workflows

### For Developers
- **[Architecture](#architecture)**: System design and data flow
- **[API Reference](#api-reference)**: Available endpoints
- **[Development](#development)**: How to extend or modify

### For Operations
- **[Deployment](#deployment)**: How to run in production
- **[Monitoring](#monitoring)**: Health checks and metrics
- **[Troubleshooting](#troubleshooting)**: Common issues and fixes

---

## 🚀 Getting Started

### Prerequisites
- Python 3.11+
- macOS (currently), Linux/Windows (future)
- Modern web browser (Chrome, Safari, Firefox)

### Installation

```bash
# Clone repository
git clone https://github.com/Vardhan-225/Amoskys.git
cd Amoskys

# Setup environment
make setup

# Generate certificates
make certs

# Start EventBus server
make run-eventbus

# In another terminal, start Flask web UI
cd web
python -m flask run --host=127.0.0.1 --port 5000
```

### Access the Dashboard
Open browser to: **http://127.0.0.1:5000/dashboard**

---

## 📊 Dashboards

AMOSKYS provides 6 specialized security dashboards:

### 1. **Cortex Command Center** (`/dashboard/cortex`)
**Purpose**: Real-time system overview and threat assessment

**Displays**:
- 🔴 Current threat score
- 🤖 Active agents count + health
- ⚠️ Recent threats (last 24h)
- 📊 System performance (CPU, Memory, Disk)
- 🧠 Neural readiness score
- 🕸️ Agent network topology

**Data Sources**:
- `/dashboard/api/live/metrics` - System metrics
- `/dashboard/api/live/threats` - Event stream
- `/dashboard/api/live/agents` - Agent status

**Refresh Rate**: Every 5 seconds

---

### 2. **Process Telemetry** (`/dashboard/processes`)
**Purpose**: Deep visibility into Mac process activity

**Displays**:
- 📈 Total process events (491K+)
- 🔢 Unique PIDs and executables
- 👥 User type distribution (Root/System/User)
- 🏷️ Process class breakdown (System/App/Daemon/3P)
- 🔝 Top 10 executables by frequency
- 📡 Live process stream (last 50)

**Data Sources**:
- `/api/process-telemetry/stats` - Aggregated stats
- `/api/process-telemetry/recent` - Recent events

**Refresh Rate**: Every 5 seconds

**Data Coverage**: 7.2 hours, 491,502 process events, 3,766 unique PIDs

---

### 3. **System Health** (`/dashboard/system`)
**Purpose**: Monitor host system performance

**Displays**:
- 💻 CPU usage (real-time)
- 🧠 Memory consumption
- 💾 Disk usage
- 🔗 Network traffic
- 📊 Performance trends
- ⚠️ Resource alerts

**Data Sources**:
- `/dashboard/api/live/metrics` - System metrics

**Refresh Rate**: Every 5 seconds

---

### 4. **SOC Operations** (`/dashboard/soc`)
**Purpose**: Security operations center threat monitoring

**Displays**:
- 🚨 Incident timeline
- 📋 Event list with filtering
- 🔍 Event details and context
- 📍 Geographic distribution
- 🎯 Attack patterns
- 📊 Threat metrics

**Data Sources**:
- `/dashboard/api/live/threats` - Threat events
- `/api/events/search` - Event search

**Refresh Rate**: Real-time via SocketIO (when implemented)

---

### 5. **Agent Management** (`/dashboard/agents`)
**Purpose**: Monitor and manage distributed agents

**Displays**:
- 🤖 Agent list with status
- 📡 Connectivity status
- 🕐 Last heartbeat time
- 📦 Agent version
- 🔧 Configuration status
- 📊 Resource utilization per agent

**Data Sources**:
- `/dashboard/api/live/agents` - Agent registry

**Refresh Rate**: Every 5 seconds

---

### 6. **Neural Insights** (`/dashboard/neural`)
**Purpose**: ML-based anomaly detection and insights

**Displays**:
- 🧠 ML model readiness
- 📈 Anomaly scores
- 🎯 Feature importance
- 📊 Detection confidence
- 🔮 Predictions
- 📚 Training data stats

**Data Sources**:
- `/api/ml/anomalies` - Anomaly scores
- `/api/ml/features` - Feature stats

**Refresh Rate**: Every 30 seconds (longer due to computation)

**Status**: In progress

---

## 🔌 API Reference

### Endpoint Categories

#### Dashboard Live Data APIs
```
GET /dashboard/api/live/metrics    → System metrics (CPU, Memory, Disk, Network)
GET /dashboard/api/live/threats    → Threat events (last 24h, max 50)
GET /dashboard/api/live/agents     → Agent status and connectivity
```

#### Process Telemetry APIs
```
GET /api/process-telemetry/stats           → Aggregated process statistics
GET /api/process-telemetry/recent          → Recent process events (paginated)
GET /api/process-telemetry/top-executables → Top executables by frequency
```

#### Event Management APIs
```
GET /api/events/search             → Search events with filters
POST /api/events/create            → Create manual event
GET /api/events/:id                → Get event details
```

#### System APIs
```
GET /api/system/metrics            → System metrics (requires auth)
GET /api/system/health             → Overall system health
GET /api/system/status             → System status
```

#### ML APIs (Future)
```
GET /api/ml/anomalies              → Anomaly scores
GET /api/ml/features               → Feature statistics
POST /api/ml/train                 → Trigger model retraining
```

---

### Response Format

All APIs return JSON with this structure:

```json
{
  "status": "success" | "error",
  "data": { ... },
  "timestamp": "2025-12-04T17:30:00Z",
  "error": "error message if status=error"
}
```

---

### Error Handling

| Code | Meaning | Action |
|------|---------|--------|
| 200 | Success | Parse data normally |
| 400 | Bad request | Check query parameters |
| 401 | Unauthorized | Add auth header |
| 404 | Not found | Check endpoint path |
| 429 | Rate limited | Implement exponential backoff |
| 500 | Server error | Retry after 5 seconds |

---

## 🏗️ Architecture

### System Overview
```
┌─────────────────────────────────────────────────────────┐
│                    Browser (User)                        │
└──────────────────────┬──────────────────────────────────┘
                       │ HTTP/WebSocket
                       ▼
┌─────────────────────────────────────────────────────────┐
│            Flask Web Server (Port 5000)                  │
│  ┌────────────────────────────────────────────────────┐ │
│  │  Dashboard Routes (/dashboard/*)                   │ │
│  │  ├── cortex.html - Command center                 │ │
│  │  ├── processes.html - Process telemetry           │ │
│  │  ├── system.html - System health                  │ │
│  │  ├── soc.html - SOC operations                    │ │
│  │  ├── agents.html - Agent management               │ │
│  │  └── neural.html - Neural insights                │ │
│  └────────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────────┐ │
│  │  API Endpoints (/api/*, /dashboard/api/*)         │ │
│  │  ├── System metrics                               │ │
│  │  ├── Process telemetry                            │ │
│  │  ├── Threat events                                │ │
│  │  ├── Agent status                                 │ │
│  │  └── Event management                             │ │
│  └────────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────────┐ │
│  │  Static Assets (/static/*)                        │ │
│  │  ├── CSS styles                                   │ │
│  │  ├── JavaScript classes                           │ │
│  │  └── Images/fonts                                 │ │
│  └────────────────────────────────────────────────────┘ │
└─────────────────┬──────────────────────────────────────┘
                  │ REST/JSON
                  ▼
┌─────────────────────────────────────────────────────────┐
│         EventBus Server (Port 50051, gRPC)              │
│  ├── Event validation & persistence                     │
│  ├── Agent connection management                        │
│  └── Real-time event streaming                         │
└─────────────────┬──────────────────────────────────────┘
                  │ gRPC
                  ▼
┌─────────────────────────────────────────────────────────┐
│       Storage Layer                                     │
│  ├── Event Store (SQLite WAL)                          │
│  ├── Agent Registry                                     │
│  ├── ML Features                                        │
│  └── System Metrics Cache                              │
└─────────────────────────────────────────────────────────┘
```

### Data Flow

1. **Event Collection**: Agents send events via gRPC
2. **Validation**: EventBus validates and stores in WAL
3. **Processing**: Python scripts aggregate and analyze
4. **Dashboard Display**: Flask serves aggregated data to web UI
5. **Real-time Updates**: JavaScript auto-refreshes every 5 seconds

---

## 🛠️ Development

### Project Structure

```
web/
├── app/
│   ├── __init__.py           # Flask app factory
│   ├── routes.py             # Main routes
│   ├── websocket.py          # WebSocket/SocketIO
│   ├── dashboard/
│   │   ├── __init__.py       # Dashboard blueprint
│   │   └── utils.py          # Helper functions
│   ├── api/
│   │   ├── __init__.py       # API blueprint
│   │   ├── auth.py           # Authentication
│   │   ├── events.py         # Event endpoints
│   │   ├── agents.py         # Agent endpoints
│   │   ├── system.py         # System endpoints
│   │   └── process_telemetry.py  # Process data
│   ├── templates/
│   │   └── dashboard/
│   │       ├── base.html     # Base template
│   │       ├── cortex.html   # Command center
│   │       ├── processes.html # Process telemetry
│   │       ├── system.html   # System health
│   │       ├── soc.html      # SOC ops
│   │       ├── agents.html   # Agent management
│   │       └── neural.html   # Neural insights
│   └── static/
│       ├── css/
│       │   ├── base.css      # Shared styles
│       │   └── mobile-responsive.css
│       └── js/
│           └── dashboards/   # Extract here (future)
│
├── wsgi.py                   # WSGI entry point
└── config.py                 # Configuration
```

### Adding a New Dashboard

1. **Create Template**: `web/app/templates/dashboard/newpage.html`
2. **Add Route**: In `web/app/dashboard/__init__.py`
   ```python
   @dashboard_bp.route('/newpage')
   def new_page():
       return render_template('dashboard/newpage.html')
   ```
3. **Create API Endpoint**: In appropriate `web/app/api/` file
4. **Test**: `curl http://localhost:5000/dashboard/newpage`

### Adding a New API Endpoint

1. **Create function** in appropriate `web/app/api/` file
2. **Add route decorator**: `@bp.route('/endpoint', methods=['GET'])`
3. **Return JSON**: `return jsonify({'status': 'success', 'data': {...}})`
4. **Test**: `curl http://localhost:5000/api/endpoint`

### Testing

```bash
# Run tests
pytest tests/

# Run with coverage
pytest --cov=web tests/

# Run specific test
pytest tests/test_dashboard.py::test_cortex_endpoint
```

---

## 🚀 Deployment

### Local Development
```bash
cd web
python -m flask run --host=127.0.0.1 --port 5000
```

### Production with Gunicorn
```bash
pip install gunicorn
gunicorn --worker-class eventlet -w 1 --bind 0.0.0.0:8000 wsgi:app
```

### Docker Deployment
```bash
docker build -t amoskys-web .
docker run -p 8000:8000 amoskys-web
```

### Configuration
Set environment variables:
```bash
export FLASK_ENV=production
export SECRET_KEY=your-secure-random-key
export DEBUG=False
```

---

## 📈 Monitoring

### Health Checks

```bash
# Check if Flask is running
curl http://localhost:5000/health

# Check EventBus
curl http://localhost:8080/healthz

# Check agent readiness
curl http://localhost:5000/api/agents/health
```

### Key Metrics

| Metric | Target | How to Check |
|--------|--------|--------------|
| Page Load | <2s | DevTools Performance tab |
| API Response | <100ms | Network tab |
| Error Rate | <0.1% | Application logs |
| Uptime | >99.9% | Monitoring dashboard |

---

## 🐛 Troubleshooting

### Dashboard not loading
```bash
# Check Flask is running
curl http://localhost:5000/dashboard/cortex

# Check console for JavaScript errors
# Open DevTools (F12) → Console tab

# Check network requests
# Open DevTools → Network tab
```

### API returns 404
```bash
# List all registered routes
flask routes

# Check endpoint path spelling
# Verify blueprint is registered in __init__.py
```

### Charts not rendering
```bash
# Check if Chart.js loaded
# Open DevTools → Sources → search "chart.js"

# Check if data is valid JSON
# Open DevTools → Network → click on API request → Response tab
```

### Auto-refresh not working
```bash
# Check JavaScript console for fetch errors
# Verify API endpoint is accessible
# Check network requests in DevTools
```

---

## 🔐 Security

### Current Protections
- ✅ CSRF protection (Flask-Session)
- ✅ XSS prevention (template escaping)
- ✅ Input validation on APIs
- ✅ Secure headers

### Future Enhancements
- [ ] User authentication
- [ ] Role-based access control (RBAC)
- [ ] API rate limiting
- [ ] Audit logging
- [ ] End-to-end encryption

---

## 📚 Additional Resources

### Related Docs
- **Architecture**: `AGENT_HARMONY_ARCHITECTURE.md`
- **Data Flow**: `DATA_FLOW_ANALYSIS.md`
- **Quickstart**: `QUICKSTART.md`

### External Resources
- Flask docs: https://flask.palletsprojects.com/
- Chart.js docs: https://www.chartjs.org/
- WebSocket docs: https://socket.io/

---

## 🤝 Contributing

### Code Style
- Python: PEP 8
- JavaScript: ES6+
- HTML/CSS: BEM methodology

### Before Committing
```bash
# Format code
black web/

# Run linter
flake8 web/

# Run tests
pytest tests/

# Run security scan
bandit -r web/
```

---

## 📞 Support

### For Issues
1. Check this guide
2. Check `QUICKSTART.md`
3. Review logs: `tail -f logs/*.log`
4. Search GitHub issues
5. Create new issue with details

---

**Last Updated**: December 4, 2025  
**Maintainer**: AMOSKYS Team  
**License**: MIT

