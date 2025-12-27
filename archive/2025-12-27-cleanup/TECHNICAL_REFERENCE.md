# AMOSKYS Technical Reference Guide
**Version**: 1.0  
**Date**: December 5, 2025  
**Purpose**: Quick lookup for architecture, APIs, data structures, and key files

---

## 🏗️ SYSTEM ARCHITECTURE

### Component Overview
```
┌─────────────────────────────────────────────────────────┐
│                    AMOSKYS Core System                   │
└─────────────────────────────────────────────────────────┘

┌──────────────────┐         ┌──────────────────┐
│   Data Agents    │         │  ML Analysis     │
│  (6 collectors)  │────────→│  (3-layer brain) │
│                  │         │                  │
│ • proc_agent     │         │ • Geometric      │
│ • snmp_agent     │         │ • Temporal       │
│ • device_scanner │         │ • Hero (IForest) │
│ • mac_telemetry  │         │                  │
│ • flowagent      │         └──────────────────┘
│ • eventbus       │                  │
└──────────────────┘                  ↓
        │                    ┌──────────────────┐
        │                    │  Alert System    │
        │                    │  (EventBus emit) │
        └───────────────────→│                  │
                             │ AlertEvent       │
                             └──────────────────┘
                                    │
                                    ↓
                    ┌───────────────────────────┐
                    │   Dashboard (Cortex)      │
                    │   Port 5000               │
                    │ • Agent status            │
                    │ • Live alerts             │
                    │ • Layer breakdown         │
                    └───────────────────────────┘
```

---

## 📡 COMMUNICATION PROTOCOLS

### EventBus (gRPC)
**Port**: 50051  
**Protocol**: gRPC + mTLS  
**Files**:
- `src/amoskys/eventbus/server.py` - EventBus server
- `src/amoskys/eventbus/client.py` - Client library
- `proto/amoskys_event.proto` - Message definitions

**Example Event Structure**:
```python
{
    "event_id": "uuid",
    "timestamp": "2025-12-05T10:30:45Z",
    "source_agent": "proc_agent",
    "event_type": "process_snapshot",
    "payload": {
        "pid": 1234,
        "command": "python",
        "cpu_percent": 45.2,
        "memory_mb": 256,
        # ... more fields
    }
}
```

### REST API (Flask)
**Port**: 5000  
**Files**: `web/app/__init__.py` (Flask app)

**Existing Endpoints**:
- `GET /` - Dashboard HTML
- `GET /api/agents` - Agent status
- `GET /api/metrics` - System metrics
- (More to be added for alerts)

**New Endpoints (To Build)**:
- `GET /api/alerts/recent?limit=50&severity=HIGH` - Get recent alerts
- `GET /api/alerts/<alert_id>` - Get single alert details

### Prometheus Metrics
**Ports**: 9000 (EventBus), 9101 (agents)  
**Files**: Every agent has prometheus metrics registration
**Key Metrics**:
- `agent_publish_ok_total` - Successful event publishes
- `agent_dropped_oversize_total` - Dropped events
- `agent_inflight_metric` - Events in flight
- Custom: Each agent adds domain-specific metrics

---

## 💾 DATA STRUCTURES

### Process Snapshot (from proc_agent)
**Table**: `processes` in `data/wal/flowagent.db`

```python
{
    "timestamp": "2025-12-05T10:30:45Z",
    "pid": 1234,
    "ppid": 1,  # Parent PID
    "uid": 501,
    "gid": 501,
    "process_name": "python",
    "command_line": "/usr/bin/python script.py",
    "cpu_percent": 45.2,
    "memory_mb": 256,
    "memory_percent": 12.5,
    "threads": 4,
    "status": "S",  # R=running, S=sleeping, etc
}
```

### SNMP Snapshot (from snmp_agent)
**Table**: `snmp` in `data/wal/flowagent.db`

```python
{
    "timestamp": "2025-12-05T10:30:45Z",
    "oid": "1.3.6.1.2.1.1.3.0",  # uptime
    "value": 123456789,
    "source": "192.168.1.100",
}
```

### Alert Event (To Be Built)
```python
{
    "alert_id": "uuid",
    "timestamp": "2025-12-05T10:30:45Z",
    "process_id": 1234,
    "process_name": "python",
    "severity": "HIGH",  # LOW, MED, HIGH, CRIT
    "confidence": 0.87,  # 0-1
    "reason_text": "Unusual parent process (bash spawned from cron)",
    "layer_scores": {
        "geometric": 0.95,
        "temporal": 0.23,
        "hero": 0.88,
    },
    "layer_reasons": [
        "Geometric: parent_pid not in allowed_parents[python]",
        "Temporal: no z-score spike detected",
        "Hero: IsolationForest anomaly_score=0.88",
    ]
}
```

---

## 🗂️ KEY FILES DIRECTORY

### Core Infrastructure
| File | Purpose |
|------|---------|
| `src/amoskys/eventbus/server.py` | EventBus gRPC server (port 50051) |
| `src/amoskys/eventbus/client.py` | gRPC client library |
| `src/amoskys/config.py` | Configuration loader + validation |
| `src/amoskys/db/schema.py` | SQLite schema definitions |

### Agents (Data Collection)
| Agent | File | Purpose | Port |
|-------|------|---------|------|
| **proc_agent** | `src/amoskys/agents/proc_agent/main.py` | Process metrics | - |
| **snmp_agent** | `src/amoskys/agents/snmp_agent/main.py` | Network metrics | 161 |
| **flowagent** | `src/amoskys/agents/flowagent/main.py` | Database persistence | - |
| **device_scanner** | `src/amoskys/agents/device_scanner/main.py` | Device discovery | - |
| **mac_telemetry** | `src/amoskys/agents/mac_telemetry/main.py` | macOS system info | - |

### Analysis (To Build)
| Module | File | Purpose |
|--------|------|---------|
| Feature Pipeline | `src/amoskys/feature_engineering/hero_process_snmp.py` | Normalize & aggregate metrics |
| Hero Reflex Engine | `src/amoskys/analysis/hero_reflex_engine.py` | ML inference (IsolationForest) |
| Geometric Analyzer | `src/amoskys/analysis/geometric_analyzer.py` | Rule-based graph analysis |
| Temporal Analyzer | `src/amoskys/analysis/temporal_analyzer.py` | Statistical spike detection |
| Fusion Engine | `src/amoskys/analysis/fusion_engine.py` | Combine 3 layer scores |

### Web / Dashboard
| File | Purpose |
|------|---------|
| `web/app/__init__.py` | Flask app factory |
| `web/app/templates/cortex.html` | Dashboard HTML (port 5000) |
| `web/app/api/alerts.py` | REST API for alerts (to build) |

### Tests
| File | Purpose | Status |
|------|---------|--------|
| `tests/component/test_bus_inflight_metric.py` | EventBus metric test | ✅ PASS |
| `tests/component/test_wal_grow_drain.py` | WAL persistence test | ✅ PASS |
| `tests/component/test_publish_paths.py` | Event publish test | ✅ PASS |
| `tests/component/test_retry_path.py` | Retry logic test | ✅ PASS |
| `tests/test_microprocessor_agent.py` | Old experimental tests | 🚫 ARCHIVED |

### Configuration
| File | Purpose |
|------|---------|
| `.env.template` | Environment variable template |
| `config/` | TLS certificates, SNMP config |
| `data/wal/flowagent.db` | SQLite database (500k+ records) |

### Models
| File | Purpose | Status |
|------|---------|--------|
| `models/hero_process_snmp_iforest.pkl` | Trained IsolationForest model | 🚫 NOT YET |

### Documentation
| File | Purpose |
|------|---------|
| `README.md` | Project overview |
| `MASTER_DEVELOPMENT_GUIDE.md` | Development setup + operations |
| `SOLO_DEVELOPER_ROADMAP.md` | 6-week implementation plan |
| `ISSUES_AND_GAPS_ASSESSMENT.md` | All issues + gaps (this session) |
| `IMPLEMENTATION_PROGRESS_TRACKER.md` | Real-time task progress (this session) |
| `QUICK_START_TODAY.md` | Step-by-step for today (this session) |

---

## 🔌 API ENDPOINTS (Current + Planned)

### Current (Working)
```
GET /                                      → Dashboard HTML
GET /api/agents                            → {"agents": [...]}
GET /api/metrics                           → {"metrics": {...}}
```

### Planned (To Build Phase 2.4)
```
GET /api/alerts/recent
  ?limit=50                                → Return up to 50 alerts
  ?severity=HIGH                           → Filter by severity
  ?since=2025-12-05T10:00:00Z             → Time range

GET /api/alerts/<alert_id>                 → Single alert details

POST /api/alerts/acknowledge/<alert_id>    → Mark as reviewed

GET /api/models/hero/status                → Model inference stats
```

---

## 🧠 THREE-LAYER BRAIN ARCHITECTURE

### Layer 1: Geometric Analyzer
**Input**: Process + SNMP features  
**Logic**: Rule-based, no ML  
**Output**: 0.0-1.0 score

```python
Rules:
- parent_pid in allowed_parents[process_name]? (0.5 weight)
- uid matches expected_users[process_name]? (0.3 weight)
- privilege escalation detected? (0.2 weight)

Score = 1.0 if ANY rule triggered else 0.0
```

### Layer 2: Temporal Analyzer
**Input**: Metric time series + 5-min rolling baseline  
**Logic**: Statistical (Z-score)  
**Output**: 0.0-1.0 score

```python
For each metric:
  z_score = (current_value - baseline_mean) / baseline_std
  flag = TRUE if |z_score| > 3.0

Score = 0.5 if single spike
Score = 1.0 if 2+ simultaneous spikes (cpu AND network)
```

### Layer 3: Hero Analyzer
**Input**: Engineered features  
**Logic**: IsolationForest ML model  
**Output**: 0.0-1.0 score

```python
model = IsolationForest(contamination=0.1)  # Expect 10% anomalies
features = [cpu%, memory%, network_bytes, age, is_new, ...]
score = model.score(features)  # -1.0 to 1.0, normalize to 0-1
```

### Fusion
```python
final_score = (0.2 * geo_score) + (0.3 * temp_score) + (0.5 * hero_score)

if final_score >= 0.7:
    severity = "CRIT"
elif final_score >= 0.5:
    severity = "HIGH"
elif final_score >= 0.3:
    severity = "MED"
else:
    severity = "LOW"
```

---

## 📊 DATABASE QUERIES

### Connect to SQLite
```bash
sqlite3 data/wal/flowagent.db

# Or with Python
import sqlite3
conn = sqlite3.connect('data/wal/flowagent.db')
cursor = conn.cursor()
```

### Useful Queries

**Get schema**:
```sql
.schema processes
.schema snmp
```

**Count records**:
```sql
SELECT COUNT(*) as count FROM processes;
SELECT COUNT(*) as count FROM snmp;
```

**Sample process record**:
```sql
SELECT * FROM processes LIMIT 1;
```

**Get top processes by CPU**:
```sql
SELECT pid, process_name, cpu_percent, memory_percent 
FROM processes 
ORDER BY cpu_percent DESC 
LIMIT 10;
```

**Get processes newer than 1 hour**:
```sql
SELECT pid, process_name, timestamp 
FROM processes 
WHERE datetime(timestamp) > datetime('now', '-1 hour')
LIMIT 20;
```

**Export to CSV for training**:
```sql
.mode csv
.headers on
.output /tmp/hero_training_data.csv
SELECT * FROM processes LIMIT 1000;
.quit
```

---

## 🚀 STARTUP & SHUTDOWN

### Start All Services
```bash
make dev-up  # Or: ./scripts/dev-run.sh (TBD)
```

Or manually:
```bash
# Terminal 1: EventBus
python -m src.amoskys.eventbus.server

# Terminal 2: Agents
python -m src.amoskys.agents.proc_agent.main
python -m src.amoskys.agents.snmp_agent.main
python -m src.amoskys.agents.flowagent.main
# etc...

# Terminal 3: Dashboard
python run_dashboard.py
```

### Check Service Health
```bash
# EventBus (gRPC on 50051)
lsof -i :50051

# Flask dashboard (HTTP on 5000)
curl http://localhost:5000

# Prometheus metrics
curl http://localhost:9000/metrics

# SNMP (UDP 161)
netstat -uln | grep 161
```

### Shutdown
```bash
make dev-down  # Or: pkill -f "python -m src.amoskys"
```

---

## 🧪 TESTING

### Run All Component Tests
```bash
cd /Users/athanneeru/Downloads/GitHub/Amoskys
pytest tests/component/ -v
```

### Run Single Test
```bash
pytest tests/component/test_bus_inflight_metric.py -v
```

### Run with Coverage
```bash
pytest tests/component/ --cov=src/amoskys --cov-report=html
```

### Create New Test
```python
# tests/component/test_my_feature.py
import pytest
from src.amoskys.analysis.geometric_analyzer import GeometricAnalyzer

def test_geometric_analyzer_detects_privilege_escalation():
    analyzer = GeometricAnalyzer()
    features = {
        "uid": 0,  # root
        "process_name": "bash",
        "parent_name": "cron",  # Unusual parent
    }
    score = analyzer.analyze(features)
    assert score > 0.5, "Should detect unusual parent"
```

---

## 🔐 SECURITY & CERTIFICATES

### TLS Setup
```bash
# Generate self-signed certs (already done)
ls -la certs/

# Check cert expiry
openssl x509 -in certs/server.crt -noout -dates
```

### mTLS Configuration
- **Server cert**: `certs/server.crt`
- **Server key**: `certs/server.key`
- **Client cert**: `certs/client.crt`
- **Client key**: `certs/client.key`
- **CA cert**: `certs/ca.crt`

Files in `src/amoskys/eventbus/server.py` lines 30-50.

---

## 📝 LOGGING

### Enable Debug Logging
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Check Log Files
```bash
tail -f logs/amoskys.log
```

### Log Locations
- **Terminal output**: When running services directly
- **File**: `logs/amoskys.log` (when using startup script)

---

## 🎯 QUICK COMMAND REFERENCE

```bash
# Clean build
rm -rf __pycache__ .pytest_cache .coverage && pytest tests/component/ -v

# Run specific test
pytest tests/component/test_bus_inflight_metric.py::test_inflight_metric_rises_then_falls -v

# Start one service
python -m src.amoskys.eventbus.server

# Check running services
ps aux | grep "python -m src.amoskys"

# Kill all services
pkill -f "python -m src.amoskys"

# Check ports
lsof -i :5000     # Flask
lsof -i :50051    # gRPC
lsof -i :9000     # Prometheus

# View database
sqlite3 data/wal/flowagent.db ".tables"

# Export data
sqlite3 data/wal/flowagent.db "SELECT * FROM processes LIMIT 1000;" > /tmp/data.csv

# Check git status
git status
git log --oneline -5
```

---

## 🆘 TROUBLESHOOTING QUICK LOOKUP

| Problem | Likely Cause | Solution |
|---------|-------------|----------|
| "Address already in use :5000" | Flask still running | `lsof -i :5000` then `kill PID` |
| "Connection refused :50051" | EventBus not running | Start EventBus first |
| "Prometheus metric collision" | Multiple imports | Check for delayed registration pattern |
| "Test timeout" | Subprocess stuck | Increase timeout from 2s to 5s |
| "Database locked" | SQLite WAL issue | Stop all services, delete `.db-wal` file |
| "ImportError: cannot import module" | PYTHONPATH wrong | `export PYTHONPATH=./src:$PYTHONPATH` |

---

## 📚 ADDITIONAL RESOURCES

- **SQLite WAL Docs**: `src/amoskys/db/schema.py`
- **gRPC Tutorial**: `src/amoskys/eventbus/server.py` (code example)
- **IsolationForest**: scikit-learn documentation
- **Flask API**: `web/app/__init__.py` (existing endpoints)
- **Prometheus**: Official client documentation

---

**Last Updated**: December 5, 2025  
**Next Review**: Weekly (update as new components are built)

---

## KEY TAKEAWAY

**AMOSKYS = Data Collection (6 agents) → Analysis (3-layer brain) → Alerts (REST API + Dashboard)**

Each phase builds the next layer. Keep this architecture in mind when implementing new features.

---

**END OF TECHNICAL REFERENCE**
