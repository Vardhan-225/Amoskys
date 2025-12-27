# AMOSKYS – Real-time Security Intelligence Platform

**Production-grade telemetry collection and threat detection for Mac/Linux environments**

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey.svg)]()

---

## Overview

AMOSKYS is a distributed security monitoring platform that provides real-time visibility into system processes, peripheral devices, and network activity. Built with a focus on **reliability, performance, and zero data loss**.

### Key Features

- **🔒 Zero-Trust Architecture** - mTLS encryption, Ed25519 signatures, immutable audit logs
- **📊 Real-Time Monitoring** - Process telemetry, USB device tracking, system health
- **💾 Reliable Data Pipeline** - Write-ahead logging ensures no event loss
- **🎯 Distributed Agents** - Lightweight collectors with intelligent retry logic
- **🌐 Modern Dashboard** - Real-time visualization with WebSocket updates
- **⚡ High Performance** - 700+ events/minute with < 100ms latency

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    AMOSKYS Platform                          │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────┐  ┌─────────────┐  ┌──────────────┐       │
│  │ Proc Agent  │  │Periph Agent │  │  SNMP Agent  │       │
│  │             │  │             │  │              │       │
│  │ • Processes │  │ • USB       │  │ • Network    │       │
│  │ • CPU/Mem   │  │ • Bluetooth │  │ • Devices    │       │
│  │ • Users     │  │ • Risk      │  │ • Metrics    │       │
│  └──────┬──────┘  └──────┬──────┘  └──────┬───────┘       │
│         │                 │                 │               │
│         └─────────────────┼─────────────────┘               │
│                           ▼                                 │
│                  ┌─────────────────┐                        │
│                  │   EventBus      │                        │
│                  │   (gRPC/mTLS)   │                        │
│                  └────────┬────────┘                        │
│                           │                                 │
│                           ▼                                 │
│                  ┌─────────────────┐                        │
│                  │  WAL Processor  │                        │
│                  │  (Queue Drain)  │                        │
│                  └────────┬────────┘                        │
│                           │                                 │
│                           ▼                                 │
│                  ┌─────────────────┐                        │
│                  │    Database     │                        │
│                  │  (SQLite + WAL) │                        │
│                  └────────┬────────┘                        │
│                           │                                 │
│                           ▼                                 │
│                  ┌─────────────────┐                        │
│                  │  Web Dashboard  │                        │
│                  │  (Flask + WS)   │                        │
│                  └─────────────────┘                        │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Prerequisites

- Python 3.8+ (3.11+ recommended)
- macOS 10.15+ or Linux (Ubuntu 20.04+, Debian 11+)
- 2GB RAM minimum
- 1GB disk space

### Installation

```bash
# Clone repository
git clone https://github.com/Vardhan-225/Amoskys.git
cd Amoskys

# Install dependencies (choose one based on your needs)
# Core only (EventBus + basic agents):
pip install -e .

# With web dashboard (recommended):
pip install -e .[web]

# Full development setup (all tools):
pip install -e .[all]

# Or install specific groups:
# pip install -e .[web,agents,dev]

# Start all services
./start_amoskys.sh
```

### Access Dashboard

```bash
# Open dashboard in browser
open http://localhost:5001/dashboard/cortex

# Or check system status
./quick_status.sh
```

---

## Components

### Core Infrastructure

#### EventBus
Central message broker handling all telemetry ingestion via gRPC with mTLS.
- **Location**: `src/amoskys/eventbus/server.py`
- **Port**: 50051 (gRPC)
- **Protocol**: gRPC with mTLS
- **Features**: Message routing, deduplication, backpressure control

#### WAL Processor
Asynchronous processor that drains the write-ahead log into permanent storage.
- **Location**: `src/amoskys/storage/wal_processor.py`
- **Throughput**: 100 events per 5 seconds
- **Reliability**: Zero data loss, transactional processing

#### Database
SQLite database with WAL mode for concurrent read/write access.
- **Location**: `data/telemetry.db`
- **Schema**: 7 tables with 18 optimized indexes
- **Size**: ~100MB per 200k events

### Agents

#### Process Agent
Monitors running processes, resource usage, and user activity.
- **Location**: `src/amoskys/agents/proc/proc_agent.py`
- **Frequency**: Every 30 seconds
- **Metrics**: PID, CPU%, Memory%, User type, Command line
- **Platform**: macOS, Linux

#### Peripheral Agent
Tracks USB, Bluetooth, and other connected devices with risk scoring.
- **Location**: `src/amoskys/agents/peripheral/peripheral_agent.py`
- **Frequency**: Every 30 seconds
- **Detection**: BadUSB, unauthorized devices, data exfiltration
- **Platform**: macOS (Linux support planned)

#### SNMP Agent (Optional)
Collects telemetry from network devices via SNMP.
- **Location**: `src/amoskys/agents/snmp/snmp_agent.py`
- **Protocol**: SNMPv2c/v3
- **Devices**: Routers, switches, IoT devices
- **Status**: Requires `pysnmp` library

### Dashboard

Web-based interface for real-time monitoring and analysis.
- **Location**: `web/app/`
- **Port**: 5001 (HTTP)
- **Tech Stack**: Flask + SocketIO + Chart.js
- **Pages**:
  - **Cortex** - Command center overview
  - **Agents** - Agent health and network status
  - **Processes** - Real-time process monitoring
  - **Peripherals** - Device connection tracking
  - **Database** - Data management and audit logs

---

## Configuration

### Environment Variables

```bash
# EventBus
export EVENTBUS_PORT=50051
export EVENTBUS_CERT_DIR=certs/

# Dashboard
export FLASK_PORT=5001
export FLASK_DEBUG=false

# Agents
export PROC_AGENT_INTERVAL=30
export PERIPHERAL_AGENT_INTERVAL=30
```

### Certificate Management

Certificates for mTLS are located in `certs/`:
- `ca.crt` - Certificate Authority (expires 2035)
- `server.crt` - Server certificate (expires 2027)
- `agent.crt` - Agent certificate
- `agent.key` - Agent private key

---

## Operations

### Service Management

```bash
# Start all services
./start_amoskys.sh

# Check status
./quick_status.sh

# Stop all services
./stop_amoskys.sh
```

### Health Monitoring

```bash
# View logs
tail -f logs/proc_agent.log
tail -f logs/eventbus.log
tail -f logs/dashboard.log

# Check database
sqlite3 data/telemetry.db "SELECT COUNT(*) FROM process_events;"

# API health check
curl http://localhost:5001/api/system/health
```

### Data Management

```bash
# Query recent events
sqlite3 data/telemetry.db "SELECT * FROM process_events ORDER BY timestamp_dt DESC LIMIT 10;"

# Export data
sqlite3 data/telemetry.db ".mode csv" ".output events.csv" "SELECT * FROM process_events;"

# Clear old data
sqlite3 data/telemetry.db "DELETE FROM process_events WHERE timestamp_dt < datetime('now', '-7 days');"
```

---

## Development

### Project Structure

```
Amoskys/
├── src/amoskys/
│   ├── agents/          # Data collection agents
│   │   ├── proc/        # Process monitoring
│   │   ├── peripheral/  # Device monitoring
│   │   └── snmp/        # Network monitoring
│   ├── eventbus/        # Message broker
│   ├── storage/         # WAL processor
│   ├── proto/           # Protocol buffers
│   ├── common/          # Shared utilities
│   └── config/          # Configuration
├── web/
│   ├── app/             # Flask application
│   │   ├── templates/   # HTML templates
│   │   ├── static/      # CSS/JS assets
│   │   ├── api/         # REST API endpoints
│   │   └── dashboard/   # Dashboard logic
│   └── wsgi.py          # WSGI entry point
├── data/
│   ├── telemetry.db     # Main database
│   └── wal/             # WAL queue
├── certs/               # mTLS certificates
├── logs/                # Application logs
└── tests/               # Unit & integration tests
```

### Running Tests

```bash
# Unit tests
pytest tests/unit/

# Integration tests
pytest tests/integration/

# Component tests
pytest tests/component/
```

### Adding a New Agent

1. Create agent directory: `src/amoskys/agents/myagent/`
2. Implement collection logic
3. Use UniversalEnvelope for publishing
4. Add agent to dashboard registry
5. Update `start_amoskys.sh`

---

## Security

### Threat Model

AMOSKYS is designed to detect:
- ✅ Unauthorized processes (privilege escalation)
- ✅ Suspicious peripheral devices (BadUSB, data exfiltration)
- ✅ Abnormal resource usage (cryptomining, DoS)
- ✅ Process injection and code execution
- ⏳ Network anomalies (C2 communication) - Planned
- ⏳ Lateral movement - Planned

### Security Best Practices

1. **Rotate Certificates**: Update mTLS certificates annually
2. **Secure Database**: Set proper file permissions on `data/telemetry.db`
3. **Audit Logs**: Review dashboard audit logs regularly
4. **Network Isolation**: Run EventBus on isolated network
5. **Update Dependencies**: Keep Python packages up-to-date

---

## Performance

### Benchmarks (macOS M2, 8GB RAM)

| Metric | Value |
|--------|-------|
| Events/second | 11-12 |
| EventBus CPU | < 0.1% |
| Agent CPU | < 0.5% each |
| Memory (total) | < 200MB |
| Disk I/O | 1-2 MB/s |
| Database size | 100MB / 200k events |
| Query latency (p99) | < 50ms |

---

## Roadmap

### Completed ✅
- Core infrastructure (EventBus, WAL, Database)
- Process and peripheral monitoring agents
- Real-time dashboard with 8 pages
- mTLS security with Ed25519 signing
- Mac/Linux compatibility

### In Progress ⏳
- Linux peripheral agent implementation
- Real-time alerting engine
- Data export functionality

### Planned 📋
- Flow Agent (network monitoring)
- Discovery Agent (network scanning)
- Machine learning anomaly detection
- OT device adapters (Modbus, OPC UA)
- Windows support

---

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Run linters
flake8 src/
black src/
mypy src/

# Run tests
pytest tests/
```

---

## Documentation

- **Architecture**: See [MAC_LINUX_ARCHITECTURE_ASSESSMENT.md](MAC_LINUX_ARCHITECTURE_ASSESSMENT.md)
- **Recent Fixes**: See [SNMP_AGENT_TODO_FIX_REPORT.md](SNMP_AGENT_TODO_FIX_REPORT.md)
- **Cleanup Plan**: See [CLEANUP_AND_AUDIT_PLAN.md](CLEANUP_AND_AUDIT_PLAN.md)
- **TODO Status**: See [TODO_STATUS_UPDATE.md](TODO_STATUS_UPDATE.md)

---

## License

MIT License - See [LICENSE](LICENSE) for details.

---

## Support

- **Issues**: https://github.com/your-org/Amoskys/issues
- **Documentation**: https://docs.amoskys.io
- **Email**: support@amoskys.io

---

**Built with 🧠 for security professionals by security professionals**
