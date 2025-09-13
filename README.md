# AMOSKYS – Neural Security Orchestration That Evolves 🧠🛡️

[![Amoskys CI](https://github.com/Vardhan-225/Amoskys/actions/workflows/ci.yml/badge.svg)](https://github.com/Vardhan-225/Amoskys/actions)
[![MIT License](https://img.shields.io/badge/license-MIT-green.svg)](./LICENSE)
[![Version](https://img.shields.io/badge/version-v1.0.0-blue.svg)](https://github.com/Vardhan-225/Amoskys/releases)
[![Powered by Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)

> **Amoskys** is a neuro-inspired security intelligence platform designed to detect, correlate, and adapt to cyber anomalies in real time. Built for resilience, engineered for evolution.

**Amoskys** is a security-focused infrastructure monitoring system designed to collect, process, and analyze security-relevant events from distributed environments in real-time.

## 🎯 Overview

Amoskys provides a foundation for building security detection and monitoring capabilities through:

- **Event Collection**: Distributed agents collect network flows, process events, and system activities
- **Secure Transport**: All communication secured with mTLS and Ed25519 cryptographic signatures
- **Reliable Processing**: Write-ahead logging (WAL) ensures no event loss during network failures
- **Backpressure Control**: Intelligent retry and rate limiting prevents system overload
- **Real-time Analysis**: Stream processing with configurable detection rules
- **Production Ready**: Comprehensive observability, metrics, and operational controls

## 🏗️ Architecture

```
┌─────────────────┐    mTLS/gRPC     ┌─────────────────┐
│   FlowAgent     │ ───────────────▶ │   EventBus      │
│                 │                  │                 │
│ • Flow Monitor  │                  │ • gRPC Server   │
│ • Process Mon   │                  │ • Validation    │
│ • WAL Storage   │                  │ • Persistence   │
│ • Retry Logic   │                  │ • Metrics       │
└─────────────────┘                  └─────────────────┘
         │                                     │
         │                                     ▼
         ▼                           ┌─────────────────┐
┌─────────────────┐                  │   Storage &     │
│   Local WAL     │                  │   Analysis      │
│                 │                  │                 │
│ • SQLite        │                  │ • Time Series   │
│ • Idempotency   │                  │ • Correlation   │
│ • Backlog Mgmt  │                  │ • Detection     │
└─────────────────┘                  └─────────────────┘
```

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- OpenSSL (for certificate generation)
- Docker (optional, for containerized deployment)

### 1. Setup Development Environment

```bash
# Clone the repository
git clone https://github.com/Vardhan-225/Amoskys.git
cd Amoskys

# Complete setup (creates venv, installs deps, generates certs, builds protos)
make setup
```

### 2. Generate TLS Certificates

```bash
# Generate CA and server/client certificates
make certs

# Generate Ed25519 signing keys
make ed25519
```

### 3. Start the EventBus Server

```bash
# Start EventBus server (default: localhost:50051)
make run-eventbus

# Or with custom configuration
./amoskys-eventbus --config config/amoskys.yaml --port 50052
```

### 4. Start FlowAgent

```bash
# In another terminal, start the flow monitoring agent
make run-agent

# Or run directly
./amoskys-agent --config config/amoskys.yaml
```

### 5. Verify System Health

```bash
# Check EventBus health
curl http://localhost:8080/healthz

# Check Agent readiness
curl http://localhost:8081/ready

# View metrics
curl http://localhost:9101/metrics
```

## 📊 Monitoring & Metrics

Amoskys provides observability through Prometheus metrics:

### EventBus Metrics
- `bus_publish_total` - Total publish requests
- `bus_inflight_requests` - Current in-flight requests
- `bus_retry_total` - Total retry responses
- `bus_publish_latency_ms` - Request latency distribution

### Agent Metrics
- `agent_publish_ok_total` - Successful publishes
- `agent_publish_retry_total` - Retried publishes
- `agent_wal_backlog_bytes` - WAL backlog size
- `agent_ready_state` - Agent readiness (0/1)

### Grafana Dashboard
```bash
# Start monitoring stack
make run-all

# Access Grafana: http://localhost:3000 (admin/admin)
# Prometheus: http://localhost:9090
```

## ⚙️ Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BUS_SERVER_PORT` | `50051` | EventBus gRPC server port |
| `BUS_OVERLOAD` | `false` | Enable overload simulation |
| `BUS_MAX_INFLIGHT` | `100` | Maximum concurrent requests |
| `IS_CERT_DIR` | `certs` | Certificate directory |
| `IS_WAL_PATH` | `data/wal/flowagent.db` | WAL database path |
| `LOGLEVEL` | `INFO` | Logging level |

### Configuration File

Create `config/amoskys.yaml`:

```yaml
eventbus:
  host: "0.0.0.0"
  port: 50051
  max_inflight: 100
  overload_mode: false

agent:
  bus_address: "localhost:50051"
  wal_path: "data/wal/flowagent.db"
  send_rate: 0  # unlimited

crypto:
  trust_map_path: "config/trust_map.yaml"
  ca_cert: "certs/ca.crt"
```

## 🧪 Testing

```bash
# Run all tests
make test

# Run specific test categories
python -m pytest tests/unit/
python -m pytest tests/component/
python -m pytest tests/integration/

# Run with coverage
python -m pytest --cov=src/amoskys tests/

# Validate configuration
python src/amoskys/config.py --validate
```

## 🏭 Production Deployment

### Docker Deployment

```bash
# Build containers
docker compose -f deploy/docker-compose.dev.yml build

# Start services
docker compose -f deploy/docker-compose.dev.yml up -d

# Check status
docker compose -f deploy/docker-compose.dev.yml ps
```

### Kubernetes Deployment

```bash
# Apply manifests
kubectl apply -f deploy/k8s/

# Check deployment
kubectl get pods -l app=amoskys
```

### Systemd Services

```bash
# Install services
sudo cp deploy/systemd/*.service /etc/systemd/system/
sudo systemctl daemon-reload

# Start services
sudo systemctl enable --now amoskys-eventbus
sudo systemctl enable --now amoskys-agent
```

## 🔒 Security Features

### Transport Security
- **mTLS**: Mutual TLS authentication for all gRPC communication
- **Certificate Validation**: Common Name (CN) allowlist for agent authentication
- **Ed25519 Signatures**: Cryptographic signatures on all message envelopes

### Data Protection
- **Idempotency**: Duplicate detection with LRU cache (5-minute TTL)
- **Size Limits**: 128KB payload cap with validation
- **Rate Limiting**: Configurable send rates and backpressure control

### Operational Security
- **Non-root Containers**: All containers run as unprivileged users
- **Read-only Filesystems**: Immutable container filesystems
- **Security Constraints**: AppArmor, seccomp, capability dropping

## 🛠️ Development

### Project Structure

```
Amoskys/
├── src/amoskys/                # Main source code
│   ├── config.py               # Configuration management
│   ├── agents/                 # Agent implementations
│   ├── eventbus/               # EventBus server
│   ├── common/                 # Shared utilities
│   └── proto/                  # Protocol definitions
├── config/                     # Configuration files
├── requirements/               # Python dependencies
│   ├── requirements.txt        # Base dependencies
│   ├── requirements-clean.txt  # Production essentials
│   ├── requirements-locked.txt # Locked versions
│   └── environment.yaml        # Conda environment
├── docs/                       # Comprehensive documentation
├── tests/                      # Test suite
├── deploy/                     # Deployment configurations
└── data/                       # Runtime data (gitignored)
```

### Adding New Agents

1. Create agent directory: `src/amoskys/agents/newagent/`
2. Implement agent interface in `main.py`
3. Add configuration to `config/amoskys.yaml`
4. Create tests in `tests/unit/test_newagent.py`
5. Update documentation

### Development Commands

```bash
make fmt                    # Format code with black
make lint                   # Lint with ruff and mypy
make proto                  # Regenerate protocol buffers
make clean                  # Clean generated files
make validate-config        # Validate configuration
```

## 📚 Documentation

### 🏗️ Core Architecture & Design
- [Architecture Guide](docs/ARCHITECTURE.md) - System design and components
- [Component Detail](docs/COMPONENT_DETAIL.md) - Comprehensive technical specifications
- [What We Built](docs/WHAT_WE_BUILT.md) - Evolution story and architectural decisions

### 🛡️ Security & Infrastructure
- [Security Model](docs/SECURITY_MODEL.md) - Defense-in-depth architecture with mTLS and Ed25519
- [Docker Usage](docs/DOCKER_USAGE.md) - Container architecture and deployment
- [Reproducibility](docs/REPRODUCIBILITY.md) - Environment locking and version management

### 🔧 Operations & Maintenance
- [Backpressure Runbook](docs/BACKPRESSURE_RUNBOOK.md) - Incident response and troubleshooting
- [Technical Assessment](docs/ASSESSMENT.md) - Quality evaluation and recommendations
- [Runbooks](docs/runbooks/) - Operational procedures

### 📈 Development & Planning
- [Phase 0 Review](docs/PHASE0_REVIEW.md) - Historical analysis and lessons learned
- [Phase 2 Plan](docs/PHASE_2_PLAN.md) - AI detection engine roadmap
- [Future Plan](docs/FUTURE_PLAN.md) - Strategic development timeline

### 🚀 Getting Started
- [Setup Guide](docs/SETUP.md) - Detailed installation instructions
- [Contributing Guide](docs/CONTRIBUTING.md) - Development guidelines

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make changes and add tests
4. Run the test suite: `make test`
5. Commit changes: `git commit -m 'Add amazing feature'`
6. Push to branch: `git push origin feature/amazing-feature`
7. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙋‍♂️ Support

For technical support and community engagement:

- **Issue Reports**: [GitHub Issues](https://github.com/Vardhan-225/Amoskys/issues)
- **Feature Requests**: [GitHub Issues](https://github.com/Vardhan-225/Amoskys/issues)
- **Community Discussion**: [GitHub Discussions](https://github.com/Vardhan-225/Amoskys/discussions)
- **Documentation**: [Project Documentation](https://github.com/Vardhan-225/Amoskys/tree/main/docs)

---

**Amoskys** - *Neural security orchestration that evolves* 🧠🛡️