# 🚀 AMOSKYS Operations Quick Guide

## Start Here

```bash
# 1. Activate environment
source .venv/bin/activate

# 2. Verify setup
make validate

# 3. Start dashboard
make run-dashboard
```

Then open: **http://localhost:5001/dashboard/agents**

---

## Common Tasks

### Start All Services
```bash
# Method 1: Dashboard (recommended - includes EventBus)
make run-dashboard

# Method 2: Individual services
make run-eventbus      # Terminal 1
make run-agent         # Terminal 2
make run-snmp-agent    # Terminal 3 (optional)
```

### View Agent Status
```bash
# In dashboard: http://localhost:5001/dashboard/agents
# Or via API:
curl http://localhost:5001/dashboard/api/agents/status
```

### Start Specific Agent
```bash
# Via Dashboard UI: Click "Start" button
# Via API:
curl -X POST http://localhost:5001/dashboard/api/agents/{agent_id}/start
```

### Stop All Services
```bash
make stop-dashboard
pkill -f "python.*eventbus"
pkill -f "python.*flowagent"
```

### View Logs
```bash
make logs-dashboard    # Flask dashboard logs
make logs-agent        # FlowAgent logs
make logs-eventbus     # EventBus logs
tail -f logs/flask.log
```

---

## Environment Setup

### First Time Setup
```bash
# Complete setup (venv, deps, certs)
make setup

# Or step-by-step:
make venv              # Create venv
make install-deps      # Install dependencies
make certs             # Generate TLS certificates
make validate          # Verify installation
```

### Activate Environment
```bash
source .venv/bin/activate
# Or use:
make check-env
make shell
```

---

## Testing

### Run All Tests
```bash
make test              # All tests (32 passing)
```

### Run Specific Tests
```bash
python -m pytest tests/unit/ -v          # Unit tests
python -m pytest tests/component/ -v     # Component tests
python -m pytest tests/api/ -v           # API tests
```

### Test With Coverage
```bash
make test-coverage
```

---

## Troubleshooting

### Dashboard Won't Start
```bash
# Check if port 5001 is in use
lsof -i :5001

# Kill existing process
pkill -f "python.*dashboard"

# Try again
make run-dashboard
```

### EventBus Won't Start
```bash
# Check if port 50051 is in use
lsof -i :50051

# Check logs
make logs-eventbus

# Verify certificates
ls -la certs/
```

### Agent Won't Connect
```bash
# Check EventBus is running
curl http://localhost:5001/dashboard/api/agents/status

# Check certificates exist
ls -la certs/client.* certs/ca.crt

# View agent logs
make logs-agent
```

### Port Already in Use
```bash
# Find and kill process using port
lsof -i :{PORT}
kill -9 {PID}

# Or use make
make stop-all
```

---

## Configuration

### Environment Variables
```bash
export FLASK_DEBUG=1           # Enable debug mode
export SECRET_KEY="your-key"   # Set secret key
export BUS_SERVER_PORT=50051   # EventBus port
export BUS_OVERLOAD=false      # Disable overload mode
```

### Configuration Files
```
config/amoskys.yaml            # Main config
config/snmp_agent.yaml         # SNMP agent config
config/trust_map.yaml          # Certificate trust map
config/microprocessor_agent.yaml # Microprocessor config
```

---

## Production Deployment

### Docker
```bash
# Build images
make build-docker

# Start with Docker Compose
docker-compose -f deploy/docker-compose.dev.yml up -d

# Check status
docker-compose -f deploy/docker-compose.dev.yml ps
```

### Systemd
```bash
# Install services
sudo cp deploy/systemd/*.service /etc/systemd/system/
sudo systemctl daemon-reload

# Start services
sudo systemctl enable amoskys-eventbus
sudo systemctl enable amoskys-agent
sudo systemctl start amoskys-eventbus
sudo systemctl start amoskys-agent

# Check status
systemctl status amoskys-*
```

### Health Checks
```bash
# Check EventBus
curl -k https://localhost:50051 --cacert certs/ca.crt

# Check FlowAgent
curl http://localhost:8081/healthz

# Check metrics
curl http://localhost:9101/metrics
```

---

## Code Quality

### Format Code
```bash
make fmt               # Format with black
make format            # Format + import sort
```

### Lint Code
```bash
make lint              # Run linters
make lint-strict       # Strict linting
```

### Security Scan
```bash
make security-scan     # Run security checks
```

### Generate Docs
```bash
make docs              # Generate documentation
```

---

## Useful Shortcuts

| Command | Purpose |
|---------|---------|
| `make help` | Show all available commands |
| `make status` | Show service status |
| `make health-check` | Quick health check |
| `make validate-config` | Validate YAML config |
| `make dump-config` | Show current config |
| `make dirs` | Create required directories |
| `make clean` | Clean artifacts |
| `make dev-reset` | Reset to clean state |

---

## Performance Tips

### For Development
- Use `make run-dashboard` for integrated experience
- Metrics update every 5 seconds (adjust if needed)
- Terminal size: 200+ columns recommended

### For Production
- Set `SECRET_KEY` environment variable
- Use Docker for isolation
- Enable HTTPS reverse proxy (Nginx/HAProxy)
- Monitor metrics with Prometheus
- Log to centralized system (ELK/Splunk)

---

## Getting Help

### Check Docs
```bash
ls docs/                       # Architecture docs
cat README.md                  # Project overview
cat STABILITY_REPORT_DECEMBER_2025.md  # Latest status
```

### View Logs
```bash
make logs-dashboard
make logs-agent
make logs-eventbus
```

### Run Diagnostics
```bash
make validate              # Full validation
make check-env             # Environment check
make health-check          # Service health
```

---

## Key URLs

| Service | URL | Notes |
|---------|-----|-------|
| Dashboard | http://localhost:5001/dashboard/agents | Agent control panel |
| API Status | http://localhost:5001/dashboard/api/agents/status | JSON API |
| EventBus | localhost:50051 | gRPC + mTLS |
| Metrics | http://localhost:9101/metrics | Prometheus format |
| Health | http://localhost:8081/healthz | FlowAgent health |

---

## Quick Reference

```bash
# One-liner to start everything
source .venv/bin/activate && make run-dashboard

# One-liner to test
source .venv/bin/activate && make test

# One-liner to clean
make clean && make dev-reset && make setup
```

---

**Last Updated**: December 5, 2025  
**Status**: ✅ Production Ready  
**For Issues**: Check logs or run `make validate`
