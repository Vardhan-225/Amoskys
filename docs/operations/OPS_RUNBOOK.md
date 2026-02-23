# AMOSKYS Operations Runbook
## Version 1.0 | December 2025

This runbook provides operational guidance for managing AMOSKYS deployments on VPS infrastructure.

---

## Table of Contents
1. [Quick Reference](#quick-reference)
2. [VPS Access](#vps-access)
3. [Directory Structure](#directory-structure)
4. [Starting Services](#starting-services)
5. [Stopping Services](#stopping-services)
6. [Viewing Logs](#viewing-logs)
7. [Health Checks](#health-checks)
8. [Troubleshooting](#troubleshooting)
9. [Deployment](#deployment)

---

## Quick Reference

| Action | Command |
|--------|---------|
| SSH to VPS | `ssh -i ~/.ssh/amoskys_key $EC2_USER@$EC2_HOST` |
| Start all services | `cd /opt/amoskys && ./start_amoskys.sh` |
| Stop all services | `cd /opt/amoskys && ./stop_amoskys.sh` |
| Check status | `cd /opt/amoskys && ./quick_status.sh` |
| View logs | `tail -f /opt/amoskys/logs/*.log` |
| Health check | `curl http://localhost:5001/api/v1/health/ping` |

---

## VPS Access

### SSH Connection
```bash
# Set environment variables (or add to ~/.bashrc)
export EC2_USER="your-username"
export EC2_HOST="your-vps-ip-or-hostname"

# Connect to VPS
ssh -i ~/.ssh/amoskys_key $EC2_USER@$EC2_HOST

# Or with password
ssh $EC2_USER@$EC2_HOST
```

### Required Ports
| Port | Service | Protocol |
|------|---------|----------|
| 22 | SSH | TCP |
| 80 | HTTP (redirect) | TCP |
| 443 | HTTPS (dashboard) | TCP |
| 5001 | Flask dev server | TCP |
| 50051 | EventBus gRPC | TCP |

---

## Directory Structure

```
/opt/amoskys/
├── src/                    # Source code
│   └── amoskys/
│       ├── agents/         # All agent implementations
│       ├── intel/          # Correlation rules & fusion engine
│       ├── eventbus/       # gRPC EventBus server
│       └── storage/        # WAL and database layer
├── web/                    # Flask web application
│   └── app/
│       ├── api/            # REST API endpoints
│       ├── dashboard/      # Dashboard logic
│       └── templates/      # HTML templates
├── data/                   # Runtime data
│   ├── telemetry.db        # Event database
│   ├── intel/              # Fusion engine database
│   └── wal/                # Write-ahead logs
├── logs/                   # Log files
├── certs/                  # TLS certificates
├── config/                 # Configuration files
├── venv/                   # Python virtual environment
├── start_amoskys.sh        # Start all services
├── stop_amoskys.sh         # Stop all services
└── quick_status.sh         # Check service status
```

---

## Starting Services

### Start All Services
```bash
cd /opt/amoskys
./start_amoskys.sh
```

This script starts:
1. EventBus (gRPC server on port 50051)
2. Flask dashboard (port 5001)
3. Core agents (proc_agent, peripheral_agent, etc.)

### Start Individual Components
```bash
# Activate virtual environment
cd /opt/amoskys
source venv/bin/activate

# Start EventBus
python -m amoskys.eventbus.server &

# Start Flask dashboard
cd web && gunicorn --bind 0.0.0.0:5001 wsgi:app &

# Start specific agent (new unified CLI)
python -m amoskys.agents.proc &
# Or with options:
python -m amoskys.agents.proc --interval 30 --log-level INFO &
```

---

## Stopping Services

### Stop All Services
```bash
cd /opt/amoskys
./stop_amoskys.sh
```

### Force Stop (if graceful fails)
```bash
# Kill by process name
pkill -f "amoskys"
pkill -f "gunicorn"

# Kill by PID file
kill $(cat /opt/amoskys/logs/flask.pid) 2>/dev/null
```

---

## Viewing Logs

### All Logs
```bash
# Tail all logs
tail -f /opt/amoskys/logs/*.log

# Specific log
tail -f /opt/amoskys/logs/eventbus.log
tail -f /opt/amoskys/logs/flask.log
tail -f /opt/amoskys/logs/proc_agent.log
```

### Log Locations
| Component | Log File |
|-----------|----------|
| EventBus | `logs/eventbus.log` |
| Dashboard | `logs/flask.log` |
| Process Agent | `logs/proc_agent.log` |
| Peripheral Agent | `logs/peripheral_agent.log` |
| Fusion Engine | `logs/fusion_engine.log` |

### Search Logs
```bash
# Find errors
grep -i error /opt/amoskys/logs/*.log

# Find specific agent issues
grep -i "agent" /opt/amoskys/logs/*.log | grep -i error
```

---

## Health Checks

### API Health Check
```bash
# Simple ping (load balancer health check)
curl http://localhost:5001/api/v1/health/ping

# Full system health
curl http://localhost:5001/api/v1/health/system | jq

# Expected response
# {
#   "status": "success",
#   "health_score": 70,
#   "threat_level": "BENIGN",
#   "agents": { "proc": "running", ... },
#   "infrastructure": { "eventbus": "running", ... }
# }
```

### Quick Status Script
```bash
cd /opt/amoskys
./quick_status.sh

# Output shows:
# - Running processes
# - Port status
# - Agent health
# - Recent errors
```

### Check Dashboard is Live
```bash
# Local check
curl -I http://localhost:5001/

# Expected: HTTP/1.1 200 OK

# From external
curl -I https://your-domain.com/
```

---

## Troubleshooting

### Common Issues

#### 1. Dashboard not loading
```bash
# Check if Flask is running
ps aux | grep gunicorn

# Check port
netstat -tlnp | grep 5001

# Start Flask
cd /opt/amoskys/web
source ../venv/bin/activate
gunicorn --bind 0.0.0.0:5001 wsgi:app
```

#### 2. EventBus connection refused
```bash
# Check EventBus status
ps aux | grep eventbus

# Check port 50051
netstat -tlnp | grep 50051

# Start EventBus
cd /opt/amoskys
source venv/bin/activate
python -m amoskys.eventbus.server
```

#### 3. No data in dashboard
```bash
# Check if agents are running
./quick_status.sh

# Check database exists
ls -la /opt/amoskys/data/

# Check for errors
grep -i error /opt/amoskys/logs/*.log | tail -20
```

#### 4. High CPU/Memory
```bash
# Check resource usage
top -c | grep -E "python|gunicorn"

# Check agent resource limits
cat /opt/amoskys/config/amoskys.yaml | grep -A5 "limits"
```

### Emergency Recovery
```bash
# 1. Stop everything
./stop_amoskys.sh
pkill -9 -f amoskys

# 2. Clear stale files
rm -f /opt/amoskys/logs/*.pid
rm -f /opt/amoskys/data/wal/*.lock

# 3. Restart
./start_amoskys.sh

# 4. Verify
./quick_status.sh
curl http://localhost:5001/api/v1/health/ping
```

---

## Deployment

### Manual Deployment
```bash
# SSH to VPS
ssh $EC2_USER@$EC2_HOST

# Navigate to project
cd /opt/amoskys

# Pull latest code
git fetch origin
git checkout main
git pull

# Update dependencies
source venv/bin/activate
pip install -e ".[all]"

# Restart services
./stop_amoskys.sh
./start_amoskys.sh

# Verify
./quick_status.sh
curl http://localhost:5001/api/v1/health/system
```

### Automated Deployment (CI/CD)
Deployments to `main` branch trigger GitHub Actions workflow:
1. Runs tests
2. SSH to VPS
3. Pulls latest code
4. Installs dependencies
5. Restarts services
6. Runs health check

See `.github/workflows/ci-cd.yml` for details.

### Post-Deployment Verification
```bash
# Check last deployment
cat /opt/amoskys/.last_deploy

# Run health check
curl -s http://localhost:5001/api/v1/health/system | jq '.health_score'

# Check all agents online
curl -s http://localhost:5001/api/v1/health/system | jq '.agents_summary'
```

---

## Contact

- **Repository**: https://github.com/your-org/amoskys
- **Documentation**: `/opt/amoskys/docs/`
- **Issues**: GitHub Issues

---

*Last updated: December 2025*
