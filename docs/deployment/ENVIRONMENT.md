# InfraSpectre Environment Setup Guide

**Purpose**: Lock Python + OS dependencies for consistent builds and reproducible development environments.

## 🎯 Environment Specifications

### System Requirements
- **OS**: macOS (tested on macOS 15+ / Big Sur+)
- **Python**: 3.13.5 (required)
- **Shell**: zsh (default on macOS)
- **Docker**: 24.0+ with Docker Compose V2
- **Make**: GNU Make 3.81+ (for build automation)

### Python Environment

#### Virtual Environment Setup
```bash
# Create virtual environment
python3 -m venv .venv

# Activate environment  
source .venv/bin/activate

# Verify Python version
python --version  # Should show Python 3.13.5
```

#### Dependencies (requirements.txt)
```txt
# Core dependencies
grpcio==1.59.0
grpcio-tools==1.59.0
protobuf==4.24.4
PyYAML==6.0.1

# Testing framework
pytest==7.4.3
pytest-asyncio==0.21.1

# Cryptography
cryptography==41.0.7
pynacl==1.5.0

# Database
sqlite3  # Built into Python

# Monitoring & Metrics
prometheus-client==0.18.0

# HTTP client for health checks
requests==2.31.0

# Development tools
black==23.9.1
ruff==0.1.3
mypy==1.6.1
```

#### Environment Variables
```bash
# InfraSpectre Configuration
export BUS_SERVER_PORT=50051
export BUS_OVERLOAD=false  
export BUS_MAX_INFLIGHT=100
export IS_CERT_DIR=certs
export IS_WAL_PATH=data/wal/flowagent.db
export LOGLEVEL=INFO

# Python path for development
export PYTHONPATH=src

# Docker configuration
export COMPOSE_PROJECT_NAME=infraspectre
```

## 📁 Directory Structure

```
InfraSpectre/
├── .venv/                      # Python virtual environment
├── src/                        # Source code
│   └── infraspectre/           # Main Python package
│       ├── agents/             # Agent implementations
│       │   └── flowagent/      # Flow monitoring agent
│       ├── eventbus/           # EventBus server
│       ├── common/             # Shared utilities
│       │   └── crypto/         # Cryptographic functions
│       ├── proto/              # Generated protocol buffers
│       └── config.py           # Configuration management
├── config/                     # Configuration files
│   ├── infraspectre.yaml      # Default configuration
│   └── trust_map.yaml         # Agent trust mapping
├── tests/                      # Test suites
│   ├── unit/                   # Unit tests
│   ├── component/              # Component integration tests
│   ├── integration/            # Full integration tests
│   └── golden/                 # Golden file tests
├── docs/                       # Documentation
├── deploy/                     # Deployment configurations
│   ├── docker-compose.dev.yml # Development environment
│   ├── k8s/                    # Kubernetes manifests
│   └── systemd/                # SystemD service files
├── proto/                      # Protocol buffer definitions
├── data/                       # Runtime data directories
│   ├── wal/                    # Write-ahead log storage
│   ├── storage/                # Event storage
│   └── metrics/                # Metrics data
├── certs/                      # TLS certificates
├── tools/                      # Development tools
├── scripts/                    # Setup and utility scripts
├── infraspectre-eventbus      # EventBus entry point
├── infraspectre-agent         # Agent entry point
├── Makefile                    # Build automation
├── requirements.txt            # Python dependencies
└── README.md                   # Project overview
```

## 🔧 Setup Instructions

### 1. Repository Setup
```bash
# Clone repository
git clone <repository-url>
cd InfraSpectre

# Set up development environment
make setup

# This runs:
# - make venv          # Create virtual environment
# - make install-deps  # Install Python dependencies  
# - make proto         # Generate protocol buffers
# - make dirs          # Create required directories
# - make certs         # Generate TLS certificates
```

### 2. Verify Installation
```bash
# Run all tests
make test

# Check configuration
make validate-config

# Test entry points
./infraspectre-eventbus --help
./infraspectre-agent --help
```

### 3. Development Workflow
```bash
# Start EventBus (Terminal 1)
make run-eventbus

# Start Agent (Terminal 2)  
make run-agent

# Run health checks
make curl-health
make curl-metrics

# Run specific test suites
make test-unit          # Unit tests only
make test-component     # Component tests only
```

## 🐳 Docker Environment

### Docker Requirements
```dockerfile
# Minimum Docker version
Docker version 24.0.0+
Docker Compose version v2.20.0+
```

### Container Environment
```bash
# Start all services
make run-all

# This starts:
# - EventBus server (port 50051)
# - Agent (port 8081)  
# - Prometheus (port 9090)
# - Grafana (port 3000)

# Stop all services
make stop-all
```

### Development Container
```bash
# Build development images
make build-docker

# Run with custom configuration
docker compose -f deploy/docker-compose.dev.yml up -d
```

## 🔍 Verification Checklist

### ✅ Environment Validation
Run these commands to verify your environment:

```bash
# 1. Python version
python --version
# Expected: Python 3.13.5

# 2. Virtual environment active
echo $VIRTUAL_ENV
# Expected: /path/to/InfraSpectre/.venv

# 3. Dependencies installed
pip list | grep grpcio
# Expected: grpcio and grpcio-tools listed

# 4. Protocol buffers generated
ls src/amoskys/proto/
# Expected: messaging_schema_pb2.py, messaging_schema_pb2_grpc.py

# 5. Configuration loading
python -c "from infraspectre.config import get_config; print('✅ Config loads')"
# Expected: ✅ Config loads

# 6. TLS certificates present
ls certs/
# Expected: ca.crt, server.crt, server.key, agent.crt, agent.key

# 7. Test suite passing
make test
# Expected: All tests passing
```

## 🔧 Troubleshooting

### Common Issues

#### 1. Python Version Mismatch
```bash
# Issue: Wrong Python version
# Solution: Install Python 3.13.5
brew install python@3.13
export PATH="/opt/homebrew/bin:$PATH"
```

#### 2. Protocol Buffer Import Errors
```bash
# Issue: Cannot import messaging_schema_pb2
# Solution: Regenerate protocol buffers
make proto
```

#### 3. Port Conflicts
```bash
# Issue: Address already in use
# Solution: Check for running processes
lsof -ti:50051 | xargs kill -9  # Kill processes on port 50051
```

#### 4. Certificate Issues
```bash
# Issue: TLS certificate errors
# Solution: Regenerate certificates
make certs
```

#### 5. Virtual Environment Issues
```bash
# Issue: Import errors or package not found
# Solution: Recreate virtual environment
rm -rf .venv
make venv
make install-deps
```

## 📊 Environment Health Check

### Quick Health Check Script
```bash
#!/bin/bash
# File: scripts/health_check.sh

echo "🔍 InfraSpectre Environment Health Check"
echo "========================================"

# Check Python version
python_version=$(python --version 2>&1)
if [[ $python_version == *"3.13.5"* ]]; then
    echo "✅ Python version: $python_version"
else
    echo "❌ Python version: $python_version (expected 3.13.5)"
fi

# Check virtual environment
if [[ -n "$VIRTUAL_ENV" ]]; then
    echo "✅ Virtual environment: Active"
else
    echo "❌ Virtual environment: Not active"
fi

# Check protocol buffers
if [[ -f "src/amoskys/proto/messaging_schema_pb2.py" ]]; then
    echo "✅ Protocol buffers: Generated"
else
    echo "❌ Protocol buffers: Missing (run 'make proto')"
fi

# Check certificates
if [[ -f "certs/ca.crt" && -f "certs/server.crt" ]]; then
    echo "✅ TLS certificates: Present"
else
    echo "❌ TLS certificates: Missing (run 'make certs')"
fi

# Test configuration
if python -c "from infraspectre.config import get_config; get_config()" 2>/dev/null; then
    echo "✅ Configuration: Loading correctly"
else
    echo "❌ Configuration: Failed to load"
fi

echo "========================================"
echo "🎯 Run 'make test' to verify full functionality"
```

## 🚀 Ready for Development

Once this environment is set up, you'll have:

- ✅ **Consistent Python environment** across all developers
- ✅ **Reproducible builds** with locked dependencies
- ✅ **Professional development workflow** with Make targets
- ✅ **Docker containerization** for deployment testing
- ✅ **Comprehensive validation** with health checks

**Next Steps**: Run `make setup && make test` to verify everything works, then proceed to development or deployment.

---
*Environment setup validated for InfraSpectre Phase 1 completion*
