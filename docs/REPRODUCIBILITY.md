# InfraSpectre Reproducibility Guide

## Overview

This document ensures **100% reproducible builds** across all development and production environments. InfraSpectre uses multiple dependency management strategies to guarantee consistent behavior.

## Environment Locking Strategy

### Python Dependencies

#### Production Requirements
```bash
# Core production dependencies only
pip install -r requirements-clean.txt
```

#### Development Requirements (Full)
```bash
# Complete development environment
pip install -r requirements-production.txt
```

#### Locked Environment (Exact Versions)
```bash
# Exact version lock for CI/CD
pip install -r requirements-locked.txt
```

### Conda Environment
```bash
# Complete environment with system packages
conda env create -f environment.yaml
conda activate infraspectre
```

## Version Matrix

### Tested Configurations

| Component | Version | Compatibility |
|-----------|---------|---------------|
| Python | 3.11.x, 3.12.x | ✅ Tested |
| Python | 3.13.x | ✅ Tested (Current) |
| Python | 3.9.x, 3.10.x | ⚠️ May work |
| gRPC | 1.66.2+ | ✅ Required |
| Protocol Buffers | 5.28.2+ | ✅ Required |
| PyYAML | 6.0.2+ | ✅ Required |
| Cryptography | 43.0.1+ | ✅ Required |

### Operating System Support

| OS | Version | Status | Notes |
|----|---------|--------|-------|
| macOS | 12+ (Monterey) | ✅ Tested | Primary development |
| Ubuntu | 20.04, 22.04 | ✅ Tested | Production target |
| Ubuntu | 24.04 | ✅ Compatible | Latest LTS |
| RHEL/CentOS | 8, 9 | ✅ Compatible | Enterprise target |
| Windows | 10, 11 | ⚠️ Untested | Should work with WSL2 |

### Container Platforms

| Platform | Version | Status |
|----------|---------|--------|
| Docker | 20.10+ | ✅ Tested |
| Docker | 24.0+ | ✅ Recommended |
| Podman | 4.0+ | ✅ Compatible |
| Kubernetes | 1.24+ | ✅ Tested |

## Installation Methods

### Method 1: Automated Setup (Recommended)
```bash
git clone https://github.com/yourusername/InfraSpectre.git
cd InfraSpectre
make setup-dev
source .venv/bin/activate
make test  # Verify installation
```

### Method 2: Manual Installation
```bash
# 1. Create virtual environment
python3.11 -m venv .venv
source .venv/bin/activate

# 2. Install dependencies
pip install -r requirements-clean.txt

# 3. Generate protocol buffers
make proto

# 4. Create directories
make dirs

# 5. Verify installation
make test
```

### Method 3: Conda Environment
```bash
# 1. Create environment from lock file
conda env create -f environment.yaml

# 2. Activate environment
conda activate infraspectre

# 3. Generate protocol buffers
make proto

# 4. Run tests
make test
```

### Method 4: Docker (Production)
```bash
# Build containers
make build-docker

# Run with docker-compose
cd deploy && docker-compose -f docker-compose.dev.yml up
```

## Dependency Management

### Core Dependencies

#### gRPC Stack
```
grpcio==1.66.2          # High-performance RPC framework
grpcio-tools==1.66.2    # Protocol buffer compiler
protobuf==5.28.2        # Message serialization
```

#### Security Stack
```
cryptography==43.0.1    # TLS and certificate management
pycryptodome==3.21.0    # Ed25519 signing and verification
```

#### Configuration & Storage
```
PyYAML==6.0.2          # Configuration file parsing
prometheus_client==0.21.0  # Metrics collection
```

#### Testing & Quality
```
pytest==8.4.1          # Test framework
pytest-asyncio==0.24.0  # Async test support
black==24.10.0          # Code formatting
isort==5.13.2           # Import sorting
flake8==7.1.1           # Linting
mypy==1.13.0            # Type checking
```

### Dependency Pinning Strategy

1. **Major.Minor Pinning**: For core dependencies (gRPC, cryptography)
2. **Exact Pinning**: For CI/CD environments (requirements-locked.txt)
3. **Range Pinning**: For development tools (pytest, black)
4. **System Dependencies**: Documented in environment.yaml

## Environment Variables

### Required for Development
```bash
export PYTHONPATH=/path/to/InfraSpectre/src
export IS_CONFIG_PATH=/path/to/InfraSpectre/config/infraspectre.yaml
```

### Required for Testing
```bash
export IS_TEST_MODE=true
export BUS_SERVER_PORT=50052  # Avoid conflicts with development
```

### Optional for Production
```bash
export BUS_SERVER_PORT=50051      # EventBus port
export IS_WAL_PATH=/data/wal.db   # WAL database location
export IS_CERT_DIR=/certs         # Certificate directory
export IS_LOG_LEVEL=INFO          # Logging level
```

## Build Reproducibility

### Deterministic Builds
```bash
# Generate reproducible builds
make clean
make proto
make test

# Verify checksums
find src/ -name "*.py" -exec sha256sum {} \; > build_checksums.txt
```

### Protocol Buffer Reproducibility
```bash
# Protocol buffers are generated deterministically
make clean
make proto
git status  # Should show no changes if deterministic
```

### Docker Build Reproducibility
```bash
# Multi-stage builds with locked dependencies
docker build --no-cache -f deploy/Dockerfile.eventbus .
docker build --no-cache -f deploy/Dockerfile.agent .
```

## Version Verification

### Runtime Version Checks
```python
# Check component versions
import grpc
import google.protobuf
import cryptography
import yaml

print(f"gRPC: {grpc.__version__}")
print(f"Protobuf: {google.protobuf.__version__}")
print(f"Cryptography: {cryptography.__version__}")
```

### Environment Validation
```bash
# Automated environment check
make validate-environment

# Manual verification
python --version
pip list | grep -E "(grpc|protobuf|cryptography|yaml)"
```

## Troubleshooting

### Common Issues

#### 1. Protocol Buffer Version Mismatch
```bash
# Symptoms: Import errors with protobuf
# Solution: Reinstall with exact versions
pip uninstall protobuf grpcio grpcio-tools
pip install protobuf==5.28.2 grpcio==1.66.2 grpcio-tools==1.66.2
```

#### 2. Python Path Issues
```bash
# Symptoms: Module not found errors
# Solution: Set PYTHONPATH correctly
export PYTHONPATH=/path/to/InfraSpectre/src:$PYTHONPATH
```

#### 3. Certificate Generation Failures
```bash
# Symptoms: TLS handshake failures
# Solution: Regenerate certificates
make certs
```

#### 4. Port Conflicts
```bash
# Symptoms: Address already in use
# Solution: Use different ports for testing
export BUS_SERVER_PORT=50052
```

### Environment Reset
```bash
# Complete environment reset
make clean
rm -rf .venv
make setup-dev
source .venv/bin/activate
make test
```

## Continuous Integration

### GitHub Actions Example
```yaml
name: Test Suite
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: [3.11, 3.12, 3.13]
    steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-python@v4
      with:
        python-version: ${{ matrix.python-version }}
    - run: pip install -r requirements-locked.txt
    - run: make proto
    - run: make test
```

### Docker CI
```bash
# CI/CD with Docker
docker build -t infraspectre-test .
docker run --rm infraspectre-test make test
```

## Security Considerations

### Dependency Scanning
```bash
# Scan for known vulnerabilities
pip install safety
safety check -r requirements-production.txt

# Alternative: Use bandit for code analysis
pip install bandit
bandit -r src/
```

### Supply Chain Security
- All dependencies are pinned to specific versions
- Use `pip-audit` for vulnerability scanning
- Regular dependency updates with security patches
- Verify package signatures when possible

## Migration Guide

### From Development to Production
1. Use `requirements-clean.txt` instead of full development requirements
2. Set production environment variables
3. Generate production certificates
4. Use production configuration files

### Updating Dependencies
1. Update `requirements.txt` with new versions
2. Test with development environment
3. Update `requirements-locked.txt` after testing
4. Update `environment.yaml` for conda users
5. Test with CI/CD pipeline
6. Update this documentation

## Compliance & Auditing

### FIPS Compliance
- Use FIPS-validated cryptographic modules in production
- Ensure OpenSSL is FIPS-enabled
- Verify certificate generation uses approved algorithms

### Audit Trail
- All dependency versions are tracked in git
- Build logs contain dependency resolution
- Security scanning results are archived
- Environment configurations are version controlled

This reproducibility guide ensures that InfraSpectre can be built and deployed consistently across all environments, from development laptops to production clusters.
