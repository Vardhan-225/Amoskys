# AMOSKYS Scripts Reference

## Automation Scripts (`scripts/automation/`)

### Core Development Scripts
- **`setup_environment_pro.py`** - Professional environment setup with dependency resolution
- **`setup_dev_env.py`** - Development environment verification and path setup  
- **`assess_repository.py`** - Comprehensive repository health assessment
- **`generate_ci_cd.py`** - CI/CD pipeline generation for GitHub Actions

### Usage Examples
```bash
# Professional environment setup
python scripts/automation/setup_environment_pro.py

# Development environment verification  
python scripts/automation/setup_dev_env.py

# Repository assessment
python scripts/automation/assess_repository.py

# Generate CI/CD pipeline
python scripts/automation/generate_ci_cd.py
```

## Demo Scripts (`scripts/demo/`)

### Phase 2.4 Development Scripts
- **`demo_phase24.py`** - Phase 2.4 feature demonstrations
- **`run_phase24.py`** - Phase 2.4 execution runner
- **`test_phase24.py`** - Phase 2.4 testing suite

### Usage Examples
```bash
# Run Phase 2.4 demo
python scripts/demo/demo_phase24.py

# Execute Phase 2.4 tasks
python scripts/demo/run_phase24.py

# Test Phase 2.4 functionality
python scripts/demo/test_phase24.py
```

## Makefile Integration

All scripts are integrated into the Makefile for easy execution:

```bash
# Environment management
make env-setup          # Uses scripts/automation/setup_environment_pro.py
make dev-setup          # Uses scripts/automation/setup_dev_env.py
make dev-verify         # Development verification
make dev-clean          # Clean development artifacts

# Assessment and health checks
make assess             # Uses scripts/automation/assess_repository.py
make health-check       # System health verification

# Standard operations
make check              # Full test suite
make clean              # Clean all artifacts
```

## Quick Start

For new developers:
```bash
# 1. Professional environment setup
make env-setup

# 2. Development environment setup
make dev-setup

# 3. Verify everything works
make dev-verify

# 4. Run tests
make check

# 5. Assess repository health
make assess
```
