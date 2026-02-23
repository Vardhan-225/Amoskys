# Amoskys Phase 1 Foundation Cleanup Plan

## 🎯 Objective
Transform Amoskys from a messy prototype into a clean, production-ready foundation for building advanced detection logic.

## 🧹 Current Structure Issues

### ❌ Problems to Fix
```
├── Amoskys/                    # DUPLICATE: Remove this entire directory
│   ├── agents/flowagent/           # Move to top-level agents/
│   ├── common/eventbus/            # Move to top-level src/
│   ├── proto_stubs/                # Move to top-level src/
│   └── requirements.txt            # Consolidate with root
├── common/eventbus/                # DUPLICATE: Remove after moving logic
├── agents/flowagent/               # OUTDATED: Replace with Amoskys version
└── Multiple .venv directories      # CONSOLIDATE: Keep only root .venv
```

## ✅ Target Clean Structure
```
Amoskys/
├── .env.example                    # Configuration template
├── .gitignore                      # Updated to ignore data/, logs/, .env
├── README.md                       # Complete documentation
├── Makefile                        # Updated for new structure
├── requirements.txt                # Consolidated dependencies
├── pyproject.toml                  # Python project configuration
├── 
├── src/                           # All source code
│   ├── infraspectre/
│   │   ├── __init__.py
│   │   ├── config.py              # Centralized configuration management
│   │   ├── agents/                # Agent implementations
│   │   │   ├── __init__.py
│   │   │   ├── base.py            # Base agent class
│   │   │   └── flowagent/         # Network flow monitoring agent
│   │   │       ├── __init__.py
│   │   │       ├── main.py        # Agent entry point
│   │   │       ├── collector.py   # Event collection logic
│   │   │       └── wal.py         # Write-ahead logging
│   │   ├── eventbus/              # Event bus server
│   │   │   ├── __init__.py
│   │   │   ├── server.py          # gRPC server implementation
│   │   │   └── handlers.py        # Request handlers
│   │   ├── common/                # Shared utilities
│   │   │   ├── __init__.py
│   │   │   ├── crypto/            # Cryptographic utilities
│   │   │   ├── metrics.py         # Prometheus metrics
│   │   │   └── utils.py           # Common utilities
│   │   └── proto/                 # Protocol definitions
│   │       ├── __init__.py
│   │       └── messaging_schema_pb2.py
│   │
├── config/                        # Configuration files
│   ├── trust_map.yaml            # Agent trust configuration
│   ├── server.yaml               # Server configuration
│   └── agents.yaml               # Agent configurations
├── 
├── data/                          # Runtime data (gitignored)
│   ├── wal/                      # Write-ahead logs
│   ├── storage/                  # Event storage
│   └── metrics/                  # Metrics data
├── 
├── docs/                         # Documentation
│   ├── ARCHITECTURE.md           # System architecture
│   ├── SETUP.md                  # Setup instructions
│   ├── CONTRIBUTING.md           # Development guidelines
│   └── runbooks/                 # Operational runbooks
├── 
├── tests/                        # Test suite
│   ├── unit/                     # Unit tests
│   ├── integration/              # Integration tests
│   └── fixtures/                 # Test fixtures
├── 
├── deploy/                       # Deployment configurations
│   ├── docker/                   # Docker configurations
│   ├── k8s/                      # Kubernetes manifests
│   └── systemd/                  # Systemd services
└── 
└── tools/                        # Development tools
    ├── loadgen.py               # Load generator
    └── scripts/                 # Utility scripts
```

## 🛠️ Execution Steps

### Step 1: Create New Clean Structure
1. Create new directory structure
2. Move and consolidate source files
3. Update import paths
4. Remove duplicate directories

### Step 2: Configuration Management
1. Create centralized config.py
2. Add .env support
3. Add configuration validation
4. Update all components to use new config

### Step 3: Documentation
1. Write comprehensive README.md
2. Create architecture documentation
3. Add setup guides
4. Document API and protocols

### Step 4: Testing Cleanup
1. Fix test isolation issues
2. Update test imports
3. Add test configuration
4. Ensure all tests pass

### Step 5: Build System
1. Update Makefile
2. Add pyproject.toml
3. Update Docker configurations
4. Test build process

## 🎯 Success Criteria
- [ ] Single source of truth for all code
- [ ] Centralized configuration management
- [ ] Clear documentation
- [ ] All tests passing
- [ ] Clean import paths
- [ ] Production-ready structure
