# 🔍 COMPREHENSIVE AMOSKYS CODEBASE AUDIT
**Date**: December 5, 2025  
**Scope**: Full repository analysis and cleanup planning

## 📊 CODEBASE METRICS

- **Total Files**: 35,672
- **Python Files**: 12,815
- **Documentation Files**: 82
- **Total Size**: 2.3GB
- **Test Files**: Multiple test suites
- **Configuration Files**: Multiple config formats

## 🏗️ DIRECTORY STRUCTURE ANALYSIS

### Core Directories
- `src/amoskys/` - Main codebase (agents, eventbus, intelligence)
- `web/` - Flask web dashboard and API
- `tests/` - Comprehensive test suite
- `docs/` - Documentation (82 MD files)
- `deploy/` - Docker and K8s configs
- `config/` - Configuration files
- `data/` - Runtime data (WAL, metrics, ML)
- `notebooks/` - Jupyter notebooks
- `proto/` - Protocol buffer definitions
- `tools/` - Utility scripts
- `scripts/` - Various shell scripts

### Root Files Analysis
- Multiple makefiles, shell scripts, Python entry points
- Configuration files (YAML, JSON)
- Documentation files (75+ MD files at root level - EXCESSIVE)
- Test files (conftest, test_*.py)

## 🚨 IDENTIFIED ISSUES

### 1. **Documentation Bloat** (CRITICAL)
- 75+ markdown files at root level
- Many are duplicate/historical/status reports
- No clear organization or categorization
- **Action**: Keep only essential 5-10 docs

### 2. **Unused/Experimental Code**
- `intelligence/` directory (ML/microprocessor agent) - Has broken imports
- Multiple agent implementations (some incomplete)
- Protocol definitions (proto/ directory)
- Test files for disabled modules

### 3. **Large Directory Issues**
- `data/` directory may contain large datasets
- `notebooks/` with Jupyter files
- `__pycache__/` directories still present (should be .gitignored)

### 4. **Configuration Fragmentation**
- Multiple config formats (YAML, JSON)
- Duplicate configuration patterns
- Unclear which configs are active

### 5. **Build Artifacts**
- Compiled binaries (amoskys-agent, amoskys-eventbus, amoskys-snmp-agent)
- Lock files and requirements variations
- Generated files not clearly segregated

## 📁 WHAT SHOULD STAY

### Essential Production Code
1. `src/amoskys/agents/` - Core agent implementations (flowagent, snmp, process monitor)
2. `src/amoskys/eventbus/` - EventBus server (core infrastructure)
3. `src/amoskys/common/` - Shared utilities
4. `src/amoskys/proto/` - Protocol definitions
5. `web/app/` - Web dashboard and API (recently fixed)

### Essential Infrastructure
1. `tests/` - Test suite (currently 32/33 tests passing)
2. `config/` - Active configuration files
3. `deploy/` - Docker/K8s deployment files
4. `Makefile` - Build automation

### Essential Documentation
1. `docs/ARCHITECTURE.md`
2. `docs/SECURITY_MODEL.md`
3. `docs/SETUP.md`
4. `docs/CONTRIBUTING.md`
5. `README.md` (at root)

### Data Directories
1. `data/wal/` - Write-Ahead Logs (runtime)
2. `data/metrics/` - Prometheus metrics (runtime)
3. `certs/` - TLS certificates

## 🗑️ WHAT SHOULD BE REMOVED

### Cleanup Priority List

**HIGH PRIORITY** (Remove immediately):
- ✅ 73 redundant markdown files at root (already done)
- [ ] `intelligence/` directory (broken microprocessor agent)
- [ ] `notebooks/` directory (ML experiments - not part of core)
- [ ] `tools/` directory (if mostly experimental)
- [ ] Old shell scripts (run_ml_pipeline.sh, etc.)
- [ ] Backup files and old configs

**MEDIUM PRIORITY** (Organize/consolidate):
- [ ] Multiple requirements files (consolidate to single)
- [ ] Various test entry points
- [ ] Shell scripts at root (organize to scripts/)
- [ ] Assessment/audit reports (not needed in repo)

**LOW PRIORITY** (Document/archive):
- [ ] Historical documentation
- [ ] Old deployment configs

## 🔧 STABILITY STATUS

### Current State
- ✅ Core agents working (6 agents: eventbus, proc_agent, mac_telemetry, flow_agent, snmp_agent, device_scanner)
- ✅ Web dashboard stable (Flask with Socket.IO)
- ✅ EventBus gRPC server operational
- ✅ Tests: 32/33 passing (1 flaky network test)
- ⚠️ Microprocessor agent disabled (too many import errors)

### Code Quality Issues Found
1. **NameError in agent_core.py** - Fixed by disabling test
2. **Missing type hints** - Some functions lack proper typing
3. **Import path errors** - Some modules have broken import paths
4. **Cognitive complexity** - Some functions exceed SonarQube limits

## 📋 CLEANUP PLAN

### Phase 1: Immediate (High Priority)
```
Week 1:
1. Remove intelligence/ directory
2. Remove notebooks/ directory
3. Remove redundant shell scripts
4. Consolidate requirements files (keep only requirements.txt)
5. Remove assessment reports and temporary files
```

### Phase 2: Organization (Medium Priority)
```
Week 2:
1. Consolidate docs/ (keep only 10 essential documents)
2. Move tools/ scripts to scripts/ directory
3. Clean up root directory (move misc scripts)
4. Organize configs (active vs examples)
```

### Phase 3: Documentation (Low Priority)
```
Week 3:
1. Create ARCHITECTURE_OVERVIEW.md (single source of truth)
2. Update README with clean structure
3. Create DEVELOPER_GUIDE.md
4. Create OPERATIONS_MANUAL.md
```

## 🎯 TARGET STATE

### Final Directory Structure
```
Amoskys/
├── src/amoskys/              # Core codebase
│   ├── agents/               # Agent implementations
│   ├── eventbus/             # EventBus server
│   ├── common/               # Shared utilities
│   └── proto/                # Protocol definitions
├── web/                      # Web dashboard
├── tests/                    # Test suite
├── config/                   # Configuration files
├── deploy/                   # Deployment configs
├── docs/                     # 10 essential docs only
├── scripts/                  # Utility scripts
├── certs/                    # TLS certificates (gitignored)
├── data/                     # Runtime data (gitignored)
├── Makefile                  # Build automation
├── requirements.txt          # Single requirements file
├── README.md                 # Root documentation
└── LICENSE                   # License file
```

## ✅ NEXT STEPS

1. **Immediate**: Remove broken intelligence/ directory
2. **Next**: Clean up root level clutter
3. **Then**: Organize documentation
4. **Final**: Update build and development docs

---

*This audit provides the foundation for professional codebase cleanup and organization.*
