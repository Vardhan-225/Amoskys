# AMOSKYS FAANG-Level Code Organization Plan

**Date:** 2025-12-27
**Status:** 🔄 IN PROGRESS
**Goal:** Transform codebase to FAANG-level organization standards

---

## Executive Summary

Current codebase assessment: **6.6/10** - Above-average with clear improvement areas

**Critical Issues Identified:**
1. ❌ Test structure doesn't mirror source (0/10 on this criterion)
2. ❌ 8 separate requirements files creating dependency confusion
3. ❌ Duplicate code (3 proc_agent variants, unclear which is canonical)
4. ❌ Root-level test files scattered outside tests/ directory
5. ⚠️ Empty `__init__.py` files missing proper API exports
6. ⚠️ Intelligence module untested (0% coverage)
7. ⚠️ 10+ deployment scripts with unclear hierarchy

**FAANG Standards Scorecard:**
| Category | Current | Target | Priority |
|----------|---------|--------|----------|
| Directory Structure | 6/10 | 9/10 | HIGH |
| Module Organization | 7/10 | 9/10 | HIGH |
| Dependency Management | 5/10 | 9/10 | CRITICAL |
| Testing Structure | 5/10 | 9/10 | CRITICAL |
| Type Hints | 6/10 | 8/10 | MEDIUM |
| Build/Deploy | 6/10 | 8/10 | HIGH |

---

## Phase 1: IMMEDIATE (High Impact) - 4-6 hours

### 1.1 Consolidate Requirements Files ⚡ CRITICAL
**Current State:** 8 separate requirements files causing confusion
```
requirements/
├── requirements.txt
├── requirements-clean.txt
├── requirements-production.txt
├── requirements-api.txt
├── requirements-locked.txt
├── requirements-web-frozen.txt
├── requirements-full-frozen.txt
└── requirements-amoskys-web.txt
```

**Target State:** Single source of truth in pyproject.toml
```toml
[project]
dependencies = [...]  # Core dependencies

[project.optional-dependencies]
dev = [...]      # Development tools
web = [...]      # Web dashboard
ml = [...]       # Intelligence features
test = [...]     # Testing frameworks
```

**Actions:**
1. Audit all 8 requirements files to identify unique dependencies
2. Consolidate into pyproject.toml with optional dependency groups
3. Create requirements.txt as pip-compatible export: `pip freeze > requirements.txt`
4. Archive old requirements/ directory to `archive/2025-12-27-cleanup/`
5. Update documentation (README.md) with new installation commands

**Success Criteria:**
- ✅ Single pyproject.toml for all dependency management
- ✅ Clear installation: `pip install -e .` (core) or `pip install -e .[dev,web]`
- ✅ No confusion about which file to use

---

### 1.2 Resolve Duplicate Proc Agent Files ⚡ CRITICAL
**Current State:** 3 variants with unclear canonical version
```
src/amoskys/agents/proc/
├── proc_agent.py           (237 lines - imported by __init__.py)
├── proc_agent_fixed.py     (300 lines - unknown purpose)
└── proc_agent_simple.py    (309 lines - unknown purpose)
```

**Actions:**
1. Read all 3 files to understand differences
2. Determine canonical version (likely `proc_agent.py` since it's in `__init__.py`)
3. If "fixed" or "simple" have improvements, merge them into canonical
4. Delete non-canonical versions
5. Update any imports/references
6. Document decision in commit message

**Success Criteria:**
- ✅ Only ONE proc_agent.py exists
- ✅ All functionality preserved
- ✅ Clear commit history explaining consolidation

---

### 1.3 Move Root-Level Test Files ⚡ HIGH
**Current State:** Test files scattered in root directory
```
/
├── test_publish_telemetry.py    ❌ Should be in tests/
├── test_dashboard.py            ❌ Should be in tests/
├── populate_test_data.py        ❌ Should be in tests/fixtures/
└── generate_mac_telemetry.py    ❌ Should be in tools/
```

**Target State:**
```
tests/
├── integration/
│   └── test_publish_telemetry.py    ✅
└── web/
    └── test_dashboard.py            ✅

tests/fixtures/
└── populate_test_data.py            ✅

tools/
└── generate_mac_telemetry.py        ✅
```

**Actions:**
1. Create `tests/integration/` directory
2. Create `tests/web/` directory
3. Create `tests/fixtures/` directory
4. Create `tools/` directory
5. Move files with git mv to preserve history
6. Update import paths if needed
7. Verify tests still run: `pytest tests/`

**Success Criteria:**
- ✅ Clean root directory (only essential config files)
- ✅ All tests discoverable by pytest
- ✅ Git history preserved with `git mv`

---

### 1.4 Restructure Tests to Mirror Source ⚡ CRITICAL
**Current State:** Test directory doesn't follow source structure
```
tests/
├── unit/ (only 2 files)
├── component/ (5 files)
├── api/ (1 file)
├── golden/ (good)
└── manual/ (good)

# Missing tests for:
# - intelligence/
# - storage/
# - edge/
# - common/
```

**Target State:**
```
tests/
├── unit/
│   ├── test_config.py
│   ├── agents/
│   │   ├── test_flowagent.py
│   │   ├── test_proc_agent.py
│   │   ├── test_snmp_agent.py
│   │   └── test_peripheral_agent.py
│   ├── common/
│   │   ├── test_canonical.py
│   │   └── test_signing.py
│   ├── storage/
│   │   ├── test_wal_processor.py
│   │   └── test_telemetry_store.py
│   ├── eventbus/
│   │   └── test_server.py
│   └── intelligence/
│       ├── test_threat_correlator.py
│       └── test_network_features.py
├── integration/ (rename from component/)
│   ├── test_bus_inflight_metric.py
│   ├── test_fitness.py
│   ├── test_publish_paths.py
│   ├── test_retry_path.py
│   └── test_wal_grow_drain.py
├── web/
│   ├── test_api_gateway.py
│   └── test_dashboard.py
├── fixtures/
│   ├── populate_test_data.py
│   └── sample_events.py
└── golden/
    └── test_envelope_bytes.py
```

**Actions:**
1. Create directory structure matching src/
2. Rename `component/` → `integration/`
3. Move `api/test_api_gateway.py` → `web/test_api_gateway.py`
4. Create placeholder test files for uncovered modules
5. Update pytest configuration in conftest.py
6. Run test suite to ensure no breakage

**Success Criteria:**
- ✅ Test directory mirrors src/ structure exactly
- ✅ Easy to find tests for any module: `tests/unit/X/` for `src/amoskys/X/`
- ✅ All existing tests still pass

---

## Phase 2: SHORT-TERM (Code Quality) - 6-8 hours

### 2.1 Populate Empty __init__.py Files
**Current State:** Many empty `__init__.py` files missing API exports
```python
# src/amoskys/__init__.py - EMPTY
# src/amoskys/agents/__init__.py - EMPTY
# src/amoskys/common/__init__.py - EMPTY
# src/amoskys/eventbus/__init__.py - EMPTY
```

**Target State:**
```python
# src/amoskys/__init__.py
"""AMOSKYS Neural Security Command Platform
Distributed telemetry collection and threat detection for Mac/Linux/OT devices
"""
from . import agents, config, eventbus, storage, intelligence
from .config import AmoskysConfig, get_config

__version__ = "1.0.0"
__all__ = ["agents", "config", "eventbus", "storage", "intelligence", "AmoskysConfig", "get_config"]

# src/amoskys/agents/__init__.py
"""Agent implementations for distributed telemetry collection"""
from .flowagent import FlowAgent, SQLiteWAL
from .proc import ProcAgent
from .snmp import SNMPAgent
from .peripheral import PeripheralAgent

__all__ = ["FlowAgent", "SQLiteWAL", "ProcAgent", "SNMPAgent", "PeripheralAgent"]
```

**Actions:**
1. Review each module's public API
2. Add module docstrings
3. Import and export public classes/functions
4. Add `__all__` for explicit API definition
5. Set `__version__` in root __init__.py

**Success Criteria:**
- ✅ Clear public API for each module
- ✅ Users can: `from amoskys.agents import ProcAgent`
- ✅ No import errors or circular dependencies

---

### 2.2 Organize Scripts into Hierarchical Structure
**Current State:** 30+ scripts in flat scripts/ directory
```
scripts/
├── automation/
├── demo/
├── ml_pipeline/
├── quick_deploy.sh
├── deploy_web.sh
├── deploy_microprocessor_agent.sh
├── test_web_local.sh
├── test_web_local_new.sh
└── ... (20+ more)
```

**Target State:**
```
scripts/
├── deploy/
│   ├── deploy.sh              (main entry point)
│   ├── deploy-web.sh
│   ├── deploy-agents.sh
│   └── deploy-ml.sh
├── test/
│   ├── run-unit-tests.sh
│   ├── run-integration-tests.sh
│   └── run-all-tests.sh
├── dev/
│   ├── setup-dev-env.sh
│   ├── start-services.sh
│   └── stop-services.sh
├── automation/               (keep existing)
├── demo/                     (keep existing)
└── ml_pipeline/             (keep existing)
```

**Actions:**
1. Create deploy/, test/, dev/ subdirectories
2. Move scripts into appropriate categories
3. Create single entry point: scripts/deploy/deploy.sh
4. Deprecate old scripts (add warnings or remove)
5. Update documentation to reference new structure

**Success Criteria:**
- ✅ Clear categorization: deploy, test, dev
- ✅ Single entry point for each category
- ✅ No duplicate or conflicting scripts

---

### 2.3 Extract WAL from FlowAgent to Storage Module
**Current State:** WAL implementation coupled to FlowAgent
```python
# src/amoskys/agents/flowagent/wal_sqlite.py
# Used by: eventbus/server.py (creates coupling)
```

**Target State:**
```python
# src/amoskys/storage/wal_sqlite.py
# Clean dependency: eventbus → storage (not eventbus → agents)
```

**Actions:**
1. Move `agents/flowagent/wal_sqlite.py` → `storage/wal_sqlite.py`
2. Update imports in:
   - `eventbus/server.py`
   - `agents/flowagent/__init__.py`
   - Any other references
3. Update `storage/__init__.py` to export WAL classes
4. Run full test suite to verify no breakage
5. Update documentation

**Success Criteria:**
- ✅ WAL in correct module (storage, not agents)
- ✅ No circular dependencies
- ✅ All tests pass

---

### 2.4 Add Type Hints to Core Modules
**Current State:** Partial type hint coverage
- config.py: 100% ✅
- eventbus/server.py: ~70% ⚠️
- agents/: ~60% ⚠️
- web/api/: ~20% ❌

**Target State:** 100% coverage for core modules

**Actions:**
1. Enable mypy strict mode: `disallow_untyped_defs = true`
2. Add type hints to:
   - All function signatures
   - Class attributes
   - Return types
3. Focus on core first: config, eventbus, storage, agents
4. Add `py.typed` marker file for package
5. Run mypy in CI

**Success Criteria:**
- ✅ `mypy src/amoskys/` passes with no errors
- ✅ 100% type coverage for core modules
- ✅ Type hints improve IDE autocomplete

---

## Phase 3: MEDIUM-TERM (Architecture) - 8-12 hours

### 3.1 Create Test Coverage for Intelligence Module
**Current State:** 0% test coverage
```
intelligence/
├── features/network_features.py         (untested)
├── fusion/threat_correlator.py          (untested)
├── integration/agent_core.py            (untested)
└── score_junction.py                    (untested)
```

**Actions:**
1. Create `tests/unit/intelligence/` structure
2. Write unit tests for each module
3. Create integration tests for threat correlation
4. Add test fixtures for sample network data
5. Achieve 80%+ coverage

**Success Criteria:**
- ✅ 80%+ test coverage for intelligence module
- ✅ Tests validate threat detection logic
- ✅ Regression prevention for ML features

---

### 3.2 Dependency Injection for Configuration
**Current State:** Global singleton pattern
```python
# Anti-pattern
config = get_config()  # Global state
```

**Target State:** Dependency injection
```python
# Better
def create_app(config: AmoskysConfig) -> Flask:
    app = Flask(__name__)
    app.config['AMOSKYS'] = config
    return app

# In tests
def test_app():
    test_config = AmoskysConfig(...)
    app = create_app(test_config)
```

**Actions:**
1. Refactor create_app() to accept config parameter
2. Update eventbus server to accept config
3. Update agents to accept config in __init__
4. Maintain backward compatibility with get_config()
5. Update tests to use injected config

**Success Criteria:**
- ✅ No global state in core modules
- ✅ Easier to test with custom configs
- ✅ Backward compatible

---

### 3.3 Documentation Generation with Sphinx
**Current State:** No auto-generated API documentation

**Target State:**
```
docs/
├── source/
│   ├── api/           (auto-generated from docstrings)
│   ├── guides/
│   └── architecture/
├── build/
└── Makefile
```

**Actions:**
1. Install Sphinx: `pip install sphinx sphinx-rtd-theme`
2. Initialize docs: `sphinx-quickstart docs/`
3. Configure autodoc extension
4. Generate API docs from docstrings
5. Add architecture diagrams
6. Host on GitHub Pages

**Success Criteria:**
- ✅ Complete API documentation generated
- ✅ Hosted at amoskys.readthedocs.io or GitHub Pages
- ✅ Auto-updated on commit

---

### 3.4 CI/CD Pipeline Enhancement
**Current State:** Basic CI in .github/workflows/ci.yml

**Target State:**
```yaml
# .github/workflows/ci.yml
jobs:
  lint:
    - black --check
    - ruff check
    - mypy src/

  test:
    - pytest tests/unit/
    - pytest tests/integration/

  coverage:
    - pytest --cov=src/ --cov-report=xml
    - codecov

  build:
    - python -m build
    - twine check dist/*
```

**Actions:**
1. Add linting job (black, ruff, mypy)
2. Add coverage reporting (codecov)
3. Add dependency security scan (safety)
4. Add Docker build verification
5. Add deployment automation

**Success Criteria:**
- ✅ All code quality checks automated
- ✅ Coverage reports visible in PR
- ✅ Deployment automated for main branch

---

## Implementation Timeline

| Phase | Duration | Priority | Dependencies |
|-------|----------|----------|--------------|
| **Phase 1** | 4-6 hours | CRITICAL | None |
| 1.1 Requirements | 1 hour | CRITICAL | None |
| 1.2 Proc Agent | 1 hour | CRITICAL | None |
| 1.3 Root Files | 1 hour | HIGH | None |
| 1.4 Test Structure | 2 hours | CRITICAL | 1.3 complete |
| **Phase 2** | 6-8 hours | HIGH | Phase 1 |
| 2.1 __init__.py | 2 hours | HIGH | Phase 1 |
| 2.2 Scripts | 2 hours | MEDIUM | None |
| 2.3 WAL Extract | 2 hours | HIGH | Phase 1 |
| 2.4 Type Hints | 4 hours | MEDIUM | None |
| **Phase 3** | 8-12 hours | MEDIUM | Phase 2 |
| 3.1 Intelligence Tests | 4 hours | HIGH | Phase 1.4 |
| 3.2 Dependency Injection | 3 hours | MEDIUM | Phase 2.1 |
| 3.3 Sphinx Docs | 3 hours | LOW | Phase 2.1 |
| 3.4 CI/CD | 4 hours | MEDIUM | Phase 2.4 |

**Total Estimated Time:** 18-26 hours across 3 phases

---

## Success Metrics

### Before (Current State)
- ✅ Directory Structure: 6/10
- ✅ Module Organization: 7/10
- ❌ Dependency Management: 5/10
- ❌ Testing Structure: 5/10
- ⚠️ Type Hints: 6/10
- ⚠️ Build/Deploy: 6/10
- **Overall: 6.6/10**

### After (Target State)
- ✅ Directory Structure: 9/10
- ✅ Module Organization: 9/10
- ✅ Dependency Management: 9/10
- ✅ Testing Structure: 9/10
- ✅ Type Hints: 8/10
- ✅ Build/Deploy: 8/10
- **Overall: 8.7/10 - FAANG LEVEL**

---

## Next Actions

1. **Start with Phase 1.1** - Consolidate requirements files (highest impact, no dependencies)
2. **Proceed sequentially** through Phase 1 (critical foundation)
3. **Review and commit** after each phase
4. **Update documentation** as changes are made
5. **Run full test suite** after each significant change

---

**Status:** Ready for execution
**Owner:** AMOSKYS Development Team
**Review:** Required after Phase 1 completion
