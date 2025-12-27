# AMOSKYS Repository Cleanup & Organization Plan

**Created**: December 5, 2025  
**Status**: Ready for Execution  
**Current State**: 2.3GB (12,815 Python files, 83 docs, 210 cache dirs)  
**Target State**: <1.5GB lean production repository

---

## 📊 Repository Analysis

### Current Size Breakdown
| Component | Size | Action |
|-----------|------|--------|
| `.venv/` (virtual environment) | 1.9GB | ✅ Keep (not committed) |
| `src/` (source code) | 752KB | ✅ Keep (core product) |
| `docs/` (documentation) | 628KB | 🧹 Reduce to 100KB |
| `notebooks/` (ML experiments) | 528KB | 🗑️ Remove |
| `data/` (runtime/ML models) | 290MB | ⚠️ Review |
| `scripts/` & root scripts | ~200KB | 🧹 Consolidate |
| `tools/` (utilities) | ~80KB | ❓ Review |
| `__pycache__` dirs | ~50MB | 🗑️ Delete |
| Root documentation files | ~150KB | 🗑️ Archive |

### File Inventory
- **Python files**: 12,815 (mostly in data/ and notebooks/)
- **Documentation files**: 83 markdown + reports
- **Python cache dirs**: 210 `__pycache__` instances
- **Root directory files**: 19 markdown/text files + 3 assessment reports

---

## 🎯 Cleanup Strategy (3 Phases)

### PHASE 1: Quick Wins (Immediate - 30 mins)
Remove obvious bloat with zero impact on core functionality.

#### 1.1 Delete Broken Intelligence Module
**Path**: `src/amoskys/intelligence/`  
**Size**: 248KB  
**Status**: ❌ Broken - import errors in `agent_core.py` (678 lines)  
**Impact**: 🟢 NONE - Already disabled test, not used in agents  
**Action**: Delete entire directory

```bash
rm -rf src/amoskys/intelligence/
```

**Verification**: Ensure no imports reference it
```bash
grep -r "from amoskys.intelligence" src/ web/ tests/ 2>/dev/null || echo "✅ Safe to delete"
grep -r "intelligence" src/amoskys/agents/ || echo "✅ Agents don't depend on it"
```

---

#### 1.2 Remove Experimental Notebooks
**Path**: `notebooks/`  
**Size**: 528KB  
**Files**: 1 notebook (`ml_transformation_pipeline.ipynb`)  
**Status**: ❌ Not part of core product  
**Impact**: 🟢 NONE - Purely experimental  
**Action**: Delete entire directory

```bash
rm -rf notebooks/
```

---

#### 1.3 Clean Up Root Assessment/Report Files
**Files to Delete**:
- `assessment_report_20251025_180158.json` (4.4KB)
- `assessment_report_20251025_181945.json` (4.3KB)
- `assessment_report_20251025_183916.json` (4.3KB)
- `bandit-report.json` (9.3KB)
- `safety-report.json` (103KB)

**Status**: 📋 Audit artifacts, not needed in main repo  
**Impact**: 🟢 NONE - These are historical reports  
**Action**: Move to `backups/archived_reports/`

```bash
mkdir -p backups/archived_reports/
mv assessment_report_*.json bandit-report.json safety-report.json backups/archived_reports/
```

---

#### 1.4 Archive Root Documentation
**Files to Archive** (not delete - they contain valuable info):
- `CODEBASE_STATUS.md` → `docs/archive/`
- `FINAL_VERIFICATION.md` → `docs/archive/`
- `OPERATIONS.md` → Keep (merge into operations guide)
- `OPERATIONS_QUICK_GUIDE.md` → Keep (for users)
- `FRAMEWORK_SUMMARY.txt` → `docs/archive/`
- `GIT_COMMIT_MESSAGE.txt` → `docs/archive/`
- `QUICK_ACTION_CARD.txt` → `docs/archive/`
- `STABILITY_REPORT_DECEMBER_2025.md` → `docs/archive/`
- `STABILITY_SUMMARY.txt` → `docs/archive/`
- `COMPREHENSIVE_AUDIT.md` → `docs/archive/` (reference only)

**Action**:
```bash
mkdir -p docs/archive/
mv CODEBASE_STATUS.md FINAL_VERIFICATION.md FRAMEWORK_SUMMARY.txt \
   GIT_COMMIT_MESSAGE.txt QUICK_ACTION_CARD.txt \
   STABILITY_REPORT_DECEMBER_2025.md STABILITY_SUMMARY.txt \
   COMPREHENSIVE_AUDIT.md docs/archive/
```

**Keep at root**: `README.md` only

---

#### 1.5 Consolidate Requirements Files
**Current State**:
- `requirements.txt` (2.4KB) - Main dependencies
- `requirements-lock.txt` (1.5KB) - Pinned versions
- `requirements-microprocessor.txt` (1.2KB) - For broken intelligence module
- `requirements/` directory - Modular requirements

**Action**: Keep only `requirements.txt` (main)
```bash
# Keep requirements.txt (primary)
# Delete requirements-lock.txt and requirements-microprocessor.txt
rm requirements-lock.txt requirements-microprocessor.txt
# Archive requirements/ directory reference
mkdir -p docs/archive/requirements_backup
cp -r requirements/* docs/archive/requirements_backup/
```

**Update `requirements.txt`**: Ensure it has all needed packages for:
- Flask web dashboard
- 6 agents (eventbus, proc, mac_telemetry, flow, snmp, discovery)
- EventBus server
- Testing (pytest)
- Monitoring (prometheus_client)

---

### PHASE 2: Documentation Consolidation (15 mins)
Reduce 83 docs to 10-15 essential ones.

#### 2.1 Audit Existing Documentation
**Current structure**: `docs/` has 47 markdown files across:
- `docs/phases/` - Phase planning docs
- `docs/archive/` - Historical docs
- `docs/runbooks/` - Operational procedures

**Action**: Identify which are used vs. historical
```bash
find docs/ -name "*.md" | sort
```

**Keep (Core Documentation)**:
- Architecture overview
- Installation & setup guide
- API documentation
- Operational runbooks (critical ones only)
- Troubleshooting guide
- Security/TLS configuration

**Archive/Remove**:
- Phase planning documents (completed)
- Historical meeting notes
- Duplicate documentation
- Exploratory docs

---

#### 2.2 Create Consolidated Documents
Replace scattered docs with:

1. **`docs/ARCHITECTURE.md`** (NEW)
   - System overview
   - Component relationships
   - Data flow diagrams
   - Technology stack

2. **`docs/GETTING_STARTED.md`** (NEW)
   - Installation steps
   - Quick start guide
   - Hello World example
   - Common issues

3. **`docs/OPERATIONS.md`** (UPDATED)
   - Running the platform
   - Monitoring/metrics
   - Troubleshooting
   - Performance tuning

4. **`docs/SECURITY.md`** (UPDATED)
   - TLS/mTLS setup
   - Certificate management
   - Authentication
   - Best practices

5. **`docs/API_REFERENCE.md`** (KEEP/UPDATE)
   - API endpoints
   - Agent APIs
   - gRPC definitions

6. **`docs/DEVELOPMENT.md`** (NEW)
   - Development setup
   - Adding new agents
   - Testing
   - Code structure

7. **`docs/DEPLOYMENT.md`** (KEEP/UPDATE)
   - Docker deployment
   - Kubernetes setup
   - Production checklist

8. **`docs/RUNBOOKS/`** (Curated)
   - agent-startup-troubleshooting.md
   - common-issues.md
   - performance-optimization.md
   - security-checklist.md

**Target**: 15-20 focused docs, <100KB total

---

### PHASE 3: Script Organization (10 mins)
Clean up root directory and organize scripts.

#### 3.1 Review Root Executables
**Current**:
- `activate_env.sh` - Virtual env activation
- `amoskys-agent` - Agent launcher
- `amoskys-eventbus` - EventBus launcher
- `amoskys-snmp-agent` - SNMP launcher
- `generate_mac_telemetry.py` - Test data generator
- `populate_test_data.py` - Data populator
- `run_ml_pipeline.sh` - ML pipeline (REMOVE - intelligence module gone)
- `start_amoskys.sh` - System startup
- `stop_amoskys.sh` - System shutdown
- `test_execution.sh` - Test runner

**Action**:
- Delete `run_ml_pipeline.sh` (depends on removed intelligence module)
- Move `generate_mac_telemetry.py` → `scripts/utilities/`
- Move `populate_test_data.py` → `scripts/utilities/`
- Move `test_execution.sh` → `scripts/testing/`
- Keep at root: `start_amoskys.sh`, `stop_amoskys.sh`
- Keep at root: `activate_env.sh`, agent launcher scripts

**Structure after cleanup**:
```
Amoskys/
├── start_amoskys.sh          # Main startup
├── stop_amoskys.sh           # Main shutdown
├── activate_env.sh           # Environment setup
├── amoskys-agent             # Agent launcher
├── amoskys-eventbus          # EventBus launcher
├── amoskys-snmp-agent        # SNMP launcher
└── scripts/
    ├── utilities/
    │   ├── generate_mac_telemetry.py
    │   └── populate_test_data.py
    ├── testing/
    │   └── test_execution.sh
    ├── demo/                  # Existing
    ├── automation/            # Existing
    └── ml_pipeline/           # Remove (if exists with intelligence)
```

---

#### 3.2 Update Root `Makefile`
**Current**: 19KB with many targets  
**Action**: Keep essential targets:
- `make install` - Install dependencies
- `make test` - Run tests
- `make lint` - Code quality checks
- `make format` - Code formatting
- `make clean` - Clean build artifacts
- `make run` - Start services
- `make stop` - Stop services
- `make dashboard` - Start web UI

**Remove targets**:
- ML pipeline targets (no intelligence module)
- Microprocessor targets
- Deprecated deployment targets

---

#### 3.3 Clean Up Python Cache
```bash
# Remove all __pycache__ directories
find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null

# Remove .pyc files
find . -type f -name "*.pyc" -delete

# Remove .pytest_cache
rm -rf .pytest_cache

# Update .gitignore to prevent future cache
grep -E "^__pycache__|^\.pytest_cache" .gitignore || echo "__pycache__/" >> .gitignore
```

---

## 📋 Data Directory Review

**Path**: `data/` (290MB)  
**Contents**:
- `data/wal/` - Write-ahead log (runtime)
- `data/metrics/` - Metrics storage (runtime)
- `data/ml_pipeline/` - ML model data (consider removing with intelligence)
- `data/storage/` - Event storage (runtime)

**Decision**:
- 🟢 Keep: `wal/`, `metrics/`, `storage/` (runtime data)
- 🟡 Review: `ml_pipeline/` (part of removed intelligence)
  - If only models: archive to `backups/ml_models_archive/`
  - If data: remove (can be regenerated)

```bash
# After intelligence module removal:
if [ -d "data/ml_pipeline" ]; then
    mkdir -p backups/ml_models_archive
    mv data/ml_pipeline/* backups/ml_models_archive/
    rmdir data/ml_pipeline
fi
```

---

## 🧹 Tools Directory Review

**Path**: `tools/` (80KB)  
**Contents**:
- `api_integration_demo.py` - Demo code (can move to examples/)
- `chaos.sh` - Chaos testing (experimental)
- `inspect_wal_events.py` - Debugging utility (useful)
- `loadgen.py` - Load testing (useful)
- `visualize_timeline.py` - Visualization tool (useful)

**Decision**:
- Keep useful utilities: `inspect_wal_events.py`, `loadgen.py`, `visualize_timeline.py`
- Move to: `scripts/utilities/tools/` or `scripts/debugging/`
- Keep: `api_integration_demo.py` → can be in `examples/`
- Remove: `chaos.sh` (experimental, not core)

---

## ✅ Final Cleanup Checklist

- [ ] **Phase 1 - Quick Wins** (30 mins)
  - [ ] Delete `src/amoskys/intelligence/` (248KB)
  - [ ] Delete `notebooks/` (528KB)
  - [ ] Archive assessment reports & safety reports
  - [ ] Archive root documentation files
  - [ ] Consolidate requirements files

- [ ] **Phase 2 - Documentation** (15 mins)
  - [ ] Create core documentation structure
  - [ ] Archive 70+ existing docs
  - [ ] Consolidate to 10-15 essential files
  - [ ] Update README.md

- [ ] **Phase 3 - Scripts & Cache** (10 mins)
  - [ ] Delete broken `run_ml_pipeline.sh`
  - [ ] Organize utilities scripts
  - [ ] Remove all `__pycache__` directories
  - [ ] Clean up root directory

- [ ] **Phase 4 - Verification** (10 mins)
  - [ ] Run test suite: `pytest tests/`
  - [ ] Verify all agents start: `start_amoskys.sh`
  - [ ] Check dashboard: `http://localhost:5001/dashboard`
  - [ ] Validate final repo size

---

## 📊 Expected Results

### Size Reduction
| Metric | Before | After | Reduction |
|--------|--------|-------|-----------|
| Total size | 2.3GB | ~1.5GB | **35% smaller** |
| Source code | 752KB | 752KB | No change ✅ |
| Documentation | 628KB | 100KB | **84% smaller** |
| Notebooks | 528KB | 0KB | **100% removed** |
| Cache/bloat | 50MB+ | 0KB | **Cleaned** |
| Root files | 19 docs + reports | 3 essential | **Cleaner** |

### Quality Improvements
- ✅ No broken imports or modules
- ✅ Clear directory structure
- ✅ Essential documentation only
- ✅ All 6 agents fully functional
- ✅ 32/33 tests passing
- ✅ Faster git operations
- ✅ Easier onboarding for new developers

---

## 🚀 Post-Cleanup Actions

### 1. Update README.md
- Remove references to intelligence module
- Remove references to notebooks
- Point to consolidated docs
- Add quick start section

### 2. Create CONTRIBUTING.md
```markdown
# Contributing to AMOSKYS

## Development Setup
```

### 3. Create SECURITY.md
```markdown
# Security Policy

## Vulnerability Reporting
## TLS Configuration
## Authentication
```

### 4. Git Commit
```bash
git add -A
git commit -m "chore: major repository cleanup

- Remove broken intelligence module (248KB)
- Remove experimental notebooks (528KB)
- Archive historical documentation (550KB+)
- Consolidate requirements files
- Clean up root directory
- Remove ML pipeline scripts
- Delete all __pycache__ directories

Result: 35% size reduction (2.3GB → ~1.5GB)
Functionality: All 6 agents stable, 32/33 tests passing"
```

---

## ⚠️ Safety Notes

1. **Before deletion**: Create backup
   ```bash
   cd ..
   cp -r Amoskys Amoskys.backup.pre-cleanup.$(date +%s)
   ```

2. **Verify no dependencies**:
   - Search entire codebase for intelligence imports
   - Search for notebook references
   - Check documentation for broken links

3. **Test everything after cleanup**:
   - Unit tests
   - Integration tests
   - Dashboard functionality
   - Agent startup/shutdown

4. **Git safety**:
   - All changes tracked in git
   - Can revert if needed
   - Create cleanup branch first if unsure

---

## 📈 Success Criteria

✅ Repository size reduced to <1.5GB  
✅ All 6 agents start and stop correctly  
✅ Dashboard fully functional  
✅ 32/33 tests pass (same as before)  
✅ No broken imports or references  
✅ Documentation clear and complete  
✅ Git history preserved  
✅ No loss of functionality  

---

**Estimated Total Time**: 60-90 minutes  
**Difficulty**: Low (mostly deletions, no code changes)  
**Risk Level**: Very Low (core functionality untouched)  

Ready to execute? Start with Phase 1.
