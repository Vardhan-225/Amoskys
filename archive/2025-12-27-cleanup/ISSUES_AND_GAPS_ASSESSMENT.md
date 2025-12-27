# AMOSKYS: Complete Issues & Gaps Assessment
**Version**: 1.0  
**Date**: December 5, 2025  
**Purpose**: Master reference for ALL known issues, gaps, and required improvements  
**Status**: For solo developer 4-6 week transformation to production-ready MVP

---

## EXECUTIVE SUMMARY

AMOSKYS is a **neuro-inspired security micro-processor** in a **transitional state**:
- **6 core agents** are functional and data-collecting (eventbus, flowagent, proc_agent, snmp_agent, device_scanner, mac_telemetry)
- **Core infrastructure** works: gRPC + mTLS, SQLite persistence, Prometheus metrics
- **500k+ records** in database, proving scale capability
- **BUT**: No ML inference pipeline, no unified alerts system, no three-layer analysis, tests have failures in older components

**Goal**: Transform into a **production-ready Process + System Health Reflex Pipeline** with explainable anomaly detection via three-layer brain (Geometric + Temporal + ML Hero).

---

## 🔴 CRITICAL ISSUES (Blocking Immediate Progress)

### Issue 1.1: Test Suite Failures (14 Failed / 47 Passed)
**Severity**: 🔴 Critical  
**Impact**: Cannot validate code changes safely  
**Root Cause**: Old microprocessor test file has undefined class references (EdgeOptimizer, UniversalTelemetryCollector)  
**Status**: Not on critical path (old experimental code)

**Files Affected**:
- `tests/test_microprocessor_agent.py` (14 failed tests)
  - TestIntelligenceFusionEngine.test_threat_detection_thresholds
  - TestDeviceDiscovery (3 tests - missing config arg)
  - TestUniversalTelemetryCollector (4 tests - undefined class)
  - TestEdgeOptimization (4 tests - undefined class)
  - TestErrorHandling (2 tests - missing deps)

**Decision**: **QUARANTINE** old test file (move to `tests/archive/`) and focus on core component tests.

**Action Items**:
- [ ] Move `tests/test_microprocessor_agent.py` → `tests/archive/test_microprocessor_agent.py.bak`
- [ ] Verify core tests pass: `pytest tests/component/ -v`
- [ ] Update CI/CD to ignore archive folder

**Effort**: 15 minutes

---

### Issue 1.2: Documentation Clutter (100+ Markdown Files)
**Severity**: 🔴 Critical (noise/confusion)  
**Impact**: Developers lost in old session notes, audit reports, analysis docs  
**Root Cause**: 6+ months of AI-generated status reports not cleaned up  
**Status**: Partially cleaned; many remain

**Files Example**:
- `AGENT_CONTROL_FINAL_STATUS_REPORT.md`
- `COMPLETE_EXECUTION_SUMMARY.md`
- `PHASE_1_5_COMPLETE.md`
- `NEURON_JOURNEY_COMPLETE.md`
- ~80 more similar files

**Decision**: **Already mostly cleaned**. Move remaining historical docs to `.docs-archive/` folder.

**Action Items**:
- [ ] Create `.docs-archive/` directory
- [ ] Move all session reports, execution summaries, old roadmaps there
- [ ] Keep only: README.md, MASTER_DEVELOPMENT_GUIDE.md, SOLO_DEVELOPER_ROADMAP.md

**Effort**: 30 minutes

---

## 🟠 MAJOR GAPS (Core Functionality Missing)

### Gap 2.1: No ML Inference Pipeline
**Severity**: 🟠 Major  
**Impact**: Cannot detect anomalies in real-time  
**Current State**: Zero ML inference, no model loading, no alert generation  
**Missing Components**:
- Feature engineering (normalize, aggregate process/SNMP data)
- Trained anomaly detection model (IsolationForest)
- Hero reflex inference engine
- Three-layer brain (Geometric, Temporal, ML-based)
- Alert event emission

**Required Effort**: 18-22 hours (per roadmap)

**Tasks from Roadmap**:
- [ ] Task 2.1: Design hero signal contract
- [ ] Task 2.2: Build feature pipeline
- [ ] Task 2.3: Train IsolationForest model
- [ ] Task 3.1: Wire model to API
- [ ] Task 3.2: Build geometric analyzer
- [ ] Task 3.3: Build temporal analyzer
- [ ] Task 3.4: Build fusion engine

---

### Gap 2.2: No Unified Alert System
**Severity**: 🟠 Major  
**Impact**: Alerts cannot be delivered or displayed  
**Current State**: No AlertEvent definition, no API endpoint, no dashboard integration  
**Missing Components**:
- AlertEvent data structure
- Alert queuing system
- REST API: `GET /api/alerts/recent`
- Dashboard widget for live alerts
- Alert severity classification (LOW/MED/HIGH/CRIT)

**Required Effort**: 5-8 hours

**Tasks**:
- [ ] Define AlertEvent protobuf (or Python dataclass)
- [ ] Create `/api/alerts/recent` endpoint in Flask
- [ ] Add alerts widget to Cortex dashboard
- [ ] Emit sample alerts for testing

---

### Gap 2.3: No Feature Engineering Module
**Severity**: 🟠 Major  
**Impact**: Cannot transform raw metrics into ML-consumable features  
**Current State**: Zero feature engineering code  
**Missing Components**:
- Feature normalization (0-1 scaling)
- Rolling window aggregation (5-min, 1-hour averages)
- Anomaly flags (new process, privilege escalation, spike)
- Join logic (process + SNMP records)

**Required Effort**: 3-4 hours

**Tasks**:
- [ ] Create `src/amoskys/feature_engineering/hero_process_snmp.py`
- [ ] Implement HeroFeaturePipeline class
- [ ] Write unit tests with 10 sample records

---

### Gap 2.4: No Model Training Pipeline
**Severity**: 🟠 Major  
**Impact**: No trained anomaly detector exists  
**Current State**: Zero trained models in `models/` directory  
**Missing Components**:
- Data export from SQLite to CSV
- Manual labeling of sample records (benign vs anomaly)
- IsolationForest model training
- Model serialization (joblib)
- Model loading & inference testing

**Required Effort**: 4-5 hours

**Tasks**:
- [ ] Create `notebooks/hero_training.ipynb`
- [ ] Export 1000+ records from database
- [ ] Label ~20 records manually
- [ ] Train IsolationForest, validate (10-fold CV)
- [ ] Save model to `models/hero_process_snmp_iforest.pkl`

---

### Gap 2.5: No Three-Layer Analysis Brain
**Severity**: 🟠 Major (high-value feature)  
**Impact**: Cannot explain detection reasoning, limited insight  
**Current State**: Scaffolding exists; no functional logic  
**Missing Components**:
- Geometric Analyzer (rule-based: process topology, privilege crossing)
- Temporal Analyzer (statistical: z-score, spike detection)
- Fusion Engine (weighted combination, layer breakdown)
- Per-layer scoring (0-1 confidence)
- Per-layer explanation (why each layer flagged event)

**Required Effort**: 10-12 hours

**Tasks**:
- [ ] Task 3.2: Build GeometricAnalyzer
- [ ] Task 3.3: Build TemporalAnalyzer
- [ ] Task 3.4: Build FusionEngine
- [ ] Integrate all three with HeroReflexEngine

---

### Gap 2.6: Dashboard Alert Integration
**Severity**: 🟠 Major  
**Impact**: Users cannot see anomalies in real-time  
**Current State**: Dashboard exists; no alert widget, no WebSocket for live updates  
**Missing Components**:
- Alert event listener on frontend
- Real-time WebSocket or polling mechanism
- Alert table widget (timestamp, severity, process name, score)
- Expandable layer breakdown section
- Alert filtering (severity, process, time range)

**Required Effort**: 4-6 hours

**Tasks**:
- [ ] Modify `web/app/templates/cortex.html`
- [ ] Add alerts table widget
- [ ] Implement alert fetch + display logic
- [ ] Style with severity colors (green/yellow/orange/red)

---

## 🟡 MODERATE GAPS (Important but Not Blocking)

### Gap 3.1: No Comprehensive Startup Script
**Severity**: 🟡 Moderate  
**Impact**: Starting system requires running 6+ commands manually  
**Current State**: `start_amoskys.sh` exists; incomplete error handling  
**Missing Components**:
- Unified `make dev-up` target
- Service dependency ordering (EventBus → agents → web)
- Health checks after each service starts
- Automatic log aggregation
- Clean shutdown with `make dev-down`

**Required Effort**: 2-3 hours

**Action Items**:
- [ ] Create/update Makefile with `dev-up`, `dev-down` targets
- [ ] Add health check function (curl EventBus gRPC, Flask, etc.)
- [ ] Log to `logs/amoskys.log` with timestamps

---

### Gap 3.2: Config Validation on Startup
**Severity**: 🟡 Moderate  
**Impact**: Misconfigurations cause cryptic errors deep in code  
**Current State**: No validation; errors bubble up during execution  
**Missing Components**:
- Validate port ranges (1-65535)
- Check file paths exist (certs, database, config)
- Validate size limits (WAL size, buffer sizes)
- Clear error messages

**Required Effort**: 1.5-2 hours

**Action Items**:
- [ ] Add `validate_config(config: dict) -> List[str]` to `src/amoskys/config.py`
- [ ] Call on startup in `eventbus/server.py`
- [ ] Return list of errors (empty = valid)

---

### Gap 3.3: No Vision Documentation (TRACTS)
**Severity**: 🟡 Moderate  
**Impact**: Future roadmap unclear, hard to prioritize R&D  
**Current State**: No TRACTS document  
**Missing Components**:
- Define 4-5 future research areas (Syscall eBPF, Memory analysis, Federation, Windows, Drift)
- Describe each TRACT (purpose, integration points, effort)
- Clarify what's MVP vs post-MVP

**Required Effort**: 2-3 hours

**Action Items**:
- [ ] Create `docs/TRACTS.md`
- [ ] Document each TRACT with purpose + timeline

---

### Gap 3.4: No Demo Documentation & Video
**Severity**: 🟡 Moderate  
**Impact**: Difficult to showcase work to stakeholders  
**Current State**: No demo docs, no video  
**Missing Components**:
- Step-by-step demo walkthrough (trigger anomaly, see alert)
- 3-5 min video recording
- Clear narration explaining three-layer brain
- Screenshots/GIFs of dashboard alerts

**Required Effort**: 3-4 hours

**Action Items**:
- [ ] Create `docs/HERO_SLICE_DEMO.md`
- [ ] Record 3-5 min video demo
- [ ] Include screenshots of dashboard in action

---

## 🟢 WORKING CORRECTLY (Keep As-Is)

### Component 4.1: EventBus (gRPC + mTLS)
**Status**: ✅ Working  
**Details**:
- Port 50051, Prometheus metrics on 9000
- Metric collision fix applied (9cb9674)
- TLS certificate generation working
- Event routing functional

**Files**:
- `src/amoskys/eventbus/server.py`
- `src/amoskys/eventbus/client.py`

---

### Component 4.2: Core Agents (6 operational)
**Status**: ✅ Working  
**Details**:
- eventbus, flowagent, proc_agent, snmp_agent, device_scanner, mac_telemetry
- All collecting data successfully
- 500k+ snapshots in database

**Files**:
- `src/amoskys/agents/*/main.py`

---

### Component 4.3: SQLite Persistence (WAL mode)
**Status**: ✅ Working  
**Details**:
- Database: `data/wal/flowagent.db`
- WAL mode enabled, writes + reads functional
- Schema supports process + SNMP snapshots

**Files**:
- `src/amoskys/db/schema.py`

---

### Component 4.4: Prometheus Metrics
**Status**: ✅ Working (post-fix)  
**Details**:
- Ports 9000, 9101 operational
- Metric collision fixed in flowagent (9cb9674)
- Component tests passing (5/6 core tests)

**Files**:
- `src/amoskys/agents/*/main.py` (all have metric init functions now)

---

### Component 4.5: Flask Dashboard (Cortex)
**Status**: ✅ Working  
**Details**:
- Port 5000, responsive HTML/CSS
- Displays agent status, system info
- Ready for alert widget integration

**Files**:
- `web/app/templates/cortex.html`
- `web/app/__init__.py` (Flask app factory)

---

### Component 4.6: Test Suite (Core Tests)
**Status**: ✅ 5/6 passing (component tests)  
**Details**:
- `tests/component/test_bus_inflight_metric.py` ✅
- `tests/component/test_publish_paths.py` ✅
- `tests/component/test_retry_path.py` ✅
- `tests/component/test_wal_grow_drain.py` ✅
- `tests/component/test_fitness.py` (skipped - prometheus not running)

**Action**: Quarantine old test file (test_microprocessor_agent.py) to keep clean CI.

---

## 📋 COMPLETE ISSUES & GAPS CHECKLIST

### CRITICAL PATH (Blocking MVP)

- [ ] **Issue 1.1**: Quarantine old test file → clean CI
  - Move `tests/test_microprocessor_agent.py` to archive
  - Verify core tests pass (5/6)
  - **Effort**: 15 min

- [ ] **Issue 1.2**: Archive old documentation
  - Move 100+ historical files to `.docs-archive/`
  - Keep only essential docs
  - **Effort**: 30 min

- [ ] **Gap 2.1**: Complete ML inference pipeline (18-22h total)
  - [ ] Design hero signal contract (1.5h)
  - [ ] Build feature pipeline (3h)
  - [ ] Train model (4h)
  - [ ] Wire model → API (5h)
  - [ ] Geometric analyzer (3h)
  - [ ] Temporal analyzer (3h)
  - [ ] Fusion engine (4h)

- [ ] **Gap 2.2**: Alert system (5-8h)
  - [ ] AlertEvent definition
  - [ ] REST API endpoint
  - [ ] Dashboard widget
  - [ ] Sample alert emission

- [ ] **Gap 2.3**: Feature engineering (3-4h)
  - [ ] Create pipeline module
  - [ ] Implement normalization, rolling avg
  - [ ] Unit tests

- [ ] **Gap 2.4**: Model training (4-5h)
  - [ ] Create training notebook
  - [ ] Export + label data
  - [ ] Train IsolationForest
  - [ ] Serialize model

- [ ] **Gap 2.5**: Three-layer brain (10-12h)
  - [ ] Geometric analyzer
  - [ ] Temporal analyzer
  - [ ] Fusion engine

- [ ] **Gap 2.6**: Dashboard integration (4-6h)
  - [ ] Alert widget
  - [ ] WebSocket/polling
  - [ ] Layer breakdown display

### SUPPORTING (High Value, Not Blocking)

- [ ] **Gap 3.1**: Startup script (2-3h)
- [ ] **Gap 3.2**: Config validation (1.5-2h)
- [ ] **Gap 3.3**: TRACTS vision doc (2-3h)
- [ ] **Gap 3.4**: Demo docs + video (3-4h)

---

## 🗺️ MAPPING TO ROADMAP TASKS

| Issue/Gap | Roadmap Task(s) | Phase | Effort |
|-----------|-----------------|-------|--------|
| Issue 1.1 | N/A (pre-roadmap) | Week 0 | 15m |
| Issue 1.2 | N/A (pre-roadmap) | Week 0 | 30m |
| Gap 2.1 | Tasks 2.1-3.4 | Weeks 2-5 | 18-22h |
| Gap 2.2 | Task 2.4 | Weeks 2-3 | 5-8h |
| Gap 2.3 | Task 2.2 | Week 2 | 3-4h |
| Gap 2.4 | Task 2.3 | Week 2 | 4-5h |
| Gap 2.5 | Tasks 3.2-3.4 | Weeks 4-5 | 10-12h |
| Gap 2.6 | Task 2.4 | Weeks 2-3 | 4-6h |
| Gap 3.1 | Task 1.4 | Week 1 | 2-3h |
| Gap 3.2 | Task 1.3 | Week 1 | 1.5-2h |
| Gap 3.3 | Task 4.1 | Week 6 | 2-3h |
| Gap 3.4 | Task 4.3 | Week 6 | 3-4h |

---

## 🎯 IMMEDIATE NEXT STEPS (TODAY)

### Step 1: Clean Up (30 minutes)
1. Move `tests/test_microprocessor_agent.py` → `tests/archive/`
2. Archive old documentation files
3. Run `pytest tests/component/ -v` → verify all pass

### Step 2: Start Task 2.1 (Design Hero Signal)
1. Query database schema: `SELECT * FROM processes LIMIT 5;`
2. List best 15 features for anomaly detection
3. Write `docs/HERO_SLICE_PROCESS_SNMP.md`

**Expected completion**: End of today

### Step 3: Start Task 2.2 (Feature Pipeline)
1. Create `src/amoskys/feature_engineering/` module
2. Implement HeroFeaturePipeline class
3. Write tests with 10 sample records

**Expected completion**: End of tomorrow

---

## 📊 CURRENT METRICS (Baseline)

| Metric | Value | Status |
|--------|-------|--------|
| Core agent tests passing | 5/6 | ✅ |
| Old test suite | 47 passed, 14 failed | ⚠️ (quarantined) |
| Database records | 500k+ | ✅ |
| Server uptime | Stable | ✅ |
| Feature pipeline | None | ❌ |
| Trained models | None | ❌ |
| Alert system | None | ❌ |
| Three-layer brain | Scaffolding only | ❌ |
| Dashboard alerts | None | ❌ |

---

## 🚀 SUCCESS CRITERIA (After All Tasks Complete)

- [ ] All core tests pass (5/6 consistently)
- [ ] Feature pipeline transforms 1000+ records cleanly
- [ ] IsolationForest model trains in < 5 min on laptop
- [ ] Hero reflex engine runs inference in < 100ms
- [ ] Alert system queues 100+ alerts without memory leak
- [ ] Dashboard displays live alerts with layer breakdown
- [ ] Geometric analyzer detects 5/5 privilege escalation tests
- [ ] Temporal analyzer detects 5/5 spike tests
- [ ] Fusion engine correctly weights three layers
- [ ] End-to-end: data → features → model → alert → UI (verified manually)
- [ ] Demo video shows all three layers analyzing a real anomaly
- [ ] TRACTS document outlines 4-5 clear R&D directions

---

## 📞 DECISION MATRIX

| Question | Answer | Rationale |
|----------|--------|-----------|
| **Move old test file to archive?** | YES | Unblocks CI, old experimental code |
| **Archive old docs?** | YES | Reduces confusion, easier navigation |
| **Use IsolationForest for MVP?** | YES | Fast, simple, interpretable |
| **Build three-layer brain?** | YES | Explainability + robustness |
| **Support eBPF in MVP?** | NO | Save for TRACT-1, requires kernel knowledge |
| **Train multiple models?** | NO | One good model sufficient for MVP |
| **Full 106-feature framework?** | NO | Hero slice (10-20 features) only |
| **Multi-node federation?** | NO | Single-node sufficient for MVP |

---

## 🎓 LEARNING NEEDED

If you get stuck, these resources help:

- **SQLite + WAL**: Review `src/amoskys/db/schema.py` + tests
- **Feature engineering**: Check `scikit-learn` preprocessing docs
- **IsolationForest**: Scikit-learn anomaly detection tutorial
- **gRPC**: Review `src/amoskys/eventbus/server.py` structure
- **Flask API**: Look at existing endpoints in `web/app/__init__.py`
- **Dashboard**: Study `web/app/templates/cortex.html` HTML structure

---

**END OF ASSESSMENT**

**Next**: Pick Step 1 or 2 from "Immediate Next Steps" and execute.
