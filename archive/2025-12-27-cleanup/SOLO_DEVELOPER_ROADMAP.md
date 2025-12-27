# AMOSKYS Solo Developer Roadmap
**Version**: 1.0  
**Status**: Active Production Planning  
**Last Updated**: December 5, 2025  
**Duration**: 6 weeks  
**Constraint**: Solo developer, 4-6 weeks, no large team

---

## 🎯 NORTH STAR VISION

Transform AMOSKYS into a **production-ready neuro-inspired security micro-processor** with ONE unforgettable end-to-end capability:

**Process + System Health Reflex Pipeline:**
```
Raw Telemetry (proc + SNMP) 
    ↓
High-Quality Features (normalize, aggregate)
    ↓
ML Inference (IsolationForest on hero slice)
    ↓
Three-Layer Brain Analysis (Geometric + Temporal + Hero)
    ↓
Explainable Alert with Confidence Scores
    ↓
Live Dashboard with Real-time Reflexes
```

**Success Criteria:**
- ✅ End-to-end: telemetry → features → model → alert → UI
- ✅ Explainability: User knows WHY the system flagged something
- ✅ Production-ready: Handles real data (500k+ points), no crashes
- ✅ Solo-achievable: No distributed consensus, no fancy models, no eBPF

---

## 📊 CURRENT STATE (Baseline)

### What's Already Working ✅
- **6 operational agents**: eventbus, flowagent, proc_agent, snmp_agent, device_scanner, mac_telemetry
- **Core infrastructure**: gRPC + mTLS, SQLite WAL, Prometheus metrics
- **Data volume**: 500k+ process + SNMP snapshots in `data/wal/flowagent.db`
- **Test coverage**: 32/33 passing (97%)
- **Server**: Flask dashboard running on port 5000

### What's BROKEN or MISSING ⚠️
- **Prometheus metric collisions**: Breaks test re-runs in flowagent & eventbus
- **Flaky network tests**: Port 8081 timeout issues (2 tests)
- **No feature pipeline**: Can't feed raw metrics to ML
- **No inference engine**: Models aren't loaded or called
- **No ML models**: No trained anomaly detector
- **No alerts API**: Dashboard can't show detections
- **Three-layer brain**: Only scaffolding, not functional
- **No explainability**: Scores have no reasoning

---

## 🗂️ WORK BREAKDOWN: 6 WEEKS

### PHASE 1: STABILITY FOUNDATION (Weeks 1-2)
**Goal**: Fix immediate blockers, ensure clean test runs, establish baseline

#### 1.1 Fix Prometheus Metric Collisions [P0] ⚠️
**File**: `src/amoskys/agents/flowagent/main.py`  
**File**: `src/amoskys/eventbus/server.py`  
**Impact**: Currently breaks test re-runs  
**Task**:
- [ ] Move metric registration from module-level to delayed init function
- [ ] Use try/except ValueError pattern for collision detection
- [ ] Call init function only in `if __name__ == "__main__"` block
- [ ] Verify: `pytest tests/ -v` passes all 33 tests

**Estimated Effort**: 2 hours

---

#### 1.2 Fix Flaky Network Test Timeouts [P1]
**Files**: `tests/component/test_bus_inflight_metric.py` & `tests/component/test_wal_grow_drain.py`  
**Impact**: Tests pass but occasionally timeout  
**Task**:
- [ ] Increase subprocess timeout from 2s to 5s
- [ ] Add force-kill fallback if process doesn't terminate gracefully
- [ ] Verify: Run full test suite 3 times, all pass

**Estimated Effort**: 1 hour

---

#### 1.3 Add Config Validation [P2]
**File**: `src/amoskys/config.py`  
**Impact**: Fail fast on bad environment variables  
**Task**:
- [ ] Create `validate_config(config)` function
- [ ] Check: port ranges (1-65535), file paths exist, size limits sensible
- [ ] Return: list of error strings or empty list if valid
- [ ] Call on startup before any agents launch
- [ ] Verify: Misconfig errors print clearly before crash

**Estimated Effort**: 1.5 hours

---

#### 1.4 Create Clean Startup Script [P2]
**File**: `scripts/dev-run.sh` or `Makefile`  
**Impact**: One command to start entire system  
**Task**:
- [ ] Create `make dev-up` target (or shell script)
- [ ] Orchestrate: EventBus → agents → web app → health checks
- [ ] Log output to `logs/amoskys.log`
- [ ] Verify: `make dev-up` starts everything without errors

**Estimated Effort**: 2 hours

---

### PHASE 2: HERO SLICE FOUNDATION (Weeks 2-3)
**Goal**: Define the ONE capability you'll ship: Process + SNMP Health Reflex

#### 2.1 Design Hero Signal Contract [P0]
**File**: `docs/HERO_SLICE_PROCESS_SNMP.md` (NEW)  
**Impact**: Clarifies what data we're working with  
**Task**:
- [ ] List 10-20 best features from process + SNMP data
  - CPU percentage (0-100)
  - Memory percentage (0-100)
  - Disk I/O bytes/sec
  - Network throughput bytes/sec
  - Dropped packets count
  - Parent process metadata
  - User/UID mismatch
  - New process (age < 1 hour)
  - New network connection
  - Memory spike (vs baseline)
- [ ] Define label scheme: "benign" vs "anomaly"
- [ ] Expected format: one row per {process_snapshot + SNMP_snapshot}
- [ ] Document: how to join data from flowagent.db

**Estimated Effort**: 1.5 hours

---

#### 2.2 Build Minimal Feature Pipeline [P1]
**File**: `src/amoskys/feature_engineering/hero_process_snmp.py` (NEW)  
**File**: `src/amoskys/feature_engineering/__init__.py` (NEW)  
**Impact**: Normalize raw metrics for ML  
**Task**:
- [ ] Create `HeroFeaturePipeline` class
- [ ] Methods:
  - `normalize_features(proc_rec, snmp_rec)` → normalized dict [0-1]
  - `rolling_avg(window_size_sec)` → compute 5m + 1h rolling means
  - `compute_flags()` → is_new, has_new_parent, net_spike, user_unusual
- [ ] NO full 106-feature framework; just hero slice
- [ ] Test: 10 process+SNMP records normalize without errors

**Estimated Effort**: 3 hours

---

#### 2.3 Train 1 Simple Anomaly Model [P1]
**File**: `notebooks/hero_training.ipynb` (NEW)  
**Impact**: Have an ML model to run inference with  
**Task**:
- [ ] Export 1000+ process+SNMP records from `data/wal/flowagent.db` → CSV
- [ ] Manual label ~20 records (5 benign, 10-15 anomalies)
- [ ] Train `IsolationForest` on engineered features
- [ ] Cross-validate: 10-fold, report precision/recall
- [ ] Export model: `models/hero_process_snmp_iforest.pkl`
- [ ] Test: Model loads, runs inference on 1 record

**Estimated Effort**: 4 hours

---

#### 2.4 Wire Model → Alert → API → UI [P1]
**File**: `src/amoskys/analysis/hero_reflex_engine.py` (NEW)  
**File**: `web/app/api/alerts.py` (NEW)  
**Impact**: Model predictions visible in dashboard  
**Task**:
- [ ] Create `HeroReflexEngine` class
  - Load trained model on startup
  - Method: `analyze(proc_rec, snmp_rec)` → alert dict
  - Return: alert_id, confidence (0-1), severity (LOW/MED/HIGH/CRIT), reason_text
- [ ] Emit AlertEvent to EventBus on each analysis
- [ ] Create REST API: `GET /api/alerts/recent?limit=50&severity=HIGH`
- [ ] Update Cortex dashboard: show live alerts with colored severity badges
- [ ] Test: Trigger synthetic alert, see it in UI

**Estimated Effort**: 5 hours

---

### PHASE 3: THREE-LAYER BRAIN (Weeks 4-5)
**Goal**: Add Geometric + Temporal analyzers, fuse scores

#### 3.1 Light Geometric Analyzer [P2]
**File**: `src/amoskys/analysis/geometric_analyzer.py` (NEW)  
**Impact**: Detect graph anomalies (process topology, privilege crossing)  
**Task**:
- [ ] Create `GeometricAnalyzer` class
- [ ] Rules:
  - Check: parent PID in allowed_parents[process_name]?
  - Check: user/UID unexpected for this process?
  - Check: process spawned from unusual parent?
- [ ] Return: 0.0-1.0 anomaly score + reason string
- [ ] No models needed; just rule-based logic
- [ ] Test: 10 normal procs → low score, 5 anomalous → high score

**Estimated Effort**: 3 hours

---

#### 3.2 Light Temporal Analyzer [P2]
**File**: `src/amoskys/analysis/temporal_analyzer.py` (NEW)  
**Impact**: Detect rate spikes, unusual patterns over time  
**Task**:
- [ ] Create `TemporalAnalyzer` class
- [ ] Maintain rolling 5-minute baseline window
- [ ] Compute Z-score for each metric vs baseline
- [ ] Rule: if |z| > 3 on CPU AND network simultaneously → anomaly
- [ ] Return: 0.0-1.0 anomaly score + reason string
- [ ] NO LSTM; just rolling averages + statistical tests
- [ ] Test: Generate spike, detect it

**Estimated Effort**: 3 hours

---

#### 3.3 Fusion Engine + Explainability [P2]
**File**: `src/amoskys/analysis/fusion_engine.py` (NEW)  
**Impact**: Combine layer scores into final decision  
**Task**:
- [ ] Create `AnalysisFusionEngine` class
- [ ] Method: `fuse(geo_score, temp_score, hero_score)` → final decision
- [ ] Weights: Geometric 0.2, Temporal 0.3, Hero 0.5
- [ ] Return:
  - final_confidence (0-1)
  - severity (LOW/MED/HIGH/CRIT)
  - per_layer_scores: {geometric: 0.1, temporal: 0.2, hero: 0.8}
  - per_layer_reasons: ["rule: parent unexpected", "z-score 4.2", "iforest anomaly"]
- [ ] Update AlertEvent: include layer breakdown
- [ ] Update dashboard: expandable "Layer Scores" section
- [ ] Test: All three layers vote, see fusion result

**Estimated Effort**: 4 hours

---

### PHASE 4: POLISH & VISION (Week 6)
**Goal**: Documentation, demo, future roadmap

#### 4.1 Create Vision Document [P3]
**File**: `docs/TRACTS.md` (NEW)  
**Impact**: Clarify R&D areas post-MVP  
**Task**:
- [ ] Define 4-5 future "TRACT" areas (research directions)
  - TRACT-1: Syscall Axon (eBPF syscall tracing, deep behavior)
  - TRACT-2: Memory Anomaly Detector (allocation pattern analysis)
  - TRACT-3: Cross-Host Geometric Brain (federation, correlation)
  - TRACT-4: Windows ETW Agent (extend to Windows)
  - TRACT-5: Drift Detection (model retraining, concept drift)
- [ ] For each: 5-10 lines describing purpose + integration points
- [ ] Document: How each plugs into AnalysisFusionEngine
- [ ] Estimate: effort + timeline for each TRACT

**Estimated Effort**: 2 hours

---

#### 4.2 Final Testing & Validation [P2]
**File**: All integration tests  
**Impact**: Ensure everything works end-to-end  
**Task**:
- [ ] Run full test suite: `pytest tests/ -v`
- [ ] Manual testing: 
  - Start system with `make dev-up`
  - Generate synthetic process spike
  - Verify alert appears in dashboard
  - Check layer breakdown is visible
- [ ] Performance check:
  - Inference latency < 100ms
  - Dashboard responsive with 50+ alerts
  - Memory stable over 1 hour

**Estimated Effort**: 2 hours

---

#### 4.3 Documentation & Demo Video [P3]
**File**: `docs/HERO_SLICE_DEMO.md` (NEW)  
**Impact**: Show the world what you built  
**Task**:
- [ ] Write 1-page demo walkthrough:
  - Normal system baseline
  - Trigger synthetic anomaly (process spike, network flood, privilege escalation)
  - Alert appears in real-time
  - Show layer breakdown (why it fired)
  - Show confidence score
- [ ] Record 3-5 min demo video:
  - Dashboard before anomaly
  - Terminal trigger command
  - Dashboard with live alert
  - Narrate: "AMOSKYS detects threats via neuro-inspired layer breakdown"
- [ ] Link to GitHub releases / YouTube

**Estimated Effort**: 3 hours

---

## 📋 DETAILED TASK LIST (In Priority Order)

### Must-Do (Will immediately unblock progress)

| # | Task | File(s) | Effort | Status |
|---|------|---------|--------|--------|
| 1 | Fix Prometheus metric collisions | flowagent/main.py, eventbus/server.py | 2h | ⏳ |
| 2 | Fix flaky test timeouts | test_bus_inflight_metric.py, test_wal_grow_drain.py | 1h | ⏳ |
| 3 | Add config validation function | config.py | 1.5h | ⏳ |
| 4 | Design hero signal contract doc | docs/HERO_SLICE_PROCESS_SNMP.md | 1.5h | ⏳ |
| 5 | Build minimal feature pipeline | feature_engineering/hero_process_snmp.py | 3h | ⏳ |
| 6 | Train IsolationForest model | notebooks/hero_training.ipynb | 4h | ⏳ |
| 7 | Wire model to API & dashboard | analysis/hero_reflex_engine.py, web/app/api/alerts.py | 5h | ⏳ |

### Should-Do (Adds significant value)

| # | Task | File(s) | Effort | Status |
|---|------|---------|--------|--------|
| 8 | Build geometric analyzer | analysis/geometric_analyzer.py | 3h | ⏳ |
| 9 | Build temporal analyzer | analysis/temporal_analyzer.py | 3h | ⏳ |
| 10 | Build fusion engine | analysis/fusion_engine.py | 4h | ⏳ |
| 11 | Create TRACTS vision doc | docs/TRACTS.md | 2h | ⏳ |
| 12 | Full end-to-end validation | all components | 2h | ⏳ |

### Nice-to-Have (If time permits)

| # | Task | File(s) | Effort | Status |
|---|------|---------|--------|--------|
| 13 | Demo video + narration | docs/HERO_SLICE_DEMO.md | 3h | ⏳ |
| 14 | Performance optimization | various | variable | ⏳ |
| 15 | Additional model types (XGBoost, LSTM) | notebooks/ | variable | ⏳ |

---

## 🧠 CONTEXT YOU'LL NEED FOR EACH TASK

### Task 1: Fix Prometheus Collisions
**Context**:
- Problem: Metrics registered at module import, breaking on test re-runs
- Solution: Delay registration until main() block
- Code pattern: `try: Counter(...) except ValueError: pass`
- Files: `src/amoskys/agents/flowagent/main.py` lines 48-75, `src/amoskys/eventbus/server.py` lines 106-110

### Task 2: Fix Flaky Timeouts
**Context**:
- Problem: `subprocess.wait(timeout=2)` too short for slow CI
- Solution: Increase to 5s + add force-kill fallback
- Files: `tests/component/test_bus_inflight_metric.py` & `test_wal_grow_drain.py`

### Task 3: Config Validation
**Context**:
- Need: Check port ranges, file existence, size limits
- Pattern: Return list of error strings, call on startup
- Benefits: Clear error messages before crash

### Task 4: Hero Signal Contract
**Context**:
- Look at: `data/wal/flowagent.db` schema
- Features needed: CPU, memory, network, process metadata
- Label scheme: benign vs anomaly
- This is design doc, no code yet

### Task 5: Feature Pipeline
**Context**:
- Input: Raw {proc_rec, snmp_rec}
- Output: Normalized dict [0-1] with engineered features
- Methods: normalize, rolling_avg, compute_flags
- Test with: 10 records from database

### Task 6: Train Model
**Context**:
- Data source: `data/wal/flowagent.db` via SQL export
- Model: IsolationForest (simple, fast, no tuning needed)
- Labels: Manual label ~20 records (5 benign, 10-15 anomalies)
- Output: `models/hero_process_snmp_iforest.pkl`
- Test: Load model, run inference

### Task 7: Wire Model → UI
**Context**:
- HeroReflexEngine: Load model, run analyze(proc, snmp) → alert dict
- AlertEvent: New event type on EventBus
- REST API: `GET /api/alerts/recent?limit=50&severity=HIGH`
- Dashboard: Show alerts with colored badges + confidence scores

### Task 8: Geometric Analyzer
**Context**:
- Input: Features dict
- Logic: Rule-based (parent PID check, user check, privilege crossing)
- Output: 0.0-1.0 score + reason string
- No ML needed; just rule logic

### Task 9: Temporal Analyzer
**Context**:
- Input: Features dict + rolling history
- Logic: Z-score vs 5-min baseline
- Rule: |z| > 3 on 2+ metrics simultaneously → anomaly
- Output: 0.0-1.0 score + reason string
- NO LSTM; statistical tests only

### Task 10: Fusion Engine
**Context**:
- Input: geo_score, temp_score, hero_score (all 0-1)
- Weights: 0.2, 0.3, 0.5
- Output: final_confidence, severity, per_layer breakdown
- Dashboard: Show layer breakdown (why system flagged event)

### Task 11: TRACTS Vision Doc
**Context**:
- Future research areas (syscall eBPF, memory analysis, federation, etc.)
- 5 TRACTs, 5-10 lines each
- Show how each integrates with AnalysisFusionEngine
- Effort + timeline estimates

### Task 12: End-to-End Validation
**Context**:
- Start system: `make dev-up`
- Trigger synthetic anomaly (CPU spike, process spawn, etc.)
- Verify: Alert appears in dashboard with layer breakdown
- Performance: Inference < 100ms, UI responsive

---

## 🚨 DO NOT DO (You'll waste time)

❌ **eBPF Syscall Tracing** (yet) – Save for TRACT-1 post-MVP  
❌ **LSTM / GNN models** – IsolationForest is sufficient  
❌ **Distributed consensus** – Single-node for now  
❌ **Multi-tenancy** – Solo developer, one tenant  
❌ **Windows agents** – macOS/Linux first, Windows is TRACT-4  
❌ **Full 106-feature framework** – Hero slice only  
❌ **Model drift detection** – Post-MVP  
❌ **A/B testing** – Not needed for MVP  

---

## 📈 SUCCESS METRICS

### By End of Week 2 (Stability)
- ✅ All 33 tests pass cleanly, no flakes
- ✅ `make dev-up` starts system in < 10 seconds
- ✅ Config validation catches bad env vars with clear errors

### By End of Week 4 (Hero Slice)
- ✅ IsolationForest model trained, saves to disk
- ✅ Hero reflex engine loads model, runs inference on test record
- ✅ Dashboard shows mock alerts with confidence scores
- ✅ API endpoint `GET /api/alerts/recent` returns JSON

### By End of Week 6 (Three-Layer Brain)
- ✅ Geometric analyzer returns scores + reasons
- ✅ Temporal analyzer detects rate spikes
- ✅ Fusion engine fuses all three layers
- ✅ Dashboard shows per-layer breakdown
- ✅ End-to-end: telemetry → model → alert → UI (working)

---

## 🔧 HOW TO USE THIS ROADMAP

### Step 1: Review Each Phase
Read through all phases, understand the flow.

### Step 2: Work Task by Task
For each task:
1. Read the task description
2. Review the context section
3. Implement the code
4. Write tests
5. Mark ✅ when done

### Step 3: Commit After Each Task
```bash
git add .
git commit -m "feat: Task N - <description>"
git push origin main
```

### Step 4: If Stuck
Check the context section for that task; it has breadcrumbs pointing to:
- Which files to modify
- What the input/output should be
- How to test it

### Step 5: After Phase Complete
Run full test suite:
```bash
pytest tests/ -v
```

If anything breaks, fix before moving to next phase.

---

## 🎬 GETTING STARTED TODAY

If you're starting fresh right now:

1. **Pick Task 1 or 4 based on mood:**
   - **Task 1 (2h)**: Fix metrics collision → all tests green
   - **Task 4 (1.5h)**: Write design doc → clarify scope

2. **Do Task 3 while tests run** (config validation)

3. **Then Task 5** (feature pipeline) – real implementation

4. **You'll have hero slice by Thursday**

---

## 📞 DECISION POINTS

**If you get stuck on:**

| Blocker | Decision |
|---------|----------|
| Model training takes too long | Use pre-trained model, skip tuning |
| Dashboard integration unclear | Build mock API first, UI second |
| Need real anomalies to test? | Generate synthetic spikes (CPU, network) |
| Prometheus issues persist? | Disable metrics temporarily, move on |
| Feature engineering is hard? | Start with just {cpu, memory, net_bytes} |

---

## 📚 REFERENCES & DATA

### Available Data
- **Process + SNMP records**: `data/wal/flowagent.db` (~500k rows)
- **Schema info**: Run `SELECT * FROM processes LIMIT 1;` to see structure
- **Export for training**: `sqlite3 data/wal/flowagent.db "SELECT * FROM processes LIMIT 1000;" > /tmp/hero_data.csv`

### Code References
- **EventBus pattern**: `src/amoskys/eventbus/server.py`
- **Agent pattern**: `src/amoskys/agents/flowagent/main.py`
- **Dashboard**: `web/app/templates/cortex.html`
- **Test examples**: `tests/component/test_bus_inflight_metric.py`

### Third-Party Libraries (Already Available)
- Prometheus client: `prometheus_client`
- ML: `scikit-learn` (IsolationForest)
- Data: `pandas`, `sqlite3`
- Model: `joblib` for save/load
- API: `flask`, `flask-restx`

---

## ⏰ WEEK-BY-WEEK BREAKDOWN

### Week 1
- **Monday**: Task 1 (Prometheus fix)
- **Tuesday**: Task 2 (Flaky tests)
- **Wednesday**: Task 3 (Config validation)
- **Thursday**: Task 4 (Hero signal contract)
- **Friday**: All tests pass, no blockers

### Week 2
- **Monday-Wednesday**: Task 5 (Feature pipeline)
- **Thursday-Friday**: Task 6 (Train model)

### Week 3
- **Mon-Tue**: Task 7 (Wire model → API → UI)
- **Wed-Thu**: Task 8 (Geometric analyzer)
- **Friday**: Integration testing

### Week 4
- **Mon-Tue**: Task 9 (Temporal analyzer)
- **Wed-Thu**: Task 10 (Fusion engine)
- **Friday**: All three layers working

### Week 5
- **Mon-Wed**: Task 12 (End-to-end validation)
- **Thu-Fri**: Performance tuning + fixes

### Week 6
- **Mon-Tue**: Task 11 (TRACTS vision doc)
- **Wed-Thu**: Task 13 (Demo video)
- **Friday**: Final polish, push to main

---

## 🏁 FINAL CHECKLIST (Before "Done")

- [ ] All 33 tests pass
- [ ] `make dev-up` starts system in < 10s
- [ ] Hero feature pipeline works on 10 test records
- [ ] IsolationForest model trains and loads
- [ ] Hero reflex engine runs inference
- [ ] Dashboard shows mock alerts with scores
- [ ] API endpoint returns alerts in JSON
- [ ] Geometric analyzer returns scores + reasons
- [ ] Temporal analyzer detects spikes
- [ ] Fusion engine fuses all layers
- [ ] Dashboard shows per-layer breakdown
- [ ] End-to-end: data → features → model → alert → UI (verified)
- [ ] TRACTS document written
- [ ] Demo video recorded + linked
- [ ] All code committed with clear messages
- [ ] README updated with new features

---

**When all items are ✅, you're done. Ship it.**

---

## APPENDIX A: File Structure (New Files to Create)

```
AMOSKYS/
├── docs/
│   ├── HERO_SLICE_PROCESS_SNMP.md          (NEW - Design contract)
│   ├── HERO_SLICE_DEMO.md                  (NEW - Demo walkthrough)
│   └── TRACTS.md                            (NEW - Vision + future TRACTs)
├── src/amoskys/
│   ├── feature_engineering/                 (NEW - Module)
│   │   ├── __init__.py
│   │   └── hero_process_snmp.py
│   └── analysis/                            (NEW - Module)
│       ├── __init__.py
│       ├── hero_reflex_engine.py
│       ├── geometric_analyzer.py
│       ├── temporal_analyzer.py
│       └── fusion_engine.py
├── web/app/api/
│   └── alerts.py                            (NEW - Alert REST API)
├── models/
│   └── hero_process_snmp_iforest.pkl        (CREATED BY TASK 6)
├── notebooks/
│   └── hero_training.ipynb                  (NEW - Model training)
├── scripts/
│   └── dev-run.sh                           (NEW - Startup script)
└── Makefile                                 (UPDATE - Add dev-up target)
```

---

**END OF ROADMAP**
