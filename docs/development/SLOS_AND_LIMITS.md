# AMOSKYS Service Level Objectives & Operational Limits

> **Status:** Active — Created 2026-02-16  
> **Scope:** Measurable performance thresholds for agents and pipeline  
> **Rule:** Every SLO must be testable via `scripts/rig/` tooling

---

## 1. Agent SLOs

### 1.1 Memory (RSS)

| SLO | Target | Measurement | Test |
|-----|--------|-------------|------|
| SLO-MEM-01 | RSS growth < 10 MB over 10 minutes | `ps -o rss=` sampled every 60s | `scripts/rig/soak_test.sh` |
| SLO-MEM-02 | Baseline RSS < 50 MB per agent at steady state | First RSS sample after 60s warm-up | `scripts/rig/profile_agents.sh` |
| SLO-MEM-03 | No OOM kills observed in 1-hour run | dmesg / Console.app (macOS) | Manual verification |

### 1.2 CPU

| SLO | Target | Measurement | Test |
|-----|--------|-------------|------|
| SLO-CPU-01 | Avg CPU < 5% per agent during idle collection | `ps -o %cpu=` over 5-minute window | `scripts/rig/profile_agents.sh` |
| SLO-CPU-02 | CPU spike < 30% during probe execution | Peak `%cpu` during collection cycle | `scripts/rig/profile_agents.sh` |

### 1.3 Availability

| SLO | Target | Measurement | Test |
|-----|--------|-------------|------|
| SLO-AVAIL-01 | Agent survives 10-minute soak without crash | Process alive at end of window | `scripts/rig/soak_test.sh` |
| SLO-AVAIL-02 | Agent survives SIGKILL — queue DB intact | `integrity_check` + `SELECT COUNT(*)` | `scripts/rig/kill_agent_randomly.sh` |
| SLO-AVAIL-03 | Zero tracebacks in agent logs during normal operation | `grep Traceback *.log` | `scripts/rig/soak_test.sh` |

### 1.4 Collection Cadence

| SLO | Target | Measurement | Test |
|-----|--------|-------------|------|
| SLO-CAD-01 | Collection loop completes within configured interval ± 5s | `loop_duration` from agent_metrics | Agent log timestamps |
| SLO-CAD-02 | Metrics telemetry emitted at least once per `metrics_interval` | `agent_metrics` events in queue | `scripts/validate_queue_data.py` |

---

## 2. Pipeline SLOs

### 2.1 Data Integrity

| SLO | Target | Measurement | Test |
|-----|--------|-------------|------|
| SLO-DATA-01 | Zero protobuf decode errors on queue drain | `ParseFromString()` success rate | `tests/pipeline/test_at_least_once.py` |
| SLO-DATA-02 | Idempotency key uniqueness — 0 duplicates per queue | `SELECT idem, COUNT(*) HAVING COUNT(*) > 1` | `tests/pipeline/test_at_least_once.py` |
| SLO-DATA-03 | All security events populate `SecurityEvent` sub-message | `HasField("security_event")` on probe events | `tests/unit/agents/common/test_queue_adapter.py` |
| SLO-DATA-04 | `collection_agent` field non-empty on every message | Queue decode check | `tests/pipeline/test_live_agent_fusion.py` |

### 2.2 Latency

| SLO | Target | Measurement | Test |
|-----|--------|-------------|------|
| SLO-LAT-01 | Event → queue storage < 100ms | Timestamp delta (event_timestamp_ns vs queue ts_ns) | Future instrumentation |
| SLO-LAT-02 | FusionEngine.evaluate_device() < 500ms for 100 events | `last_eval_duration_ms` metric | `tests/pipeline/test_e2e_fusion.py` |

### 2.3 Throughput

| SLO | Target | Measurement | Test |
|-----|--------|-------------|------|
| SLO-THRU-01 | Queue can ingest 100 events/second sustained | Benchmark: `enqueue()` in tight loop, measure wall time | Future benchmark |
| SLO-THRU-02 | Queue backpressure drops oldest when at capacity | `max_size` enforcement | `tests/pipeline/test_at_least_once.py::TestBackpressure` |

---

## 3. Intelligence SLOs

### 3.1 Detection

| SLO | Target | Measurement | Test |
|-----|--------|-------------|------|
| SLO-DET-01 | SSH brute force (≥3 failures + success) → incident | Event injection + evaluate | `tests/pipeline/test_e2e_fusion.py` |
| SLO-DET-02 | Persistence after auth → incident | Event injection + evaluate | `tests/pipeline/test_e2e_fusion.py` |
| SLO-DET-03 | Benign events → 0 incidents (false positive rate = 0%) | Benign scenario injection | `tests/pipeline/test_e2e_fusion.py::TestBenignChecks` |

### 3.2 Scoring

| SLO | Target | Measurement | Test |
|-----|--------|-------------|------|
| SLO-SCORE-01 | Risk score in [0, 100] range | `DeviceRiskSnapshot.score` bounds check | `tests/pipeline/test_e2e_fusion.py` |
| SLO-SCORE-02 | Risk score increases after threat events | Pre/post comparison | `tests/pipeline/test_e2e_fusion.py::TestRiskScore` |
| SLO-SCORE-03 | ScoreJunction confidence in [0.0, 1.0] range | Unit test bounds | `tests/unit/intelligence/test_score_junction.py` |

---

## 4. Operational Limits

### 4.1 Resource Budgets (per agent, t3.micro = 1 vCPU, 1 GB RAM)

| Resource | Budget | Rationale |
|----------|--------|-----------|
| RSS | ≤ 80 MB per agent | 3 agents + fusion + OS ≈ 400 MB, within 1 GB |
| CPU | ≤ 10% sustained per agent | Single core shared by 3 agents + OS |
| Disk (queue) | ≤ 100 MB per queue | Auto-trimmed by backpressure |
| Open FDs | ≤ 50 per agent | SQLite + logs + probe sockets |
| Threads | ≤ 5 per agent | Main + probe threads |

### 4.2 Queue Limits

| Parameter | Default | Configurable | Notes |
|-----------|---------|-------------|-------|
| `max_size` | 10,000 rows | Yes | Oldest dropped when exceeded |
| WAL journal | Always enabled | No | Required for crash recovery |
| Synchronous | NORMAL | No | Balances durability and speed |
| Idem key TTL | Lifetime of row | N/A | Uniqueness enforced by UNIQUE INDEX |

### 4.3 Fusion Limits

| Parameter | Default | Notes |
|-----------|---------|-------|
| `window_minutes` | 30 | Events older than window are trimmed |
| `eval_interval` | 60s | How often rules are evaluated per device |
| Max events per device buffer | Unbounded (trimmed by window) | Consider hard cap at 10,000 |
| Incident DB | SQLite, WAL mode | Single-writer, concurrent reads OK |

---

## 5. Measurement Tools

| Tool | Measures | Usage |
|------|----------|-------|
| `scripts/rig/soak_test.sh` | RSS, crashes, tracebacks, DB integrity over time | `./scripts/rig/soak_test.sh --duration 10` |
| `scripts/rig/profile_agents.sh` | RSS, CPU, FDs, threads at high frequency | `./scripts/rig/profile_agents.sh --duration 5 --sample 10` |
| `scripts/rig/kill_agent_randomly.sh` | Crash recovery, DB integrity after SIGKILL | `./scripts/rig/kill_agent_randomly.sh --rounds 3` |
| `scripts/rig/inject_events.py` | Detection accuracy, false positive rate | `python scripts/rig/inject_events.py --all` |
| `scripts/validate_queue_data.py` | Protobuf decode quality, field completeness | `python scripts/validate_queue_data.py --queue protocol_collectors` |

---

## 6. SLO Validation Status

| SLO ID | Status | Evidence | Date |
|--------|--------|----------|------|
| SLO-MEM-01 | ✅ Validated | soak_test.sh 10-min run: RSS growth < 1 MB post-warmup (stable at ~27 MB) | 2026-02-16 |
| SLO-MEM-02 | ✅ Validated | Steady-state RSS: KA=26 MB, PC=28 MB, DD=29 MB (all < 50 MB) | 2026-02-16 |
| SLO-AVAIL-01 | ✅ Validated | 10-minute soak: all 3 agents alive at end | 2026-02-16 |
| SLO-AVAIL-02 | ✅ Validated | kill_agent_randomly.sh: 3/3 rounds, all DBs intact after kill -9 | 2026-02-16 |
| SLO-AVAIL-03 | ✅ Validated | 0 tracebacks in 10-minute soak logs | 2026-02-16 |
| SLO-DATA-01 | ✅ Validated | 11/11 rows decoded, 0 errors | 2026-02-16 |
| SLO-DATA-02 | ✅ Validated | 0 duplicate idem keys | 2026-02-16 |
| SLO-DATA-03 | ✅ Validated | 67/67 queue_adapter tests pass | 2026-02-16 |
| SLO-DATA-04 | ✅ Validated | GAP-07 fix verified | 2026-02-16 |
| SLO-DET-01 | ✅ Validated | 16/16 e2e_fusion tests pass | 2026-02-16 |
| SLO-DET-02 | ✅ Validated | persistence_after_auth E2E test | 2026-02-16 |
| SLO-DET-03 | ✅ Validated | 3 benign checks, 0 incidents | 2026-02-16 |
| SLO-SCORE-01 | ✅ Validated | risk score bounds in E2E test | 2026-02-16 |
| SLO-SCORE-02 | ✅ Validated | risk score increases test | 2026-02-16 |
| SLO-SCORE-03 | ✅ Validated | 48/48 score_junction tests | 2026-02-16 |
