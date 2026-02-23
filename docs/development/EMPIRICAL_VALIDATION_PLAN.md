# AMOSKYS Empirical Validation Plan

> **Status:** Active — Created 2026-02-16 from Mac Lab empirical run  
> **Scope:** What works today, what doesn't, what "validated" means  
> **Rule:** No feature development until claims in this document are proven or disproven

---

## 0. Validation Claims Register

Each claim is testable. Each has a component, evidence needed, test method, metric, and pass/fail threshold.

### Agent Lifecycle Claims (CL-01 through CL-05)

| ID | Claim | Component(s) | Evidence | Test Method | Metric | Pass/Fail | Env |
|----|-------|-------------|----------|-------------|--------|-----------|-----|
| CL-01 | KernelAuditAgentV2 starts, registers 7 probes, enters 30s collection loop without crash | `kernel_audit_agent_v2.py`, `base.py`, `probes.py` | Agent log shows "7 probes active", `loops_started` increments | `run_trinity_local.sh` → check log + queue metrics | `loops_started ≥ 3` after 90s, 0 crashes | **PASS** ✅ (validated 2026-02-16: 7 loops, 0 failures) | Mac |
| CL-02 | ProtocolCollectorsV2 starts, registers 10 probes, enters 30s collection loop, produces probe events from stub collector | `protocol_collectors_v2.py`, `StubProtocolCollector` | Agent log shows "10 probes active", queue contains `protocol_threat` events | `run_trinity_local.sh` → decode queue | `probe_events_emitted ≥ 1` per cycle | **PASS** ✅ (validated 2026-02-16: 7 probe events in 7 loops) | Mac |
| CL-03 | DeviceDiscoveryV2 starts, registers 6 probes, enters 30s collection loop | `device_discovery_v2.py`, `probes.py` | Agent log shows "6 probes ready", metrics increment | `run_trinity_local.sh` → check log + queue | `loops_started ≥ 3`, 0 crashes | **PASS** ✅ (validated 2026-02-16: 7 loops, 0 failures) | Mac |
| CL-04 | Agent emits `agent_metrics` telemetry every `metrics_interval` seconds via `queue_adapter` | `base.py` `_maybe_emit_metrics_telemetry()` | Queue DB contains `agent_metrics` events with populated attributes | Decode queue protobuf, check attributes dict | All of `loops_started`, `loops_succeeded`, `events_emitted`, `last_success_ns` present and non-empty | **PASS** ✅ (validated 2026-02-16: all 3 agents emit complete metrics) | Mac |
| CL-05 | Agent survives SIGTERM gracefully — no corrupt SQLite, no zombie processes | `base.py` `_handle_signal()` | `kill -TERM <pid>` → agent stops, queue DB is readable | Kill agents, then `sqlite3 <db> "SELECT COUNT(*) FROM queue"` succeeds | DB readable, 0 zombies | **PASS** ✅ (validated 2026-02-16: clean kill, DBs readable) | Mac |

### Data Pipeline Claims (CL-06 through CL-11)

| ID | Claim | Component(s) | Evidence | Test Method | Metric | Pass/Fail | Env |
|----|-------|-------------|----------|-------------|--------|-----------|-----|
| CL-06 | `LocalQueue` stores protobuf-serialized `DeviceTelemetry` in SQLite WAL mode with idempotency keys | `local_queue.py`, `queue_adapter.py` | Queue DB has `queue` table, `idem` column, WAL journal | Check schema + journal_mode pragma | `UNIQUE INDEX queue_idem` exists, `journal_mode=wal` | **PASS** ✅ (validated 2026-02-16: schema verified, idem index present) | Mac |
| CL-07 | `LocalQueueAdapter.enqueue()` generates unique idempotency keys in format `{agent}:{device}:{ts_ns}:{seq}` | `queue_adapter.py` | Decode `idem` column values from queue DB | `SELECT idem FROM queue LIMIT 5` | All keys match pattern, no duplicates | **PASS** ✅ (validated 2026-02-16: keys verified) | Mac |
| CL-08 | Protobuf `DeviceTelemetry` round-trips correctly: serialize → SQLite → deserialize with all fields intact | `universal_telemetry.proto`, `queue_adapter.py` | Decode stored blobs, verify `device_id`, `collection_agent`, `events`, `attributes` | Python decode script against live queue | `ParseFromString()` succeeds on 100% of rows, `device_id` matches | **PASS** ✅ (validated 2026-02-16: 11/11 protocol_collectors rows decoded, 0 errors) | Mac |
| CL-09 | EventBus gRPC deduplication cache rejects duplicate `idem_key` within TTL window | `eventbus/server.py` `DeduplicationCache` | Unit test with same key twice | `test_eventbus_core.py` | Second lookup returns `True` (seen) | **PASS** ✅ (16/16 unit tests) | Mac |
| CL-10 | Circuit breaker transitions CLOSED→OPEN after `failure_threshold` failures, OPEN→HALF_OPEN after timeout | `base.py` `CircuitBreaker` | Unit test state transitions | `test_hardened_base.py` | All 11 circuit breaker tests pass | **PASS** ✅ (33/33 unit tests) | Mac |
| CL-11 | `protocol_threat` events emitted by ProtocolCollectors probes populate `SecurityEvent` protobuf sub-message with category, MITRE techniques, risk_score, source_ip, and analyst_notes | `protocol_collectors_v2.py`, `queue_adapter.py` `_dict_to_telemetry()` | Decode queue, check `HasField("security_event")` | `test_queue_adapter.py` (67 tests) | `security_event` populated, `collection_agent` set | **PASS** ✅ (fixed 2026-02-16: GAP-01 + GAP-07 resolved, 67/67 tests pass, 94% coverage) | Mac |

### Threat Detection Claims (CL-12 through CL-17)

| ID | Claim | Component(s) | Evidence | Test Method | Metric | Pass/Fail | Env |
|----|-------|-------------|----------|-------------|--------|-----------|-----|
| CL-12 | `SuspiciousPathDetector` flags execution from `/tmp`, `/dev/shm`, hidden dirs, and suspicious extensions | `threat_detection.py` | Unit tests with known-bad paths | `test_threat_detection.py` | 11/11 path tests pass | **PASS** ✅ | Mac |
| CL-13 | `LOLBinDetector` identifies `osascript`, `curl\|sh`, `bash` reverse shells, `python` socket abuse, `nc` listeners | `threat_detection.py` | Unit tests with command strings | `test_threat_detection.py` | 8/8 LOLBin tests pass, safe commands not flagged | **PASS** ✅ | Mac |
| CL-14 | `ReverseShellDetector` detects `bash /dev/tcp`, python reverse shell, `nc -e`, `mkfifo` patterns | `threat_detection.py` | Unit tests with command patterns | `test_threat_detection.py` | 7/7 tests pass, normal SSH not flagged | **PASS** ✅ | Mac |
| CL-15 | `PersistenceDetector` detects LaunchAgent/Daemon creation, cron modification, bashrc writes | `threat_detection.py` | Unit tests with file paths | `test_threat_detection.py` | 6/6 tests pass | **PASS** ✅ | Mac |
| CL-16 | `C2Detector` identifies known C2 ports, beaconing patterns (60s intervals), high outbound traffic ratio | `threat_detection.py` | Unit tests with network context | `test_threat_detection.py` | 6/6 tests pass, normal HTTPS not flagged | **PASS** ✅ | Mac |
| CL-17 | `ThreatAnalyzer.analyze_*` returns structured `ThreatIndicator` objects with MITRE `AttackPhase`, confidence score, and evidence strings | `threat_detection.py` | Unit tests on analyzer output shape | `test_threat_detection.py` | 7/7 analyzer tests pass, summary contains `indicators`, `max_confidence`, `attack_phases` | **PASS** ✅ | Mac |

### Intelligence Layer Claims (CL-18 through CL-22)

| ID | Claim | Component(s) | Evidence | Test Method | Metric | Pass/Fail | Env |
|----|-------|-------------|----------|-------------|--------|-----------|-----|
| CL-18 | `FusionEngine` maintains per-device event buffers within a configurable time window and trims expired events | `fusion_engine.py` | Unit test: add events, advance time past window, verify trim | `test_e2e_fusion.py::TestBufferTrimming` | Buffer contains only events within `window_minutes` | **PASS** ✅ (validated: buffer trimming tests pass in test_e2e_fusion.py) | Mac |
| CL-19 | `FusionEngine.evaluate()` runs rule-based detection and emits `Incident` objects with MITRE technique IDs | `fusion_engine.py`, `rules.py`, `advanced_rules.py` | End-to-end test with live agents | `test_live_agent_fusion.py` (10 tests) | Tests pass, incidents have `techniques` field | **PASS** ✅ (validated: 10/10 live agent fusion tests pass, end-to-end with real agent data) | Mac |
| CL-20 | `ScoreJunction` computes per-device `ThreatScore` in range [0, 100] with confidence in [0, 1] from correlated events | `score_junction.py` | Unit tests cover EventBuffer, CorrelationEngine, ScoreJunction, process_telemetry | `test_score_junction.py` (48 tests) | Score in range, confidence bounded, threat levels correct | **PASS** ✅ (fixed 2026-02-16: GAP-05 resolved, 48/48 tests pass. Fixed 3 proto bugs: HasField on scalar, alert_data→alarm_data, additional_context→attributes) | Mac |
| CL-21 | Fusion → Incident → Alert pipeline produces an alert with MITRE mapping and evidence event IDs | Full pipeline | End-to-end integration test | `test_e2e_fusion.py` | Alert contains `incident_id`, `techniques[]`, `event_ids[]` | **PASS** ✅ (validated: end-to-end fusion pipeline tests pass in test_e2e_fusion.py) | Mac |
| CL-22 | Alert explanations contain traceable evidence: every claim maps to a specific event ID or rule ID | Explanation generation | Review explanation output format | Needs `tests/explain/test_explain_bundle.py` | 0 unsourced sentences in explanation | **NOT IMPLEMENTED** — no explanation generator exists yet | N/A |

### Operational Claims (CL-23 through CL-25)

| ID | Claim | Component(s) | Evidence | Test Method | Metric | Pass/Fail | Env |
|----|-------|-------------|----------|-------------|--------|-----------|-----|
| CL-23 | 3 Trinity agents run concurrently for 10+ minutes on macOS without memory leak or crash | All V2 agents | `ps aux` RSS monitoring over time | `soak_test.sh` (10-min run) + `test_soak_agents.py` (pytest) | RSS growth < 10MB over 10 min (post-warmup), 0 crashes | **PASS** ✅ (validated: 10-min soak_test.sh completed — all agents alive, 0 tracebacks, DBs intact, RSS stable post-warmup. pytest soak also passes with warmup-skip fix) | Mac |
| CL-24 | `lab_check.sh` gates deployment: all 10 checks pass before any `ssh -i ~/.ssh/amoskys-deploy` | `lab_check.sh` | Run gate check | `bash scripts/lab_check.sh` | 10/10 PASSED | **PASS** ✅ (validated 2026-02-16) | Mac |
| CL-25 | Queue data survives agent crash: kill -9 agent, restart, queue DB is intact and readable | `local_queue.py` WAL mode | Kill -9, restart, read queue | `kill_agent_randomly.sh` (3 rounds) + `test_soak_agents.py::test_crash_recovery_kill9` | `SELECT COUNT(*) FROM queue` succeeds after kill -9 | **PASS** ✅ (validated: 3 chaos test rounds — random agent killed each round, survivors alive, all DBs intact. pytest kill-9 test also passes) | Mac |

---

## 1. Validation Phases

### Phase 1: Foundation (Current — P0/P1 complete)
**Goal:** Prove agents start, collect, and store data correctly on Mac.

| Task | Status | Evidence |
|------|--------|----------|
| Trinity agents launch and run | ✅ Done | Logs + queue data from 2026-02-16 run |
| Unit tests pass (462/462) | ✅ Done | `lab_check.sh` 10/10 |
| Protobuf round-trip works | ✅ Done | `validate_queue_data.py` decoded 11 rows, 0 errors |
| Entry points resolve | ✅ Done | 3/3 entry points importable |
| mypy config consolidated | ✅ Done | Single source in `pyproject.toml` |

### Phase 2: Data Integrity (Next)
**Goal:** Prove the pipeline doesn't lose, duplicate, or corrupt events.

| Task | Status | Deliverable |
|------|--------|-------------|
| At-least-once delivery test | ✅ Done (18/18 pass) | `tests/pipeline/test_at_least_once.py` |
| Ordering-per-device-stream test | ✅ Included in at-least-once (FIFO test) | `tests/pipeline/test_at_least_once.py::test_fifo_ordering` |
| Crash recovery test (kill -9 → restart → verify) | ✅ Done (2 tests) | `tests/pipeline/test_at_least_once.py::TestCrashRecovery` |
| Idempotent write test (duplicate idem key rejected) | ✅ Done (3 tests) | `tests/pipeline/test_at_least_once.py::TestIdempotentWrites` |
| 10-minute soak test with RSS monitoring | ✅ Done | `scripts/rig/soak_test.sh` + `tests/soak/test_soak_agents.py` |

### Phase 3: Detection Accuracy
**Goal:** Prove that probe rules fire correctly on known-good and known-bad inputs.

| Task | Status | Deliverable |
|------|--------|-------------|
| Scenario suite (15-30 scenarios) | Not started | `docs/validation/SCENARIO_SUITE.md` |
| MITRE mapping validation | Not started | `docs/validation/MITRE_MAPPING_VALIDATION.md` |
| False positive baseline (developer workstation) | Not started | 1-hour benign run, count alerts |
| Probe-level accuracy tests (per-probe ground truth) | Partial (unit tests exist for threat_detection) | Expand to all 67 probes |

### Phase 4: Intelligence & Scoring
**Goal:** Prove fusion, scoring, and explanation are deterministic and evidence-backed.

| Task | Status | Deliverable |
|------|--------|-------------|
| ScoreJunction contract test | ✅ Done (48/48 pass) | `tests/unit/intelligence/test_score_junction.py` |
| FusionEngine end-to-end test | ✅ Done (test_e2e_fusion + test_live_agent_fusion) | `tests/pipeline/test_e2e_fusion.py`, `tests/pipeline/test_live_agent_fusion.py` |
| Explanation quality gate | Not started | `docs/validation/EXPLANATION_QUALITY_GATES.md` |
| Explanation regression tests | Not started | `tests/explain/test_explain_bundle.py` |

### Phase 5: Operational Readiness
**Goal:** Measure performance, define SLOs, validate recovery paths.

| Task | Status | Deliverable |
|------|--------|-------------|
| SLOs defined | ✅ Done | `docs/validation/SLOS_AND_LIMITS.md` |
| Agent resource profiling | ✅ Done | `scripts/rig/profile_agents.sh` |
| Chaos testing (random agent kill) | ✅ Done (3 rounds) | `scripts/rig/kill_agent_randomly.sh` |
| Reproducibility standards | ✅ Done | `docs/validation/REPRODUCIBILITY.md` |

---

## 2. Known Gaps (Empirically Discovered 2026-02-16)

### GAP-01: ~~`protocol_threat` events have no structured security data~~ **RESOLVED ✅**
- **What:** ProtocolCollectors probes produced events with `event_type=protocol_threat`, `severity=MEDIUM`, but `attributes={}`, `tags=[]`, `security_event` not populated.
- **Why:** `_dict_to_telemetry()` in `queue_adapter.py` mapped only `metric_data`, not probe-specific threat fields.
- **Fix applied (2026-02-16):** Extended `_dict_to_telemetry()` with `_populate_security_event()` helper. Now maps MITRE techniques, source/dest IPs, category, confidence→risk_score, description→analyst_notes. Added `_SECURITY_EVENT_TYPES` frozenset (12 event types). Flattens `data` dict into `attributes`. Validated by 67 unit tests (94% coverage).

### GAP-02: KernelAudit produces 0 probe events on macOS
- **What:** `events_emitted=0`, `probe_events_emitted=0` on all cycles.
- **Why:** macOS has no `/var/log/audit/audit.log`. AuditdLogCollector returns empty. No macOS-native audit source exists in the codebase.
- **Impact:** KernelAudit is Linux-only. On Mac lab, it exercises the lifecycle but produces no threat telemetry.
- **Acceptable for now:** Mac lab validates infrastructure. Real KernelAudit testing requires Linux (EC2 or container).

### GAP-03: DeviceDiscovery produces 0 probe events on macOS
- **What:** `events_emitted=0`, `probe_events_emitted=0`.
- **Why:** ARP probe uses `ip neigh show` (Linux) and `/proc/net/arp` (Linux). Both fail silently on macOS.
- **Impact:** Same as GAP-02 — lifecycle validated but no probe output.
- **Fix (optional):** Add `arp -a` fallback for macOS in ARPDiscoveryProbe.

### GAP-04: No end-to-end pipeline test exists
- **What:** No test validates Agent → Queue → FusionEngine → Incident → Alert.
- **Why:** Components were built independently with mock interfaces.
- **Impact:** Can't prove the full pipeline works without manual orchestration.

### GAP-05: ~~ScoreJunction has 0 tests~~ **RESOLVED ✅**
- **What:** `score_junction.py` (520 LOC) computes `ThreatScore` objects but had no test file.
- **Fix applied:** Rebuilt `tests/unit/intelligence/test_score_junction.py` from scratch — 48 tests covering CorrelatedEvent, EventBuffer, CorrelationEngine, ScoreJunction, ThreatScore, and GAP-05 regression guards. Also fixed 3 proto bugs in `score_junction.py`: removed `HasField("numeric_value")` (proto3 scalar), `alert_data`→`alarm_data`, `additional_context`→`attributes`.
- **Validation:** 48/48 tests pass, all GAP-05 regression guards green.

### GAP-06: Explanation generation doesn't exist
- **What:** No component generates human-readable alert explanations with evidence tracing.
- **Impact:** CL-22 cannot be validated until an explanation generator is built.

### GAP-07: `collection_agent` field empty on probe events
- **What:** `protocol_threat` events decoded from queue have `collection_agent=""` (empty string).
- **Why:** When ProtocolCollectors' `collect_data()` builds event dicts and they're converted by `queue_adapter._dict_to_telemetry()`, the `collection_agent` field is set from `event.get("collection_agent", "")` which isn't in the dict.
- **Fix:** Set `collection_agent` in `_dict_to_telemetry()` from `self.agent_name` instead of relying on the dict.

---

## 3. Truth Harness Requirements

### 3.1 Minimal Test Rig

| Deliverable | Purpose | Status |
|-------------|---------|--------|
| `scripts/run_trinity_local.sh` | Launch 3 agents on Mac | ✅ Exists, validated |
| `scripts/validate_queue_data.py` | Decode and inspect queue protobuf | ✅ Exists, validated |
| `scripts/lab_check.sh` | Pre-deploy gate (10 checks) | ✅ Exists, 10/10 |
| `scripts/rig/generate_events.py` | Synthetic event generator for controlled testing | ✅ Exists, validated |
| `scripts/rig/replay_events.py` | Replay recorded event streams through pipeline | ❌ Not started |

### 3.2 Ground Truth Sources

| Telemetry Family | Ground Truth Source (Mac) | Ground Truth Source (Linux) | Status |
|-----------------|--------------------------|---------------------------|--------|
| Process events | `ps`, `lsof`, Activity Monitor | `/proc`, `auditd`, `perf` | Agents exist (ProcAgent V2/V3) |
| Network flows | `netstat`, `lsof -i`, `nettop` | `ss`, `conntrack`, `pcap` | FlowAgent V2 exists |
| Kernel syscalls | Not available natively | `auditd`, `bpftrace` | Linux-only (GAP-02) |
| File integrity | `fs_usage`, FSEvents | `inotifywait`, `auditd` | FIM Agent V2 exists |
| Protocol events | Stub collector (simulated) | Real network log parsing | StubProtocolCollector validated |
| DNS queries | `log stream --predicate 'process == "mDNSResponder"'` | `/var/log/syslog`, `tcpdump` | DNS Agent V2 exists |
| Device discovery | `arp -a` (needs macOS fallback) | `ip neigh`, `/proc/net/arp` | Linux-only (GAP-03) |
| Persistence mechanisms | `launchctl list`, `crontab -l` | `systemctl`, `crontab -l` | PersistenceAgent V2 exists |
| USB/Peripheral | `system_profiler SPUSBDataType` | `udevadm monitor` | PeripheralAgent V2 exists |
| Auth events | `/var/log/system.log` | `journalctl`, `/var/log/auth.log` | AuthGuard V2 exists |

---

## 4. Empirical Baseline (2026-02-16 Mac Lab Run)

### Run Configuration
```
git_commit:    (current HEAD)
environment:   macOS, Python 3.11, AMOSKYS_ENV=MAC_DEV
device_id:     mac-akash
collection_interval: 30s
metrics_interval:    60s
duration:      ~3 minutes (7 collection cycles)
agents:        KernelAuditV2, ProtocolCollectorsV2, DeviceDiscoveryV2
```

### Results Summary

| Agent | Loops | Probe Events | Metrics Events | Queue Rows | Decode Errors | Status |
|-------|-------|-------------|----------------|------------|---------------|--------|
| KernelAuditV2 | 7 | 0 | 3 | 3 | 0 | ✅ Healthy (no audit source on Mac) |
| ProtocolCollectorsV2 | 7 | 7 | 3 | 11 | 0 | ✅ Healthy (stub events + metrics) |
| DeviceDiscoveryV2 | 7 | 0 | 3 | 3 | 0 | ✅ Healthy (no ARP on Mac) |

### Key Observations
1. All agents survived 7 complete cycles with 0 errors and 0 crashes
2. `agent_metrics` telemetry has full attribute coverage (8 fields populated)
3. `protocol_threat` events are structurally valid protobuf but carry no security detail (GAP-01)
4. SQLite WAL mode works correctly — no corruption after process termination
5. Idempotency keys are correctly unique and well-formed

---

## 5. Pass/Fail Summary

| Category | Total Claims | Passed | Known Gap | Untested |
|----------|-------------|--------|-----------|----------|
| Agent Lifecycle | 5 | 5 | 0 | 0 |
| Data Pipeline | 6 | 5 | 1 | 0 |
| Threat Detection | 6 | 6 | 0 | 0 |
| Intelligence Layer | 5 | 4 | 1 | 0 |
| Operational | 3 | 3 | 0 | 0 |
| **Total** | **25** | **23** | **2** | **0** |

**Bottom line:** 23/25 claims validated. Remaining 2 gaps: CL-11 (data pipeline — known proto field gap) and CL-22 (explanation generation — not yet implemented, deferred to Phase 3). All operational readiness claims (CL-23/24/25) now pass. Intelligence layer (CL-18/19/20/21) validated with end-to-end fusion and scoring tests. 332 total tests passing (328 regression + 4 soak/chaos).
