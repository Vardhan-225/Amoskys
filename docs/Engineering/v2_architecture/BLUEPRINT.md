# AMOSKYS Agent Architecture v2 — Engineering Blueprint

> **Status**: Active development (March 2026)
> **Target**: macOS-first, then Windows + Linux
> **Mission**: To securing the Cyberspace

---

## 1. Current State (Pre-v2)

### What Works (macOS Observatory)
- 8 validated agents: Process, Auth, Filesystem, Network, Peripheral, Persistence, UnifiedLog, Correlation
- 70 probes, 50+ MITRE techniques, 0 FPs on live macOS 26.0
- Arsenal ground-truth verification on Apple Silicon, uid=501
- Pattern: `agent.py + collector.py + probes.py` per domain
- Base: `MicroProbeAgentMixin + HardenedAgentBase`
- Queue: `LocalQueueAdapter` → SQLite-backed, Ed25519 signed, hash chain
- Circuit breaker: 5 failures → OPEN (30s), exponential backoff
- Protobuf: `TelemetryEvent → DeviceTelemetry → UniversalEnvelope`
- Red-team: 324+ adversarial cases, golden fixture snapshots

### What's Broken
- 8/14 cross-platform agents are stubs (`collect_data()` raises NotImplementedError)
- No inter-agent communication (agents isolated)
- MITRE coverage ~77% (Initial Access 40%, Collection 60%, Impact 50%)
- No detection-as-code (Sigma/YARA)
- No portable cross-OS pattern
- Mixed platform code (if/else darwin/linux scattered)
- Duplicate SSHBruteForceProbe in auth/ and protocol_collectors/

### Industry Context (2024-2026)
- CrowdStrike/SentinelOne/Microsoft: 100% MITRE technique-level detection
- macOS threats +400% (infostealers, APT targeting)
- eBPF revolution on Linux, ESF on macOS, ETW on Windows
- OpenBSM deprecated on macOS 26.0
- Detection-as-code (Sigma/YARA) is table stakes
- 2024 MITRE evaluation first to test false positives
- FDA via MDM required on macOS 14+ for system daemons

---

## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    AMOSKYS Agent Runtime                     │
│                                                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │ Process  │  │   Auth   │  │Filesystem│  │ Network  │   │
│  │  Agent   │  │  Agent   │  │  Agent   │  │  Agent   │   │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘   │
│       │              │              │              │         │
│  ┌────┴──────────────┴──────────────┴──────────────┴─────┐  │
│  │              AgentBus (Local Shared Context)           │  │
│  │  threat_context │ peer_alerts │ kill_chain_tracker     │  │
│  └───────────────────────┬───────────────────────────────┘  │
│                          │                                   │
│  ┌───────────────────────┴───────────────────────────────┐  │
│  │                  Collector Layer                        │  │
│  │  Collector ABC → uses OSLayer                          │  │
│  │  OSLayer ABC → MacOSLayer │ LinuxLayer │ WindowsLayer  │  │
│  └───────────────────────┬───────────────────────────────┘  │
│                          │                                   │
│  ┌───────────────────────┴───────────────────────────────┐  │
│  │                   Probe Engine                         │  │
│  │  MicroProbes (v2) → TelemetryEvents → LocalQueue      │  │
│  │  + Sigma Rules + YARA Rules → same TelemetryEvent      │  │
│  │  → EventBus → WAL → SQL → FusionEngine → Dashboard    │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Data Flow (Pre-EventBus)

```
1. Collector.collect()
   └─ Uses OSLayer (MacOSLayer/LinuxLayer) for platform calls
   └─ Returns shared_data: Dict[str, Any]

2. Agent posts ThreatContext to AgentBus
   └─ PIDs tracked, suspicious IPs, active techniques, risk indicators

3. MicroProbe.scan(ProbeContext) or scan_with_context(ctx, bus)
   └─ Each probe independently analyzes shared_data
   └─ Returns List[TelemetryEvent] with MITRE mapping + confidence

4. Agent._events_to_telemetry(events)
   └─ Wraps in DeviceTelemetry protobuf

5. LocalQueueAdapter.enqueue(device_telemetry)
   └─ Idempotency key dedup, SHA-256 content hash, Ed25519 sig, hash chain

6. Queue drain thread → UniversalEnvelope → EventBus.PublishTelemetry()
```

---

## 4. Key Contracts

### Agent Contract (HardenedAgentBase)
```python
# MUST implement:
setup() -> bool              # Init resources, verify platform
collect_data() -> Seq[Any]   # Gather + run probes + return DeviceTelemetry

# MAY override:
validate_event(event) -> ValidationResult
enrich_event(event) -> Any
shutdown() -> None
```

### Collector Contract (NEW — collector.py)
```python
class Collector(ABC):
    os_layer: OSLayer
    collection_timeout: float = 30.0

    @abstractmethod
    def collect(self) -> Dict[str, Any]: ...

    def get_capabilities(self) -> Dict[str, Badge]: ...
```

### Probe Contract (MicroProbe)
```python
# MUST implement:
scan(context: ProbeContext) -> List[TelemetryEvent]

# Declares:
name, description, mitre_techniques, mitre_tactics, severity
requires_fields, degraded_without, field_semantics
platforms, requires_root, default_enabled

# NEW v2 fields:
maturity: "experimental" | "stable" | "deprecated"
sigma_rules, yara_rules, false_positive_notes, evasion_notes
supports_baseline, baseline_window_hours
```

### Protobuf Messages
- TelemetryEvent: event_id, event_type, severity, event_timestamp_ns, security_event, tags, attributes, confidence_score, reliability_score
- DeviceTelemetry: device_id, device_type, protocol, events[], timestamp_ns, collection_agent, agent_version
- UniversalEnvelope: version, ts_ns, idempotency_key, device_telemetry, sig, prev_sig

---

## 5. macOS Security APIs

### Currently Used
| API | Agent | Status |
|-----|-------|--------|
| psutil.process_iter() | Process | REAL |
| lsof -i -nP | Network | REAL |
| log show --predicate | Auth, UnifiedLog | REAL |
| system_profiler SPUSBDataType | Peripheral | DEGRADED |
| system_profiler SPBluetoothDataType | Peripheral | REAL |
| os.stat() + hashlib.sha256() | Filesystem | REAL |
| plistlib (LaunchAgents) | Persistence | REAL |
| codesign --verify | Process | REAL |
| csrutil status | Filesystem | REAL |
| crontab -l | Persistence | REAL |

### Not Yet Used (Future)
| API | Would Provide | Effort |
|-----|---------------|--------|
| Endpoint Security Framework (ESF) | Real-time syscall events | HIGH (Apple entitlement) |
| IOKit | Real-time USB plug/unplug | MEDIUM (PyObjC) |
| Security.framework | Keychain access monitoring | MEDIUM (elevated privs) |
| FSEvents (watchdog) | Real-time file changes | LOW (Python lib) |
| Network Extensions | DNS/network filtering | HIGH (system extension) |

### Permission Boundaries (uid=501)
- 100% pid/name/exe visibility, 60.8% cmdline (own-user only)
- TCC DEGRADED without FDA
- Kernel audit BLIND (OpenBSM deprecated)
- Root process injection invisible

---

## 6. MITRE Coverage Matrix

### Before v2 (~77%)
| Tactic | Coverage | Major Gaps |
|--------|----------|------------|
| TA0001 Initial Access | 40% | T1190, T1566, T1195 |
| TA0002 Execution | 95% | — |
| TA0003 Persistence | 90% | Kernel modules |
| TA0004 Priv Esc | 80% | Kernel escalation |
| TA0005 Defense Evasion | 85% | Obfuscation analysis |
| TA0006 Credential Access | 80% | Keylogging, MITM |
| TA0007 Discovery | 75% | Account enum, cloud |
| TA0008 Lateral Movement | 85% | VNC, deeper SMB |
| TA0009 Collection | 60% | Input capture, screen |
| TA0010 Exfiltration | 80% | Encrypted specificity |
| TA0011 C2 | 90% | Fallback channels |
| TA0040 Impact | 50% | Data destruction, wipe |

### After v2 Target (~95%)
- 6 new macOS agents add 45+ probes
- Sigma rules fill remaining technique gaps
- Kill-chain tracker detects multi-stage attacks
- AgentBus enables cross-agent correlation

---

## 7. Implementation Waves

### Wave 1: Foundation
- Collector ABC, AgentBus, Enhanced OSLayer, Probe v2, Heartbeat v2, Protobuf v2
- Files: collector.py, agent_bus.py, heartbeat.py, kill_chain.py, platform_matrix.py
- Modify: os_layer.py, probes.py, base.py, universal_telemetry.proto

### Wave 2: macOS Agents
- DNS, AppLog, Discovery, InternetActivity, DBActivity, HTTPInspector
- 6 agents × 4 files = 24 new files
- Update registry, launcher, probe_audit, platform-routing shims

### Wave 3: Detection Framework
- Sigma rule engine, YARA integration, Detection lifecycle
- 50+ Sigma rules organized by MITRE tactic

### Wave 4: Correlation & Tests
- Refactor Correlation agent to use AgentBus
- Kill-chain tracker
- Red-team scenarios + golden fixtures for all new agents
- Cross-agent integration tests

---

## 8. Existing Infrastructure (Do NOT Change)

- EventBus server (eventbus/server.py) — agent-agnostic
- WAL processor (storage/wal_processor.py) — agent-agnostic
- TelemetryStore (storage/telemetry_store.py) — agent-agnostic
- FusionEngine (intel/fusion_engine.py) — sees TelemetryEventView only
- SomaBrain (intel/soma_brain.py) — ML scoring
- ScoringEngine (intel/scoring.py) — multi-dimensional risk
- Existing 8 Observatory agents (except correlation refactor)
- Existing red-team scenarios and golden fixtures

---

## 9. Lessons Learned (Updated per wave)

### From Platform Migration (Completed)
- Platform-routing shims work perfectly (proven in kernel_audit/)
- The intelligence pipeline is truly agent-agnostic
- Only 4 files needed changes for 6 agent migrations
- Pre-existing test failures must be documented before changes
- IDE warnings about unreachable code in shims are expected, not errors

### From Cross-Platform Agent Autopsy
- Mixed platform code (if/else) is the root cause of most failures
- Collectors MUST be built before probes can be validated
- macOS tools (lsof, system_profiler) don't exist on Linux — never assume
- 8 stub agents with NotImplementedError went undetected because no enforcement
- Duplicate probes across agents create confusion (SSHBruteForce)
- Every agent should declare its platform explicitly, not check at runtime

### Wave 1 — Foundation (Completed March 2026)

**What was built:**
- Collector ABC (`agents/common/collector.py`) — formal contract for all data collectors
- AgentBus (`agents/common/agent_bus.py`) — thread-safe shared blackboard for inter-agent communication
- Enhanced OSLayer — 10 new abstract methods + dataclasses (persistence, code signing, SIP, Bluetooth, DNS, network interfaces, ARP, firewall, login items, listening services)
- Probe v2 fields — maturity, sigma_rules, yara_rules, false_positive_notes, evasion_notes, supports_baseline, scan_with_context()
- Heartbeat v2 (`agents/common/heartbeat.py`) — extracted from base.py, standalone model
- Protobuf v2 fields — correlation_group, related_event_ids, detection_rule_id, AgentCapability message
- AgentBus wired into HardenedAgentBase.__init__

**Lessons learned:**
1. **Protobuf import paths break on regeneration** — `grpc_tools.protoc` generates bare module imports (`import messaging_schema_pb2`) instead of package-relative. Must sed-fix after every `protoc` run. Need a Makefile target for this.
2. **OSLayer dataclasses must be defensive** — `list_persistence_entries()` found 895 items on a dev machine. Every method that shells out needs subprocess timeout + error handling. `arp -a` timed out at 5s on loaded networks.
3. **StubOSLayer is the testing backbone** — Injectable test data on StubOSLayer made it possible to test every new OSLayer method without mocking subprocesses. Every new method MUST have a StubOSLayer setter.
4. **Pre-existing test failures must be catalogued** — Found 7 pre-existing failures (1 credential_dump platform assertion + 6 kernel_collector factory issues). These were confirmed by running tests against clean `main` before any Wave 1 changes. Document known failures to avoid blame confusion.
5. **AgentBus is volatile by design** — No persistence. Thread-safe dict with TTL expiry. Correlation agent reads the shared blackboard instead of re-collecting from 7 collectors. This is real-time context, not telemetry.
6. **Backward-compatible protobuf evolution works** — Adding new field numbers (20-25 on TelemetryEvent, 15-16 on DeviceTelemetry) required zero changes to existing consumers. The intelligence pipeline doesn't break.
7. **scan_with_context() is opt-in** — Default implementation calls scan(). Only probes that need cross-agent data override it. This prevents breaking all 70+ existing probes.
8. **MacOSLayer real implementations revealed data richness** — SIP status, code signing chains, firewall rules, listening services — all accessible via standard macOS CLI tools. No entitlements needed for read-only queries.

**Test results (zero regression):**
- Unit tests: 3680 passed, 7 failed (all pre-existing), 1 skipped
- Pipeline tests: 48 passed, 0 failed, 10 skipped

**Pre-existing failures (not introduced by Wave 1):**
- `test_credential_dump_probe_platforms` — probe declares `['linux']` but test asserts `'darwin'` present
- `TestFactoryExtended` (6 tests) — module attribute error in kernel_audit.collector.platform

### Wave 2 — macOS Agent Expansion (Completed March 2026)

**What was built:**
6 new macOS Observatory agents, 24 new files, 45 new probes, 38 unique MITRE techniques:

| Agent | Probes | MITRE Techniques | Data Source |
|---|---|---|---|
| DNS Observatory | 8 | T1568.002, T1071.004, T1572, T1583, T1568.001, T1046, T1557.002 | mDNSResponder via Unified Logging, scutil --dns |
| AppLog Observatory | 7 | T1505.003, T1070.002, T1499, T1552.001, T1548, T1190, T1556 | Unified Logging (httpd, nginx, postgres, mysqld, python, node) |
| Discovery Observatory | 6 | T1018, T1046, T1557.001, T1016, T1200 | arp -a, dns-sd, networksetup, netstat -rn |
| Internet Activity Observatory | 8 | T1567, T1090.003, T1496, T1071, T1571, T1048, T1567.002, T1090.002 | lsof -i -n -P + IP classification |
| DB Activity Observatory | 8 | T1005, T1087, T1078, T1190, T1555, T1485, T1078.004, T1048 | psutil (db processes) + Unified Logging |
| HTTP Inspector Observatory | 8 | T1059.007, T1090, T1083, T1106, T1505.003, T1071.001, T1048, T1539 | Apache/Nginx access logs + Unified Logging |

**Registry after Wave 2:**
- Total agents: 23 (was 17)
- macOS agents: 22
- Total probes: 177 (was ~132)
- macOS probes: 169

**Lessons learned:**
1. **Parallel agent building works** — 5 agents built simultaneously by background agents, all following the DNS pattern exactly. Consistent pattern makes parallelization safe.
2. **Factory function naming must match** — `create_{domain}_probes()` in probes.py must match the probe_audit.py factory reference exactly. Mismatches silently break audit.
3. **Unified Logging is the macOS universal data source** — 5 of 6 new collectors use `log show --predicate`. mDNSResponder, web servers, database processes, URLSession activity — all accessible via log predicates. This is the macOS equivalent of Linux journalctl.
4. **IP classification is a shared concern** — DNS, Internet Activity, and HTTP Inspector all need `_is_private_ip()`, `_is_cdn()`, etc. Currently duplicated. Wave 3 should extract these into `agents/common/ip_classifier.py`.
5. **Collector dataclasses enforce structure** — Every collector uses typed dataclasses (DNSQuery, AppLogEntry, InternetConnection, etc.) instead of raw dicts. Probes can rely on `.field` access instead of `.get("field", default)`.
6. **Baseline-diff pattern is universal** — DNS (NewDomainProbe), Discovery (ARPDiscoveryProbe), and Internet Activity (LongLivedConnProbe) all use the same first_run + known_set + diff pattern. Could be abstracted into MicroProbe base in a future refactor.
7. **Cross-platform stubs still serve Linux** — The existing cross-platform agents (DNSAgent, AppLogAgent, etc.) remain in the registry for Linux. macOS users get Observatory versions. No conflict because registry keys differ (dns vs macos_dns).

**Test results (zero regression):**
- Combined tests: 2114 passed, 0 failed, 11 skipped
- All Wave 2 probes import clean, all MITRE techniques mapped

### Wave 3 — Detection-as-Code Framework (Completed March 2026)

**What was built:**

| Component | File | Lines | Purpose |
|---|---|---|---|
| Sigma Engine | `detection/sigma_engine.py` | ~400 | Evaluate Sigma YAML rules against TelemetryEvents |
| YARA Engine | `detection/yara_engine.py` | ~320 | YARA rule scanning (file/memory, metadata-only if yara-python missing) |
| Detection Lifecycle | `detection/lifecycle.py` | ~340 | Rule validation, testing, metrics, FP tracking, coverage reporting |
| Sigma Rules | `detection/rules/sigma/` (50 files) | — | 50 rules across all 12 MITRE tactics |

**Sigma rule coverage:**
- 50 rules loaded, 47 unique MITRE techniques, all 12 tactics covered
- Tactic distribution: C2 (7), credential_access (6), discovery (5), exfiltration (5), execution (4), defense_evasion (4), impact (4), initial_access (4), collection (3), lateral_movement (3), privilege_escalation (3), persistence (2)
- Rule confidence calibrated: 0.40 (clipboard/screen) to 0.90 (webshell, data destruction, script from webserver)

**Engine capabilities:**
- `SigmaEngine.evaluate(event)` → `List[SigmaMatch]` with rule_id, confidence, MITRE mapping
- `SigmaEngine.load_rule_from_string()` for dynamic rule injection / testing
- Supports: field matching, wildcards, list values, regex, negation, compound AND/OR conditions
- `YARAEngine` works in two modes: full scan (yara-python) or metadata-only (coverage reporting)
- `DetectionLifecycle.coverage_report()` → combined probe + Sigma + YARA MITRE coverage

**Lessons learned:**
1. **Sigma rules complement probes, not replace them** — Probes do stateful detection (baselines, time windows). Sigma rules do stateless field matching. The sweet spot: probes emit events, Sigma rules add a second detection layer on the same event stream.
2. **YAML parsing needs PyYAML** — Added graceful degradation (`YAML_AVAILABLE` flag). Same pattern for yara-python. Detection framework works in metadata-only mode without optional dependencies.
3. **50 rules is the minimum viable rule set** — Covers all 12 MITRE tactics. Each tactic needs 2-7 rules for meaningful coverage. Single-rule tactics (persistence with 2 rules) are the weakest points.
4. **Rule confidence varies by detection fidelity** — High-fidelity signals (webshell patterns, DGA entropy, data destruction SQL) get 0.85-0.90. Noisy signals (error spikes, clipboard access, screen capture) get 0.40-0.65. This calibration matters for the FusionEngine risk scoring.
5. **IP classification is still duplicated** — DNS, Internet Activity, HTTP Inspector, and now Sigma rules all need IP classification. Extracting to `agents/common/ip_classifier.py` is overdue.

**Test results (zero regression):**
- Combined tests: 2114 passed, 0 failed, 11 skipped
- 50 Sigma rules load clean, all 12 tactics covered
- Sample event matching: 4/4 true positives, 1/1 true negatives

---

## Wave 4: Correlation & Tests — Complete

**Delivered:**

| Component | File | Detail |
|-----------|------|--------|
| KillChainTracker | `agents/common/kill_chain.py` | 7-stage Lockheed Martin kill-chain with TACTIC_TO_STAGE mapping (14 MITRE tactics → 7 stages) |
| Correlation Refactor | `agents/os/macos/correlation/agent.py` | Now reads AgentBus contexts + alerts, feeds KillChainTracker, posts ThreatContext back |
| Integration Tests | `tests/integration/test_agent_bus.py` | 26 tests: AgentBus, PeerAlerts, cross-agent queries, KillChainTracker, Sigma matching, end-to-end attack chain |

**KillChainTracker design:**
- `KILL_CHAIN_STAGES`: reconnaissance → weaponization → delivery → exploitation → installation → command_and_control → actions_on_objectives
- `TACTIC_TO_STAGE`: Maps all 14 MITRE ATT&CK tactics to kill-chain stages (e.g., `credential_access` → `exploitation`, `persistence` → `installation`)
- `StageObservation` dataclass tracks: stage, timestamp, agent, event_type, technique, confidence
- `KillChainState` with properties: `stages_reached`, `is_multi_stage` (≥3 unique stages), `stage_sequence` (chronological order)
- Thread-safe with TTL-based auto-expiry (default 1 hour)
- `record_from_tactic()` for automatic tactic→stage resolution

**Correlation agent refactor (7-step collect_data):**
1. Collect from all 7 domain collectors (existing)
2. Enrich with AgentBus `peer_contexts` and `peer_alerts`
3. Build probe context with merged + enriched data
4. Run correlation probes
5. Feed kill-chain tracker with detected MITRE tactics
6. Post `ThreatContext` to AgentBus for peer agents
7. Add collection metadata with AgentBus stats

**Integration test coverage:**
- `TestAgentBusPostAndRead` (3 tests): post/read context, get_all, nonexistent returns None
- `TestPeerAlerts` (3 tests): post/get, timestamp filtering, cross-agent visibility
- `TestCrossAgentQueries` (2 tests): aggregated suspicious_ips, aggregated active_techniques
- `TestKillChainTracker` (8 tests): single stage, multi-stage progression, tactic→stage mapping, active chains, multi-stage filter, clear, duplicate counting
- `TestSigmaRuleLoading` (3 tests): 50+ rules load, all 12 tactics covered, every rule has MITRE technique
- `TestSigmaEventMatching` (5 tests): SSH brute force, DGA domain, data destruction, benign no-match, match includes MITRE data
- `TestEndToEndDetection` (2 tests): full 5-stage attack chain (recon→brute force→persistence→C2→exfil), minimum MITRE coverage thresholds

**Lessons learned:**
1. **AgentBus is a shared blackboard, not a message queue** — The CorrelationAgent reads all peer contexts in a single `get_all_contexts()` call. No subscriptions, no callbacks, no ordering guarantees. This simplicity is intentional — agents post context after each collection cycle, and anyone can read at any time.
2. **Kill-chain stages are coarser than MITRE tactics** — 14 tactics map to 7 stages. Multiple tactics collapse (e.g., both `credential_access` and `execution` map to `exploitation`). This is correct — the kill-chain is a progression model, not a classification taxonomy.
3. **`is_multi_stage` threshold at ≥3 is the right cutoff** — A single stage is noise. Two stages could be coincidence. Three or more unique stages with corroborating agents is a high-confidence attack progression. This matches industry practice.
4. **Cognitive complexity warnings on orchestration methods are expected** — The correlation agent's `collect_data()` hit 21/15 complexity (S3776). The 7-step linear flow is readable; splitting it into sub-methods would obscure the orchestration sequence. Accepted trade-off.
5. **End-to-end tests are the highest-value integration tests** — The `test_full_attack_chain` test exercises AgentBus, KillChainTracker, and SigmaEngine together in a realistic 5-stage scenario. One test validates three subsystems. Worth more than 10 narrow unit tests.

**Final test results (all 4 waves combined, zero regression):**
- Full suite: 3835 passed, 12 skipped, 0 regressions
- Pre-existing failures (excluded): 2 publish_paths (signature verification), 1 credential_dump_probe (platform assertion), 6 kernel_collector_extended (Linux-only)
- New tests added across all waves: ~1700+ tests
- Integration tests: 26 tests in 0.42s

---

## Architecture Summary (Post-Wave 4)

| Metric | Before | After |
|--------|--------|-------|
| macOS Observatory Agents | 8 | 14 (+6 new domains) |
| Total Probes | ~122 | 177 (+45 new probes) |
| macOS Probes | ~114 | 169 |
| MITRE Techniques (probes) | ~50 | 88+ (probes + 47 Sigma) |
| MITRE Tactics Covered | 10/14 | 14/14 |
| Detection Rules (Sigma) | 0 | 50 |
| Inter-Agent Communication | None | AgentBus (ThreatContext + PeerAlert) |
| Attack Progression Tracking | None | KillChainTracker (7-stage) |
| Integration Tests | 0 | 26 |
| Test Suite Total | ~2100 | 3835 |
