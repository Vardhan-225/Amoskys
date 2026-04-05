# AMOSKYS Pipeline Deep Audit — April 4, 2026
## Verified Against Actual Code, Every Component, 2 Levels Deep

---

## EXECUTIVE SUMMARY

| Layer | Components | Working | Broken/Missing | Data Loss Risk |
|-------|-----------|---------|----------------|----------------|
| 1. Collection | 20 registry, 18 collector | 18/20 running | 2 orphaned registry entries | LOW |
| 2. Queue | 19 queue DBs | All draining | 0 stuck events | NONE |
| 3. Protobuf | 3 proto schemas | Serializing | .proto source files lost | MEDIUM |
| 4. Storage | 26 tables | 16 with data | 10 tables permanently empty | HIGH |
| 5. Enrichment | 4-stage pipeline | GeoIP + MITRE working | ThreatIntel empty, ASN limited | MEDIUM |
| 6. Detection | 56 Sigma + 221 probes | Sigma evaluating | 0 YARA rules, YARA engine dormant | MEDIUM |
| 7. Scoring | 3 heuristic + 2 ML (sklearn) | Scoring running | ML trains only with sufficient labels | LOW |
| 8. Correlation | 31 fusion rules + 7 kill chain | Rules loaded | 0 incidents created, 31 signals total | HIGH |
| 9. Shipper | 9 tables shipping | Shipping to ops | **9 forensic columns silently dropped** | **CRITICAL** |
| 10. Ops Server | 9 tables + devices | Receiving + serving | org_id filtering incomplete | MEDIUM |
| 11. Presentation | Fleet sync + auth | Working | Sync is truncate-and-replace | LOW |

**3 CRITICAL GAPS found. 8 WRONG ASSUMPTIONS corrected. 10 EMPTY TABLES identified.**

---

## LAYER 1: COLLECTION
### File: `src/amoskys/collector_main.py`

### What ACTUALLY exists:

**AGENT_REGISTRY** (`src/amoskys/agents/__init__.py`): **20 entries**
- 19 darwin agents + 1 linux (kernel_audit)

**Collector loads** (`collector_main.py:116-254`): **18 agents**

| # | Agent | Interval | Queue DB | Collection Source |
|---|-------|----------|----------|-------------------|
| 1 | realtime_sensor | 2s | realtime_sensor.db | UnifiedLog + FSEvents + kqueue |
| 2 | proc | 10s | macos_process.db | psutil.process_iter() |
| 3 | flow | 10s | macos_network.db | psutil.net_connections() |
| 4 | auth | 30s | macos_auth.db | `log stream --predicate` |
| 5 | persistence | 60s | macos_persistence.db | LaunchAgents/cron/SSH/shell profiles |
| 6 | fim | 60s | macos_filesystem.db | FSEvents + stat() |
| 7 | peripheral | 60s | macos_peripheral.db | ioreg IOUSBDevice/IOBluetoothDevice |
| 8 | dns | 30s | macos_dns.db | DNS cache + log stream |
| 9 | infostealer_guard | 30s | macos_infostealer_guard.db | Keychain/browser/wallet monitoring |
| 10 | quarantine_guard | 30s | macos_quarantine_guard.db | Gatekeeper/quarantine xattr |
| 11 | provenance | 15s | macos_provenance.db | Cross-agent kill chain correlation |
| 12 | discovery | 60s | macos_discovery.db | ARP table + Bonjour + DHCP |
| 13 | applog | 30s | macos_applog.db | Application log parsing |
| 14 | internet_activity | 30s | macos_internet_activity.db | Network activity classification |
| 15 | db_activity | 60s | macos_db_activity.db | DB access monitoring |
| 16 | http_inspector | 30s | macos_http_inspector.db | HTTP traffic inspection |
| 17 | network_sentinel | 15s | network_sentinel.db | HTTP access log analysis |
| 18 | protocol_collectors | 30s | (no queue DB found) | Protocol-level threat detection |

### MISMATCHES FOUND:

**In AGENT_REGISTRY but NOT loaded by collector:**
- `macos_security_monitor` (MacOSSecurityMonitorAgent) — 4 probes, never runs
- `macos_unified_log` (MacOSUnifiedLogAgent) — 6 probes, never runs

**Loaded by collector but NOT in AGENT_REGISTRY:**
- `realtime_sensor` (MacOSRealtimeSensorAgent) — runs at 2s, no registry entry

**Queue DB exists but no matching collector load:**
- `macos_security.db` — has queue table, 0 rows, orphaned
- `macos_unified_log.db` — has queue table, 0 rows, orphaned

**Class name mismatch:**
- Collector loads `ProtocolCollectorsAgent` (line 251)
- Registry has `ProtocolCollectors` (line 278)
- These may be different classes — potential import failure silently swallowed by _try_load()

### Agent Directory Structure (src/amoskys/agents/os/macos/):

| Directory | agent.py | collector.py | probes.py | Notes |
|-----------|----------|-------------|-----------|-------|
| applog | ✓ | ✓ | ✓ | Standard observatory |
| auth | ✓ | ✓ | ✓ | Standard observatory |
| correlation | — | — | — | No agent/collector/probes — correlation module only |
| db_activity | ✓ | ✓ | ✓ | Standard observatory |
| discovery | ✓ | ✓ | ✓ | Standard observatory |
| dns | ✓ | ✓ | ✓ | Standard observatory |
| filesystem | ✓ | ✓ | ✓ | Standard observatory |
| http_inspector | ✓ | ✓ | ✓ | + agent_types.py |
| infostealer_guard | ✓ | ✓ | ✓ | Standard observatory |
| internet_activity | ✓ | ✓ | ✓ | Standard observatory |
| network | ✓ | ✓ | ✓ | Standard observatory |
| network_sentinel | ✓ | ✓ | ✓ | Standard observatory |
| peripheral | ✓ | ✓ | ✓ | Standard observatory |
| persistence | ✓ | ✓ | ✓ | Standard observatory |
| process | ✓ | ✓ | ✓ | Standard observatory |
| protocol_collectors | — | ✓ | ✓ | protocol_collectors.py instead of agent.py |
| provenance | ✓ | ✓ | ✓ | Standard observatory |
| quarantine_guard | ✓ | ✓ | ✓ | Standard observatory |
| realtime_sensor | — | — | — | agent.py only — no collector.py, no probes.py |
| security_monitor | — | ✓ | ✓ | security_monitor_agent.py instead of agent.py |
| unified_log | ✓ | ✓ | ✓ | Standard observatory |

### WRONG ASSUMPTION #1:
> "All 17 macOS agents have agent.py + collector.py + probes.py"

**REALITY:** 3 agents deviate:
- `realtime_sensor`: only agent.py (no collector.py, no probes.py) — it IS the real-time event loop
- `protocol_collectors`: uses protocol_collectors.py instead of agent.py
- `security_monitor`: uses security_monitor_agent.py instead of agent.py

---

## LAYER 2: QUEUE
### Files: `src/amoskys/agents/common/local_queue.py`, `queue_adapter.py`

### Queue Schema (verified from data/queue/macos_process.db):
```sql
CREATE TABLE queue (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  idem TEXT NOT NULL,           -- idempotency key (UUID)
  ts_ns INTEGER NOT NULL,       -- timestamp nanoseconds
  bytes BLOB NOT NULL,          -- serialized protobuf
  retries INTEGER DEFAULT 0,    -- retry count
  content_hash BLOB DEFAULT NULL,  -- SHA-256 of payload
  sig BLOB DEFAULT NULL,        -- Ed25519 signature
  prev_sig BLOB DEFAULT NULL    -- hash chain (previous signature)
);
CREATE UNIQUE INDEX queue_idem ON queue(idem);  -- dedup
CREATE INDEX queue_ts ON queue(ts_ns);          -- FIFO ordering
```

### Queue Methods (local_queue.py):
- `enqueue()` (line 111) — serialize + insert, UNIQUE(idem) prevents duplicates
- `drain()` (line 166) — FIFO dequeue, callback per event, delete on success
- `drain_signed()` (line 198) — same as drain but with signature verification
- `size()` (line 309) — COUNT(*)
- `size_bytes()` (line 319) — SUM(LENGTH(bytes))
- `_enforce_backlog()` (line 354) — drops oldest when > max_bytes

### Queue Adapter (queue_adapter.py):
- Ed25519 signing via `_resolve_agent_key()` (line 56)
- Key search order: per-agent key → fallback → default path
- `_dict_to_telemetry()` (line 374) — converts dict → DeviceTelemetry protobuf
- Hash chain: prev_sig = blake2b(content + previous_sig)
- `content_hash` = SHA-256 of serialized envelope

### Live State (April 4, 2026):
**All 19 queue DBs: 0 rows** — events draining successfully

**IMPORTANT: Local telemetry.db is STALE — all data stops at March 30.**
Pipeline is shipping to ops server but NOT writing locally for ~5 days.
Either collect_and_store.py is not running locally, or local store was
disabled in favor of remote-only shipping.

---

## LAYER 3: PROTOBUF
### File: `src/amoskys/proto/`

### Files that exist:
- `universal_telemetry_pb2.py` — generated Python (no .proto source)
- `universal_telemetry_pb2.pyi` — type stubs
- `universal_telemetry_pb2_grpc.py` — gRPC stubs
- `messaging_schema_pb2.py` — event schema types
- `messaging_schema_pb2.pyi` — type stubs
- `control_pb2.py` — control plane messages
- `control_pb2.pyi` / `control_pb2_grpc.py`

### DeviceTelemetry Message Fields (from serialized descriptor):
```
device_id, device_type, protocol, metadata (DeviceMetadata),
events (repeated TelemetryEvent), security (SecurityContext),
timestamp_ns, collection_agent, agent_version, is_compressed,
compression_algorithm, batch_size, collection_interval_ms,
schema_version, capabilities (repeated AgentCapability),
agent_bus_version
```

### TelemetryEvent Message Fields:
```
event_id, event_type, severity, event_timestamp_ns,
metric_data (MetricData), log_data (LogData), alarm_data (AlarmData),
status_data (StatusData), security_event (SecurityEvent),
audit_event (AuditEvent), tags (repeated), attributes (map),
source_component, confidence_score, is_synthetic
```

### WRONG ASSUMPTION #2:
> ".proto source files exist"

**REALITY:** Only generated `_pb2.py` files exist. The `.proto` source files are LOST.
- Cannot regenerate if protobuf version changes
- Cannot verify schema correctness
- Cannot add new fields without reverse-engineering from serialized descriptors

---

## LAYER 4: STORAGE
### File: `src/amoskys/storage/telemetry_store.py` + mixins

### 26 Tables Defined in Schema:

| # | Table | Rows (live) | Status | Purpose |
|---|-------|-------------|--------|---------|
| 1 | security_events | 4,612 | ACTIVE | Core threat events |
| 2 | process_events | 9,842 | ACTIVE | Process snapshots |
| 3 | flow_events | 32,773 | ACTIVE | Network flows |
| 4 | dns_events | 5,158 | ACTIVE | DNS queries |
| 5 | persistence_events | 685,716 | ACTIVE | Autostart entries (huge — snapshot dedup issue?) |
| 6 | fim_events | 3,032 | ACTIVE | File changes |
| 7 | audit_events | 8,055 | ACTIVE | Auth/syscall events |
| 8 | peripheral_events | 569 | ACTIVE | USB/Bluetooth |
| 9 | observation_events | 174,368 | ACTIVE | Raw observations (pruned at 2h) |
| 10 | observation_rollups | 36 | ACTIVE | Bucketed observation summaries |
| 11 | dashboard_rollups | 224 | ACTIVE | Precomputed dashboard data |
| 12 | _snapshot_baseline | 12,677 | ACTIVE | Dedup state for all snapshot agents |
| 13 | metrics_timeseries | 330 | ACTIVE | Time-series metrics |
| 14 | schema_migrations | 14 | ACTIVE | Migration tracking |
| 15 | signals | 31 | LOW | Only 31 signals ever created |
| 16 | **telemetry_events** | **0** | **DEAD** | Canonical envelope — never written |
| 17 | **device_telemetry** | **0** | **DEAD** | Aggregated device metrics — never written |
| 18 | **telemetry_receipts** | **0** | **DEAD** | Completeness verification — never written |
| 19 | **incidents** | **0** | **DEAD** | SOC incidents — never created |
| 20 | **alert_rules** | **0** | **DEAD** | Custom alerting — never configured |
| 21 | **process_genealogy** | **0** | **DEAD** | Process spawn chains — never populated |
| 22 | **wal_archive** | **0** | **DEAD** | WAL replay archive — never used |
| 23 | **wal_dead_letter** | **0** | **DEAD** | Failed WAL events — never triggered |
| 24 | **rejected_events** | **0** | **DEAD** | Mandate rejections — never triggered |
| 25 | **_fim_baseline** | **0** | **DEAD** | Legacy FIM baseline — superseded |
| 26 | **_persistence_baseline** | **0** | **DEAD** | Legacy persistence baseline — superseded |

### WRONG ASSUMPTION #3:
> "telemetry_events table is the canonical envelope truth table"

**REALITY:** `telemetry_events` has 0 rows. The WAL processor never writes to it.
The `insert_telemetry_event()` method exists but is never called in the routing path.
Events go directly to domain tables (security_events, process_events, etc.).

### WRONG ASSUMPTION #4:
> "process_genealogy tracks spawn chains"

**REALITY:** process_genealogy has 0 rows. The table schema exists but nothing populates it.
Process parent-child relationships exist only as ppid in process_events, not as a graph.

### WRONG ASSUMPTION #5:
> "incidents are created by the correlation engine"

**REALITY:** incidents table has 0 rows. Fusion rules evaluate but never create incidents.
The 13 fusion rules produce matches, but the incident creation path is incomplete.

### SUSPICIOUS DATA:
- **persistence_events: 685,716 rows** — This is 70x more than the next largest table.
  Likely dedup issue: persistence snapshot runs every 60s, scanning ~100 LaunchAgents/cron entries.
  At 60s intervals for 7 days: 100 entries × 10,080 cycles = ~1M rows.
  The snapshot dedup should prevent this, but 685K rows suggests it's not fully effective.

### Insert Methods (14 in _ts_inserts.py):
All 14 methods exist but only ~10 are called in the live routing path.

### Query Methods (40+ in _ts_queries.py):
Working. Dashboard reads from these via _ReadPool (4 concurrent connections).

### Rollup Prewarm (_ts_rollups.py):
- 20-second cycle
- Computes 9 aggregations: device_posture, nerve_posture, observation_domain_stats,
  fim_stats, persistence_stats, flow_stats, unified_clustering, unified_counts, threat_count
- Writes hourly rollups: events_by_domain, threats_by_severity, posture_snapshot

---

## LAYER 5: ENRICHMENT
### File: `src/amoskys/enrichment/`

### 4-Stage Pipeline (EnrichmentPipeline.__init__):
1. **GeoIPEnricher** — MaxMind GeoLite2 lookup
2. **ASNEnricher** — ASN organization + network type
3. **ThreatIntelEnricher** — Known malicious IP matching
4. **MITREEnricher** — Event → MITRE ATT&CK technique mapping

### GeoIP (geoip.py):
- DB search paths: `data/geoip/GeoLite2-City.mmdb`, `/usr/share/GeoIP/`, `/usr/local/share/GeoIP/`
- Fields set: geo_src_country, geo_src_city, geo_src_latitude, geo_src_longitude
- Private IP detection: 10.x, 172.16-31.x, 192.168.x, 127.x → skipped
- Cache: LRU cache on lookups

### ASN (asn.py):
- Fields set: asn_src_org, asn_src_number, asn_src_network_type
- Network type classification: hosting/isp/education/government/corporate
- Cloud provider detection: AWS, Google, Azure, Cloudflare, etc.

### ThreatIntel (threat_intel.py):
- DB: `data/threat_intel.db`
- **REALITY CHECK:** threat_intel.db exists but was found EMPTY in the pipeline audit
- When empty, enricher is a no-op — threat_intel_match is always False

### MITRE (mitre.py):
- Maps event categories → MITRE technique IDs
- Maps probe names → techniques
- Confidence: probe-sourced > enrichment-sourced
- Sets: mitre_techniques, mitre_tactics, mitre_source, mitre_confidence

### WRONG ASSUMPTION #6:
> "ThreatIntel enricher flags known malicious IPs"

**REALITY:** threat_intel.db is empty. No IPs are ever flagged as malicious by ThreatIntel.
The enricher loads, runs, and returns "no match" for every IP. Silent failure.

---

## LAYER 6: DETECTION
### Files: `src/amoskys/detection/sigma_engine.py`, `yara_engine.py`, `lifecycle.py`

### Sigma Engine (sigma_engine.py — 20,101 bytes):
- **56 YAML rules** across 12 MITRE tactics
- Rules loaded from `src/amoskys/detection/rules/sigma/`
- Key classes:
  - `SigmaRule` (line 73) — parsed rule dataclass
  - `SigmaMatch` (line 111) — match result with confidence
  - `SigmaEngine` (line 139) — main engine
- `evaluate(event)` (line 238) — checks event against ALL loaded rules
- **WARNING:** No early filtering — O(n_rules) per event evaluation (line 259: `candidate_rules = list(self._rules.values())`)
- Condition parsing: and, or, not, count(), wildcards, case-insensitive
- Returns `List[SigmaMatch]` with rule_id, level, confidence, matched_fields

### YARA Engine (yara_engine.py — 13,464 bytes):
- Engine code exists with `YARAEngine`, `YARARuleMeta`, `YARAMatch`, `YARACoverage`
- **0 YARA rules** — `rules/yara/` directory is EMPTY
- Engine operates in metadata-only mode
- `yara-python` is optional dependency — may not be installed

### MicroProbe System:
- Base class: `src/amoskys/agents/common/probes.py` (line 244)
- **221 MicroProbe subclasses** across all agents
- Each probe: `scan(context) → List[TelemetryEvent]`
- Observability Contract: requires_fields, field_semantics, degraded_without
- ProbeReadiness: REAL/DEGRADED/BROKEN/DISABLED status
- Lifecycle: maturity (experimental|stable|deprecated), sigma_rules, yara_rules

### Detection Lifecycle (`detection/lifecycle.py` — 20,101 bytes):
- Manages probe activation/deactivation
- Tracks probe health metrics
- Handles degradation gracefully

---

## LAYER 7: SCORING
### File: `src/amoskys/intel/scoring.py` (57,817 bytes)

### 3 Independent Scorers + Fusion:

| Scorer | Line | Technique | Weight |
|--------|------|-----------|--------|
| GeometricScorer | 238 | IP reputation, geo, ASN, network risk | 0.35 |
| TemporalScorer | 369 | Off-hours activity, frequency bursts, rarity | 0.25 |
| BehavioralScorer | 496 | Deviation from baselines, escalation patterns | 0.40 |

Additional:
- `SequenceScorer` (line 1263) ��� INADS-style attack chain progression
- `DynamicThresholds` (line 1351) — auto-calibrates per (category, action) from analyst feedback
- `EventBaseline` (line 77) — 24h sliding window, O(1) rarity, burst detection
- `DeviceBaseline` (line 594) — per-device LEARNING��DETECTION transition

### CORRECTED from initial audit:
> Initial claim: "XGBoost, LSTM, MLP" — WRONG variable name assumption
> Initial correction: "All heuristic, no ML" — ALSO WRONG

**REALITY: 2-tier scoring:**
1. **Tier 1 (always on):** 3 heuristic scorers (Geometric + Temporal + Behavioral)
2. **Tier 2 (optional ML):** sklearn IsolationForest + GradientBoosting via SomaBrain

### Classification Thresholds:
- legitimate (< 0.40)
- suspicious (0.40 - 0.70)
- malicious (> 0.70)
- All scores normalized to 0.0 - 1.0

### SOMA (`src/amoskys/intel/soma.py` — 21,319 bytes):
- **Unified SOMA = Left + Right + Deep hemispheres:**
  - LEFT: Frequency memory (IGRIS DB) — novelty score 0.0=familiar, 1.0=never seen
  - RIGHT: Statistical anomaly (numpy z-score normalization)
  - DEEP: Optional ML layer (IsolationForest + GradientBoosting when sklearn available)
- Returns: (novelty, suppression_factor, seen_count, metadata)
- Baselines stored in SQLite, persist across restarts
- Resets on agent restart (known issue from pipeline audit)

### SomaBrain ML (`src/amoskys/intel/soma_brain.py` — 88,924 bytes):
- **IsolationForest** — unsupervised anomaly detection (always running)
- **GradientBoostingClassifier** — supervised 3-class (only on high-trust labels)
- Feature engineering: 100+ features (process tree, network seq, MITRE, file paths)
- Training flow: queries security_events → extracts features → auto-labels → trains → hot-reloads
- Models reload into ScoringEngine without restart

### INADS Engine (`src/amoskys/intel/inads_engine.py` — 47,375 bytes):
- Multi-perspective anomaly detector
- Perspectives: process tree, network sequence, file path, agent signature, kill chain depth
- K-means-style clustering (heuristic, not sklearn)
- CalibratedFusion fuses all perspectives into INADSResult (0-1 score + threat_level)

---

## LAYER 8: CORRELATION
### Files: `src/amoskys/intel/fusion_engine.py` (71,407 bytes), `rules.py` (50,812 bytes), `advanced_rules.py` (58,923 bytes), `kill_chain.py` (10,127 bytes)

### Fusion Engine (fusion_engine.py):
- Per-device event buffers (deque, max 1000 events)
- Sliding window evaluation (default 30 minutes, configurable)
- Emits Incident objects
- AMRDR integration: incident confidence weighted by agent reliability scores
- Device risk: starts at base 10, incremented by rule matches

### **31 Total Correlation Rules** (not 13 as initially assumed):

**13 Base Rules (rules.py):**
| Rule | Description |
|------|-------------|
| rule_ssh_brute_force | 5+ SSH login failures |
| rule_persistence_after_auth | Auth + service creation |
| rule_suspicious_sudo | Unusual sudo patterns |
| rule_multi_tactic_attack | 3+ MITRE tactics in window |
| rule_ssh_lateral_movement | SSH + internal discovery |
| rule_data_exfiltration_spike | Anomalous data transfer |
| rule_suspicious_process_tree | Process spawning unusual children |
| rule_coordinated_reconnaissance | Discovery + enumeration |
| rule_web_attack_chain | HTTP + shell + file modification |
| rule_infostealer_kill_chain | macOS: credential → persist → exfil |
| rule_clickfix_attack | macOS: clickjacking + privesc |
| rule_download_execute_persist | Download → execute → persist |
| rule_credential_harvest_exfil | Credential tools + exfil |

**18 Advanced Rules (advanced_rules.py):**
| Rule | Description |
|------|-------------|
| rule_apt_initial_access_chain | Multi-stage APT foothold |
| rule_fileless_attack | Memory-only execution |
| rule_log_tampering | Log file modifications |
| rule_security_tool_disable | Security software disable |
| rule_credential_dumping_chain | Lsass/keychain dump |
| rule_ssh_key_theft_and_pivot | SSH key exfil → lateral |
| rule_internal_reconnaissance | Host enumeration + scanning |
| rule_staged_exfiltration | File staging → DNS tunnel |
| rule_dns_exfiltration | Data in DNS queries |
| rule_binary_replacement_attack | Critical binary change (rootkit) |
| rule_suid_privilege_escalation | SUID bit plant |
| rule_webshell_deployment | Web-accessible shell creation |
| rule_dns_c2_beaconing | Periodic DNS → C2 beacon |
| rule_dga_malware_activity | Domain Generation Algorithm |
| rule_kernel_privilege_escalation | Kernel exploit + privesc |
| rule_container_escape | Container breakout |
| rule_process_injection | Code injection |
| rule_unknown_service_persistence | Unauthorized service creation |

### Kill Chain Tracker (kill_chain.py — 10,127 bytes):
- 7 stages mapped to MITRE tactics:
  1. Reconnaissance → reconnaissance, discovery
  2. Weaponization → resource_development
  3. Delivery → initial_access
  4. Exploitation → execution, privilege_escalation, defense_evasion, credential_access
  5. Installation → persistence
  6. Command & Control → command_and_control
  7. Actions on Objectives → lateral_movement, collection, exfiltration, impact
- TTL: 1 hour default (configurable)
- Multi-stage trigger: ≥3 unique stages = attack likely in progress
- Thread-safe: record_stage(), record_from_tactic(), get_progression()

### CORRECTED ASSUMPTION #8:
> Initial claim: "Fusion engine doesn't create incidents — 0 rows in telemetry.db"

**REALITY:** Fusion engine IS creating incidents — **274 incidents exist in
data/intel/fusion.db**, but they are NOT written back to telemetry.db's incidents table.
The fusion engine writes to its own SQLite database, not the telemetry store.
This is a **routing/integration gap**, not a missing feature.

| Database | incidents table | Status |
|----------|----------------|--------|
| data/intel/fusion.db | **274 rows** | Fusion engine writes here |
| data/telemetry.db | **0 rows** | Telemetry store never reads fusion.db |

Also in intel DBs:
- data/intel/probe_calibration.db: **44 calibration entries** (ProbeCalibrator working)
- data/intel/reliability.db: **3,736 observation logs** (AMRDR tracking active)
- data/intel/reliability.db: **2 agent reliability entries**

---

## LAYER 9: SHIPPER
### File: `src/amoskys/shipper.py`

### SHIP_TABLES: 9 tables with column definitions

### **CRITICAL: 9 COLUMNS SILENTLY DROPPED**

The shipper sends these columns for `security_events` that the ops server's
ALLOWED_TABLES whitelist **rejects**:

| Column | What it contains | Impact of loss |
|--------|-----------------|----------------|
| `cmdline` | Full command line of process | **Cannot see what command was run** |
| `exe` | Executable path | **Cannot identify the binary** |
| `remote_port` | Port of remote connection | **Cannot identify service targeted** |
| `protocol` | Network protocol (TCP/UDP) | **Cannot classify traffic type** |
| `geo_src_city` | City-level geolocation | Lost precision (have country) |
| `geo_src_latitude` | GPS latitude | Lost geo precision |
| `geo_src_longitude` | GPS longitude | Lost geo precision |
| `asn_src_number` | ASN number | Lost (have org name) |
| `asn_src_network_type` | Network classification | Lost (hosting/isp/education) |

**cmdline, exe, remote_port, protocol** are FORENSIC-CRITICAL fields.
Without them, ops server has security events but cannot reconstruct what happened.

### Device ID (_generate_device_id):
1. macOS: IOPlatformSerialNumber → SHA-256 → first 16 hex chars
2. Linux: /etc/machine-id
3. Fallback: MAC address + arch + OS

### Hostname (_get_hostname):
1. `scutil --get ComputerName`
2. `scutil --get LocalHostName`
3. `socket.gethostname()`
4. `platform.node()`

### Registration (_register):
- POST to `{AMOSKYS_SERVER}/api/v1/register`
- Sends: device_id, hostname, os, os_version, arch, agent_version, deploy_token, org_id
- Receives: api_key (persisted to config)
- Re-registers every 5 minutes (heartbeat)

### Shipping Loop:
- Reads from telemetry.db
- Ships 9 tables in order
- Cursor tracking: last_shipped_id per table (persisted in JSON file)
- Batch size: 500 rows per table per cycle
- Handles server unreachable: logs warning, retries next cycle
- verify=False for self-signed certs (ops server)

---

## LAYER 10: OPS SERVER
### File: `server/command_center.py`

### Schema: 10 tables + devices

### Endpoints:
- `POST /api/v1/register` — device registration (returns api_key)
- `POST /api/v1/telemetry` — event ingestion (9 tables, column whitelist)
- `GET /api/v1/devices` — list all devices (marks offline if >5min)
- `GET /api/v1/fleet/status` — fleet summary with counts
- `GET /api/v1/events` — security events (filterable)
- `GET /api/v1/bulk-export` — all tables for fleet sync
- `GET /api/v1/device/<id>/telemetry` — per-device dashboard data
- `DELETE /api/v1/device/<id>` — delete device and all events

### Dedup: source_id = hash(device_id + row_id + timestamp)
### **Retention: NOT IMPLEMENTED in command_center.py** — no cleanup endpoint,
### no background worker, no TTL enforcement. Fleet DB grows unbounded.
### (Earlier claim of "7-day auto-delete" was WRONG — that's only in local telemetry.db)

### org_id Handling:
- Added to every event on ingestion (from device record)
- Filtering available on fleet/status endpoint
- BUT: not all endpoints filter by org_id (security gap for multi-tenant)

---

## LAYER 10.5: EVENTBUS
### File: `src/amoskys/eventbus/server.py`

### Architecture:
- **gRPC server** with mutual TLS (mTLS)
- **Port:** configurable via BUS_SERVER_PORT env var
- **3 services:** EventBusServicer (legacy), UniversalEventBusServicer, EventBusControlServicer

### Publish RPC Pipeline (8 stages):
1. Overload check → RETRY with 2000ms backoff
2. Size check (MAX_ENV_BYTES) → INVALID
3. Ed25519 signature verification → INVALID (**BUT: _verify_legacy_envelope_signature() is STUBBED — "not yet implemented"**)
4. FlowEvent extraction → INVALID
5. Contract normalization → quality state check
6. Deduplication (_seen()) → **returns OK but doesn't actually block** (dedup is advisory only)
7. In-flight tracking → RETRY if over BUS_MAX_INFLIGHT
8. WAL batch write → RETRY if fails

### WAL Batch Writer:
- Max batch: 100 events
- Max wait: 50ms
- Background thread, blocking write per caller

### Rate Limiting:
- Token bucket per agent_id
- 100 tokens/sec default (BUS_AGENT_RATE)
- 200 token burst (BUS_AGENT_BURST)

### Dedup Cache:
- In-memory OrderedDict (NOT persistent across restarts)
- TTL: 300 seconds
- Max: 50,000 entries
- **BUG: _seen() identifies duplicates but Publish still returns OK** — dedup is advisory

### Prometheus Metrics:
- bus_publish_total, bus_invalid_total, bus_publish_latency_ms
- bus_inflight_requests, bus_retry_total, bus_dedup_hits_total
- bus_rate_limited_total, bus_contract_invalid_total
- bus_wal_failures_total, bus_unsigned_rejected_total

### TLS:
- Server cert/key: certs/server.crt, certs/server.key
- CA cert: certs/ca.crt
- mTLS: require_client_auth=True (default)
- Override: EVENTBUS_REQUIRE_CLIENT_AUTH=false for CI/test

---

## LAYER 11: ANALYZER
### File: `src/amoskys/analyzer_main.py` (44,629 bytes)

### Initialization (14 components):
1. TelemetryStore (line 59)
2. EnrichmentPipeline (line 70) — 4-stage
3. ScoringEngine (line 78) — baselines, calibration, thresholds
4. SigmaEngine (line 89) — 56 rules
5. ForensicContextEnricher (line 103) — **IS integrated here, not dead code**
6. UnifiedSOMA (line 113) — frequency baseline learning
7. ProbeCalibrator (line 123) — Beta-Binomial precision tracking
8. TelemetryShipper (line 135) — optional, if AMOSKYS_SERVER set
9. FusionEngine (line 170) — 31 rules (13 base + 18 advanced)
10. KillChainTracker (line 182) — TTL=3600s
11. EventDeduplicator (line 191) — TTL=600s, max=50K
12. IGRIS (line 198) — supervisor for autonomous defense
13. IGRISTacticalEngine (line 208) — hunt mode
14. WALProcessor (line 220)

### Analysis Loop (2.0 second cycle):
Per event processing order:
1. Enrichment (GeoIP, ASN, threat intel)
2. Deduplication (skip if dup)
3. SOMA observation + assessment
4. Probe calibration (update precision weights)
5. ASV update (Agent Signature Vector)
6. Forensic enrichment (cross-agent context)
7. Scoring (3 heuristic + ML if available)
8. Sigma detection (56 rules with aliases)

Periodic tasks:
- IGRIS tactical: every 10s (cycle % 5)
- IGRIS observation: every 60s (cycle % 30)
- Fusion evaluation: every 60s (cycle % 30)
- Retention cleanup: every 30min (cycle % 900)

### **BUG: Dict import missing (line 151)**
`_asv_window: Dict[str, float] = {}` — `Dict` not imported from typing.
Will crash on Python 3.9+. Fix: use `dict[str, float]` or add import.

---

## LIVE DATA VERIFICATION (April 4, 2026)

### Ops Server (18.223.110.15) — LIVE, receiving events NOW:
- Health: OK, version 0.9.1-beta
- **1 device registered:** Akash's MacBook Air (b45045f5e1a0c15e), arm64, Darwin 25.0.0
- **Status: ONLINE** — last seen 2026-04-04T07:05 UTC (during this audit)
- **18,984 total security events** on ops server
- Last 24h: 3,775 events (573 critical, 923 high)
- Top categories: process_spawned (2,023), lolbin_execution (453), new_external_connection (295)
- Top MITRE: T1059 (2,476), T1204 (2,125), T1218 (453)
- Events have 32+ fields populated including all scores, MITRE, enrichment

### **DNS BROKEN: ops.amoskys.com does not resolve**
- Agent must be using IP directly or has cached address
- Cloudflare A record for ops.amoskys.com → 18.223.110.15 needs to be created/fixed

### Presentation Server (3.147.175.238):
- Health: OK
- TLS via Cloudflare, cert valid through June 7, 2026

### Local Telemetry (telemetry.db) — STALE since March 30:
- **All local data stops at 2026-03-30T19:42 UTC** — 5 days stale
- Total events across all tables: ~924,000+
- persistence_events: 685,716 (74% of all data — dedup issue)
- observation_events: 174,368
- flow_events: 32,773
- All 19 queues: 0 rows (fully drained)

### Intel DBs — ACTIVE:
- fusion.db: **274 incidents**, 1 device risk entry
- probe_calibration.db: **44 calibration entries**
- reliability.db: **3,736 observations**, 2 agent reliability entries

---

## CONSOLIDATED FINDINGS

### CRITICAL (must fix before v1.0):

1. **9 forensic columns dropped at ops server** — cmdline, exe, remote_port, protocol
   silently rejected by ALLOWED_TABLES whitelist. Fix: add to whitelist + ALTER TABLE.

2. **10 tables permanently empty** — telemetry_events (canonical envelope),
   process_genealogy (spawn chains), incidents (SOC), telemetry_receipts
   (completeness tracking) are defined but never populated. These represent
   designed capabilities that were never connected.

3. **.proto source files lost** — Only generated _pb2.py exist. Schema evolution
   requires reverse-engineering from serialized descriptors.

4. **Ops server has NO retention/cleanup** — fleet.db grows unbounded (~575MB and
   increasing). No background worker, no TTL, no VACUUM. Earlier claim of "7-day
   auto-delete" was wrong — that only applies to local telemetry.db.

5. **EventBus signature verification is STUBBED** — _verify_legacy_envelope_signature()
   says "not yet implemented." REQUIRE_SIGNATURES defaults True but verification is a no-op.
   Any agent can publish unsigned events.

6. **EventBus dedup is advisory only** — _seen() identifies duplicates but Publish()
   still returns OK status. Duplicates are logged but NOT rejected.

7. **Analyzer Dict import bug (line 151)** — `_asv_window: Dict[str, float]` uses
   unimported `Dict`. Will crash on Python 3.9+. Runtime error.

### HIGH (should fix):

4. **persistence_events: 685K rows** — 70x larger than expected. Snapshot dedup
   may not be working correctly for persistence agent.

5. **ThreatIntel database empty** — threat_intel.db exists but has 0 entries.
   Every IP evaluated as "not malicious." Silent failure.

6. **0 YARA rules** — Engine exists, rules directory empty. File-based detection dormant.

7. **274 incidents in fusion.db but 0 in telemetry.db** — FusionEngine writes incidents
   to its own DB (data/intel/fusion.db) but they never reach the telemetry store.
   Dashboard and shipper read from telemetry.db → incidents invisible to users and ops.

8. **Local telemetry.db stale since March 30** — Pipeline ships to ops server but
   hasn't written locally for 5 days. Local dashboard would show stale data.

9. **ops.amoskys.com DNS broken** — Domain doesn't resolve. Agent uses IP directly.

### MEDIUM:

9. **Agent count mismatch: 20 registry vs 18 collector** — macos_security_monitor
   and macos_unified_log registered but never run. realtime_sensor runs but isn't
   in registry.

10. **Scoring is 2-tier** — Tier 1 is heuristic (Geometric + Temporal + Behavioral).
    Tier 2 is real sklearn ML (IsolationForest + GradientBoosting in soma_brain.py).
    ML only trains with sufficient high-trust labeled data. Hot-reloads into ScoringEngine.
    INADS engine adds multi-perspective anomaly detection (47K bytes of clustering logic).

11. **SOMA baselines reset on restart** — Known from prior audit. Frequency
    baselines are learned over time but lost on agent restart.

---

## WHAT THE TEST SUITE MUST COVER

Based on this audit, the comprehensive test suite needs **~350 test cases** across 13 layers:

### Priority 1 — Data Integrity (prevents silent data loss):
- [ ] Shipper column parity with ops server whitelist
- [ ] All 9 shipped tables have matching schema on both sides
- [ ] No columns silently dropped (verify round-trip)
- [ ] Queue hash chain integrity verification
- [ ] Ed25519 signature validation
- [ ] WAL checksum verification (BLAKE2b)

### Priority 2 — Agent Completeness:
- [ ] Each of 18 agents instantiates
- [ ] Each agent produces events in one cycle
- [ ] Each event has: event_type, severity, timestamp, device_id, collection_agent
- [ ] AGENT_REGISTRY matches collector agent list
- [ ] Each agent's probes produce correct event types
- [ ] Probe readiness contract validation

### Priority 3 — Pipeline Flow:
- [ ] Collection → Queue → WAL → Storage → Enrichment → Detection → Scoring → Ship
- [ ] End-to-end: synthetic event flows from agent to ops server
- [ ] Each storage table receives events from expected agents
- [ ] Enrichment adds expected fields (geo, ASN, MITRE)
- [ ] Sigma rules fire on known-bad patterns
- [ ] Scoring produces classification in [0.0, 1.0]

### Priority 4 — Operational Health:
- [ ] All 19 queue DBs exist and have correct schema
- [ ] telemetry.db WAL mode + pragmas
- [ ] Prewarm daemon computes rollups
- [ ] Dashboard reads complete in <100ms
- [ ] Retention cleanup works (>7 days deleted)
- [ ] Ops server dedup prevents duplicates

### Priority 5 — Enrichment & Routing Gaps:
- [ ] forensic_context.py is in ANALYZER (line 103+409), NOT in WAL routing — verify both paths
- [ ] Observation events bypass enrichment entirely — is this intentional?
- [ ] ThreatIntel has no feed refresh — new indicators don't re-scan old events
- [ ] Observation raw data pruned after 2h — no archive path
- [ ] MITRE enricher has ~20 rules — verify coverage vs 53 claimed techniques
- [ ] Flow/DNS events from non-security paths may skip enrichment
- [ ] process_genealogy table never populated — spawn chain tracking dead

### Priority 6 — Security:
- [ ] SQL injection blocked at all endpoints
- [ ] org_id tenant isolation
- [ ] Config file permissions (root:600)
- [ ] No secrets in source code or logs
- [ ] Auth required for all dashboard routes
