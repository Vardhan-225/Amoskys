# Quick Reference Tables - EventBus/WAL/Storage Audit

## EventBus Publish Flow (Handler: lines 946-1133)

| Step | Operation | Line | Pass Condition | Fail Response |
|------|-----------|------|----------------|---------------|
| 1 | Record metrics | 1023 | Always | N/A |
| 2 | Check overload | 1026 | `is_overloaded() == False` | RETRY(2000ms) |
| 3 | Check size | 1036 | `≤ MAX_ENV_BYTES (131KB)` | INVALID("too large") |
| 4 | Verify signature | 1047 | Valid or optional | INVALID("sig failed") |
| 5 | Check idempotency | 1060 | Not seen in 300s | OK("duplicate") |
| 6 | Increment inflight | 1068 | Always | N/A |
| 7 | Check inflight limit | 1071 | `< BUS_MAX_INFLIGHT` | RETRY(1000ms) |
| 8 | Extract flow | 1081 | Valid flow/payload | INVALID("missing flow") |
| 9 | Write WAL | 1104 | Write succeeds | RETRY(2000ms) |
| 10 | Return ACK | 1121 | Always | OK("accepted") |

## Deduplication Cache (_seen function, lines 251-273)

```
_dedupe: OrderedDict[str, float] (idem → timestamp)
Size: max 50,000 entries (DEDUPE_MAX)
TTL: 300 seconds (DEDUPE_TTL_SEC)

Entry lifecycle:
1. Check if seen: in_dict(idem) → return True
2. Auto-expire: remove entries older than now - 300s
3. Add new: _dedupe[idem] = now
4. Evict oldest: if len > 50K, pop first entry
5. Move to end: if found again, move to end (MRU order)
```

## WAL Hash Chain Formula

```
Genesis: sig_0 = 0x00...00 (32 zero bytes)

For each write:
  checksum = BLAKE2b(env_bytes, digest_size=32)
  prev_sig = sig_last OR GENESIS_SIG
  sig = BLAKE2b(env_bytes || prev_sig, digest_size=32)

  INSERT wal(idem, ts_ns, bytes, checksum, sig, prev_sig)

Chain structure:
  Row 1: sig_1 = BLAKE2b(env_1 || 0x00...00)
  Row 2: sig_2 = BLAKE2b(env_2 || sig_1)
  Row 3: sig_3 = BLAKE2b(env_3 || sig_2)
  ...
```

## Verification in WAL Processor (lines 119-157)

```
For each batch row:
  1. BLAKE2b check:
     expected = BLAKE2b(raw_bytes)
     if stored_checksum ≠ expected:
        → Quarantine with "BLAKE2b checksum mismatch"

  2. Chain check:
     expected_sig = BLAKE2b(raw_bytes || stored_prev_sig)
     if stored_sig ≠ expected_sig:
        → Quarantine with "hash chain signature mismatch"
        → Increment chain_break_count

  3. Parse & process:
     envelope = UniversalEnvelope()
     envelope.ParseFromString(raw_bytes)
     Route to appropriate table

  4. Delete from WAL:
     DELETE FROM wal WHERE id = row_id
     COMMIT
```

## Storage Schema Quick Lookup

| Table | Rows Per... | Indexes | Primary Keys |
|-------|------------|---------|--------------|
| process_events | device+timestamp | timestamp, device, exe, is_suspicious | UNIQUE(device_id, pid, timestamp_ns) |
| device_telemetry | device+timestamp | timestamp, device_id | UNIQUE(device_id, timestamp_ns) |
| flow_events | 5-tuple+timestamp | timestamp, ips, None | UNIQUE(device, src_ip, dst_ip, ports, ts_ns) |
| security_events | device+timestamp | timestamp, risk_score, classification | None |
| peripheral_events | device+timestamp | timestamp, device, type, risk, unauthorized | None |
| dns_events | device+domain+timestamp | timestamp, domain, risk, type | UNIQUE(device, domain, query_type, ts_ns) |
| audit_events | device+timestamp | timestamp, syscall, risk, exe | None |
| persistence_events | device+timestamp | timestamp, mechanism, risk, entry | None |
| fim_events | device+path+timestamp | timestamp, path, risk, type | None |
| wal_dead_letter | — | quarantined_at DESC | None |

## Enrichment Pipeline Stages

### Stage 1: GeoIP (geoip.py, lines 99-163)

```
Input: event dict with src_ip, dst_ip, source_ip fields
Output: event dict with geo_* fields added

Skip conditions:
  - IP is None or empty → skip
  - IP is private (127.*, 10.*, 192.168.*, 172.16.*, 0.*, ::1, fe80:) → skip
  - DB not available → skip

Lookup: MaxMind GeoLite2-City MMDB
Cache: LRU 10,000 entries

Returns:
  - geo_src_country: ISO code (US, GB, CN, etc.)
  - geo_src_country_name: Full name
  - geo_src_city: City name
  - geo_src_latitude: Float
  - geo_src_longitude: Float
  - geo_src_continent: Continent name
  - geo_src_timezone: IANA timezone
```

### Stage 2: ASN (asn.py, lines 138-191)

```
Input: event dict with src_ip, dst_ip, source_ip fields
Output: event dict with asn_* fields added

Lookup: MaxMind GeoLite2-ASN MMDB
Cache: LRU 10,000 entries

Classification logic:
  1. Known ASN numbers → return: hosting, tor, vpn
  2. Org name keywords:
     - "hosting", "cloud", "server", "datacenter" → hosting
     - "university", "college", "education" → education
     - "government", "federal", "military" → government
     - "telecom", "isp", "broadband" → residential
     - Default → corporate

Returns:
  - asn_src_number: ASN number (15169, etc.)
  - asn_src_org: Organization name
  - asn_src_network_type: Classification
  - asn_src_is_hosting: Boolean
  - asn_src_is_tor: Boolean
  - asn_src_is_vpn: Boolean
```

### Stage 3: ThreatIntel (threat_intel.py, lines 161-250)

```
Input: event dict
Output: event dict with threat_* fields added

Checks performed:
  - src_ip, dst_ip, source_ip → indicator_type="ip"
  - domain, hostname → indicator_type="domain"
  - file_hash, sha256, new_hash → indicator_type="file_hash"

Lookup: Local SQLite table "indicators"
Cache: LRU 10,000 entries, 3600s TTL
Expiry handling: Automatic filtering by expires_at column

If any match found:
  - Use highest severity match (critical > high > medium > low)
  - Set threat_intel_match = True
  - Set threat_source = best["source"]
  - Set threat_severity = best["severity"]

If no match:
  - Set threat_intel_match = False
```

## Configuration Parameters

### EventBus (server.py)

```
BUS_SERVER_PORT
  Type: int
  Default: from config.eventbus.port
  Example: 5000
  Impact: gRPC listen port

BUS_OVERLOAD
  Type: bool
  Default: false
  Example: export BUS_OVERLOAD=true
  Impact: Force RETRY on all requests if true

BUS_MAX_ENV_BYTES
  Type: int
  Default: 131072 (128KB)
  Example: export BUS_MAX_ENV_BYTES=262144
  Impact: Size limit for envelopes

BUS_DEDUPE_TTL_SEC
  Type: int
  Default: 300 (5 minutes)
  Example: export BUS_DEDUPE_TTL_SEC=600
  Impact: How long to remember idempotency keys

BUS_DEDUPE_MAX
  Type: int
  Default: 50000
  Example: export BUS_DEDUPE_MAX=100000
  Impact: Max dedup cache size

BUS_REQUIRE_SIGNATURES
  Type: bool
  Default: false (BACKWARD COMPAT WARNING)
  Example: export BUS_REQUIRE_SIGNATURES=true
  Impact: Enforce Ed25519 signature verification

EVENTBUS_REQUIRE_CLIENT_AUTH
  Type: bool
  Default: true
  Example: export EVENTBUS_REQUIRE_CLIENT_AUTH=false
  Impact: Enforce mTLS client certificate requirement
```

### WAL (wal_sqlite.py)

```
path
  Type: str
  Default: config.agent.wal_path
  Example: /var/amoskys/wal.db
  Impact: SQLite database file location

max_bytes
  Type: int
  Default: 200 * 1024 * 1024 (200MB)
  Example: max_bytes=1024*1024*1024 (1GB)
  Impact: Max WAL size before auto-delete oldest

vacuum_threshold
  Type: float
  Default: 0.3
  Example: vacuum_threshold=0.5
  Impact: Fraction of deleted space before VACUUM runs
```

### Storage (telemetry_store.py)

```
db_path
  Type: str
  Default: data/telemetry.db
  Example: /var/amoskys/telemetry.db
  Impact: TelemetryStore database file location
```

### Enrichment

```
GeoIP DB path: /usr/share/GeoIP/GeoLite2-City.mmdb
ASN DB path: /usr/share/GeoIP/GeoLite2-ASN.mmdb
ThreatIntel DB path: data/threat_intel.db

Cache sizes:
  - GeoIP: 10,000 IPs (configurable)
  - ASN: 10,000 IPs (configurable)
  - ThreatIntel: 10,000 checks, 3600s TTL

Determinism:
  - Same input (same IP, domain, hash) → same output
  - Output changes if DB is updated/reloaded
  - Not thread-safe: each enricher instance has own DB connection
```

## Metric Definitions

| Metric | Type | Labels | Notes |
|--------|------|--------|-------|
| bus_publish_total | Counter | — | Incremented per Publish RPC |
| bus_invalid_total | Counter | — | Incremented on INVALID response |
| bus_retry_total | Counter | — | Incremented on RETRY response |
| bus_publish_latency_ms | Histogram | — | Measured at end of handler |
| bus_inflight_requests | Gauge | — | Current count, updated via ±inflight |
| bus_dedup_hits_total | Counter | — | Duplicates caught |
| bus_wal_write_failures_total | Counter | — | WAL write failures |

## Error Codes

| Status | Value | Semantics | Retry? |
|--------|-------|-----------|--------|
| OK | 0 | Event accepted and persisted (or duplicate) | No |
| RETRY | 1 | Transient error, client should retry with backoff | Yes |
| INVALID | 2 | Permanent error, don't retry same envelope | No |
| UNAUTHORIZED | 3 | Client not authorized (unused) | No |
| ERROR | 4+ | Unexpected server error | Maybe |

## WAL Backpressure Policy

```
Trigger: backlog_bytes() > max_bytes

Action: Drop oldest events (lowest id) until backlog < max_bytes
  FOR each row in wal ORDER BY id:
    DELETE wal WHERE id = row.id
    freed += row.size
    IF freed >= (backlog - max_bytes):
      break

Logging: WARNING "Backpressure: dropped N events (X bytes)"

VACUUM: Triggered if:
  - Time since last VACUUM > 5 minutes AND
  - Deleted bytes > vacuum_threshold * file_size_bytes()

Impact:
  - Recent events preserved (tail-drop, not head-drop)
  - Oldest events lost first
  - Unbounded file growth prevented
```

## Schema Version Tracking

```
Migration 001: Add schema_version INTEGER DEFAULT 1 to all tables
  Purpose: Track schema version for future compatibility
  All existing rows marked as version 1

Migration 002: Add GeoIP/ASN columns
  Flow events: geo_src_*, geo_dst_*, asn_src_*, asn_dst_*
  Security events: geo_src_*, asn_src_*
  Idempotent: Uses ALTER TABLE ADD COLUMN

Migration 003: Add ThreatIntel columns
  Flow, security, DNS, FIM events: threat_intel_match, threat_source, threat_severity
  Idempotent: Uses ALTER TABLE ADD COLUMN

Auto-applied: During TelemetryStore.__init__() via auto_migrate()
```

## Event Routing Rules (wal_processor.py)

```
if event.type == "STATUS" AND source_component == "peripheral_agent":
  → peripheral_events table

if event.HasField("security_event"):
  → security_events table
  + domain routing:
    if attrs["pid"] AND collection_agent in ("proc-agent-v3", "proc_agent_v3"):
      → process_events
    if attrs["dst_ip"] AND "flow" in collection_agent:
      → flow_events
    if "usb" in event_category OR "peripheral" in collection_agent:
      → peripheral_events
    if "dns" in collection_agent OR attrs["domain"]:
      → dns_events
    if "kernel" in collection_agent AND attrs["syscall"]:
      → audit_events
    if "persistence" in collection_agent:
      → persistence_events
    if "fim" in collection_agent AND attrs["path"]:
      → fim_events
```

## Thread Safety Analysis

| Component | Lock | Granularity | Status |
|-----------|------|-------------|--------|
| EventBus Publish | _inflight_lock | Per inc/dec | Safe |
| Dedup cache | _dedupe_lock | Entire cache | Safe |
| WAL write | _lock (RWLock) | Read prev_sig + insert | Safe |
| Enrichment | None | Per instance per thread | Check if safe |
| Storage writes | SQLite locks | Per INSERT | Safe |

## Known Limitations

1. **Dedup TTL (300s)**: Clients retrying after 300s may see duplicates
2. **No persistent auth**: No CN authorization (trust map defined but unused)
3. **Separate WAL processor**: Events queue if processor crashes
4. **No event replay**: Dead letter queue is permanent
5. **Limited tracing**: Cannot follow single event through system
6. **Cache explosion**: 10k RPS exceeds 50k dedup cache in 5 seconds
7. **No request batching**: Each event = individual INSERT

## Performance Estimates

```
Single Publish RPC:
  - Size check: ~1ms
  - Signature verify (Ed25519): ~50-100ms if enabled
  - Dedup check: ~0.1ms
  - Inflight check: ~0.1ms
  - Extract flow: ~1ms
  - WAL write (SQLite): ~5-10ms
  Total: ~60-120ms (without sig) or ~110-220ms (with sig)

WAL Processor batch (100 events):
  - Read: ~10ms
  - Verify checksums & chain: ~10ms
  - Parse & route: ~20ms
  - Enrich (GeoIP/ASN/ThreatIntel): ~100-500ms (if DBs available)
  - Insert to storage: ~50-100ms
  - Commit & delete: ~10ms
  Total: ~200-700ms per batch

Throughput estimates:
  - EventBus alone: ~5k-10k RPS (limited by signature/WAL latency)
  - With WAL processor: ~1k sustained (limited by enrichment & storage)
```
