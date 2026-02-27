# EXHAUSTIVE TECHNICAL AUDIT: EventBus, WAL, and Storage Layers
## Amoskys Network Security Platform

**Audit Date:** February 2026
**Scope:** Complete trace of event flow from EventBus ingestion → WAL persistence → Storage → Enrichment
**Code Refs:** All line numbers reference absolute paths in source tree

---

## EXECUTIVE SUMMARY

This audit traces the complete lifecycle of a network flow event from initial arrival at the EventBus server through persistent storage in the telemetry database. The architecture is a three-stage pipeline:

1. **EventBus Server (gRPC)**: Receives, validates, and ACKs events
2. **WAL Layer (SQLite)**: Provides durable queue with hash-chain integrity
3. **Storage Layer (TelemetryStore)**: Permanent domain-specific tables with enrichment

**Critical Finding:** EventBus → WAL write path is implemented, but WAL → Storage processing happens in separate `wal_processor.py` with independent threading. Events are NOT synchronously persisted; the dashboard sees real-time events only if the processor is running.

---

## PART 1: EVENTBUS SERVER AUDIT

### Location
**File:** `/sessions/ecstatic-loving-gauss/mnt/Amoskys/src/amoskys/eventbus/server.py`

### A. Server Initialization: `serve()` Function (lines 1455-1689)

**Sequence:**
1. **Line 1543-1551:** Initialize WAL storage (`SQLiteWAL`)
   - Path: `config.agent.wal_path`
   - Max bytes: `config.storage.max_wal_bytes`
   - Thread-safe with `_wal_lock` (line 103)

2. **Line 1556-1564:** Set overload mode from CLI or environment
   - CLI flag: `--overload {on|off|auto}`
   - Env var: `BUS_OVERLOAD` (lines 147-150)
   - Global `_OVERLOAD` flag controls RETRY responses

3. **Line 1572-1585:** Start Prometheus metrics servers
   - Ports: `config.eventbus.metrics_port_1`, `metrics_port_2`
   - Metrics exported on separate HTTP servers (line 1574)

4. **Line 1588:** Create gRPC server with 50 thread pool workers
   - `futures.ThreadPoolExecutor(max_workers=50)`

5. **Line 1591-1614:** Load TLS certificates for mTLS
   - Server cert: `certs/server.crt` (line 1594)
   - Server key: `certs/server.key` (line 1592)
   - CA cert: `certs/ca.crt` (line 1596)
   - Enforce client auth: `require_client_auth` (line 1600-1601)
   - Status: **Implemented, required for all connections**

6. **Line 1617-1619:** Bind gRPC server to port
   - Port from env: `BUS_SERVER_PORT` (line 1617)
   - Default: `config.eventbus.port`
   - TLS credentials applied via `add_secure_port()`

7. **Line 1622-1632:** Register service implementations
   - Legacy `EventBusServicer` (line 1623)
   - New `UniversalEventBusServicer` (line 1626)
   - Both respond to `Publish()` and `PublishTelemetry()` RPCs

8. **Line 1634-1648:** Load Ed25519 signing keys
   - Path: `certs/agent.ed25519.pub`
   - Used by `_verify_legacy_envelope_signature()` and `_verify_envelope_signature()`
   - **Status: Implemented but only used if keys exist; failures are logged as warnings**

9. **Line 1651-1664:** Load trust map for per-agent authorization
   - File: `config.crypto.trust_map_path`
   - Maps client CNs to Ed25519 public keys
   - **Status: Function exists but not enforced in Publish handler**

10. **Line 1667-1668:** Start health check HTTP server
    - Port: `8080`
    - Endpoint: `GET /healthz` (line 1431)

11. **Line 1671-1672:** Start gRPC server
    - Blocks indefinitely, serves requests via thread pool

12. **Line 1676-1683:** Graceful shutdown loop
    - Waits for `_SHOULD_EXIT` flag (set by SIGHUP/SIGTERM)
    - Drains in-flight requests with 10-second grace period (line 1675)

### B. Publish RPC Handler: `EventBusServicer.Publish()` (lines 946-1133)

**Flow diagram:**
```
Publish(request) →
  [1] Check overload? → if yes, RETRY(2000ms)
  [2] Size check (MAX_ENV_BYTES) → if fail, INVALID
  [3] Verify signature (Ed25519) → if fail, INVALID
  [4] Check idempotency (dedup cache) → if duplicate, OK("duplicate")
  [5] Increment inflight counter
  [6] Check inflight limit → if exceed, RETRY(1000ms)
  [7] Extract FlowEvent from envelope
  [8] Write to WAL (if configured) → if fail, RETRY(2000ms)
  [9] Return OK("accepted")
```

**Detailed execution:**

**Step 1: Overload Check (lines 1018-1030)**
```python
BUS_REQS.inc()  # Line 1023: count all Publish calls
if is_overloaded():  # Line 1026: check global _OVERLOAD flag
    BUS_RETRY_TOTAL.inc()  # Line 1028
    BUS_LAT.observe(latency)  # Line 1029
    return _ack_retry(OVERLOAD_REASON, 2000)  # Line 1030
```
- Semantic: If server is in overload mode, immediately reject with backoff hint
- No processing if overloaded
- **Code ref:** `is_overloaded()` at line 188

**Step 2: Envelope Size Validation (lines 1035-1044)**
```python
if _sizeof_env(request) > MAX_ENV_BYTES:  # MAX_ENV_BYTES = 131072 (128KB)
    BUS_INVALID.inc()  # Line 1040
    return INVALID response  # Line 1042-1043
```
- Function: `_sizeof_env()` (lines 224-245) calls `SerializeToString()`
- Prevents memory exhaustion attacks
- **Default limit:** 128KB (configurable via `BUS_MAX_ENV_BYTES`)

**Step 3: Signature Verification (lines 1046-1051)**
```python
sig_valid, sig_error = _verify_legacy_envelope_signature(request)  # Line 1047
if not sig_valid:
    BUS_INVALID.inc()  # Line 1050
    return INVALID  # Line 1051
```

**Signature verification details** (lines 512-550):
- Check if `sig` field exists (line 524)
- If absent and `REQUIRE_SIGNATURES=true` (env var), reject (line 527-528)
- If absent and `REQUIRE_SIGNATURES=false`, accept (line 530-531) ← **Default: backward compat**
- If present, verify Ed25519 signature:
  - Reconstruct payload: copy envelope, clear `sig` and `prev_sig` fields (lines 538-541)
  - Verify using `AGENT_PUBKEY` (line 544)
  - On failure, return INVALID (lines 546-547)
- **Current status:** Signatures optional unless explicitly required

**Step 4: Idempotency Deduplication (lines 1053-1065)**
```python
pub_idem = request.idempotency_key or request.idem or f"unknown_{request.ts_ns}"
if _seen(pub_idem):  # Line 1060
    BUS_DEDUP_HITS.inc()  # Line 1061
    return _ack_ok("duplicate")  # Line 1065
```

**Dedup cache details** (lines 251-273):
```python
_dedupe: OrderedDict[str, float]  # Maps idem→timestamp
TTL: DEDUPE_TTL_SEC = 300 seconds  # Line 212 (configurable)
Max size: DEDUPE_MAX = 50000 entries  # Line 213 (configurable)

_seen(idem):  # Lines 251-273
  [A] Acquire lock
  [B] Expire old entries (TTL check, FIFO via OrderedDict)
  [C] If seen before, move to end, return True
  [D] Add new entry with current timestamp
  [E] Evict oldest if size > DEDUPE_MAX
  [F] Return False
```
- **Thread-safe:** Uses `_dedupe_lock` (line 248)
- **Eviction:** Oldest entries (lowest insertion time) are removed first
- **Semantics:** Duplicate requests return OK (idempotent), not rejected

**Step 5: Inflight Tracking (lines 1067-1078)**
```python
inflight = _inc_inflight()  # Line 1068
try:
    if inflight > BUS_MAX_INFLIGHT:  # BUS_MAX_INFLIGHT = config.eventbus.max_inflight
        BUS_RETRY_TOTAL.inc()  # Line 1075
        return _ack_retry(...)  # Line 1076
finally:
    _dec_inflight()  # Line 1126
```

**Inflight management** (lines 553-628):
```python
_inflight: int = 0  # Global counter
_inflight_lock: threading.Lock()

_inc_inflight():  # Lines 553-588
  Lock → _inflight += 1 → Update gauge → Release lock

_dec_inflight():  # Lines 591-628
  Lock → _inflight = max(0, _inflight-1) → Update gauge → Release lock
```
- **Backpressure:** If in-flight requests exceed limit, reject with RETRY
- **Default limit:** From config (likely 1000-10000 based on typical patterns)

**Step 6: FlowEvent Extraction (lines 1080-1084)**
```python
flow = _flow_from_envelope(request)  # Line 1081
# Logs: src_ip, dst_ip, bytes_tx
```

**Extraction logic** (lines 631-687):
```python
_flow_from_envelope(env):
  [A] Try new format: env.flow (structured field)
      if hasattr(env, "flow") and env.flow.ByteSize() > 0:
          return env.flow
  [B] Try legacy format: env.payload (serialized bytes)
      payload = getattr(env, "payload", b"")
      if payload:
          msg = pb.FlowEvent()
          msg.ParseFromString(payload)
          return msg
  [C] If both fail, raise ValueError("Envelope missing flow/payload")
```
- Supports both new protobuf structure and legacy serialized format
- **Backward compat:** Old agents sending `payload` field still work

**Step 7: WAL Write (lines 1086-1124)**
```python
if wal_storage:
    try:
        with _wal_lock:  # Thread-safe WAL access
            idem = request.idempotency_key or request.idem or f"unknown_{request.ts_ns}"
            ts_ns = request.ts_ns
            env_bytes = request.SerializeToString()

            written = wal_storage.write_raw(idem, ts_ns, env_bytes)  # Line 1104
            if written:
                wal_written = True  # Line 1106
            else:
                wal_duplicate = True  # Line 1111
    except Exception as wal_err:
        logger.error("AOC1_WAL_WRITE_FAILURE: %s", wal_err)  # Line 1116
        BUS_WAL_FAILURES.inc()  # Line 1117
```

**ACK decision** (lines 1120-1124):
```python
if wal_written or wal_duplicate or not wal_storage:
    return _ack_ok("accepted")  # Line 1121
else:
    BUS_RETRY_TOTAL.inc()  # Line 1123
    return _ack_retry("WAL write failed, retry", 2000)  # Line 1124
```

**Critical semantics:**
- OK if: WAL write succeeded, duplicate detected (idempotent), or no WAL configured
- RETRY if: WAL write failed
- **Implication:** Event is ACKed to client only AFTER (or if) WAL write succeeds
- **P0-EB-2:** "ACK after WAL" pattern ensures client knows event is persisted

### C. PublishTelemetry RPC Handler (lines 1184-1333)

Similar flow to `Publish()`, but for `UniversalEnvelope` format:

**Key differences:**
1. **Signature verification:** Uses `_verify_envelope_signature()` (lines 1221-1231)
   - Checks `envelope.sig` and `envelope.signing_algorithm` (line 468)
   - Only Ed25519 supported (line 486)
   - Returns `SECURITY_VIOLATION` status on failure (line 1229)

2. **Event extraction:** Checks multiple message types
   - `device_telemetry` (line 1262)
   - `process` (line 1267)
   - `flow` (line 1272)

3. **WAL write:** Same pattern as `Publish()` (lines 1284-1307)

### D. Prometheus Metrics Exported (lines 105-141)

| Metric | Type | Purpose |
|--------|------|---------|
| `bus_publish_total` | Counter | Total Publish RPC calls |
| `bus_invalid_total` | Counter | Invalid envelope count |
| `bus_publish_latency_ms` | Histogram | Request latency |
| `bus_inflight_requests` | Gauge | Current in-flight requests |
| `bus_retry_total` | Counter | RETRY responses issued |
| `bus_dedup_hits_total` | Counter | Duplicates caught |
| `bus_wal_write_failures_total` | Counter | WAL write failures |

**Ports:**
- Metrics HTTP: ports from `config.eventbus.metrics_port_1/2`
- Health check: `0.0.0.0:8080/healthz`
- gRPC: `[::]:{BUS_SERVER_PORT}` with TLS

### E. Configuration Parameters

| Parameter | Env Var | Default | Purpose |
|-----------|---------|---------|---------|
| Server port | `BUS_SERVER_PORT` | config value | gRPC listen port |
| Max inflight | — | config value | Backpressure limit |
| Hard max | — | config value | Absolute ceiling |
| Overload mode | `BUS_OVERLOAD` | false | Force reject mode |
| Max envelope | `BUS_MAX_ENV_BYTES` | 131072 | Size limit |
| Dedup TTL | `BUS_DEDUPE_TTL_SEC` | 300 | Cache expiry |
| Dedup max | `BUS_DEDUPE_MAX` | 50000 | Cache size |
| Require signatures | `BUS_REQUIRE_SIGNATURES` | false | Enforce Ed25519 |
| Require client auth | `EVENTBUS_REQUIRE_CLIENT_AUTH` | true | mTLS enforcement |

### F. Error Handling & Status Codes

**PublishAck.Status enum:**
```protobuf
OK = 0          → Event accepted and persisted (or duplicate)
RETRY = 1       → Transient error, client should retry with backoff
INVALID = 2     → Permanent error, malformed envelope
UNAUTHORIZED = 3 → Client not authorized (not used yet)
ERROR = 4+      → Server error (internal error)
```

**When each is returned:**
- **OK:** Valid envelope, passed all checks, WAL write succeeded/duplicate/no WAL
- **RETRY:** Overloaded, inflight limit exceeded, WAL write failed, transient errors
- **INVALID:** Size exceeded, signature invalid, missing flow/payload, parse error
- **ERROR:** Unexpected exceptions (caught at line 1130-1132)

---

## PART 2: WAL LAYER AUDIT

### Location
**File:** `/sessions/ecstatic-loving-gauss/mnt/Amoskys/src/amoskys/agents/flowagent/wal_sqlite.py`

### A. WAL Initialization: `SQLiteWAL.__init__()` (lines 77-107)

**Constructor signature:**
```python
def __init__(
    self,
    path="wal.db",
    max_bytes=200 * 1024 * 1024,  # 200MB default
    vacuum_threshold=0.3
):
```

**Initialization steps:**
1. **Line 96:** Create parent directory if needed
2. **Line 103-105:** Connect to SQLite with auto-commit (`isolation_level=None`)
   - Timeout: 5 seconds
   - `check_same_thread=False` allows multiple threads
3. **Line 106:** Execute schema script (line 35-49):
   ```sql
   PRAGMA journal_mode=WAL;
   PRAGMA synchronous=FULL;
   CREATE TABLE wal (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     idem TEXT NOT NULL UNIQUE,
     ts_ns INTEGER NOT NULL,
     bytes BLOB NOT NULL,
     checksum BLOB NOT NULL,
     sig BLOB,
     prev_sig BLOB
   );
   CREATE UNIQUE INDEX wal_idem ON wal(idem);
   CREATE INDEX wal_ts ON wal(ts_ns);
   ```
   - **WAL mode:** SQLite's native WAL journal format
   - **synchronous=FULL:** Fsync on every commit (safe against crashes)
   - **idem unique index:** Prevents duplicate writes

4. **Line 107:** Migrate chain columns if needed (lines 109-122)
   - Idempotent: checks if `sig`/`prev_sig` already exist
   - Adds columns if missing (legacy WAL upgrade path)

### B. Hash Chain Computation: `_compute_chain_sig()` (lines 55-61)

**Formula:**
```python
def _compute_chain_sig(env_bytes: bytes, prev_sig: bytes) -> bytes:
    return hashlib.blake2b(env_bytes + prev_sig, digest_size=32).digest()
```

**Semantics:**
- Hash the concatenation: `env_bytes || prev_sig`
- Output: 32-byte BLAKE2b digest
- Genesis value: `GENESIS_SIG = b"\x00" * 32` (line 52)

**Chain structure:**
```
Row 1: sig_1 = BLAKE2b(env_1 || GENESIS_SIG)
Row 2: sig_2 = BLAKE2b(env_2 || sig_1)
Row 3: sig_3 = BLAKE2b(env_3 || sig_2)
...
```

**Tamper detection:**
- If env_1 is modified, sig_1 changes
- Sig_2 computation expects old sig_1, gets different value → chain breaks
- Any deletion or reordering breaks all downstream signatures

### C. Write Path: `write_raw()` (lines 131-157)

**Function signature:**
```python
def write_raw(self, idem: str, ts_ns: int, env_bytes: bytes) -> bool:
    """Write to WAL with BLAKE2b checksum and hash chain.

    Returns:
        True if written, False if duplicate
    """
```

**Execution:**
1. **Line 145:** Compute BLAKE2b checksum of envelope
   ```python
   checksum = hashlib.blake2b(env_bytes, digest_size=32).digest()
   ```

2. **Line 146-147:** Acquire lock for chain integrity
   ```python
   with self._lock:
       prev_sig = self._get_last_sig()  # Get sig from last row, or GENESIS_SIG
   ```

3. **Line 148:** Compute this entry's signature
   ```python
   sig = _compute_chain_sig(env_bytes, prev_sig)
   ```

4. **Line 150-153:** Insert into SQLite
   ```sql
   INSERT INTO wal(idem, ts_ns, bytes, checksum, sig, prev_sig)
   VALUES(?, ?, ?, ?, ?, ?)
   ```

5. **Line 154-157:** Handle duplicate
   ```python
   except sqlite3.IntegrityError:
       return False  # Duplicate idem key
   ```

**Thread safety:**
- Lock held for entire duration (line 146)
- Gets previous sig, computes new sig, inserts atomically
- No race window where chain is inconsistent

**Key invariant:** Every row's `prev_sig` matches the previous row's `sig`

### D. Read Path: `process_batch()` in WAL Processor (lines 64-210)

**Location:** `/sessions/ecstatic-loving-gauss/mnt/Amoskys/src/amoskys/storage/wal_processor.py`

**Function signature:**
```python
def process_batch(self, batch_size: int = 100) -> int:
    """Process batch of events from WAL with BLAKE2b verification.

    Args:
        batch_size: Number of events (capped at 500)

    Returns:
        Number successfully processed

    Raises:
        sqlite3.OperationalError: If WAL locked/corrupt
    """
```

**Verification steps:**

**Step 1: BLAKE2b checksum verification (lines 119-142)**
```python
if stored_checksum is not None:
    stored_cs = bytes(stored_checksum)
    expected = hashlib.blake2b(raw, digest_size=32).digest()

    if len(stored_cs) != 32:
        logger.error("CHECKSUM_INVALID_SIZE: ... quarantine")
        self._quarantine(row_id, raw, "invalid checksum size")
        continue

    if stored_cs != expected:
        logger.error("CHECKSUM_MISMATCH: ... quarantine")
        self._quarantine(row_id, raw, "BLAKE2b checksum mismatch")
        continue
```

**Detection:** If any byte of the envelope is corrupted, checksum fails immediately.

**Step 2: Hash chain verification (lines 144-157)**
```python
if stored_sig is not None and stored_prev_sig is not None:
    prev = bytes(stored_prev_sig)
    expected_sig = hashlib.blake2b(raw + prev, digest_size=32).digest()

    if bytes(stored_sig) != expected_sig:
        logger.error("CHAIN_BREAK: ... quarantine")
        self._quarantine(row_id, raw, "hash chain signature mismatch")
        self.chain_break_count += 1
        continue
```

**Detection:**
- Recompute sig using `env_bytes + prev_sig`
- If stored sig doesn't match, chain is broken
- Indicates tampering or database corruption

**Step 3: Processing (lines 159-175)**
```python
envelope = telemetry_pb2.UniversalEnvelope()
envelope.ParseFromString(raw)  # Parse protobuf

if envelope.HasField("device_telemetry"):
    self._process_device_telemetry(envelope.device_telemetry, ts_ns, idem)
elif envelope.HasField("process"):
    self._process_process_event(envelope.process, ts_ns, idem)
elif envelope.HasField("flow"):
    self._process_flow_event(envelope.flow, ts_ns)

processed_ids.append(row_id)
processed += 1
```

**Step 4: Deletion from WAL (lines 184-190)**
```python
if processed_ids:
    placeholders = ",".join("?" * len(processed_ids))
    conn.execute(
        f"DELETE FROM wal WHERE id IN ({placeholders})",
        processed_ids
    )
    conn.commit()
```

**Semantics:** "ACK after store" — events deleted from WAL only after successful processing (or error handling/quarantine).

### E. Backpressure: `_enforce_backlog()` (lines 290-327)

**Mechanism:**
```python
def _enforce_backlog(self):
    """Drop oldest events if backlog exceeds max_bytes."""
    total = self.backlog_bytes()  # SUM(length(bytes)) from WAL
    if total <= self.max_bytes:
        return

    to_free = total - self.max_bytes
    freed = 0
    dropped_count = 0

    # FIFO order: delete oldest first (lowest id)
    cur = self.db.execute("SELECT id, length(bytes), idem FROM wal ORDER BY id")
    for rowid, sz, idem in cur:
        self.db.execute("DELETE FROM wal WHERE id=?", (rowid,))
        freed += sz
        dropped_count += 1
        self.deleted_since_vacuum += 1
        if freed >= to_free:
            break

    if dropped_count > 0:
        logger.warning(f"Backpressure: dropped {dropped_count} events ({freed} bytes)")

    self._maybe_vacuum()
```

**Semantics:** "Tail-drop" — when queue exceeds max_bytes, oldest entries are discarded first. Recent events preserved.

**Default:** 200MB max backlog

### F. Vacuum Trigger (lines 329-368)

**Policy:**
- Runs every ≥5 minutes (lines 340-341)
- Only if deleted bytes exceed `vacuum_threshold * file_size` (lines 343-350)
- Rebuilds database to reclaim space

**Trade-off:** VACUUM is expensive but necessary to prevent unbounded file growth.

### G. Genesis State & Chain Bootstrapping

**Genesis signature:**
```python
GENESIS_SIG = b"\x00" * 32  # Line 52
```

**Lookup path** (lines 124-129):
```python
def _get_last_sig(self) -> bytes:
    """Return sig of most recent entry, or GENESIS_SIG if empty."""
    row = self.db.execute("SELECT sig FROM wal ORDER BY id DESC LIMIT 1").fetchone()
    if row and row[0]:
        return bytes(row[0])
    return GENESIS_SIG
```

**Bootstrap:** First entry's `prev_sig = GENESIS_SIG`, so `sig_1 = BLAKE2b(env_1 || GENESIS_SIG)`.

---

## PART 3: STORAGE LAYER AUDIT

### Location
**File:** `/sessions/ecstatic-loving-gauss/mnt/Amoskys/src/amoskys/storage/telemetry_store.py`

### A. Database Schema (lines 31-466)

**Core tables:**

#### 1. process_events
```sql
CREATE TABLE process_events (
    id INTEGER PRIMARY KEY,
    timestamp_ns INTEGER NOT NULL,
    timestamp_dt TEXT NOT NULL,
    device_id TEXT NOT NULL,
    pid INTEGER NOT NULL,
    ppid INTEGER,
    exe TEXT,
    cmdline TEXT,
    username TEXT,
    cpu_percent REAL,
    memory_percent REAL,
    num_threads INTEGER,
    num_fds INTEGER,
    user_type TEXT,          -- root, system, user
    process_category TEXT,   -- system, application, daemon
    is_suspicious BOOLEAN DEFAULT 0,
    anomaly_score REAL,
    confidence_score REAL,
    collection_agent TEXT,
    agent_version TEXT,
    UNIQUE(device_id, pid, timestamp_ns)
);
```

**Indexes:**
- `idx_process_timestamp` on `timestamp_ns DESC`
- `idx_process_device` on `(device_id, timestamp_ns DESC)`
- `idx_process_exe` on `exe`
- `idx_process_suspicious` on `(is_suspicious, timestamp_ns DESC)`

#### 2. device_telemetry
```sql
CREATE TABLE device_telemetry (
    id INTEGER PRIMARY KEY,
    timestamp_ns INTEGER NOT NULL,
    timestamp_dt TEXT NOT NULL,
    device_id TEXT NOT NULL,
    device_type TEXT,
    protocol TEXT,
    manufacturer TEXT,
    model TEXT,
    ip_address TEXT,
    mac_address TEXT,
    total_processes INTEGER,
    total_cpu_percent REAL,
    total_memory_percent REAL,
    metric_events INTEGER DEFAULT 0,
    log_events INTEGER DEFAULT 0,
    security_events INTEGER DEFAULT 0,
    collection_agent TEXT,
    agent_version TEXT,
    UNIQUE(device_id, timestamp_ns)
);
```

#### 3. flow_events
```sql
CREATE TABLE flow_events (
    id INTEGER PRIMARY KEY,
    timestamp_ns INTEGER NOT NULL,
    timestamp_dt TEXT NOT NULL,
    device_id TEXT NOT NULL,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT,
    bytes_tx INTEGER,
    bytes_rx INTEGER,
    packets_tx INTEGER,
    packets_rx INTEGER,
    is_suspicious BOOLEAN DEFAULT 0,
    threat_score REAL,
    -- Enrichment fields (added by migrations)
    geo_src_country TEXT,
    geo_src_city TEXT,
    geo_src_latitude REAL,
    geo_src_longitude REAL,
    asn_src_number INTEGER,
    asn_src_org TEXT,
    asn_src_network_type TEXT,
    threat_intel_match BOOLEAN DEFAULT 0,
    threat_source TEXT,
    threat_severity TEXT,
    UNIQUE(device_id, src_ip, dst_ip, src_port, dst_port, timestamp_ns)
);
```

#### 4. security_events
```sql
CREATE TABLE security_events (
    id INTEGER PRIMARY KEY,
    timestamp_ns INTEGER NOT NULL,
    timestamp_dt TEXT NOT NULL,
    device_id TEXT NOT NULL,
    event_category TEXT,
    event_action TEXT,
    event_outcome TEXT,
    risk_score REAL,
    confidence REAL,
    mitre_techniques TEXT,      -- JSON array
    geometric_score REAL,       -- From XGBoost
    temporal_score REAL,        -- From LSTM
    behavioral_score REAL,      -- From MLP
    final_classification TEXT,  -- legitimate, suspicious, malicious
    description TEXT,
    indicators TEXT,            -- JSON object
    requires_investigation BOOLEAN DEFAULT 0,
    collection_agent TEXT,
    agent_version TEXT
);
```

#### 5. peripheral_events
```sql
CREATE TABLE peripheral_events (
    id INTEGER PRIMARY KEY,
    timestamp_ns INTEGER NOT NULL,
    timestamp_dt TEXT NOT NULL,
    device_id TEXT NOT NULL,
    peripheral_device_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    device_name TEXT,
    device_type TEXT,
    vendor_id TEXT,
    product_id TEXT,
    serial_number TEXT,
    manufacturer TEXT,
    connection_status TEXT,
    previous_status TEXT,
    mount_point TEXT,
    files_transferred INTEGER DEFAULT 0,
    bytes_transferred INTEGER DEFAULT 0,
    is_authorized BOOLEAN DEFAULT 0,
    risk_score REAL,
    confidence_score REAL,
    threat_indicators TEXT,  -- JSON array
    collection_agent TEXT,
    agent_version TEXT
);
```

#### 6. dns_events
```sql
CREATE TABLE dns_events (
    id INTEGER PRIMARY KEY,
    timestamp_ns INTEGER NOT NULL,
    timestamp_dt TEXT NOT NULL,
    device_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    query_type TEXT,
    response_code TEXT,
    source_ip TEXT,
    process_name TEXT,
    pid INTEGER,
    event_type TEXT,
    dga_score REAL,
    is_beaconing BOOLEAN DEFAULT 0,
    beacon_interval_seconds REAL,
    is_tunneling BOOLEAN DEFAULT 0,
    risk_score REAL DEFAULT 0.0,
    confidence REAL DEFAULT 0.0,
    mitre_techniques TEXT,
    collection_agent TEXT,
    agent_version TEXT,
    threat_intel_match BOOLEAN DEFAULT 0,
    threat_source TEXT,
    threat_severity TEXT
);
```

#### 7. audit_events
```sql
CREATE TABLE audit_events (
    id INTEGER PRIMARY KEY,
    timestamp_ns INTEGER NOT NULL,
    timestamp_dt TEXT NOT NULL,
    device_id TEXT NOT NULL,
    host TEXT,
    syscall TEXT NOT NULL,
    event_type TEXT NOT NULL,
    pid INTEGER,
    ppid INTEGER,
    uid INTEGER,
    euid INTEGER,
    gid INTEGER,
    egid INTEGER,
    exe TEXT,
    comm TEXT,
    cmdline TEXT,
    cwd TEXT,
    target_path TEXT,
    target_pid INTEGER,
    target_comm TEXT,
    risk_score REAL DEFAULT 0.0,
    confidence REAL DEFAULT 0.0,
    mitre_techniques TEXT,
    reason TEXT,
    collection_agent TEXT,
    agent_version TEXT
);
```

#### 8. persistence_events
```sql
CREATE TABLE persistence_events (
    id INTEGER PRIMARY KEY,
    timestamp_ns INTEGER NOT NULL,
    timestamp_dt TEXT NOT NULL,
    device_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    mechanism TEXT,
    entry_id TEXT,
    path TEXT,
    command TEXT,
    schedule TEXT,
    user TEXT,
    change_type TEXT,
    old_command TEXT,
    new_command TEXT,
    risk_score REAL DEFAULT 0.0,
    confidence REAL DEFAULT 0.0,
    mitre_techniques TEXT,
    reason TEXT,
    collection_agent TEXT,
    agent_version TEXT
);
```

#### 9. fim_events
```sql
CREATE TABLE fim_events (
    id INTEGER PRIMARY KEY,
    timestamp_ns INTEGER NOT NULL,
    timestamp_dt TEXT NOT NULL,
    device_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    path TEXT NOT NULL,
    change_type TEXT,
    old_hash TEXT,
    new_hash TEXT,
    old_mode TEXT,
    new_mode TEXT,
    file_extension TEXT,
    owner_uid INTEGER,
    owner_gid INTEGER,
    risk_score REAL DEFAULT 0.0,
    confidence REAL DEFAULT 0.0,
    mitre_techniques TEXT,
    reason TEXT,
    patterns_matched TEXT,      -- JSON array
    collection_agent TEXT,
    agent_version TEXT
);
```

#### 10. incidents (SOC incident management)
```sql
CREATE TABLE incidents (
    id INTEGER PRIMARY KEY,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL DEFAULT 'medium',  -- critical, high, medium, low
    status TEXT NOT NULL DEFAULT 'open',      -- open, investigating, contained, resolved, closed
    assignee TEXT,
    source_event_ids TEXT,  -- JSON array of security_event IDs
    mitre_techniques TEXT,  -- JSON array
    indicators TEXT,        -- JSON object
    resolution_notes TEXT,
    resolved_at TEXT
);
```

#### 11. alert_rules (custom alerting)
```sql
CREATE TABLE alert_rules (
    id INTEGER PRIMARY KEY,
    created_at TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    enabled BOOLEAN DEFAULT 1,
    event_category TEXT,
    min_risk_score REAL DEFAULT 0.0,
    severity TEXT DEFAULT 'medium',
    cooldown_seconds INTEGER DEFAULT 300,
    last_triggered_at TEXT,
    trigger_count INTEGER DEFAULT 0
);
```

#### 12. metrics_timeseries
```sql
CREATE TABLE metrics_timeseries (
    id INTEGER PRIMARY KEY,
    timestamp_ns INTEGER NOT NULL,
    timestamp_dt TEXT NOT NULL,
    metric_name TEXT NOT NULL,
    metric_type TEXT,       -- GAUGE, COUNTER
    device_id TEXT,
    value REAL NOT NULL,
    unit TEXT,
    min_value REAL,
    max_value REAL,
    avg_value REAL,
    sample_count INTEGER,
    UNIQUE(metric_name, device_id, timestamp_ns)
);
```

#### 13. wal_archive (raw events for replay)
```sql
CREATE TABLE wal_archive (
    id INTEGER PRIMARY KEY,
    archived_at INTEGER NOT NULL,
    original_ts_ns INTEGER NOT NULL,
    idempotency_key TEXT UNIQUE,
    envelope_bytes BLOB NOT NULL,
    checksum BLOB NOT NULL
);
```

#### 14. wal_dead_letter (failed processing)
```sql
CREATE TABLE wal_dead_letter (
    id INTEGER PRIMARY KEY,
    row_id INTEGER NOT NULL,
    error_msg TEXT NOT NULL,
    envelope_bytes BLOB NOT NULL,
    quarantined_at TEXT NOT NULL,
    source TEXT DEFAULT 'wal_processor'
);
```

### B. Migration System

**Location:** `/sessions/ecstatic-loving-gauss/mnt/Amoskys/src/amoskys/storage/migrations/`

**Applied migrations:**

#### 001_add_schema_version.sql
Adds `schema_version` column (default 1) to all domain tables.
- Purpose: Version tracking for future compatibility

#### 002_add_geo_columns.sql
Adds GeoIP enrichment columns to `flow_events` and `security_events`:
- `geo_src_country`, `geo_src_city`, `geo_src_latitude`, `geo_src_longitude`
- `asn_src_number`, `asn_src_org`, `asn_src_network_type`
- (Destination IPs added for flow_events only)

#### 003_add_threat_intel_columns.sql
Adds threat intelligence columns to multiple tables:
- `flow_events`, `security_events`, `dns_events`, `fim_events`
- Columns: `threat_intel_match`, `threat_source`, `threat_severity`

**Auto-migration on startup** (lines 492-503):
```python
try:
    from amoskys.storage.migrations.migrate import auto_migrate
    applied = auto_migrate(db_path)
    if applied > 0:
        logger.info("Applied %d pending schema migration(s)", applied)
except Exception:
    logger.warning("Schema migration failed — continuing")
```

### C. Data Routing: WAL Processor Domain Routing (lines 263-418)

**Routing logic** in `_route_events()` (lines 263-305):

```python
for event in events:
    # Peripheral STATUS events → peripheral_events table
    if event.event_type == "STATUS" and event.source_component == "peripheral_agent":
        self._process_peripheral_event(...)

    # SecurityEvent sub-message → security_events table + domain tables
    if event.HasField("security_event"):
        self._process_security_event(...)
        self._route_security_to_domain_tables(...)
```

**Security event routing** (lines 306-418):

Extracts event attributes and routes to domain-specific tables based on event type and source agent:

```python
if attrs.get("pid") and collection_agent in ("proc-agent-v3", "proc_agent_v3"):
    self._extract_process_from_security(...)  # → process_events

if attrs.get("dst_ip") and "flow" in collection_agent:
    self._extract_flow_from_security(...)     # → flow_events

if "usb" in cat or "peripheral" in collection_agent:
    self._extract_peripheral_from_security(...) # → peripheral_events

if "dns" in collection_agent or attrs.get("domain"):
    self._extract_dns_from_security(...)     # → dns_events

if "kernel" in collection_agent and attrs.get("syscall"):
    self._extract_audit_from_security(...)   # → audit_events

if "persistence" in collection_agent:
    self._extract_persistence_from_security(...) # → persistence_events

if "fim" in collection_agent and attrs.get("path"):
    self._extract_fim_from_security(...)     # → fim_events
```

### D. Enrichment Integration (lines 318-323)

```python
# A4.4: Enrich attributes with GeoIP, ASN, and threat intelligence
if self._pipeline is not None:
    try:
        self._pipeline.enrich(attrs)
    except Exception:
        logger.debug("Enrichment failed — continuing")
```

**Enrichment adds fields to event attributes dict before insertion:**
- GeoIP: `geo_src_country`, `geo_src_city`, etc.
- ASN: `asn_src_number`, `asn_src_org`, etc.
- ThreatIntel: `threat_intel_match`, `threat_source`, `threat_severity`

---

## PART 4: ENRICHMENT PIPELINE AUDIT

### Location
**Files:**
- `/sessions/ecstatic-loving-gauss/mnt/Amoskys/src/amoskys/enrichment/__init__.py`
- `/sessions/ecstatic-loving-gauss/mnt/Amoskys/src/amoskys/enrichment/geoip.py`
- `/sessions/ecstatic-loving-gauss/mnt/Amoskys/src/amoskys/enrichment/asn.py`
- `/sessions/ecstatic-loving-gauss/mnt/Amoskys/src/amoskys/enrichment/threat_intel.py`

### A. Pipeline Architecture: `EnrichmentPipeline` (lines 35-131)

**Three-stage pipeline:**

```python
def __init__(self, ...):
    self._geoip = GeoIPEnricher(db_path=geoip_db_path)
    self._asn = ASNEnricher(db_path=asn_db_path)
    self._threat_intel = ThreatIntelEnricher(
        db_path=threat_intel_db_path or "data/threat_intel.db"
    )
    self._stages: List[tuple] = [
        ("geoip", self._geoip),
        ("asn", self._asn),
        ("threat_intel", self._threat_intel),
    ]
```

**Execution** (lines 75-107):
```python
def enrich(self, event: Dict[str, Any]) -> Dict[str, Any]:
    succeeded = 0
    attempted = 0

    for name, enricher in self._stages:
        if not enricher.available:
            continue
        attempted += 1
        try:
            enricher.enrich_event(event)
            succeeded += 1
        except Exception:
            logger.warning("Enrichment stage '%s' failed", name, exc_info=True)

    # Set status
    if attempted == 0:
        event["enrichment_status"] = "raw"
    elif succeeded == attempted:
        event["enrichment_status"] = "enriched"
    else:
        event["enrichment_status"] = "partial"

    return event
```

**Semantics:**
- Each stage is optional (failures don't block others)
- Input/Output: Mutable event dict (enriched in-place)
- Status: "raw" (no stages), "partial" (some failed), "enriched" (all succeeded)
- Determinism: Same input produces same output (unless DBs change)

### B. GeoIP Enricher (geoip.py)

**Database:** MaxMind GeoLite2-City (MMDB format)

**Initialization** (lines 55-92):
```python
def __init__(self, db_path: Optional[str] = None, cache_size: int = 10_000):
    paths_to_try = [db_path] if db_path else _DEFAULT_DB_PATHS
    # Checks: /usr/share/GeoIP/, /var/lib/GeoIP/, data/geoip/

    for candidate in paths_to_try:
        if candidate and Path(candidate).is_file():
            self._reader = maxminddb.open_database(candidate)
            self._available = True
            break

    self._lookup_cached = lru_cache(maxsize=cache_size)(self._lookup_impl)
```

**Lookup** (lines 99-113):
```python
def lookup(self, ip: str) -> Optional[Dict[str, Any]]:
    if not ip or _is_private_ip(ip):
        return None  # Short-circuit private IPs
    if not self._available:
        return None
    return self._lookup_cached(ip)
```

**Private IP detection** (lines 36-43):
```python
_SKIP_PREFIXES = ("127.", "10.", "192.168.", "172.16.", "0.", "::1", "fe80:")

def _is_private_ip(ip: str) -> bool:
    if any(ip.startswith(p) for p in _SKIP_PREFIXES):
        return True
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True  # Unparseable → skip
```

**Implementation** (lines 115-138):
```python
def _lookup_impl(self, ip: str) -> Optional[Dict[str, Any]]:
    try:
        record = self._reader.get(ip)
        if not record:
            return None

        return {
            "country": country.get("iso_code"),          # e.g., "US"
            "country_name": country.get("names", {}).get("en"),  # "United States"
            "city": city.get("names", {}).get("en"),     # "Mountain View"
            "latitude": location.get("latitude"),        # 37.386
            "longitude": location.get("longitude"),      # -122.084
            "continent": continent.get("names", {}).get("en"),  # "North America"
            "timezone": location.get("time_zone"),       # "America/Los_Angeles"
        }
    except Exception:
        logger.debug("GeoIP lookup failed", exc_info=True)
        return None
```

**Event enrichment** (lines 140-163):
```python
def enrich_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
    for ip_field, prefix in [
        ("src_ip", "geo_src_"),
        ("dst_ip", "geo_dst_"),
        ("source_ip", "geo_src_"),
    ]:
        ip = event.get(ip_field)
        if ip:
            geo = self.lookup(ip)
            if geo:
                for k, v in geo.items():
                    event[f"{prefix}{k}"] = v
    return event
```

**Output fields:**
- `geo_src_country`, `geo_src_country_name`, `geo_src_city`, `geo_src_latitude`, `geo_src_longitude`, `geo_src_continent`, `geo_src_timezone`
- `geo_dst_*` (similar, for destination IPs)

**Cache:** LRU, default 10,000 entries
- `cache_info()` returns hits, misses, size, maxsize

### C. ASN Enricher (asn.py)

**Database:** MaxMind GeoLite2-ASN

**Initialization** (lines 104-132):
Similar to GeoIP; checks default paths and loads MMDB reader.

**Lookup** (lines 138-154):
```python
def lookup(self, ip: str) -> Optional[Dict[str, Any]]:
    if not ip or not self._available:
        return None

    from amoskys.enrichment.geoip import _is_private_ip
    if _is_private_ip(ip):
        return None

    return self._lookup_cached(ip)
```

**Implementation** (lines 156-176):
```python
def _lookup_impl(self, ip: str) -> Optional[Dict[str, Any]]:
    record = self._reader.get(ip)
    if not record:
        return None

    asn_number = record.get("autonomous_system_number")
    asn_org = record.get("autonomous_system_organization")
    network_type = _classify_network(asn_number, asn_org)

    return {
        "asn_number": asn_number,         # e.g., 15169
        "asn_org": asn_org,               # "Google LLC"
        "network_type": network_type,     # "hosting"
        "is_hosting": network_type == "hosting",
        "is_tor": network_type == "tor",
        "is_vpn": network_type == "vpn",
    }
```

**Network classification** (lines 67-95):
```python
def _classify_network(asn_number: Optional[int], asn_org: Optional[str]) -> str:
    # Known ASN lists
    _HOSTING_ASNS = {16509, 14618, 15169, 8075, 13335, ...}  # AWS, Google, Azure
    _TOR_ASNS = {680, 553, ...}
    _VPN_ASNS = {9009, 212238, 20473, ...}

    if asn_number in _HOSTING_ASNS:
        return "hosting"
    if asn_number in _TOR_ASNS:
        return "tor"
    if asn_number in _VPN_ASNS:
        return "vpn"

    org_lower = (asn_org or "").lower()

    if any(kw in org_lower for kw in {"hosting", "cloud", "server", "datacenter"}):
        return "hosting"
    if any(kw in org_lower for kw in {"university", "college", "education"}):
        return "education"
    if any(kw in org_lower for kw in {"government", "federal", "military"}):
        return "government"
    if any(kw in org_lower for kw in {"telecom", "isp", "broadband"}):
        return "residential"

    return "corporate"
```

**Output fields:**
- `asn_src_number`, `asn_src_org`, `asn_src_network_type`, `asn_src_is_hosting`, `asn_src_is_tor`, `asn_src_is_vpn`
- `asn_dst_*` (similar, for destination IPs)

### D. Threat Intelligence Enricher (threat_intel.py)

**Database:** Local SQLite (not external feed)

**Schema** (lines 32-46):
```sql
CREATE TABLE indicators (
    id INTEGER PRIMARY KEY,
    indicator TEXT NOT NULL,
    type TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'medium',  -- critical, high, medium, low
    source TEXT,
    description TEXT,
    added_at TEXT NOT NULL,
    expires_at TEXT,
    UNIQUE(indicator, type)
);
```

**Indicator types:** IP, domain, file_hash, url

**Initialization** (lines 58-76):
```python
def __init__(
    self,
    db_path: str = "data/threat_intel.db",
    cache_size: int = 10_000,
    cache_ttl_seconds: int = 3600,
):
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    self._db_path = db_path
    self._cache_ttl = cache_ttl_seconds

    self._conn = sqlite3.connect(db_path, check_same_thread=False, timeout=5.0)
    self._conn.executescript(_SCHEMA)

    self._check_cached = lru_cache(maxsize=cache_size)(self._check_impl)
    self._available = True
```

**Lookup** (lines 161-177):
```python
def check_indicator(
    self,
    value: str,
    indicator_type: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    if not value:
        return None
    self._maybe_expire_cache()
    key = (value.strip().lower(), indicator_type or "")
    return self._check_cached(key)
```

**Implementation** (lines 179-208):
```python
def _check_impl(self, key: tuple) -> Optional[Dict[str, Any]]:
    value, itype = key
    try:
        if itype:
            row = self._conn.execute(
                "SELECT * FROM indicators WHERE indicator = ? AND type = ? "
                "AND (expires_at IS NULL OR expires_at > ?) LIMIT 1",
                (value, itype, datetime.now(timezone.utc).isoformat()),
            ).fetchone()
        else:
            row = self._conn.execute(
                "SELECT * FROM indicators WHERE indicator = ? "
                "AND (expires_at IS NULL OR expires_at > ?) LIMIT 1",
                (value, datetime.now(timezone.utc).isoformat()),
            ).fetchone()

        if row:
            return {
                "matched": True,
                "indicator": row["indicator"],
                "type": row["type"],
                "severity": row["severity"],
                "source": row["source"],
                "description": row["description"],
            }
        return None
    except Exception:
        return None
```

**Event enrichment** (lines 210-250):
```python
def enrich_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
    matches: List[Dict[str, Any]] = []

    # Check IP fields
    for field in ("src_ip", "dst_ip", "source_ip"):
        ip = event.get(field)
        if ip:
            result = self.check_indicator(ip, "ip")
            if result:
                matches.append(result)

    # Check domain fields
    for field in ("domain", "hostname"):
        domain = event.get(field)
        if domain:
            result = self.check_indicator(domain, "domain")
            if result:
                matches.append(result)

    # Check hash fields
    for field in ("file_hash", "sha256", "new_hash"):
        h = event.get(field)
        if h:
            result = self.check_indicator(h, "file_hash")
            if result:
                matches.append(result)

    if matches:
        event["threat_intel_match"] = True
        # Use highest severity match
        best = min(matches, key=lambda m: {"critical": 0, "high": 1, ...}.get(..., 99))
        event["threat_source"] = best["source"]
        event["threat_severity"] = best["severity"]
    else:
        event["threat_intel_match"] = False

    return event
```

**Output fields:**
- `threat_intel_match`: Boolean
- `threat_source`: String (feed name)
- `threat_severity`: String (critical, high, medium, low)

**CSV loading** (lines 127-159):
```python
def load_csv(self, csv_path_or_text: str, source: Optional[str] = None) -> int:
    # Expected columns: indicator, type, severity, source, expiry
    # Returns count of loaded indicators
```

**Cache:** LRU with TTL-based expiration
- Default: 10,000 entries, 3600-second TTL
- `_maybe_expire_cache()` clears entire cache if TTL elapsed

---

## PART 5: END-TO-END EVENT TRACE

### Complete Flow for a Single Network Flow Event

**T0: Event Creation**
```
Agent creates FlowEvent protobuf:
  src_ip="192.0.2.1"
  dst_ip="198.51.100.42"
  src_port=45678
  dst_port=443
  protocol="TCP"
  bytes_tx=1024
  bytes_rx=2048
```

**T1: EventBus Publish RPC (lines 946-1133 of server.py)**
```
1. Agent calls: stub.Publish(Envelope{flow=FlowEvent})
2. EventBusServicer.Publish() receives request

3. Overload check (line 1026)
   → is_overloaded() = False, continue

4. Size check (line 1036)
   → _sizeof_env(request) = ~150 bytes < 131072, pass

5. Signature verification (line 1047)
   → _verify_legacy_envelope_signature(request)
   → REQUIRE_SIGNATURES = false, accept

6. Idempotency check (line 1060)
   → idem = request.idempotency_key = "agent-1-12345"
   → _seen(idem) = False (first time), continue

7. Inflight tracking (line 1068)
   → inflight = 42 < max_inflight (e.g., 1000), continue

8. Extract FlowEvent (line 1081)
   → _flow_from_envelope(request)
   → Returns parsed FlowEvent

9. WAL write (line 1104)
   → wal_storage.write_raw(idem, ts_ns, env_bytes)
   → Checksum: BLAKE2b(env_bytes) = 0x123...
   → prev_sig = GENESIS_SIG (or last sig)
   → sig = BLAKE2b(env_bytes || prev_sig) = 0x456...
   → INSERT: (idem='agent-1-12345', ts_ns=1708974000000000000,
              bytes=<protobuf>, checksum=0x123..., sig=0x456..., prev_sig=GENESIS_SIG)
   → Returns True (written)

10. Return ACK (line 1121)
    → PublishAck.Status.OK, reason="accepted"
```

**T2: WAL Storage (wal_sqlite.py)**
```
Event now persists in SQLite WAL table:
  id=1234
  idem='agent-1-12345'
  ts_ns=1708974000000000000
  bytes=<Envelope protobuf>
  checksum=0x123...
  sig=0x456...
  prev_sig=GENESIS_SIG

Backlog check: total_bytes ~150 < 200MB, no eviction
```

**T3: WAL Processor Loop (wal_processor.py)**
```
process_batch() called (every 5 seconds):

1. Query WAL: SELECT id, bytes, ts_ns, idem, checksum, sig, prev_sig FROM wal LIMIT 100
   → Returns row (1234, <bytes>, 1708974000000000000, 'agent-1-12345', 0x123..., 0x456..., GENESIS_SIG)

2. BLAKE2b verification (line 122)
   → stored_cs = bytes(0x123...)
   → expected = BLAKE2b(<bytes>) = 0x123...
   → Match! Continue

3. Hash chain verification (line 147)
   → prev = bytes(GENESIS_SIG)
   → expected_sig = BLAKE2b(<bytes> || GENESIS_SIG) = 0x456...
   → stored_sig = bytes(0x456...)
   → Match! Continue

4. Parse envelope (line 161-162)
   → envelope = UniversalEnvelope()
   → envelope.ParseFromString(<bytes>)

5. Route event (lines 165-172)
   → envelope.HasField("flow") = True
   → Call _process_flow_event(envelope.flow, ts_ns=1708974000000000000)

6. Insert into flow_events table (lines 993-1022)
   → INSERT INTO flow_events (
       timestamp_ns=1708974000000000000,
       timestamp_dt='2024-02-26T11:00:00.000000',
       device_id='unknown',
       src_ip='192.0.2.1',
       dst_ip='198.51.100.42',
       src_port=45678,
       dst_port=443,
       protocol='TCP',
       bytes_tx=1024,
       bytes_rx=2048,
       is_suspicious=False
     )

7. Enrichment (lines 318-323)
   a) GeoIP lookup: src_ip='192.0.2.1' is private → skip
                    dst_ip='198.51.100.42' is public
                    → geo_dst_country='US', geo_dst_city='Newark', geo_dst_latitude=40.735...

   b) ASN lookup: dst_ip='198.51.100.42' (example: Verisign)
                  → asn_dst_number=701, asn_dst_org='Verizon Business', asn_dst_network_type='corporate'

   c) ThreatIntel check: src_ip='192.0.2.1' not in indicators
                         dst_ip='198.51.100.42' → check_indicator(...) = None
                         → threat_intel_match=False

   Fields added to attributes dict, then inserted via UPDATE:
   UPDATE flow_events SET
     geo_dst_country='US',
     geo_dst_city='Newark',
     asn_dst_number=701,
     asn_dst_org='Verizon Business',
     asn_dst_network_type='corporate',
     threat_intel_match=False

8. Delete from WAL (line 188)
   → DELETE FROM wal WHERE id=1234
   → COMMIT

9. Metrics
   → processed_count += 1
```

**T4: Dashboard Query**
```
Frontend queries: SELECT * FROM flow_events WHERE timestamp_dt > '2024-02-26T10:00:00' AND is_suspicious=False
→ Returns enriched event with:
  timestamp_ns=1708974000000000000
  src_ip='192.0.2.1'
  dst_ip='198.51.100.42'
  geo_dst_country='US'
  geo_dst_city='Newark'
  asn_dst_number=701
  threat_intel_match=False
```

---

## PART 6: CRITICAL GAPS & ISSUES

### A. Not Yet Implemented

1. **Authorization (CN checking)** (lines 341-433, server.py)
   - `_peer_cn_from_context()` and `_load_trust()` are defined but never called
   - **Impact:** Client certificates are validated by TLS, but agent CN not checked against trust map
   - **Fix needed:** Call `_load_trust()` in serve() and check CN in Publish handler

2. **Idempotency key deduplication in Publish** (lines 1054-1065)
   - **Status:** Implemented for dedup check
   - **Issue:** Cache expires after 300 seconds, but clients may retry forever
   - **Risk:** Duplicate events after TTL expires not detected

3. **Subscribe RPC** (lines 1134-1173)
   - Currently returns `UNIMPLEMENTED` status
   - **Issue:** No streaming endpoint for real-time event subscriptions

4. **Health check readiness** (lines 1378-1452)
   - Returns 200 if process is alive, but doesn't verify gRPC readiness
   - **Impact:** Kubernetes may route traffic before server is fully initialized

### B. Race Conditions & Thread Safety

1. **WAL chain initialization race** (lines 124-129, wal_sqlite.py)
   - **Scenario:** Two threads call `write_raw()` simultaneously on empty WAL
   - **Issue:** Both read GENESIS_SIG, both compute sig_1 = BLAKE2b(env || GENESIS_SIG)
   - **Current mitigation:** Lock held (line 146), but reading previous sig is outside critical section
   - **Status:** Actually safe because lock covers read + compute + insert atomically

2. **Inflight counter underflow** (lines 591-628)
   - **Current:** `_inflight = max(0, _inflight - 1)` prevents negative
   - **Issue:** If threads miscount, counter can get stuck
   - **Mitigation:** Adequate, metric will be slightly inaccurate but bounded

3. **Dedup cache eviction race** (lines 251-273)
   - **Lock:** `_dedupe_lock` held entire duration
   - **Status:** Thread-safe

### C. Data Loss Scenarios

1. **Event published before WAL initialized**
   - Lines 1090-1117: `if wal_storage:` branch
   - **Scenario:** If WAL fails to initialize, wal_storage=None, ACK returned without persistence
   - **Impact:** Event returned OK to client but NOT durable
   - **Log:** Line 1549 warns if WAL fails, but doesn't fail the server

2. **WAL processor not running**
   - **Scenario:** wal_processor.py is a separate process, not integrated
   - **Impact:** Events accumulate in WAL but never reach storage tables
   - **Detection:** Must monitor WAL row count separately

3. **Quarantine without retry**
   - Lines 211-238: `_quarantine()` sends to dead_letter table
   - **Current:** Dead letter is permanent; no replay mechanism
   - **Issue:** Corrupted events are never recovered

### D. Performance Issues

1. **Signature verification for every request** (lines 1046-1051)
   - **Current:** Verifies all incoming envelopes against AGENT_PUBKEY
   - **Issue:** Crypto operations are slow
   - **Optimization:** Could cache verified agents or batch verify

2. **Dedup cache explosion**
   - **Default:** 50,000 entries, 300-second TTL
   - **Issue:** With 10k RPS, cache will hit limit and evict valid recent entries
   - **Risk:** Duplicates from retries after 50k entries not detected

3. **No batching in WAL write**
   - Each event: individual SQLite INSERT
   - **Optimization:** Could batch 100 events per transaction

### E. Security Issues

1. **Backward compatibility mode for signatures** (line 217-221)
   - Default: `REQUIRE_SIGNATURES=false`
   - **Issue:** Unauthenticated events accepted by default
   - **Recommendation:** Change default to true in production

2. **Trust map not validated**
   - Lines 341-383: Trust map loaded but never used
   - **Impact:** All agents with valid client certs accepted regardless of CN

3. **Overload mode can be set externally**
   - `set_overload_setting()` (lines 155-185) can be called from CLI
   - **Issue:** No authentication on CLI flag, orchestrator could toggle
   - **Severity:** Medium (affects availability, not confidentiality)

### F. Missing Observability

1. **No metrics for hash chain breaks**
   - Only logged at ERROR level (line 150-152, wal_processor.py)
   - **Add:** Counter `wal_chain_breaks_total`

2. **No metrics for quarantine rate**
   - **Add:** Counter `wal_quarantine_total` and `wal_quarantine_bytes_total`

3. **No tracing for event lifecycle**
   - Cannot follow single event from Publish → WAL → Storage
   - **Add:** Idempotency key in all logs

---

## PART 7: COMPLETE REQUEST/RESPONSE EXAMPLES

### Example 1: Successful Flow Event Publication

**Client request:**
```protobuf
Envelope {
  idempotency_key: "agent-1-flow-67890"
  ts_ns: 1708974000000000000
  flow: {
    src_ip: "192.0.2.1"
    dst_ip: "198.51.100.42"
    src_port: 45678
    dst_port: 443
    protocol: "TCP"
    bytes_tx: 1024
    bytes_rx: 2048
  }
}
```

**Server processing:**
1. Size check: 150 bytes < 131KB ✓
2. Signature check: none present, REQUIRE_SIGNATURES=false ✓
3. Dedup check: first time ✓
4. Inflight check: 42 < 1000 ✓
5. WAL write: success, returns True ✓

**Server response:**
```protobuf
PublishAck {
  status: OK
  reason: "accepted"
}
```

**Event stored in WAL:**
```sql
INSERT INTO wal VALUES (
  1234,                          -- id
  'agent-1-flow-67890',          -- idem
  1708974000000000000,           -- ts_ns
  <envelope bytes>,              -- bytes
  0x123456...,                   -- checksum (BLAKE2b)
  0x456789...,                   -- sig (hash chain)
  0x000000...                    -- prev_sig (GENESIS_SIG)
)
```

### Example 2: Duplicate Detected

**Client sends same request again:**
```protobuf
Envelope {
  idempotency_key: "agent-1-flow-67890"
  ...
}
```

**Server processing:**
1. Dedup check: idem found in cache with timestamp T-45 seconds ✓
2. Return immediately with OK("duplicate")

**No WAL write, no inflight reservation**

### Example 3: Overload Rejection

**Server in overload mode: _OVERLOAD=true**

**Client sends request:**

**Server processing:**
1. Overload check: is_overloaded() = true
2. Return immediately: RETRY("Server is overloaded", backoff_hint_ms=2000)

**No further processing**

### Example 4: Envelope Too Large

**Client sends 200KB envelope (> 131KB limit)**

**Server processing:**
1. Size check: 200KB > 131KB
2. Increment BUS_INVALID counter
3. Return: INVALID("Envelope too large (200KB > 131KB bytes)")

**Logged:** `[Publish] Envelope too large: 200000 bytes`

---

## PART 8: SCHEMA VERSIONING & MIGRATIONS

### Applied Migrations

**Migration tracker:** SQLite metadata table or directory-based versioning

**001 - add_schema_version (lines 1-14 of 001_add_schema_version.sql)**
```sql
ALTER TABLE process_events ADD COLUMN schema_version INTEGER DEFAULT 1;
ALTER TABLE device_telemetry ADD COLUMN schema_version INTEGER DEFAULT 1;
ALTER TABLE flow_events ADD COLUMN schema_version INTEGER DEFAULT 1;
ALTER TABLE security_events ADD COLUMN schema_version INTEGER DEFAULT 1;
... (all 10 domain tables)
```

**002 - add_geo_columns (lines 1-25 of 002_add_geo_columns.sql)**
```sql
ALTER TABLE flow_events ADD COLUMN geo_src_country TEXT;
ALTER TABLE flow_events ADD COLUMN geo_src_city TEXT;
ALTER TABLE flow_events ADD COLUMN geo_src_latitude REAL;
ALTER TABLE flow_events ADD COLUMN geo_src_longitude REAL;
ALTER TABLE flow_events ADD COLUMN asn_src_number INTEGER;
... (geo/ASN fields for flow and security events)
```

**003 - add_threat_intel_columns (lines 1-18 of 003_add_threat_intel_columns.sql)**
```sql
ALTER TABLE flow_events ADD COLUMN threat_intel_match BOOLEAN DEFAULT 0;
ALTER TABLE flow_events ADD COLUMN threat_source TEXT;
ALTER TABLE flow_events ADD COLUMN threat_severity TEXT;
... (same for security, dns, fim events)
```

**Auto-application:** Lines 492-503 of telemetry_store.py call `auto_migrate(db_path)` on startup

---

## PART 9: DEPENDENCY CHAIN

```
Client Agent
  ↓ gRPC Publish(Envelope)
EventBus Server
  ├─ Validate (size, sig, dedup, inflight)
  ├─ Extract FlowEvent
  └─ WAL write (if wal_storage configured)
      ├─ Compute BLAKE2b checksum
      ├─ Compute hash chain sig
      └─ INSERT into wal table (SQLite)

WAL Processor (separate process)
  ├─ Read from wal table (batch_size=100)
  ├─ Verify checksums & chain
  ├─ Parse envelope
  ├─ Route to domain tables based on event type
  │   ├─ FlowEvent → flow_events
  │   ├─ ProcessEvent → process_events
  │   ├─ DeviceTelemetry.events → {security, peripheral, dns, ...}_events
  │   └─ ...
  ├─ Enrich with pipeline
  │   ├─ GeoIP (MaxMind DB)
  │   ├─ ASN (MaxMind DB)
  │   └─ ThreatIntel (SQLite local)
  ├─ Insert enriched row
  └─ DELETE from wal (commit)

Storage Layer
  └─ TelemetryStore (permanent DB)
      ├─ process_events
      ├─ device_telemetry
      ├─ flow_events
      ├─ security_events
      ├─ peripheral_events
      ├─ dns_events
      ├─ audit_events
      ├─ persistence_events
      ├─ fim_events
      ├─ incidents
      ├─ alert_rules
      └─ metrics_timeseries

Dashboard
  └─ Query storage layer (SELECT from domain tables)
```

---

## PART 10: CONFIGURATION REFERENCE

### EventBus Server (server.py)
- **BUS_SERVER_PORT:** gRPC listen port
- **BUS_OVERLOAD:** Force overload mode (true|false)
- **BUS_MAX_ENV_BYTES:** Size limit (default 131072)
- **BUS_DEDUPE_TTL_SEC:** Dedup cache TTL (default 300)
- **BUS_DEDUPE_MAX:** Dedup cache size (default 50000)
- **BUS_REQUIRE_SIGNATURES:** Enforce Ed25519 signatures (default false)
- **EVENTBUS_REQUIRE_CLIENT_AUTH:** Enforce mTLS (default true)

### WAL (wal_sqlite.py)
- **Path:** config.agent.wal_path
- **max_bytes:** config.storage.max_wal_bytes (default 200MB)
- **vacuum_threshold:** Fraction of DB to reclaim (default 0.3)

### Storage (telemetry_store.py)
- **db_path:** Database file location (default data/telemetry.db)

### Enrichment
- **GeoIP DB:** /usr/share/GeoIP/GeoLite2-City.mmdb (or configurable)
- **ASN DB:** /usr/share/GeoIP/GeoLite2-ASN.mmdb (or configurable)
- **ThreatIntel DB:** data/threat_intel.db (or configurable)
- **Cache sizes:** 10,000 entries default
- **ThreatIntel TTL:** 3600 seconds

---

## SUMMARY TABLE

| Component | Protocol | Port | Auth | State | Notes |
|-----------|----------|------|------|-------|-------|
| EventBus gRPC | gRPC/TLS | BUS_SERVER_PORT | mTLS required | Receiving | Validates, dedupes, writes WAL |
| EventBus Health | HTTP | 8080 | None | Available | Returns 200 if running |
| Prometheus Metrics | HTTP | metrics_port_1/2 | None | Exporting | 7 metrics exported |
| WAL SQLite | SQLite | N/A (local) | None | Persisting | BLAKE2b checksums + hash chain |
| TelemetryStore SQLite | SQLite | N/A (local) | None | Storing | 14 domain + archive + dead-letter tables |
| Enrichment | Local DBs | N/A (local) | None | Ready | GeoIP, ASN, ThreatIntel |

---

## FINAL NOTES

1. **Event durability:** Guaranteed only if EventBus AND WAL Processor are running
2. **Idempotency:** Guaranteed for 300 seconds (DEDUPE_TTL_SEC) within same client
3. **Chain integrity:** BLAKE2b prevents corruption detection; hash chain detects tampering
4. **Enrichment:** Applied during WAL→Storage transition, not at EventBus ingestion
5. **Authorization:** Defined but not enforced (trust map not checked)
6. **Backward compat:** Signatures optional, legacy Envelope format supported
