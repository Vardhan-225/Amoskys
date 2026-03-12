#!/usr/bin/env python3
"""
Permanent Telemetry Storage for AMOSKYS Dashboard

This module creates and manages the permanent telemetry database that stores
processed events from the WAL for dashboard queries and ML analysis.

Database Design:
- process_events: Individual process telemetry events
- device_telemetry: Aggregated device-level telemetry
- flow_events: Network flow events
- security_events: Security-relevant events for threat analysis

Supports the 3-layer ML architecture:
- Geometric features: Process trees, connection patterns
- Temporal features: Time series, event sequences
- Behavioral features: Anomaly scores, confidence metrics
"""

import json
import logging
import queue
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("TelemetryStore")


class _ReadPool:
    """Pool of read-only SQLite connections for parallel dashboard queries.

    WAL mode supports unlimited concurrent readers.  By giving each request
    thread its own connection we eliminate the serialisation bottleneck that
    a single ``_read_lock`` caused (posture endpoint: 1.6 s → <200 ms).
    """

    def __init__(self, db_path: str, size: int = 4):
        self._pool: queue.Queue = queue.Queue()
        for _ in range(size):
            conn = sqlite3.connect(db_path, check_same_thread=False, timeout=5.0)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA query_only=ON")
            conn.execute("PRAGMA cache_size=-16000")  # 16 MB per conn
            self._pool.put(conn)

    @contextmanager
    def connection(self):
        conn = self._pool.get()
        try:
            yield conn
        finally:
            self._pool.put(conn)

    def close(self):
        while not self._pool.empty():
            try:
                self._pool.get_nowait().close()
            except queue.Empty:
                break


class _TTLCache:
    """Thread-safe TTL cache for dashboard query results.

    Keyed by (method_name, hours) tuples.  Each entry expires after
    ``ttl_seconds`` (default 5 s) — long enough to coalesce the burst
    of WebSocket pushes that hit the same endpoint within one dashboard
    refresh cycle, short enough that the data stays fresh.
    """

    def __init__(self, ttl_seconds: float = 5.0):
        self._ttl = ttl_seconds
        self._store: Dict[str, tuple] = {}  # key → (result, expiry_monotonic)
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            result, expiry = entry
            if time.monotonic() > expiry:
                del self._store[key]
                return None
            return result

    def put(self, key: str, value: Any, ttl: float = 0) -> None:
        with self._lock:
            self._store[key] = (value, time.monotonic() + (ttl or self._ttl))

    def invalidate(self, prefix: str = "") -> None:
        """Drop all entries whose key starts with *prefix* (or all if empty)."""
        with self._lock:
            if not prefix:
                self._store.clear()
            else:
                self._store = {
                    k: v for k, v in self._store.items() if not k.startswith(prefix)
                }


# Database schema for permanent storage
SCHEMA = """
-- Enable WAL mode for better concurrency
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA cache_size=-64000;  -- 64MB cache

-- Canonical envelope truth table (raw ingress contract events)
CREATE TABLE IF NOT EXISTS telemetry_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    idempotency_key TEXT,
    timestamp_ns INTEGER NOT NULL,
    ingest_timestamp_ns INTEGER,
    timestamp_dt TEXT NOT NULL,
    device_id TEXT,
    agent_id TEXT,
    probe_name TEXT,
    probe_version TEXT,
    event_type TEXT,
    device_type TEXT,
    payload_kind TEXT,
    schema_version INTEGER DEFAULT 1,
    quality_state TEXT DEFAULT 'valid',
    contract_violation_code TEXT DEFAULT 'NONE',
    missing_fields TEXT,
    envelope_bytes BLOB,
    wal_row_id INTEGER,
    wal_checksum BLOB,
    wal_sig BLOB,
    wal_prev_sig BLOB
);
CREATE INDEX IF NOT EXISTS idx_telemetry_events_time ON telemetry_events(timestamp_ns DESC);
CREATE INDEX IF NOT EXISTS idx_telemetry_events_device ON telemetry_events(device_id, timestamp_ns DESC);
CREATE INDEX IF NOT EXISTS idx_telemetry_events_quality ON telemetry_events(quality_state, timestamp_ns DESC);

-- Process Events Table (for behavioral/temporal analysis)
CREATE TABLE IF NOT EXISTS process_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_ns INTEGER NOT NULL,
    timestamp_dt TEXT NOT NULL,

    -- Process identification
    device_id TEXT NOT NULL,
    pid INTEGER NOT NULL,
    ppid INTEGER,
    exe TEXT,
    cmdline TEXT,
    username TEXT,

    -- Resource metrics (for geometric analysis)
    cpu_percent REAL,
    memory_percent REAL,
    num_threads INTEGER,
    num_fds INTEGER,

    -- Classification fields
    user_type TEXT,  -- root, system, user
    process_category TEXT,  -- system, application, daemon, etc.

    -- Security context
    is_suspicious BOOLEAN DEFAULT 0,
    anomaly_score REAL,
    confidence_score REAL,

    -- Metadata
    collection_agent TEXT,
    agent_version TEXT,
    quality_state TEXT DEFAULT 'valid',
    training_exclude BOOLEAN DEFAULT 0,
    contract_violation_code TEXT DEFAULT 'NONE',
    missing_fields TEXT,
    raw_attributes_json TEXT,

    -- Indexes for fast queries
    UNIQUE(device_id, pid, timestamp_ns)
);

CREATE INDEX IF NOT EXISTS idx_process_timestamp ON process_events(timestamp_ns DESC);
CREATE INDEX IF NOT EXISTS idx_process_device ON process_events(device_id, timestamp_ns DESC);
CREATE INDEX IF NOT EXISTS idx_process_exe ON process_events(exe);
CREATE INDEX IF NOT EXISTS idx_process_suspicious ON process_events(is_suspicious, timestamp_ns DESC);

-- Device Telemetry Table (aggregated metrics)
CREATE TABLE IF NOT EXISTS device_telemetry (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_ns INTEGER NOT NULL,
    timestamp_dt TEXT NOT NULL,

    device_id TEXT NOT NULL,
    device_type TEXT,
    protocol TEXT,

    -- Device metadata
    manufacturer TEXT,
    model TEXT,
    ip_address TEXT,
    mac_address TEXT,

    -- Aggregated metrics
    total_processes INTEGER,
    total_cpu_percent REAL,
    total_memory_percent REAL,

    -- Event counts by type
    metric_events INTEGER DEFAULT 0,
    log_events INTEGER DEFAULT 0,
    security_events INTEGER DEFAULT 0,

    -- Collection info
    collection_agent TEXT,
    agent_version TEXT,

    UNIQUE(device_id, timestamp_ns)
);

CREATE INDEX IF NOT EXISTS idx_device_timestamp ON device_telemetry(timestamp_ns DESC);
CREATE INDEX IF NOT EXISTS idx_device_id ON device_telemetry(device_id, timestamp_ns DESC);

-- Flow Events Table (for network analysis)
CREATE TABLE IF NOT EXISTS flow_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
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

    -- Security analysis
    is_suspicious BOOLEAN DEFAULT 0,
    threat_score REAL,
    quality_state TEXT DEFAULT 'valid',
    training_exclude BOOLEAN DEFAULT 0,
    contract_violation_code TEXT DEFAULT 'NONE',
    missing_fields TEXT,
    raw_attributes_json TEXT,

    UNIQUE(device_id, src_ip, dst_ip, src_port, dst_port, timestamp_ns)
);

CREATE INDEX IF NOT EXISTS idx_flow_timestamp ON flow_events(timestamp_ns DESC);
CREATE INDEX IF NOT EXISTS idx_flow_ips ON flow_events(src_ip, dst_ip);

-- Security Events Table (for threat correlation)
CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_ns INTEGER NOT NULL,
    timestamp_dt TEXT NOT NULL,

    device_id TEXT NOT NULL,
    event_category TEXT,  -- AUTHENTICATION, INTRUSION, MALWARE
    event_action TEXT,
    event_outcome TEXT,

    -- Threat intelligence
    risk_score REAL,
    confidence REAL,
    mitre_techniques TEXT,  -- JSON array

    -- ML layer scores (for decision fusion)
    geometric_score REAL,   -- From XGBoost
    temporal_score REAL,    -- From LSTM
    behavioral_score REAL,  -- From MLP
    final_classification TEXT,  -- legitimate, suspicious, malicious

    -- Details
    description TEXT,
    indicators TEXT,  -- JSON

    requires_investigation BOOLEAN DEFAULT 0,

    -- Collection metadata
    collection_agent TEXT,
    agent_version TEXT,

    -- Enrichment pipeline results (A4.4)
    enrichment_status TEXT DEFAULT 'raw',  -- raw, partial, enriched
    threat_intel_match BOOLEAN DEFAULT 0,
    geo_src_country TEXT,
    asn_src_org TEXT,

    -- Temporal fields (probe-local detection timestamps)
    event_timestamp_ns INTEGER DEFAULT NULL,
    event_id TEXT DEFAULT NULL,
    probe_latency_ns INTEGER DEFAULT NULL,

    -- Contract quality lineage
    quality_state TEXT DEFAULT 'valid',
    training_exclude BOOLEAN DEFAULT 0,
    contract_violation_code TEXT DEFAULT 'NONE',
    missing_fields TEXT,

    -- MITRE provenance metadata
    mitre_source TEXT DEFAULT 'probe',
    mitre_confidence REAL DEFAULT 0.0,
    mitre_evidence TEXT,

    -- Lossless attribute preservation
    raw_attributes_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_security_timestamp ON security_events(timestamp_ns DESC);
CREATE INDEX IF NOT EXISTS idx_security_risk ON security_events(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_security_classification ON security_events(final_classification);
CREATE INDEX IF NOT EXISTS idx_security_event_timestamp ON security_events(event_timestamp_ns DESC);
CREATE INDEX IF NOT EXISTS idx_security_event_id ON security_events(event_id);

-- Peripheral Events Table (USB/Bluetooth/external devices)
CREATE TABLE IF NOT EXISTS peripheral_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_ns INTEGER NOT NULL,
    timestamp_dt TEXT NOT NULL,

    device_id TEXT NOT NULL,
    peripheral_device_id TEXT NOT NULL,  -- Unique ID of peripheral
    event_type TEXT NOT NULL,  -- CONNECTED, DISCONNECTED, FILE_TRANSFER

    -- Device identification
    device_name TEXT,
    device_type TEXT,  -- USB_STORAGE, KEYBOARD, MOUSE, CAMERA, BLUETOOTH, etc.
    vendor_id TEXT,
    product_id TEXT,
    serial_number TEXT,
    manufacturer TEXT,
    address TEXT,

    -- Connection details
    connection_status TEXT,  -- CONNECTED, DISCONNECTED
    previous_status TEXT,
    mount_point TEXT,

    -- File transfer tracking
    files_transferred INTEGER DEFAULT 0,
    bytes_transferred INTEGER DEFAULT 0,

    -- Security analysis
    is_authorized BOOLEAN DEFAULT 0,
    risk_score REAL,
    confidence_score REAL,
    threat_indicators TEXT,  -- JSON array

    -- Collection info
    collection_agent TEXT,
    agent_version TEXT,

    -- Contract quality lineage
    quality_state TEXT DEFAULT 'valid',
    training_exclude BOOLEAN DEFAULT 0,
    contract_violation_code TEXT DEFAULT 'NONE',
    missing_fields TEXT,

    -- Lossless attribute preservation
    raw_attributes_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_peripheral_timestamp ON peripheral_events(timestamp_ns DESC);
CREATE INDEX IF NOT EXISTS idx_peripheral_device ON peripheral_events(peripheral_device_id);
CREATE INDEX IF NOT EXISTS idx_peripheral_type ON peripheral_events(device_type);
CREATE INDEX IF NOT EXISTS idx_peripheral_risk ON peripheral_events(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_peripheral_unauthorized ON peripheral_events(is_authorized, timestamp_ns DESC);

-- Metrics aggregation table (for time series analysis)
CREATE TABLE IF NOT EXISTS metrics_timeseries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_ns INTEGER NOT NULL,
    timestamp_dt TEXT NOT NULL,

    metric_name TEXT NOT NULL,
    metric_type TEXT,  -- GAUGE, COUNTER
    device_id TEXT,

    value REAL NOT NULL,
    unit TEXT,

    -- Statistical aggregation (for temporal analysis)
    min_value REAL,
    max_value REAL,
    avg_value REAL,
    sample_count INTEGER,

    UNIQUE(metric_name, device_id, timestamp_ns)
);

CREATE INDEX IF NOT EXISTS idx_metrics_name_time ON metrics_timeseries(metric_name, device_id, timestamp_ns DESC);

-- Incidents Table (for SOC incident management)
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL DEFAULT 'medium',  -- critical, high, medium, low
    status TEXT NOT NULL DEFAULT 'open',  -- open, investigating, contained, resolved, closed
    assignee TEXT,
    source_event_ids TEXT,  -- JSON array of security_event IDs
    mitre_techniques TEXT,  -- JSON array
    indicators TEXT,  -- JSON object
    resolution_notes TEXT,
    resolved_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_incident_status ON incidents(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_incident_severity ON incidents(severity, created_at DESC);

-- Alert Rules Table (for custom alerting)
CREATE TABLE IF NOT EXISTS alert_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    enabled BOOLEAN DEFAULT 1,
    event_category TEXT,  -- filter by category (or NULL for all)
    min_risk_score REAL DEFAULT 0.0,  -- trigger threshold
    severity TEXT DEFAULT 'medium',  -- alert severity when triggered
    cooldown_seconds INTEGER DEFAULT 300,  -- minimum time between alerts
    last_triggered_at TEXT,
    trigger_count INTEGER DEFAULT 0
);

-- DNS Events Table (for DNS threat analysis and ML)
CREATE TABLE IF NOT EXISTS dns_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_ns INTEGER NOT NULL,
    timestamp_dt TEXT NOT NULL,

    device_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    query_type TEXT,           -- A, AAAA, TXT, MX, CNAME, etc.
    response_code TEXT,        -- NOERROR, NXDOMAIN, SERVFAIL
    source_ip TEXT,

    -- Process attribution
    process_name TEXT,
    pid INTEGER,

    -- Threat analysis
    event_type TEXT,           -- dns_query, dga_domain_detected, dns_beaconing_detected, etc.
    dga_score REAL,            -- DGA probability 0.0-1.0
    is_beaconing BOOLEAN DEFAULT 0,
    beacon_interval_seconds REAL,
    is_tunneling BOOLEAN DEFAULT 0,

    -- Security context
    risk_score REAL DEFAULT 0.0,
    confidence REAL DEFAULT 0.0,
    mitre_techniques TEXT,     -- JSON array

    -- Collection
    collection_agent TEXT,
    agent_version TEXT,

    -- Contract quality lineage
    quality_state TEXT DEFAULT 'valid',
    training_exclude BOOLEAN DEFAULT 0,
    contract_violation_code TEXT DEFAULT 'NONE',
    missing_fields TEXT,

    -- Lossless attribute preservation
    raw_attributes_json TEXT,

    UNIQUE(device_id, domain, query_type, timestamp_ns)
);

CREATE INDEX IF NOT EXISTS idx_dns_timestamp ON dns_events(timestamp_ns DESC);
CREATE INDEX IF NOT EXISTS idx_dns_domain ON dns_events(domain);
CREATE INDEX IF NOT EXISTS idx_dns_risk ON dns_events(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_dns_type ON dns_events(event_type);

-- Kernel Audit Events Table (syscall monitoring)
CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_ns INTEGER NOT NULL,
    timestamp_dt TEXT NOT NULL,

    device_id TEXT NOT NULL,
    host TEXT,
    syscall TEXT NOT NULL,      -- execve, setuid, init_module, ptrace, etc.
    event_type TEXT NOT NULL,   -- kernel_execve_high_risk, kernel_privesc_syscall, etc.

    -- Process context
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

    -- Target (for ptrace, chmod, etc.)
    target_path TEXT,
    target_pid INTEGER,
    target_comm TEXT,

    -- Security context
    risk_score REAL DEFAULT 0.0,
    confidence REAL DEFAULT 0.0,
    mitre_techniques TEXT,     -- JSON array
    reason TEXT,
    source_ip TEXT,
    username TEXT,
    collector_timestamp TEXT,

    -- Collection
    collection_agent TEXT,
    agent_version TEXT,

    -- Contract quality lineage
    quality_state TEXT DEFAULT 'valid',
    training_exclude BOOLEAN DEFAULT 0,
    contract_violation_code TEXT DEFAULT 'NONE',
    missing_fields TEXT,

    -- Lossless attribute preservation
    raw_attributes_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp_ns DESC);
CREATE INDEX IF NOT EXISTS idx_audit_syscall ON audit_events(syscall);
CREATE INDEX IF NOT EXISTS idx_audit_risk ON audit_events(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_audit_exe ON audit_events(exe);

-- Persistence Events Table (autostart and backdoor detection)
CREATE TABLE IF NOT EXISTS persistence_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_ns INTEGER NOT NULL,
    timestamp_dt TEXT NOT NULL,

    device_id TEXT NOT NULL,
    event_type TEXT NOT NULL,   -- persistence_launchd_created, persistence_cron_modified, etc.
    mechanism TEXT,             -- launchd, systemd, cron, ssh_key, shell_profile, browser_ext, etc.

    -- Entry details
    entry_id TEXT,             -- Unique ID for the persistence entry
    path TEXT,                 -- File path of persistence mechanism
    command TEXT,              -- Command to execute
    schedule TEXT,             -- Cron schedule if applicable
    user TEXT,                 -- User context

    -- Change tracking
    change_type TEXT,          -- created, modified, deleted, enabled, disabled
    old_command TEXT,
    new_command TEXT,

    -- Security context
    risk_score REAL DEFAULT 0.0,
    confidence REAL DEFAULT 0.0,
    mitre_techniques TEXT,     -- JSON array
    reason TEXT,

    -- Collection
    collection_agent TEXT,
    agent_version TEXT,

    -- Contract quality lineage
    quality_state TEXT DEFAULT 'valid',
    training_exclude BOOLEAN DEFAULT 0,
    contract_violation_code TEXT DEFAULT 'NONE',
    missing_fields TEXT,

    -- Lossless attribute preservation
    raw_attributes_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_persistence_timestamp ON persistence_events(timestamp_ns DESC);
CREATE INDEX IF NOT EXISTS idx_persistence_mechanism ON persistence_events(mechanism);
CREATE INDEX IF NOT EXISTS idx_persistence_risk ON persistence_events(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_persistence_entry ON persistence_events(entry_id);

-- FIM Events Table (file integrity monitoring)
CREATE TABLE IF NOT EXISTS fim_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_ns INTEGER NOT NULL,
    timestamp_dt TEXT NOT NULL,

    device_id TEXT NOT NULL,
    event_type TEXT NOT NULL,   -- critical_file_tampered, suid_bit_added, webshell_detected, etc.
    path TEXT NOT NULL,

    -- Change details
    change_type TEXT,          -- created, modified, deleted, permission_changed
    old_hash TEXT,
    new_hash TEXT,
    old_mode TEXT,
    new_mode TEXT,

    -- File metadata
    file_extension TEXT,
    owner_uid INTEGER,
    owner_gid INTEGER,
    is_suid BOOLEAN DEFAULT 0,
    mtime REAL,
    size INTEGER,

    -- Security context
    risk_score REAL DEFAULT 0.0,
    confidence REAL DEFAULT 0.0,
    mitre_techniques TEXT,     -- JSON array
    reason TEXT,
    patterns_matched TEXT,     -- JSON array of matched patterns

    -- Collection
    collection_agent TEXT,
    agent_version TEXT,

    -- Contract quality lineage
    quality_state TEXT DEFAULT 'valid',
    training_exclude BOOLEAN DEFAULT 0,
    contract_violation_code TEXT DEFAULT 'NONE',
    missing_fields TEXT,

    -- Lossless attribute preservation
    raw_attributes_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_fim_timestamp ON fim_events(timestamp_ns DESC);
CREATE INDEX IF NOT EXISTS idx_fim_path ON fim_events(path);
CREATE INDEX IF NOT EXISTS idx_fim_risk ON fim_events(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_fim_type ON fim_events(event_type);

-- Raw WAL events archive (for replay/debugging)
CREATE TABLE IF NOT EXISTS wal_archive (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    archived_at INTEGER NOT NULL,
    original_ts_ns INTEGER NOT NULL,
    idempotency_key TEXT UNIQUE,
    envelope_bytes BLOB NOT NULL,
    checksum BLOB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_archive_ts ON wal_archive(original_ts_ns DESC);

-- Dead letter queue for failed WAL processing (P0-S1)
CREATE TABLE IF NOT EXISTS wal_dead_letter (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    row_id INTEGER NOT NULL,
    error_msg TEXT NOT NULL,
    reason_code TEXT DEFAULT 'UNKNOWN',
    replay_cmd TEXT DEFAULT '',
    envelope_bytes BLOB NOT NULL,
    quarantined_at TEXT NOT NULL,
    source TEXT DEFAULT 'wal_processor'
);
CREATE INDEX IF NOT EXISTS idx_dead_letter_ts ON wal_dead_letter(quarantined_at DESC);

-- Generic observations (P3 domains)
CREATE TABLE IF NOT EXISTS observation_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_ns INTEGER NOT NULL,
    timestamp_dt TEXT NOT NULL,
    device_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    event_type TEXT DEFAULT 'observation',
    attributes TEXT NOT NULL,
    risk_score REAL DEFAULT 0.0,
    event_source TEXT DEFAULT 'observation',
    collection_agent TEXT,
    agent_version TEXT,
    quality_state TEXT DEFAULT 'valid',
    training_exclude BOOLEAN DEFAULT 0,
    contract_violation_code TEXT DEFAULT 'NONE',
    missing_fields TEXT
);
CREATE INDEX IF NOT EXISTS idx_observation_events_device_ts ON observation_events(device_id, timestamp_ns);
CREATE INDEX IF NOT EXISTS idx_observation_events_domain ON observation_events(domain);
CREATE INDEX IF NOT EXISTS idx_observation_events_ts ON observation_events(timestamp_ns);

-- Observation shaping rollups (Balanced mode under pressure)
CREATE TABLE IF NOT EXISTS observation_rollups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    window_start_ns INTEGER NOT NULL,
    window_end_ns INTEGER NOT NULL,
    domain TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    sample_attributes TEXT NOT NULL,
    total_count INTEGER NOT NULL DEFAULT 0,
    first_seen_ns INTEGER NOT NULL,
    last_seen_ns INTEGER NOT NULL,
    device_id TEXT,
    collection_agent TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_observation_rollups_unique
    ON observation_rollups(domain, window_start_ns, fingerprint);
CREATE INDEX IF NOT EXISTS idx_observation_rollups_domain
    ON observation_rollups(domain, window_start_ns DESC);
"""


class TelemetryStore:
    """Permanent storage for processed telemetry data"""

    def __init__(self, db_path: str = "data/telemetry.db"):
        """Initialize telemetry store with schema

        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path

        # Create parent directory
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

        # Initialize database
        self.db = sqlite3.connect(db_path, check_same_thread=False, timeout=10.0)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")

        # Create schema
        self.db.executescript(SCHEMA)
        self.db.commit()
        self._migrate_wal_dead_letter_schema()

        # A3.3: Auto-apply pending schema migrations on startup
        try:
            from amoskys.storage.migrations.migrate import auto_migrate

            applied = auto_migrate(db_path)
            if applied > 0:
                logger.info("Applied %d pending schema migration(s)", applied)
        except Exception:
            logger.warning(
                "Schema migration check failed — continuing with existing schema",
                exc_info=True,
            )
        self._migrate_convergence_schema()

        logger.info(f"Initialized TelemetryStore at {db_path}")

        # Thread-safety: serialize all SQLite operations through a lock.
        # The dashboard WebSocket updater thread and Flask request threads
        # share this singleton — concurrent access causes SQLITE_MISUSE.
        self._lock = threading.Lock()

        # Pool of read-only connections for dashboard queries.
        # WAL mode allows unlimited concurrent readers — the pool
        # eliminates the serialisation bottleneck that a single
        # _read_lock caused on parallel dashboard API calls.
        self._read_pool = _ReadPool(db_path, size=4)

        # Batch mode: when active, inserts skip per-row commits.
        # WALProcessor calls begin_batch() before a batch and end_batch() after.
        self._batch_mode: bool = False
        self._batch_count: int = 0

        # Dashboard query cache — coalesces bursts of identical queries
        # within a 5-second window (typical WebSocket push interval).
        self._cache = _TTLCache(ttl_seconds=5.0)

        # Background prewarm: keep expensive summary caches hot so users
        # never hit a cold 1-2 s query.  Runs every 25 s (TTL is 30 s).
        self._prewarm_thread = threading.Thread(
            target=self._prewarm_loop, daemon=True, name="cache-prewarm"
        )
        self._prewarm_thread.start()

    def _migrate_wal_dead_letter_schema(self) -> None:
        """Ensure wal_dead_letter has reason/replay metadata columns."""
        try:
            cols = {
                row["name"]
                for row in self.db.execute("PRAGMA table_info(wal_dead_letter)")
            }
            if "reason_code" not in cols:
                self.db.execute(
                    "ALTER TABLE wal_dead_letter ADD COLUMN reason_code TEXT DEFAULT 'UNKNOWN'"
                )
            if "replay_cmd" not in cols:
                self.db.execute(
                    "ALTER TABLE wal_dead_letter ADD COLUMN replay_cmd TEXT DEFAULT ''"
                )
            self.db.commit()
        except sqlite3.Error:
            logger.exception("Failed to migrate wal_dead_letter schema")

    def _ensure_column(self, table: str, column: str, ddl: str) -> None:
        """Add a column if it does not already exist."""
        exists = self.db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
            (table,),
        ).fetchone()
        if not exists:
            return
        cols = {row["name"] for row in self.db.execute(f"PRAGMA table_info({table})")}
        if column not in cols:
            self.db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")

    def _migrate_convergence_schema(self) -> None:
        """Backfill convergence columns used by contract/quality lineage."""
        try:
            # Envelope lineage
            self._ensure_column("telemetry_events", "wal_row_id", "INTEGER")
            self._ensure_column("telemetry_events", "wal_checksum", "BLOB")
            self._ensure_column("telemetry_events", "wal_sig", "BLOB")
            self._ensure_column("telemetry_events", "wal_prev_sig", "BLOB")

            # Security quality + MITRE provenance
            self._ensure_column(
                "security_events", "quality_state", "TEXT DEFAULT 'valid'"
            )
            self._ensure_column(
                "security_events", "training_exclude", "BOOLEAN DEFAULT 0"
            )
            self._ensure_column(
                "security_events", "contract_violation_code", "TEXT DEFAULT 'NONE'"
            )
            self._ensure_column("security_events", "missing_fields", "TEXT")
            self._ensure_column(
                "security_events", "mitre_source", "TEXT DEFAULT 'probe'"
            )
            self._ensure_column(
                "security_events", "mitre_confidence", "REAL DEFAULT 0.0"
            )
            self._ensure_column("security_events", "mitre_evidence", "TEXT")
            self._ensure_column("security_events", "raw_attributes_json", "TEXT")

            # Domain observation quality lineage + lossless payload
            domain_tables = [
                "process_events",
                "flow_events",
                "dns_events",
                "audit_events",
                "persistence_events",
                "fim_events",
                "peripheral_events",
                "observation_events",
            ]
            for table in domain_tables:
                self._ensure_column(table, "quality_state", "TEXT DEFAULT 'valid'")
                self._ensure_column(table, "training_exclude", "BOOLEAN DEFAULT 0")
                self._ensure_column(
                    table, "contract_violation_code", "TEXT DEFAULT 'NONE'"
                )
                self._ensure_column(table, "missing_fields", "TEXT")
                self._ensure_column(table, "raw_attributes_json", "TEXT")

            # Field preservation for typed tables
            self._ensure_column("audit_events", "source_ip", "TEXT")
            self._ensure_column("audit_events", "username", "TEXT")
            self._ensure_column("audit_events", "collector_timestamp", "TEXT")
            self._ensure_column("fim_events", "is_suid", "BOOLEAN DEFAULT 0")
            self._ensure_column("fim_events", "mtime", "REAL")
            self._ensure_column("fim_events", "size", "INTEGER")
            self._ensure_column("peripheral_events", "address", "TEXT")

            # Observation shaping rollups
            self.db.execute(
                """
                CREATE TABLE IF NOT EXISTS observation_rollups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    window_start_ns INTEGER NOT NULL,
                    window_end_ns INTEGER NOT NULL,
                    domain TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    sample_attributes TEXT NOT NULL,
                    total_count INTEGER NOT NULL DEFAULT 0,
                    first_seen_ns INTEGER NOT NULL,
                    last_seen_ns INTEGER NOT NULL,
                    device_id TEXT,
                    collection_agent TEXT
                )
                """
            )
            self.db.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_observation_rollups_unique "
                "ON observation_rollups(domain, window_start_ns, fingerprint)"
            )
            self.db.execute(
                "CREATE INDEX IF NOT EXISTS idx_observation_rollups_domain "
                "ON observation_rollups(domain, window_start_ns DESC)"
            )
            self.db.commit()
        except sqlite3.Error:
            logger.exception("Failed to migrate convergence schema")

    # ── Cache Prewarm ──

    def _prewarm_loop(self) -> None:
        """Background thread that refreshes expensive summary caches.

        Invalidates then re-queries the 5 heaviest endpoints so the cache
        is always fresh.  Cycle: ~5 s queries + 20 s sleep = 25 s < 30 s TTL.
        """
        time.sleep(2)
        _keys = [
            ("device_posture:24", lambda: self.get_device_posture(hours=24)),
            (
                "observation_domain_stats:24",
                lambda: self.get_observation_domain_stats(hours=24),
            ),
            ("fim_stats:24", lambda: self.get_fim_stats(hours=24)),
            ("persistence_stats:24", lambda: self.get_persistence_stats(hours=24)),
            ("flow_stats:24", lambda: self.get_flow_stats(hours=24)),
            (
                "unified_clustering:24",
                lambda: self.get_unified_event_clustering(hours=24),
            ),
            ("unified_counts:24", lambda: self.get_unified_event_counts(hours=24)),
            (
                "threat_count:24:0.1",
                lambda: self.get_threat_count(hours=24, min_risk=0.1),
            ),
        ]
        while True:
            try:
                for cache_key, fn in _keys:
                    self._cache.invalidate(cache_key)
                    fn()
            except Exception:
                pass  # non-critical — next cycle will retry
            time.sleep(20)

    # ── Batch API (used by WALProcessor for single-commit batches) ──

    def begin_batch(self) -> None:
        """Enter batch mode — per-insert commits are suppressed."""
        self._batch_mode = True
        self._batch_count = 0

    def end_batch(self) -> None:
        """Commit all buffered inserts and leave batch mode."""
        try:
            self.db.commit()
        finally:
            self._batch_mode = False
            self._batch_count = 0
            # New data committed — invalidate dashboard query cache so the
            # next request picks up fresh numbers.
            self._cache.invalidate()

    def _commit(self) -> None:
        """Commit unless in batch mode."""
        if self._batch_mode:
            self._batch_count += 1
            return
        self.db.commit()
        self._cache.invalidate()

    def insert_telemetry_event(self, event_data: Dict[str, Any]) -> Optional[int]:
        """Insert canonical ingress envelope event into telemetry_events."""
        try:
            cursor = self.db.execute(
                """
                INSERT OR REPLACE INTO telemetry_events (
                    event_id, idempotency_key, timestamp_ns, ingest_timestamp_ns,
                    timestamp_dt, device_id, agent_id, probe_name, probe_version,
                    event_type, device_type, payload_kind, schema_version,
                    quality_state, contract_violation_code, missing_fields,
                    envelope_bytes, wal_row_id, wal_checksum, wal_sig, wal_prev_sig
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_data.get("event_id"),
                    event_data.get("idempotency_key"),
                    event_data.get("timestamp_ns"),
                    event_data.get("ingest_timestamp_ns"),
                    event_data.get("timestamp_dt"),
                    event_data.get("device_id"),
                    event_data.get("agent_id"),
                    event_data.get("probe_name"),
                    event_data.get("probe_version"),
                    event_data.get("event_type"),
                    event_data.get("device_type"),
                    event_data.get("payload_kind"),
                    event_data.get("schema_version", 1),
                    event_data.get("quality_state", "valid"),
                    event_data.get("contract_violation_code", "NONE"),
                    event_data.get("missing_fields"),
                    event_data.get("envelope_bytes"),
                    event_data.get("wal_row_id"),
                    event_data.get("wal_checksum"),
                    event_data.get("wal_sig"),
                    event_data.get("wal_prev_sig"),
                ),
            )
            self._commit()
            return cursor.lastrowid
        except sqlite3.Error as e:
            logger.error("Failed to insert telemetry event: %s", e)
            return None

    def insert_process_event(self, event_data: dict[str, Any]) -> Optional[int]:
        """Insert a process event.

        Args:
            event_data: Dictionary with process event fields.

        Returns:
            Row ID of inserted event, or None if failed.
        """
        try:
            cursor = self.db.execute(
                """
                INSERT OR REPLACE INTO process_events (
                    timestamp_ns, timestamp_dt, device_id, pid, ppid, exe, cmdline,
                    username, cpu_percent, memory_percent, num_threads, num_fds,
                    user_type, process_category, is_suspicious, anomaly_score,
                    confidence_score, collection_agent, agent_version,
                    name, parent_name, create_time, status, cwd,
                    is_own_user, process_guid, event_source, quality_state,
                    training_exclude, contract_violation_code, missing_fields,
                    raw_attributes_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                          ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    event_data.get("timestamp_ns"),
                    event_data.get("timestamp_dt"),
                    event_data.get("device_id"),
                    event_data.get("pid"),
                    event_data.get("ppid"),
                    event_data.get("exe"),
                    event_data.get("cmdline"),
                    event_data.get("username"),
                    event_data.get("cpu_percent"),
                    event_data.get("memory_percent"),
                    event_data.get("num_threads"),
                    event_data.get("num_fds"),
                    event_data.get("user_type"),
                    event_data.get("process_category"),
                    event_data.get("is_suspicious", False),
                    event_data.get("anomaly_score"),
                    event_data.get("confidence_score"),
                    event_data.get("collection_agent"),
                    event_data.get("agent_version"),
                    event_data.get("name"),
                    event_data.get("parent_name"),
                    event_data.get("create_time"),
                    event_data.get("status"),
                    event_data.get("cwd"),
                    event_data.get("is_own_user", False),
                    event_data.get("process_guid"),
                    event_data.get("event_source", "observation"),
                    event_data.get("quality_state", "valid"),
                    event_data.get("training_exclude", False),
                    event_data.get("contract_violation_code", "NONE"),
                    event_data.get("missing_fields"),
                    event_data.get("raw_attributes_json"),
                ),
            )
            self._commit()
            return cursor.lastrowid
        except sqlite3.Error as e:
            logger.error("Failed to insert process event: %s", e)
            return None

    def get_recent_processes(
        self, limit: int = 100, device_id: Optional[str] = None
    ) -> list[dict[str, Any]]:
        """Get recent process events

        Args:
            limit: Maximum number of events to return
            device_id: Filter by device ID (optional)

        Returns:
            List of process event dictionaries
        """
        if device_id:
            query = """
                SELECT * FROM process_events
                WHERE device_id = ?
                ORDER BY timestamp_ns DESC
                LIMIT ?
            """
            cursor = self.db.execute(query, (device_id, limit))
        else:
            query = """
                SELECT * FROM process_events
                ORDER BY timestamp_ns DESC
                LIMIT ?
            """
            cursor = self.db.execute(query, (limit,))

        return [dict(row) for row in cursor.fetchall()]

    def get_statistics(self) -> dict[str, Any]:
        """Get database statistics

        Returns:
            Dictionary with table counts and time ranges
        """
        stats = {}

        with self._lock:
            cursor = self.db.execute("SELECT COUNT(*) FROM process_events")
            stats["process_events_count"] = cursor.fetchone()[0]

            cursor = self.db.execute("SELECT COUNT(*) FROM device_telemetry")
            stats["device_telemetry_count"] = cursor.fetchone()[0]

            cursor = self.db.execute("SELECT COUNT(*) FROM flow_events")
            stats["flow_events_count"] = cursor.fetchone()[0]

            cursor = self.db.execute("SELECT COUNT(*) FROM security_events")
            stats["security_events_count"] = cursor.fetchone()[0]

            for tbl in (
                "dns_events",
                "audit_events",
                "persistence_events",
                "fim_events",
                "peripheral_events",
            ):
                try:
                    cursor = self.db.execute(f"SELECT COUNT(*) FROM {tbl}")
                    stats[f"{tbl}_count"] = cursor.fetchone()[0]
                except sqlite3.Error:
                    stats[f"{tbl}_count"] = 0

            cursor = self.db.execute(
                """
                SELECT
                    MIN(timestamp_dt) as oldest,
                    MAX(timestamp_dt) as newest
                FROM process_events
            """
            )
            row = cursor.fetchone()
            stats["time_range"] = {"oldest": row[0], "newest": row[1]}

        return stats

    # --- Security Events ---

    def insert_security_event(self, event_data: Dict[str, Any]) -> Optional[int]:
        """Insert a security event.

        Args:
            event_data: Dictionary with security event fields.

        Returns:
            Row ID of inserted event, or None if failed.
        """
        try:
            cursor = self.db.execute(
                """
                INSERT INTO security_events (
                    timestamp_ns, timestamp_dt, device_id,
                    event_category, event_action, event_outcome,
                    risk_score, confidence, mitre_techniques,
                    final_classification, description, indicators,
                    requires_investigation, collection_agent, agent_version,
                    enrichment_status, threat_intel_match,
                    geo_src_country, geo_src_city,
                    geo_src_latitude, geo_src_longitude,
                    asn_src_org, asn_src_number, asn_src_network_type,
                    event_timestamp_ns, event_id, probe_latency_ns,
                    quality_state, training_exclude,
                    contract_violation_code, missing_fields,
                    mitre_source, mitre_confidence, mitre_evidence,
                    raw_attributes_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                          ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                          ?, ?, ?, ?)
                """,
                (
                    event_data.get("timestamp_ns", int(time.time() * 1e9)),
                    event_data.get(
                        "timestamp_dt",
                        datetime.now(timezone.utc).isoformat(),
                    ),
                    event_data.get("device_id", "unknown"),
                    event_data.get("event_category"),
                    event_data.get("event_action"),
                    event_data.get("event_outcome"),
                    event_data.get("risk_score", 0.0),
                    event_data.get("confidence", 0.0),
                    json.dumps(event_data.get("mitre_techniques", [])),
                    event_data.get("final_classification", "legitimate"),
                    event_data.get("description"),
                    json.dumps(event_data.get("indicators", {})),
                    event_data.get("requires_investigation", False),
                    event_data.get("collection_agent"),
                    event_data.get("agent_version"),
                    event_data.get("enrichment_status", "raw"),
                    event_data.get("threat_intel_match", False),
                    event_data.get("geo_src_country"),
                    event_data.get("geo_src_city"),
                    event_data.get("geo_src_latitude"),
                    event_data.get("geo_src_longitude"),
                    event_data.get("asn_src_org"),
                    event_data.get("asn_src_number"),
                    event_data.get("asn_src_network_type"),
                    event_data.get("event_timestamp_ns"),
                    event_data.get("event_id"),
                    event_data.get("probe_latency_ns"),
                    event_data.get("quality_state", "valid"),
                    event_data.get("training_exclude", False),
                    event_data.get("contract_violation_code", "NONE"),
                    event_data.get("missing_fields"),
                    event_data.get("mitre_source", "probe"),
                    event_data.get(
                        "mitre_confidence", event_data.get("confidence", 0.0)
                    ),
                    json.dumps(event_data.get("mitre_evidence", [])),
                    event_data.get("raw_attributes_json"),
                ),
            )
            self._commit()
            return cursor.lastrowid
        except sqlite3.Error as e:
            logger.error("Failed to insert security event: %s", e)
            return None

    def insert_flow_event(self, event_data: Dict[str, Any]) -> Optional[int]:
        """Insert a network flow event."""
        try:
            cursor = self.db.execute(
                """
                INSERT OR IGNORE INTO flow_events (
                    timestamp_ns, timestamp_dt, device_id,
                    src_ip, dst_ip, src_port, dst_port, protocol,
                    bytes_tx, bytes_rx, packets_tx, packets_rx,
                    is_suspicious, threat_score,
                    geo_src_country, geo_src_city, geo_src_latitude, geo_src_longitude,
                    geo_dst_country, geo_dst_city, geo_dst_latitude, geo_dst_longitude,
                    asn_src_number, asn_src_org, asn_src_network_type,
                    asn_dst_number, asn_dst_org, asn_dst_network_type,
                    threat_intel_match, threat_source, threat_severity,
                    pid, process_name, conn_user, state,
                    collection_agent, agent_version, event_source, quality_state,
                    training_exclude, contract_violation_code, missing_fields,
                    raw_attributes_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                          ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                          ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_data.get("timestamp_ns", int(time.time() * 1e9)),
                    event_data.get(
                        "timestamp_dt",
                        datetime.now(timezone.utc).isoformat(),
                    ),
                    event_data.get("device_id", "unknown"),
                    event_data.get("src_ip"),
                    event_data.get("dst_ip"),
                    event_data.get("src_port"),
                    event_data.get("dst_port"),
                    event_data.get("protocol"),
                    event_data.get("bytes_tx", 0),
                    event_data.get("bytes_rx", 0),
                    event_data.get("packets_tx", 0),
                    event_data.get("packets_rx", 0),
                    event_data.get("is_suspicious", False),
                    event_data.get("threat_score", 0.0),
                    event_data.get("geo_src_country"),
                    event_data.get("geo_src_city"),
                    event_data.get("geo_src_latitude"),
                    event_data.get("geo_src_longitude"),
                    event_data.get("geo_dst_country"),
                    event_data.get("geo_dst_city"),
                    event_data.get("geo_dst_latitude"),
                    event_data.get("geo_dst_longitude"),
                    event_data.get("asn_src_number"),
                    event_data.get("asn_src_org"),
                    event_data.get("asn_src_network_type"),
                    event_data.get("asn_dst_number"),
                    event_data.get("asn_dst_org"),
                    event_data.get("asn_dst_network_type"),
                    event_data.get("threat_intel_match", False),
                    event_data.get("threat_source"),
                    event_data.get("threat_severity"),
                    event_data.get("pid"),
                    event_data.get("process_name"),
                    event_data.get("conn_user"),
                    event_data.get("state"),
                    event_data.get("collection_agent"),
                    event_data.get("agent_version"),
                    event_data.get("event_source", "observation"),
                    event_data.get("quality_state", "valid"),
                    event_data.get("training_exclude", False),
                    event_data.get("contract_violation_code", "NONE"),
                    event_data.get("missing_fields"),
                    event_data.get("raw_attributes_json"),
                ),
            )
            self._commit()
            return cursor.lastrowid
        except sqlite3.Error as e:
            logger.error("Failed to insert flow event: %s", e)
            return None

    def insert_peripheral_event(self, event_data: Dict[str, Any]) -> Optional[int]:
        """Insert a peripheral (USB/Bluetooth) event."""
        try:
            cursor = self.db.execute(
                """
                INSERT INTO peripheral_events (
                    timestamp_ns, timestamp_dt, device_id, peripheral_device_id,
                    event_type, device_name, device_type, vendor_id, product_id,
                    serial_number, manufacturer, address, connection_status, previous_status,
                    mount_point, files_transferred, bytes_transferred,
                    is_authorized, risk_score, confidence_score, threat_indicators,
                    collection_agent, agent_version, event_source, quality_state,
                    training_exclude, contract_violation_code, missing_fields,
                    raw_attributes_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_data.get("timestamp_ns", int(time.time() * 1e9)),
                    event_data.get(
                        "timestamp_dt",
                        datetime.now(timezone.utc).isoformat(),
                    ),
                    event_data.get("device_id", "unknown"),
                    event_data.get("peripheral_device_id", "unknown"),
                    event_data.get("event_type", "CONNECTED"),
                    event_data.get("device_name"),
                    event_data.get("device_type"),
                    event_data.get("vendor_id"),
                    event_data.get("product_id"),
                    event_data.get("serial_number"),
                    event_data.get("manufacturer"),
                    event_data.get("address"),
                    event_data.get("connection_status"),
                    event_data.get("previous_status"),
                    event_data.get("mount_point"),
                    event_data.get("files_transferred", 0),
                    event_data.get("bytes_transferred", 0),
                    event_data.get("is_authorized", True),
                    event_data.get("risk_score", 0.0),
                    event_data.get("confidence_score", 0.0),
                    json.dumps(event_data.get("threat_indicators", [])),
                    event_data.get("collection_agent"),
                    event_data.get("agent_version"),
                    event_data.get("event_source", "observation"),
                    event_data.get("quality_state", "valid"),
                    event_data.get("training_exclude", False),
                    event_data.get("contract_violation_code", "NONE"),
                    event_data.get("missing_fields"),
                    event_data.get("raw_attributes_json"),
                ),
            )
            self._commit()
            return cursor.lastrowid
        except sqlite3.Error as e:
            logger.error("Failed to insert peripheral event: %s", e)
            return None

    def insert_dns_event(self, event_data: Dict[str, Any]) -> Optional[int]:
        """Insert a DNS event (query, DGA detection, beaconing, etc.)."""
        try:
            cursor = self.db.execute(
                """
                INSERT OR IGNORE INTO dns_events (
                    timestamp_ns, timestamp_dt, device_id, domain, query_type,
                    response_code, source_ip, process_name, pid, event_type,
                    dga_score, is_beaconing, beacon_interval_seconds, is_tunneling,
                    risk_score, confidence, mitre_techniques,
                    collection_agent, agent_version,
                    response_ips, ttl, response_size, is_reverse, event_source,
                    quality_state, training_exclude, contract_violation_code,
                    missing_fields, raw_attributes_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                          ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_data.get("timestamp_ns", int(time.time() * 1e9)),
                    event_data.get(
                        "timestamp_dt", datetime.now(timezone.utc).isoformat()
                    ),
                    event_data.get("device_id", "unknown"),
                    event_data.get("domain", ""),
                    event_data.get("query_type"),
                    event_data.get("response_code"),
                    event_data.get("source_ip"),
                    event_data.get("process_name"),
                    event_data.get("pid"),
                    event_data.get("event_type"),
                    event_data.get("dga_score"),
                    event_data.get("is_beaconing", False),
                    event_data.get("beacon_interval_seconds"),
                    event_data.get("is_tunneling", False),
                    event_data.get("risk_score", 0.0),
                    event_data.get("confidence", 0.0),
                    json.dumps(event_data.get("mitre_techniques", [])),
                    event_data.get("collection_agent"),
                    event_data.get("agent_version"),
                    (
                        json.dumps(event_data.get("response_ips", []))
                        if event_data.get("response_ips")
                        else None
                    ),
                    event_data.get("ttl"),
                    event_data.get("response_size"),
                    event_data.get("is_reverse", False),
                    event_data.get("event_source", "observation"),
                    event_data.get("quality_state", "valid"),
                    event_data.get("training_exclude", False),
                    event_data.get("contract_violation_code", "NONE"),
                    event_data.get("missing_fields"),
                    event_data.get("raw_attributes_json"),
                ),
            )
            self._commit()
            return cursor.lastrowid
        except sqlite3.Error as e:
            logger.error("Failed to insert DNS event: %s", e)
            return None

    def insert_audit_event(self, event_data: Dict[str, Any]) -> Optional[int]:
        """Insert a kernel audit event (syscall monitoring)."""
        try:
            cursor = self.db.execute(
                """
                INSERT INTO audit_events (
                    timestamp_ns, timestamp_dt, device_id, host, syscall,
                    event_type, pid, ppid, uid, euid, gid, egid,
                    exe, comm, cmdline, cwd, target_path, target_pid,
                    target_comm, risk_score, confidence, mitre_techniques,
                    reason, source_ip, username, collector_timestamp,
                    collection_agent, agent_version, event_source, quality_state,
                    training_exclude, contract_violation_code, missing_fields,
                    raw_attributes_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_data.get("timestamp_ns", int(time.time() * 1e9)),
                    event_data.get(
                        "timestamp_dt", datetime.now(timezone.utc).isoformat()
                    ),
                    event_data.get("device_id", "unknown"),
                    event_data.get("host"),
                    event_data.get("syscall", ""),
                    event_data.get("event_type", ""),
                    event_data.get("pid"),
                    event_data.get("ppid"),
                    event_data.get("uid"),
                    event_data.get("euid"),
                    event_data.get("gid"),
                    event_data.get("egid"),
                    event_data.get("exe"),
                    event_data.get("comm"),
                    event_data.get("cmdline"),
                    event_data.get("cwd"),
                    event_data.get("target_path"),
                    event_data.get("target_pid"),
                    event_data.get("target_comm"),
                    event_data.get("risk_score", 0.0),
                    event_data.get("confidence", 0.0),
                    json.dumps(event_data.get("mitre_techniques", [])),
                    event_data.get("reason"),
                    event_data.get("source_ip"),
                    event_data.get("username"),
                    event_data.get("collector_timestamp"),
                    event_data.get("collection_agent"),
                    event_data.get("agent_version"),
                    event_data.get("event_source", "observation"),
                    event_data.get("quality_state", "valid"),
                    event_data.get("training_exclude", False),
                    event_data.get("contract_violation_code", "NONE"),
                    event_data.get("missing_fields"),
                    event_data.get("raw_attributes_json"),
                ),
            )
            self._commit()
            return cursor.lastrowid
        except sqlite3.Error as e:
            logger.error("Failed to insert audit event: %s", e)
            return None

    def insert_persistence_event(self, event_data: Dict[str, Any]) -> Optional[int]:
        """Insert a persistence mechanism event."""
        try:
            cursor = self.db.execute(
                """
                INSERT INTO persistence_events (
                    timestamp_ns, timestamp_dt, device_id, event_type,
                    mechanism, entry_id, path, command, schedule, user,
                    change_type, old_command, new_command,
                    risk_score, confidence, mitre_techniques, reason,
                    collection_agent, agent_version,
                    content_hash, program, label, run_at_load, keep_alive,
                    event_source, quality_state, training_exclude,
                    contract_violation_code, missing_fields, raw_attributes_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                          ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_data.get("timestamp_ns", int(time.time() * 1e9)),
                    event_data.get(
                        "timestamp_dt", datetime.now(timezone.utc).isoformat()
                    ),
                    event_data.get("device_id", "unknown"),
                    event_data.get("event_type", ""),
                    event_data.get("mechanism"),
                    event_data.get("entry_id"),
                    event_data.get("path"),
                    event_data.get("command"),
                    event_data.get("schedule"),
                    event_data.get("user"),
                    event_data.get("change_type"),
                    event_data.get("old_command"),
                    event_data.get("new_command"),
                    event_data.get("risk_score", 0.0),
                    event_data.get("confidence", 0.0),
                    json.dumps(event_data.get("mitre_techniques", [])),
                    event_data.get("reason"),
                    event_data.get("collection_agent"),
                    event_data.get("agent_version"),
                    event_data.get("content_hash"),
                    event_data.get("program"),
                    event_data.get("label"),
                    event_data.get("run_at_load", False),
                    event_data.get("keep_alive", False),
                    event_data.get("event_source", "observation"),
                    event_data.get("quality_state", "valid"),
                    event_data.get("training_exclude", False),
                    event_data.get("contract_violation_code", "NONE"),
                    event_data.get("missing_fields"),
                    event_data.get("raw_attributes_json"),
                ),
            )
            self._commit()
            return cursor.lastrowid
        except sqlite3.Error as e:
            logger.error("Failed to insert persistence event: %s", e)
            return None

    def insert_fim_event(self, event_data: Dict[str, Any]) -> Optional[int]:
        """Insert a file integrity monitoring event."""
        try:
            cursor = self.db.execute(
                """
                INSERT INTO fim_events (
                    timestamp_ns, timestamp_dt, device_id, event_type, path,
                    change_type, old_hash, new_hash, old_mode, new_mode,
                    file_extension, owner_uid, owner_gid, is_suid, mtime, size,
                    risk_score, confidence, mitre_techniques, reason,
                    patterns_matched, collection_agent, agent_version,
                    event_source, quality_state, training_exclude,
                    contract_violation_code, missing_fields, raw_attributes_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_data.get("timestamp_ns", int(time.time() * 1e9)),
                    event_data.get(
                        "timestamp_dt", datetime.now(timezone.utc).isoformat()
                    ),
                    event_data.get("device_id", "unknown"),
                    event_data.get("event_type", ""),
                    event_data.get("path", ""),
                    event_data.get("change_type"),
                    event_data.get("old_hash"),
                    event_data.get("new_hash"),
                    event_data.get("old_mode"),
                    event_data.get("new_mode"),
                    event_data.get("file_extension"),
                    event_data.get("owner_uid"),
                    event_data.get("owner_gid"),
                    event_data.get("is_suid", False),
                    event_data.get("mtime"),
                    event_data.get("size"),
                    event_data.get("risk_score", 0.0),
                    event_data.get("confidence", 0.0),
                    json.dumps(event_data.get("mitre_techniques", [])),
                    event_data.get("reason"),
                    json.dumps(event_data.get("patterns_matched", [])),
                    event_data.get("collection_agent"),
                    event_data.get("agent_version"),
                    event_data.get("event_source", "observation"),
                    event_data.get("quality_state", "valid"),
                    event_data.get("training_exclude", False),
                    event_data.get("contract_violation_code", "NONE"),
                    event_data.get("missing_fields"),
                    event_data.get("raw_attributes_json"),
                ),
            )
            self._commit()
            return cursor.lastrowid
        except sqlite3.Error as e:
            logger.error("Failed to insert FIM event: %s", e)
            return None

    def insert_observation_event(self, event_data: Dict[str, Any]) -> Optional[int]:
        """Insert a generic observation event (P3 domains without dedicated tables)."""
        try:
            cursor = self.db.execute(
                """
                INSERT INTO observation_events (
                    timestamp_ns, timestamp_dt, device_id, domain,
                    event_type, attributes, risk_score, event_source,
                    collection_agent, agent_version, quality_state,
                    training_exclude, contract_violation_code, missing_fields,
                    raw_attributes_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_data.get("timestamp_ns", int(time.time() * 1e9)),
                    event_data.get(
                        "timestamp_dt", datetime.now(timezone.utc).isoformat()
                    ),
                    event_data.get("device_id", "unknown"),
                    event_data.get("domain", "unknown"),
                    event_data.get("event_type", "observation"),
                    json.dumps(event_data.get("attributes", {})),
                    event_data.get("risk_score", 0.0),
                    event_data.get("event_source", "observation"),
                    event_data.get("collection_agent"),
                    event_data.get("agent_version"),
                    event_data.get("quality_state", "valid"),
                    event_data.get("training_exclude", False),
                    event_data.get("contract_violation_code", "NONE"),
                    event_data.get("missing_fields"),
                    event_data.get("raw_attributes_json"),
                ),
            )
            self._commit()
            return cursor.lastrowid
        except sqlite3.Error as e:
            logger.error("Failed to insert observation event: %s", e)
            return None

    def upsert_observation_rollup(self, rollup_data: Dict[str, Any]) -> Optional[int]:
        """Upsert observation rollup bucket for adaptive shaping."""
        try:
            self.db.execute(
                """
                INSERT INTO observation_rollups (
                    window_start_ns, window_end_ns, domain, fingerprint,
                    sample_attributes, total_count, first_seen_ns, last_seen_ns,
                    device_id, collection_agent
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(domain, window_start_ns, fingerprint) DO UPDATE SET
                    window_end_ns=excluded.window_end_ns,
                    total_count=observation_rollups.total_count + excluded.total_count,
                    last_seen_ns=excluded.last_seen_ns,
                    sample_attributes=excluded.sample_attributes,
                    device_id=excluded.device_id,
                    collection_agent=excluded.collection_agent
                """,
                (
                    rollup_data.get("window_start_ns"),
                    rollup_data.get("window_end_ns"),
                    rollup_data.get("domain"),
                    rollup_data.get("fingerprint"),
                    json.dumps(rollup_data.get("sample_attributes", {})),
                    int(rollup_data.get("total_count", 1)),
                    rollup_data.get("first_seen_ns"),
                    rollup_data.get("last_seen_ns"),
                    rollup_data.get("device_id"),
                    rollup_data.get("collection_agent"),
                ),
            )
            self._commit()
            return 1
        except sqlite3.Error as e:
            logger.error("Failed to upsert observation rollup: %s", e)
            return None

    def insert_device_telemetry(self, event_data: Dict[str, Any]) -> Optional[int]:
        """Insert a device telemetry snapshot."""
        try:
            cursor = self.db.execute(
                """
                INSERT OR REPLACE INTO device_telemetry (
                    timestamp_ns, timestamp_dt, device_id, device_type,
                    protocol, manufacturer, model, ip_address, mac_address,
                    total_processes, total_cpu_percent, total_memory_percent,
                    metric_events, log_events, security_events,
                    collection_agent, agent_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_data.get("timestamp_ns", int(time.time() * 1e9)),
                    event_data.get(
                        "timestamp_dt",
                        datetime.now(timezone.utc).isoformat(),
                    ),
                    event_data.get("device_id", "unknown"),
                    event_data.get("device_type"),
                    event_data.get("protocol"),
                    event_data.get("manufacturer"),
                    event_data.get("model"),
                    event_data.get("ip_address"),
                    event_data.get("mac_address"),
                    event_data.get("total_processes", 0),
                    event_data.get("total_cpu_percent", 0.0),
                    event_data.get("total_memory_percent", 0.0),
                    event_data.get("metric_events", 0),
                    event_data.get("log_events", 0),
                    event_data.get("security_events", 0),
                    event_data.get("collection_agent"),
                    event_data.get("agent_version"),
                ),
            )
            self._commit()
            return cursor.lastrowid
        except sqlite3.Error as e:
            logger.error("Failed to insert device telemetry: %s", e)
            return None

    def insert_metrics_timeseries(self, event_data: Dict[str, Any]) -> Optional[int]:
        """Insert a metrics timeseries data point."""
        try:
            cursor = self.db.execute(
                """
                INSERT OR REPLACE INTO metrics_timeseries (
                    timestamp_ns, timestamp_dt, metric_name, metric_type,
                    device_id, value, unit, min_value, max_value,
                    avg_value, sample_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_data.get("timestamp_ns", int(time.time() * 1e9)),
                    event_data.get(
                        "timestamp_dt",
                        datetime.now(timezone.utc).isoformat(),
                    ),
                    event_data.get("metric_name"),
                    event_data.get("metric_type", "GAUGE"),
                    event_data.get("device_id"),
                    event_data.get("value", 0.0),
                    event_data.get("unit"),
                    event_data.get("min_value"),
                    event_data.get("max_value"),
                    event_data.get("avg_value"),
                    event_data.get("sample_count", 1),
                ),
            )
            self._commit()
            return cursor.lastrowid
        except sqlite3.Error as e:
            logger.error("Failed to insert metrics timeseries: %s", e)
            return None

    def get_recent_security_events(
        self,
        limit: int = 50,
        hours: int = 24,
        severity: Optional[str] = None,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Query security_events with time window and optional filter.

        Args:
            limit: Maximum events to return.
            hours: Time window in hours.
            severity: Optional filter on final_classification.
            offset: Number of rows to skip (for pagination).

        Returns:
            List of event dicts.
        """
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        params: list = [cutoff_ns]
        query = "SELECT * FROM security_events WHERE timestamp_ns > ?"

        if severity:
            query += " AND final_classification = ?"
            params.append(severity)

        query += " ORDER BY timestamp_ns DESC LIMIT ? OFFSET ?"
        params.append(limit)
        params.append(offset)

        with self._lock:
            try:
                cursor = self.db.execute(query, params)
                return [dict(row) for row in cursor.fetchall()]
            except sqlite3.Error as e:
                logger.error("Failed to query security events: %s", e)
                return []

    def get_unified_threat_events(
        self,
        limit: int = 50,
        hours: int = 24,
        offset: int = 0,
        min_risk: float = 0.0,
    ) -> List[Dict[str, Any]]:
        """Query all domain tables via UNION ALL for a unified threat view.

        Returns events from all domain tables, optionally filtered to only
        those exceeding min_risk (for threat-feed: show actual detections).
        """
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        risk_clause = f"AND risk_score > {min_risk}" if min_risk > 0 else ""
        risk_clause_anom = f"AND anomaly_score > {min_risk}" if min_risk > 0 else ""
        risk_clause_threat = f"AND threat_score > {min_risk}" if min_risk > 0 else ""
        query = f"""
            SELECT id, 'security' as source, event_category as type,
                   description, risk_score, confidence,
                   timestamp_ns, timestamp_dt, mitre_techniques, indicators,
                   collection_agent, device_id, final_classification,
                   requires_investigation, event_action
            FROM security_events WHERE timestamp_ns > ? {risk_clause}
            UNION ALL
            SELECT id, 'persistence', event_type, reason, risk_score,
                   confidence, timestamp_ns, timestamp_dt, mitre_techniques,
                   NULL, collection_agent, device_id, NULL, 1, change_type
            FROM persistence_events WHERE timestamp_ns > ? {risk_clause}
            UNION ALL
            SELECT id, 'process', process_category, exe, anomaly_score,
                   confidence_score, timestamp_ns, timestamp_dt, NULL,
                   NULL, collection_agent, device_id, NULL,
                   CAST(is_suspicious AS INT), NULL
            FROM process_events WHERE timestamp_ns > ? {risk_clause_anom}
            UNION ALL
            SELECT id, 'fim', event_type, reason, risk_score,
                   confidence, timestamp_ns, timestamp_dt, mitre_techniques,
                   NULL, collection_agent, device_id, NULL, 0, change_type
            FROM fim_events WHERE timestamp_ns > ? {risk_clause}
            UNION ALL
            SELECT id, 'flow', protocol,
                   'Flow: ' || COALESCE(src_ip,'?') || ':' || COALESCE(src_port,0)
                   || ' -> ' || COALESCE(dst_ip,'?') || ':' || COALESCE(dst_port,0),
                   threat_score, 0.5, timestamp_ns, timestamp_dt, NULL,
                   NULL, NULL, device_id, NULL,
                   CAST(is_suspicious AS INT), NULL
            FROM flow_events WHERE timestamp_ns > ? {risk_clause_threat}
            UNION ALL
            SELECT id, 'dns', event_type, 'DNS: ' || domain, risk_score,
                   confidence, timestamp_ns, timestamp_dt, mitre_techniques,
                   NULL, collection_agent, device_id, NULL, 0, NULL
            FROM dns_events WHERE timestamp_ns > ? {risk_clause}
            UNION ALL
            SELECT id, 'audit', event_type, reason, risk_score,
                   confidence, timestamp_ns, timestamp_dt, mitre_techniques,
                   NULL, collection_agent, device_id, NULL, 0, NULL
            FROM audit_events WHERE timestamp_ns > ? {risk_clause}
            ORDER BY timestamp_ns DESC LIMIT ? OFFSET ?
        """
        params = [cutoff_ns] * 7 + [limit, offset]
        with self._lock:
            try:
                cursor = self.db.execute(query, params)
                cols = [d[0] for d in cursor.description]
                return [dict(zip(cols, row)) for row in cursor.fetchall()]
            except sqlite3.Error as e:
                logger.error("Failed unified threat query: %s", e)
                return []

    def get_threat_count(self, hours: int = 24, min_risk: float = 0.1) -> int:
        """Fast count of events exceeding min_risk across scored tables."""
        cache_key = f"threat_count:{hours}:{min_risk}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        query = """
            SELECT SUM(cnt) FROM (
                SELECT COUNT(*) as cnt FROM security_events
                    WHERE timestamp_ns > ? AND risk_score > ?
                UNION ALL
                SELECT COUNT(*) FROM persistence_events
                    WHERE timestamp_ns > ? AND risk_score > ?
                UNION ALL
                SELECT COUNT(*) FROM process_events
                    WHERE timestamp_ns > ? AND anomaly_score > ?
                UNION ALL
                SELECT COUNT(*) FROM fim_events
                    WHERE timestamp_ns > ? AND risk_score > ?
                UNION ALL
                SELECT COUNT(*) FROM flow_events
                    WHERE timestamp_ns > ? AND threat_score > ?
                UNION ALL
                SELECT COUNT(*) FROM dns_events
                    WHERE timestamp_ns > ? AND risk_score > ?
                UNION ALL
                SELECT COUNT(*) FROM audit_events
                    WHERE timestamp_ns > ? AND risk_score > ?
            )
        """
        with self._read_pool.connection() as rdb:
            try:
                row = rdb.execute(query, (cutoff_ns, min_risk) * 7).fetchone()
                count = row[0] or 0 if row else 0
                self._cache.put(cache_key, count, ttl=30)
                return count
            except sqlite3.Error:
                return 0

    def get_unified_event_counts(self, hours: int = 24) -> Dict[str, Any]:
        """Aggregate event counts across all domain tables."""
        cache_key = f"unified_counts:{hours}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        # Tables where GROUP BY is fast (< 300K rows each)
        tables = {
            "security_events": "event_category",
            "persistence_events": "event_type",
            "process_events": "process_category",
            "fim_events": "event_type",
            "flow_events": "protocol",
            "dns_events": "event_type",
            "audit_events": "event_type",
            "peripheral_events": "event_type",
        }
        # Large tables: COUNT only (GROUP BY too expensive on millions of rows)
        count_only_tables = ["observation_events"]
        result: Dict[str, Any] = {"total": 0, "by_source": {}, "by_category": {}}
        with self._read_pool.connection() as rdb:
            for table, cat_col in tables.items():
                try:
                    row = rdb.execute(
                        f"SELECT COUNT(*) FROM {table} WHERE timestamp_ns > ?",
                        (cutoff_ns,),
                    ).fetchone()
                    count = row[0] if row else 0
                    result["by_source"][table.replace("_events", "")] = count
                    result["total"] += count

                    cats = rdb.execute(
                        f"SELECT {cat_col}, COUNT(*) FROM {table} "
                        f"WHERE timestamp_ns > ? GROUP BY {cat_col}",
                        (cutoff_ns,),
                    ).fetchall()
                    for cat_row in cats:
                        if cat_row[0]:
                            result["by_category"][cat_row[0]] = (
                                result["by_category"].get(cat_row[0], 0) + cat_row[1]
                            )
                except sqlite3.Error:
                    continue
            for table in count_only_tables:
                try:
                    row = rdb.execute(
                        f"SELECT COUNT(*) FROM {table} WHERE timestamp_ns > ?",
                        (cutoff_ns,),
                    ).fetchone()
                    count = row[0] if row else 0
                    result["by_source"][table.replace("_events", "")] = count
                    result["total"] += count
                except sqlite3.Error:
                    continue
        self._cache.put(cache_key, result, ttl=30)
        return result

    def get_security_event_counts(self, hours: int = 24) -> Dict[str, Any]:
        """Aggregate counts by category and classification.

        Returns:
            Summary dict with category counts, classification counts,
            and total.
        """
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        result: Dict[str, Any] = {
            "total": 0,
            "by_category": {},
            "by_classification": {},
        }

        with self._lock:
            try:
                cursor = self.db.execute(
                    "SELECT COUNT(*) FROM security_events WHERE timestamp_ns > ?",
                    (cutoff_ns,),
                )
                result["total"] = cursor.fetchone()[0]

                cursor = self.db.execute(
                    """SELECT event_category, COUNT(*) as cnt
                       FROM security_events WHERE timestamp_ns > ?
                       GROUP BY event_category""",
                    (cutoff_ns,),
                )
                for row in cursor.fetchall():
                    if row[0]:
                        result["by_category"][row[0]] = row[1]

                cursor = self.db.execute(
                    """SELECT final_classification, COUNT(*) as cnt
                       FROM security_events WHERE timestamp_ns > ?
                       GROUP BY final_classification""",
                    (cutoff_ns,),
                )
                for row in cursor.fetchall():
                    if row[0]:
                        result["by_classification"][row[0]] = row[1]

            except sqlite3.Error as e:
                logger.error("Failed to count security events: %s", e)

        return result

    def get_threat_score_data(self, hours: int = 1) -> Dict[str, Any]:
        """Calculate threat score across ALL domain tables.

        Returns:
            Dict with threat_score (0-100), threat_level, event_count.
        """
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)

        try:
            # UNION ALL risk scores from every domain table
            query = """
                SELECT COUNT(*) as cnt,
                       COALESCE(AVG(rs), 0) as avg_risk,
                       COALESCE(MAX(rs), 0) as max_risk,
                       COALESCE(SUM(CASE WHEN rs > 0.7 THEN 1 ELSE 0 END), 0) as critical_count
                FROM (
                    SELECT risk_score as rs FROM security_events WHERE timestamp_ns > ?
                    UNION ALL
                    SELECT risk_score FROM persistence_events WHERE timestamp_ns > ?
                    UNION ALL
                    SELECT anomaly_score FROM process_events WHERE timestamp_ns > ?
                    UNION ALL
                    SELECT risk_score FROM fim_events WHERE timestamp_ns > ?
                    UNION ALL
                    SELECT threat_score FROM flow_events WHERE timestamp_ns > ?
                    UNION ALL
                    SELECT risk_score FROM dns_events WHERE timestamp_ns > ?
                )
            """
            with self._lock:
                cursor = self.db.execute(query, (cutoff_ns,) * 6)
                row = cursor.fetchone()
            cnt = row[0]
            avg_risk = row[1]
            max_risk = row[2]
            critical_count = row[3]

            # Score: weighted blend of average risk and critical event density
            if cnt == 0:
                score = 0.0
            else:
                score = min(
                    100.0,
                    (avg_risk * 50) + (critical_count * 10) + (max_risk * 20),
                )

            if score >= 75:
                level = "critical"
            elif score >= 50:
                level = "high"
            elif score >= 25:
                level = "medium"
            elif score > 0:
                level = "low"
            else:
                level = "none"

            return {
                "threat_score": round(score, 1),
                "threat_level": level,
                "event_count": cnt,
                "avg_risk": round(avg_risk, 3),
                "max_risk": round(max_risk, 3),
                "critical_count": critical_count,
            }

        except sqlite3.Error as e:
            logger.error("Failed to calculate threat score: %s", e)
            return {
                "threat_score": 0,
                "threat_level": "none",
                "event_count": 0,
            }

    def get_security_event_clustering(self, hours: int = 24) -> Dict[str, Any]:
        """Cluster security events by category/severity/hour.

        Returns:
            Dict with by_category, by_severity, by_hour groupings.
        """
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        result: Dict[str, Any] = {
            "by_category": {},
            "by_severity": {"low": 0, "medium": 0, "high": 0, "critical": 0},
            "by_hour": {},
        }

        with self._lock:
            try:
                # By category
                cursor = self.db.execute(
                    """SELECT event_category, COUNT(*) as cnt
                       FROM security_events WHERE timestamp_ns > ?
                       GROUP BY event_category ORDER BY cnt DESC""",
                    (cutoff_ns,),
                )
                for row in cursor.fetchall():
                    if row[0]:
                        result["by_category"][row[0]] = row[1]

                # By severity (map risk_score to levels)
                cursor = self.db.execute(
                    """SELECT
                           SUM(CASE WHEN risk_score < 0.25 THEN 1 ELSE 0 END) as low_cnt,
                           SUM(CASE WHEN risk_score >= 0.25 AND risk_score < 0.5 THEN 1 ELSE 0 END) as med_cnt,
                           SUM(CASE WHEN risk_score >= 0.5 AND risk_score < 0.75 THEN 1 ELSE 0 END) as high_cnt,
                           SUM(CASE WHEN risk_score >= 0.75 THEN 1 ELSE 0 END) as crit_cnt
                       FROM security_events WHERE timestamp_ns > ?""",
                    (cutoff_ns,),
                )
                row = cursor.fetchone()
                if row:
                    result["by_severity"] = {
                        "low": row[0] or 0,
                        "medium": row[1] or 0,
                        "high": row[2] or 0,
                        "critical": row[3] or 0,
                    }

                # By hour (extract hour from timestamp_dt)
                cursor = self.db.execute(
                    """SELECT SUBSTR(timestamp_dt, 12, 2) as hour, COUNT(*) as cnt
                       FROM security_events WHERE timestamp_ns > ?
                       GROUP BY hour ORDER BY hour""",
                    (cutoff_ns,),
                )
                for row in cursor.fetchall():
                    if row[0]:
                        result["by_hour"][row[0]] = row[1]

            except sqlite3.Error as e:
                logger.error("Failed to cluster security events: %s", e)

        return result

    def get_unified_event_clustering(self, hours: int = 24) -> Dict[str, Any]:
        """Cluster events across ALL domain tables by severity, agent, and hour.

        Returns:
            Dict with by_severity, by_agent, by_hour, by_source groupings.
        """
        cache_key = f"unified_clustering:{hours}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        result: Dict[str, Any] = {
            "by_severity": {"low": 0, "medium": 0, "high": 0, "critical": 0},
            "by_agent": {},
            "by_hour": {},
            "by_source": {},
        }

        # Severity buckets from all tables with risk_score
        sev_query = """
            SELECT
                SUM(CASE WHEN rs < 0.25 THEN 1 ELSE 0 END),
                SUM(CASE WHEN rs >= 0.25 AND rs < 0.5 THEN 1 ELSE 0 END),
                SUM(CASE WHEN rs >= 0.5 AND rs < 0.75 THEN 1 ELSE 0 END),
                SUM(CASE WHEN rs >= 0.75 THEN 1 ELSE 0 END)
            FROM (
                SELECT risk_score as rs FROM security_events WHERE timestamp_ns > ?
                UNION ALL
                SELECT risk_score FROM persistence_events WHERE timestamp_ns > ?
                UNION ALL
                SELECT anomaly_score FROM process_events WHERE timestamp_ns > ?
                UNION ALL
                SELECT risk_score FROM fim_events WHERE timestamp_ns > ?
                UNION ALL
                SELECT threat_score FROM flow_events WHERE timestamp_ns > ?
                UNION ALL
                SELECT risk_score FROM dns_events WHERE timestamp_ns > ?
            )
        """
        # Hourly histogram from scored domain tables (fast path)
        hour_query = """
            SELECT hr, SUM(cnt) FROM (
                SELECT SUBSTR(timestamp_dt, 12, 2) as hr, COUNT(*) as cnt
                FROM security_events WHERE timestamp_ns > ? GROUP BY hr
                UNION ALL
                SELECT SUBSTR(timestamp_dt, 12, 2), COUNT(*)
                FROM persistence_events WHERE timestamp_ns > ? GROUP BY 1
                UNION ALL
                SELECT SUBSTR(timestamp_dt, 12, 2), COUNT(*)
                FROM process_events WHERE timestamp_ns > ? GROUP BY 1
                UNION ALL
                SELECT SUBSTR(timestamp_dt, 12, 2), COUNT(*)
                FROM fim_events WHERE timestamp_ns > ? GROUP BY 1
                UNION ALL
                SELECT SUBSTR(timestamp_dt, 12, 2), COUNT(*)
                FROM flow_events WHERE timestamp_ns > ? GROUP BY 1
                UNION ALL
                SELECT SUBSTR(timestamp_dt, 12, 2), COUNT(*)
                FROM dns_events WHERE timestamp_ns > ? GROUP BY 1
            ) GROUP BY hr ORDER BY hr
        """

        with self._read_pool.connection() as rdb:
            try:
                row = rdb.execute(sev_query, (cutoff_ns,) * 6).fetchone()
                if row:
                    result["by_severity"] = {
                        "low": row[0] or 0,
                        "medium": row[1] or 0,
                        "high": row[2] or 0,
                        "critical": row[3] or 0,
                    }

                for hr_row in rdb.execute(hour_query, (cutoff_ns,) * 6).fetchall():
                    if hr_row[0]:
                        result["by_hour"][hr_row[0]] = hr_row[1]

                # Per-source counts across ALL domain tables
                tables = {
                    "security": "security_events",
                    "persistence": "persistence_events",
                    "process": "process_events",
                    "fim": "fim_events",
                    "flow": "flow_events",
                    "dns": "dns_events",
                    "observation": "observation_events",
                    "audit": "audit_events",
                    "peripheral": "peripheral_events",
                }
                for label, table in tables.items():
                    cnt = rdb.execute(
                        f"SELECT COUNT(*) FROM {table} WHERE timestamp_ns > ?",
                        (cutoff_ns,),
                    ).fetchone()[0]
                    result["by_source"][label] = cnt

                # Per-agent counts from scored tables with collection_agent
                for table in [
                    "security_events",
                    "persistence_events",
                    "process_events",
                    "fim_events",
                    "dns_events",
                    "audit_events",
                ]:
                    rows = rdb.execute(
                        f"SELECT collection_agent, COUNT(*) FROM {table} "
                        f"WHERE timestamp_ns > ? AND collection_agent IS NOT NULL "
                        f"GROUP BY collection_agent",
                        (cutoff_ns,),
                    ).fetchall()
                    for r in rows:
                        if r[0]:
                            result["by_agent"][r[0]] = (
                                result["by_agent"].get(r[0], 0) + r[1]
                            )

            except sqlite3.Error as e:
                logger.error("Failed unified event clustering: %s", e)

        self._cache.put(cache_key, result, ttl=30)
        return result

    # --- Log Search / Threat Hunting ---

    def search_events(
        self,
        query: str = "",
        table: str = "security_events",
        hours: int = 24,
        limit: int = 100,
        offset: int = 0,
        min_risk: Optional[float] = None,
        category: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Full-text search across event tables for threat hunting.

        Args:
            query: Free-text search across description, indicators, event_category
            table: Table to search (security_events, process_events, flow_events, peripheral_events)
            hours: Time window
            limit: Max rows
            offset: Pagination offset
            min_risk: Minimum risk_score filter
            category: Filter by event_category

        Returns:
            Dict with results list, total_count, and pagination info.
        """
        allowed_tables = {
            "security_events",
            "process_events",
            "flow_events",
            "peripheral_events",
            "dns_events",
            "audit_events",
            "persistence_events",
            "fim_events",
            "observation_events",
        }
        if table not in allowed_tables:
            table = "security_events"

        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        params: list = [cutoff_ns]
        where_clauses = ["timestamp_ns > ?"]

        if query:
            if table == "security_events":
                where_clauses.append(
                    "(description LIKE ? OR indicators LIKE ? OR event_category LIKE ?)"
                )
                q = f"%{query}%"
                params.extend([q, q, q])
            elif table == "process_events":
                where_clauses.append(
                    "(exe LIKE ? OR cmdline LIKE ? OR username LIKE ?)"
                )
                q = f"%{query}%"
                params.extend([q, q, q])
            elif table == "flow_events":
                where_clauses.append(
                    "(src_ip LIKE ? OR dst_ip LIKE ? OR protocol LIKE ?)"
                )
                q = f"%{query}%"
                params.extend([q, q, q])
            elif table == "peripheral_events":
                where_clauses.append(
                    "(device_name LIKE ? OR device_type LIKE ? OR manufacturer LIKE ?)"
                )
                q = f"%{query}%"
                params.extend([q, q, q])
            elif table == "dns_events":
                where_clauses.append(
                    "(domain LIKE ? OR event_type LIKE ? OR process_name LIKE ?)"
                )
                q = f"%{query}%"
                params.extend([q, q, q])
            elif table == "audit_events":
                where_clauses.append(
                    "(syscall LIKE ? OR exe LIKE ? OR comm LIKE ? OR reason LIKE ?)"
                )
                q = f"%{query}%"
                params.extend([q, q, q, q])
            elif table == "persistence_events":
                where_clauses.append(
                    "(mechanism LIKE ? OR path LIKE ? OR command LIKE ? OR reason LIKE ?)"
                )
                q = f"%{query}%"
                params.extend([q, q, q, q])
            elif table == "fim_events":
                where_clauses.append(
                    "(path LIKE ? OR event_type LIKE ? OR reason LIKE ?)"
                )
                q = f"%{query}%"
                params.extend([q, q, q])
            elif table == "observation_events":
                where_clauses.append("(attributes LIKE ? OR domain LIKE ?)")
                q = f"%{query}%"
                params.extend([q, q])

        if min_risk is not None and table in (
            "security_events",
            "peripheral_events",
            "dns_events",
            "audit_events",
            "persistence_events",
            "fim_events",
        ):
            where_clauses.append("risk_score >= ?")
            params.append(min_risk)

        if category and table == "security_events":
            where_clauses.append("event_category = ?")
            params.append(category)

        where_sql = " AND ".join(where_clauses)

        try:
            # Count total
            count_cursor = self.db.execute(
                f"SELECT COUNT(*) FROM {table} WHERE {where_sql}", params
            )
            total = count_cursor.fetchone()[0]

            # Fetch page
            fetch_params = params + [limit, offset]
            cursor = self.db.execute(
                f"SELECT * FROM {table} WHERE {where_sql} ORDER BY timestamp_ns DESC LIMIT ? OFFSET ?",
                fetch_params,
            )
            rows = [dict(r) for r in cursor.fetchall()]

            return {
                "results": rows,
                "total_count": total,
                "page_size": limit,
                "offset": offset,
                "has_more": (offset + limit) < total,
            }
        except sqlite3.Error as e:
            logger.error("Search failed: %s", e)
            return {
                "results": [],
                "total_count": 0,
                "page_size": limit,
                "offset": 0,
                "has_more": False,
            }

    # --- MITRE ATT&CK Coverage ---

    def get_mitre_coverage(self) -> Dict[str, Any]:
        """Get MITRE ATT&CK technique coverage from security events.

        Returns:
            Dict mapping technique IDs to hit counts and event categories.
        """
        try:
            # Fetch individual rows (no GROUP BY) so each row contributes
            # count=1 to every technique in its JSON array.
            cursor = self.db.execute(
                "SELECT mitre_techniques, event_category "
                "FROM security_events WHERE mitre_techniques IS NOT NULL"
            )
            coverage: Dict[str, Dict] = {}
            for row in cursor.fetchall():
                try:
                    techniques = json.loads(row[0]) if row[0] else []
                except (json.JSONDecodeError, TypeError):
                    continue
                if not isinstance(techniques, list):
                    continue
                cat = row[1] or "unknown"
                for tech in techniques:
                    if tech not in coverage:
                        coverage[tech] = {"count": 0, "categories": {}}
                    coverage[tech]["count"] += 1
                    coverage[tech]["categories"][cat] = (
                        coverage[tech]["categories"].get(cat, 0) + 1
                    )
            return coverage
        except sqlite3.Error as e:
            logger.error("Failed to get MITRE coverage: %s", e)
            return {}

    # --- Incident Management ---

    def create_incident(self, data: Dict[str, Any]) -> Optional[int]:
        """Create a security incident."""
        now = datetime.now(timezone.utc).isoformat()
        try:
            cursor = self.db.execute(
                """INSERT INTO incidents (
                    created_at, updated_at, title, description, severity,
                    status, assignee, source_event_ids, mitre_techniques,
                    indicators
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    now,
                    now,
                    data.get("title", "Untitled Incident"),
                    data.get("description", ""),
                    data.get("severity", "medium"),
                    data.get("status", "open"),
                    data.get("assignee"),
                    json.dumps(data.get("source_event_ids", [])),
                    json.dumps(data.get("mitre_techniques", [])),
                    json.dumps(data.get("indicators", {})),
                ),
            )
            self._commit()
            return cursor.lastrowid
        except sqlite3.Error as e:
            logger.error("Failed to create incident: %s", e)
            return None

    def update_incident(self, incident_id: int, data: Dict[str, Any]) -> bool:
        """Update an existing incident."""
        now = datetime.now(timezone.utc).isoformat()
        sets = ["updated_at = ?"]
        params: list = [now]
        allowed = {
            "title",
            "description",
            "severity",
            "status",
            "assignee",
            "resolution_notes",
        }
        for k, v in data.items():
            if k in allowed:
                sets.append(f"{k} = ?")
                params.append(v)
        if data.get("status") == "resolved" and not data.get("resolved_at"):
            sets.append("resolved_at = ?")
            params.append(now)
        params.append(incident_id)
        try:
            self.db.execute(
                f"UPDATE incidents SET {', '.join(sets)} WHERE id = ?", params
            )
            self._commit()
            return True
        except sqlite3.Error as e:
            logger.error("Failed to update incident: %s", e)
            return False

    def get_incidents(
        self, status: Optional[str] = None, limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Get incidents with optional status filter."""
        with self._lock:
            try:
                if status:
                    cursor = self.db.execute(
                        "SELECT * FROM incidents WHERE status = ? ORDER BY created_at DESC LIMIT ?",
                        (status, limit),
                    )
                else:
                    cursor = self.db.execute(
                        "SELECT * FROM incidents ORDER BY created_at DESC LIMIT ?",
                        (limit,),
                    )
                return [dict(r) for r in cursor.fetchall()]
            except sqlite3.Error as e:
                logger.error("Failed to get incidents: %s", e)
                return []

    def get_incident(self, incident_id: int) -> Optional[Dict[str, Any]]:
        """Get a single incident by ID."""
        with self._lock:
            try:
                cursor = self.db.execute(
                    "SELECT * FROM incidents WHERE id = ?", (incident_id,)
                )
                row = cursor.fetchone()
                return dict(row) if row else None
            except sqlite3.Error as e:
                logger.error("Failed to get incident: %s", e)
                return None

    # --- Metrics History ---

    def get_metrics_history(
        self, metric_name: str, hours: int = 24, device_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get historical metrics for time-series charts."""
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        try:
            if device_id:
                cursor = self.db.execute(
                    "SELECT * FROM metrics_timeseries WHERE metric_name = ? AND device_id = ? AND timestamp_ns > ? ORDER BY timestamp_ns",
                    (metric_name, device_id, cutoff_ns),
                )
            else:
                cursor = self.db.execute(
                    "SELECT * FROM metrics_timeseries WHERE metric_name = ? AND timestamp_ns > ? ORDER BY timestamp_ns",
                    (metric_name, cutoff_ns),
                )
            return [dict(r) for r in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error("Failed to get metrics history: %s", e)
            return []

    # ── Data Retention ──

    def cleanup_old_data(self, max_age_days: int = 90) -> Dict[str, int]:
        """Delete telemetry data older than max_age_days.

        Called periodically by WALProcessor to prevent unbounded DB growth.

        Returns:
            Dict mapping table name to number of rows deleted.
        """
        cutoff_ns = int((time.time() - max_age_days * 86400) * 1e9)
        cutoff_dt = datetime.fromtimestamp(
            time.time() - max_age_days * 86400, tz=timezone.utc
        ).isoformat()

        tables_ns = [
            "process_events",
            "flow_events",
            "security_events",
            "peripheral_events",
            "dns_events",
            "audit_events",
            "persistence_events",
            "fim_events",
        ]
        tables_dt = ["device_telemetry", "metrics_timeseries"]
        deleted: Dict[str, int] = {}

        for table in tables_ns:
            try:
                cursor = self.db.execute(
                    f"DELETE FROM {table} WHERE timestamp_ns < ?", (cutoff_ns,)
                )
                deleted[table] = cursor.rowcount
            except sqlite3.Error:
                deleted[table] = 0

        for table in tables_dt:
            try:
                cursor = self.db.execute(
                    f"DELETE FROM {table} WHERE timestamp_dt < ?", (cutoff_dt,)
                )
                deleted[table] = cursor.rowcount
            except sqlite3.Error:
                deleted[table] = 0

        # Dead letters and WAL archive: keep 30 days
        short_cutoff_dt = datetime.fromtimestamp(
            time.time() - 30 * 86400, tz=timezone.utc
        ).isoformat()
        for table in ["wal_dead_letter", "wal_archive"]:
            try:
                cursor = self.db.execute(
                    f"DELETE FROM {table} WHERE quarantined_at < ? OR created_at < ?",
                    (short_cutoff_dt, short_cutoff_dt),
                )
                deleted[table] = cursor.rowcount
            except sqlite3.Error:
                deleted[table] = 0

        self.db.commit()

        total = sum(deleted.values())
        if total > 0:
            logger.info(
                "Retention cleanup: deleted %d rows across %d tables (age > %dd)",
                total,
                sum(1 for v in deleted.values() if v > 0),
                max_age_days,
            )
        return deleted

    # ── Observatory Query Methods ──

    @staticmethod
    def _risk_to_status(risk: float, count: int) -> str:
        """Map risk score + count to a status label."""
        if risk > 0.7:
            return "critical"
        if risk > 0.3:
            return "warning"
        return "healthy" if count > 0 else "inactive"

    @staticmethod
    def _risk_to_threat_level(risk: float) -> str:
        """Map max risk score to threat level."""
        if risk > 0.7:
            return "critical"
        if risk > 0.3:
            return "elevated"
        return "clear"

    def _query_domain_posture(self, table: str, risk_col: str, cutoff_ns: int) -> Dict:
        """Query a single domain table for posture stats. Caller holds self._lock."""
        try:
            row = self.db.execute(
                f"SELECT COUNT(*), MAX(timestamp_ns), COALESCE(MAX({risk_col}), 0), "
                f"COALESCE(AVG({risk_col}), 0) "
                f"FROM {table} WHERE timestamp_ns > ?",
                (cutoff_ns,),
            ).fetchone()
            count = row[0] or 0
            domain_max = row[2] or 0.0
            return {
                "count": count,
                "latest_ns": row[1] or 0,
                "max_risk": round(domain_max, 3),
                "avg_risk": round(row[3] or 0, 3),
                "status": self._risk_to_status(domain_max, count),
            }
        except sqlite3.Error:
            return {
                "count": 0,
                "latest_ns": 0,
                "max_risk": 0,
                "avg_risk": 0,
                "status": "inactive",
            }

    def get_device_posture(self, hours: int = 24) -> Dict[str, Any]:
        """Cross-domain device health summary.

        Optimized: single UNION ALL query instead of 9 sequential queries.
        Uses covering indexes from migration 011 for index-only scans.
        Results are cached for 5 s to coalesce WebSocket bursts.
        """
        cache_key = f"device_posture:{hours}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        cutoff_ns = int((time.time() - hours * 3600) * 1e9)

        # Single UNION ALL — each branch does COUNT/MAX/AVG on its covering
        # index (timestamp_ns, risk_col).  SQLite evaluates all 9 branches
        # in one planner pass and returns 9 rows.
        posture_query = """
            SELECT 'process' as label, COUNT(*), MAX(timestamp_ns),
                   COALESCE(MAX(anomaly_score), 0), COALESCE(AVG(anomaly_score), 0)
            FROM process_events WHERE timestamp_ns > ?1
            UNION ALL
            SELECT 'network', COUNT(*), MAX(timestamp_ns),
                   COALESCE(MAX(threat_score), 0), COALESCE(AVG(threat_score), 0)
            FROM flow_events WHERE timestamp_ns > ?1
            UNION ALL
            SELECT 'dns', COUNT(*), MAX(timestamp_ns),
                   COALESCE(MAX(risk_score), 0), COALESCE(AVG(risk_score), 0)
            FROM dns_events WHERE timestamp_ns > ?1
            UNION ALL
            SELECT 'auth', COUNT(*), MAX(timestamp_ns),
                   COALESCE(MAX(risk_score), 0), COALESCE(AVG(risk_score), 0)
            FROM audit_events WHERE timestamp_ns > ?1
            UNION ALL
            SELECT 'files', COUNT(*), MAX(timestamp_ns),
                   COALESCE(MAX(risk_score), 0), COALESCE(AVG(risk_score), 0)
            FROM fim_events WHERE timestamp_ns > ?1
            UNION ALL
            SELECT 'persistence', COUNT(*), MAX(timestamp_ns),
                   COALESCE(MAX(risk_score), 0), COALESCE(AVG(risk_score), 0)
            FROM persistence_events WHERE timestamp_ns > ?1
            UNION ALL
            SELECT 'peripherals', COUNT(*), MAX(timestamp_ns),
                   COALESCE(MAX(risk_score), 0), COALESCE(AVG(risk_score), 0)
            FROM peripheral_events WHERE timestamp_ns > ?1
            UNION ALL
            SELECT 'observations', COUNT(*), MAX(timestamp_ns),
                   COALESCE(MAX(risk_score), 0), COALESCE(AVG(risk_score), 0)
            FROM observation_events WHERE timestamp_ns > ?1
            UNION ALL
            SELECT '_security_count', COUNT(*), 0, 0, 0
            FROM security_events WHERE timestamp_ns > ?1
        """
        result: Dict[str, Any] = {
            "domains": {},
            "total_events": 0,
            "threat_level": "clear",
        }
        max_risk = 0.0
        with self._read_pool.connection() as rdb:
            try:
                rows = rdb.execute(posture_query, (cutoff_ns,)).fetchall()
                for r in rows:
                    label, count, latest, domain_max, avg_risk = (
                        r[0],
                        r[1] or 0,
                        r[2] or 0,
                        r[3] or 0.0,
                        r[4] or 0.0,
                    )
                    if label == "_security_count":
                        result["security_detections"] = count
                        continue
                    result["domains"][label] = {
                        "count": count,
                        "latest_ns": latest,
                        "max_risk": round(domain_max, 3),
                        "avg_risk": round(avg_risk, 3),
                        "status": self._risk_to_status(domain_max, count),
                    }
                    result["total_events"] += count
                    max_risk = max(max_risk, domain_max)
            except sqlite3.Error as e:
                logger.error("Device posture query failed: %s", e)
                result["security_detections"] = 0
        result["threat_level"] = self._risk_to_threat_level(max_risk)
        result["posture_score"] = max(0, round(100 - (max_risk * 100), 1))
        self._cache.put(cache_key, result, ttl=30)  # summary view — 30s TTL
        return result

    def get_cross_domain_timeline(
        self, hours: int = 24, limit: int = 200
    ) -> List[Dict]:
        """Unified timeline across ALL domain tables."""
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        query = """
            SELECT timestamp_ns, timestamp_dt, 'process' as domain, 'process' as event_type,
                   COALESCE(exe, '') as summary, COALESCE(anomaly_score, 0) as risk_score
            FROM process_events WHERE timestamp_ns > ?1
            UNION ALL
            SELECT timestamp_ns, timestamp_dt, 'network' as domain, 'flow' as event_type,
                   COALESCE(dst_ip || ':' || CAST(dst_port AS TEXT), '') as summary,
                   COALESCE(threat_score, 0) as risk_score
            FROM flow_events WHERE timestamp_ns > ?1
            UNION ALL
            SELECT timestamp_ns, timestamp_dt, 'dns' as domain, COALESCE(event_type, 'query'),
                   COALESCE(domain, ''), COALESCE(risk_score, 0)
            FROM dns_events WHERE timestamp_ns > ?1
            UNION ALL
            SELECT timestamp_ns, timestamp_dt, 'auth' as domain, COALESCE(event_type, 'audit'),
                   COALESCE(exe, ''), COALESCE(risk_score, 0)
            FROM audit_events WHERE timestamp_ns > ?1
            UNION ALL
            SELECT timestamp_ns, timestamp_dt, 'files' as domain, COALESCE(change_type, 'change'),
                   COALESCE(path, ''), COALESCE(risk_score, 0)
            FROM fim_events WHERE timestamp_ns > ?1
            UNION ALL
            SELECT timestamp_ns, timestamp_dt, 'persistence' as domain, COALESCE(mechanism, 'unknown'),
                   COALESCE(path, ''), COALESCE(risk_score, 0)
            FROM persistence_events WHERE timestamp_ns > ?1
            UNION ALL
            SELECT timestamp_ns, timestamp_dt, 'security' as domain, COALESCE(event_category, 'detection'),
                   COALESCE(description, ''), COALESCE(risk_score, 0)
            FROM security_events WHERE timestamp_ns > ?1
            ORDER BY timestamp_ns DESC LIMIT ?2
        """
        with self._lock:
            try:
                rows = self.db.execute(query, (cutoff_ns, limit)).fetchall()
                return [
                    {
                        "timestamp_ns": r[0],
                        "timestamp_dt": r[1],
                        "domain": r[2],
                        "event_type": r[3],
                        "summary": r[4],
                        "risk_score": r[5],
                    }
                    for r in rows
                ]
            except sqlite3.Error as e:
                logger.error("Cross-domain timeline failed: %s", e)
                return []

    # ── DNS Intelligence ──

    def get_dns_stats(self, hours: int = 24) -> Dict[str, Any]:
        """DNS query analytics."""
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        with self._lock:
            try:
                row = self.db.execute(
                    """SELECT COUNT(*), COUNT(DISTINCT domain),
                       SUM(CASE WHEN dga_score > 0.7 THEN 1 ELSE 0 END),
                       SUM(CASE WHEN is_beaconing = 1 THEN 1 ELSE 0 END)
                    FROM dns_events WHERE timestamp_ns > ?""",
                    (cutoff_ns,),
                ).fetchone()
                # Query type distribution
                qt_rows = self.db.execute(
                    "SELECT query_type, COUNT(*) FROM dns_events WHERE timestamp_ns > ? "
                    "GROUP BY query_type ORDER BY COUNT(*) DESC",
                    (cutoff_ns,),
                ).fetchall()
                # Response code distribution
                rc_rows = self.db.execute(
                    "SELECT response_code, COUNT(*) FROM dns_events WHERE timestamp_ns > ? "
                    "GROUP BY response_code ORDER BY COUNT(*) DESC",
                    (cutoff_ns,),
                ).fetchall()
                return {
                    "total_queries": row[0] or 0,
                    "unique_domains": row[1] or 0,
                    "dga_suspects": row[2] or 0,
                    "beaconing_domains": row[3] or 0,
                    "by_query_type": {r[0]: r[1] for r in qt_rows if r[0]},
                    "by_response_code": {r[0]: r[1] for r in rc_rows if r[0]},
                }
            except sqlite3.Error as e:
                logger.error("DNS stats failed: %s", e)
                return {
                    "total_queries": 0,
                    "unique_domains": 0,
                    "dga_suspects": 0,
                    "beaconing_domains": 0,
                }

    def get_dns_top_domains(self, hours: int = 24, limit: int = 20) -> List[Dict]:
        """Top queried domains."""
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        with self._lock:
            try:
                rows = self.db.execute(
                    """SELECT domain, COUNT(*) as cnt, query_type, process_name,
                       MAX(dga_score) as max_dga, MAX(CASE WHEN is_beaconing THEN 1 ELSE 0 END) as beacon
                    FROM dns_events WHERE timestamp_ns > ? AND domain IS NOT NULL
                    GROUP BY domain ORDER BY cnt DESC LIMIT ?""",
                    (cutoff_ns, limit),
                ).fetchall()
                return [
                    {
                        "domain": r[0],
                        "count": r[1],
                        "query_type": r[2],
                        "process_name": r[3],
                        "dga_score": r[4] or 0,
                        "is_beaconing": bool(r[5]),
                    }
                    for r in rows
                ]
            except sqlite3.Error as e:
                logger.error("DNS top domains failed: %s", e)
                return []

    def get_dns_dga_suspects(
        self, hours: int = 24, min_score: float = 0.5, limit: int = 50
    ) -> List[Dict]:
        """Domains with high DGA scores."""
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        with self._lock:
            try:
                rows = self.db.execute(
                    """SELECT domain, dga_score, process_name, source_ip, timestamp_dt, query_type
                    FROM dns_events WHERE timestamp_ns > ? AND dga_score >= ?
                    ORDER BY dga_score DESC LIMIT ?""",
                    (cutoff_ns, min_score, limit),
                ).fetchall()
                return [
                    {
                        "domain": r[0],
                        "dga_score": r[1],
                        "process_name": r[2],
                        "source_ip": r[3],
                        "timestamp": r[4],
                        "query_type": r[5],
                    }
                    for r in rows
                ]
            except sqlite3.Error as e:
                logger.error("DNS DGA query failed: %s", e)
                return []

    def get_dns_beaconing(self, hours: int = 24, limit: int = 50) -> List[Dict]:
        """Domains exhibiting beaconing behavior."""
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        with self._lock:
            try:
                rows = self.db.execute(
                    """SELECT domain, beacon_interval_seconds, COUNT(*) as cnt, process_name
                    FROM dns_events WHERE timestamp_ns > ? AND is_beaconing = 1
                    GROUP BY domain ORDER BY cnt DESC LIMIT ?""",
                    (cutoff_ns, limit),
                ).fetchall()
                return [
                    {
                        "domain": r[0],
                        "interval_seconds": r[1],
                        "query_count": r[2],
                        "process_name": r[3],
                    }
                    for r in rows
                ]
            except sqlite3.Error as e:
                logger.error("DNS beaconing query failed: %s", e)
                return []

    def get_dns_timeline(self, hours: int = 24) -> List[Dict]:
        """DNS query counts bucketed by time."""
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        with self._lock:
            try:
                rows = self.db.execute(
                    """SELECT SUBSTR(timestamp_dt, 1, 13) as hour, COUNT(*) as cnt,
                       SUM(CASE WHEN dga_score > 0.5 THEN 1 ELSE 0 END) as suspicious
                    FROM dns_events WHERE timestamp_ns > ?
                    GROUP BY hour ORDER BY hour""",
                    (cutoff_ns,),
                ).fetchall()
                return [
                    {"hour": r[0], "count": r[1], "suspicious": r[2] or 0} for r in rows
                ]
            except sqlite3.Error as e:
                logger.error("DNS timeline failed: %s", e)
                return []

    # ── Network Intelligence ──

    def get_flow_stats(self, hours: int = 24) -> Dict[str, Any]:
        """Network flow summary.

        Optimized: uses covering index idx_flow_stats_covering for the
        aggregate query and idx_flow_protocol_covering for the GROUP BY.
        Results are cached for 5 s.
        """
        cache_key = f"flow_stats:{hours}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        with self._read_pool.connection() as rdb:
            try:
                row = rdb.execute(
                    """SELECT COUNT(*), COUNT(DISTINCT dst_ip),
                       SUM(COALESCE(bytes_tx, 0)), SUM(COALESCE(bytes_rx, 0)),
                       COUNT(DISTINCT geo_dst_country),
                       SUM(CASE WHEN threat_intel_match = 1 THEN 1 ELSE 0 END),
                       SUM(CASE WHEN is_suspicious = 1 THEN 1 ELSE 0 END)
                    FROM flow_events WHERE timestamp_ns > ?""",
                    (cutoff_ns,),
                ).fetchone()
                proto_rows = rdb.execute(
                    "SELECT protocol, COUNT(*) FROM flow_events WHERE timestamp_ns > ? "
                    "GROUP BY protocol ORDER BY COUNT(*) DESC",
                    (cutoff_ns,),
                ).fetchall()
                result = {
                    "total_flows": row[0] or 0,
                    "unique_destinations": row[1] or 0,
                    "bytes_sent": row[2] or 0,
                    "bytes_received": row[3] or 0,
                    "countries_reached": row[4] or 0,
                    "threat_intel_hits": row[5] or 0,
                    "suspicious_flows": row[6] or 0,
                    "by_protocol": {r[0]: r[1] for r in proto_rows if r[0]},
                }
                self._cache.put(cache_key, result, ttl=30)
                return result
            except sqlite3.Error as e:
                logger.error("Flow stats failed: %s", e)
                return {"total_flows": 0}

    def get_flow_geo_stats(self, hours: int = 24) -> Dict[str, Any]:
        """GeoIP destination aggregation.  Cached 5 s."""
        cache_key = f"flow_geo:{hours}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        with self._read_pool.connection() as rdb:
            try:
                countries = rdb.execute(
                    "SELECT geo_dst_country, COUNT(*) as cnt, SUM(COALESCE(bytes_tx,0)+COALESCE(bytes_rx,0)) as total_bytes "
                    "FROM flow_events INDEXED BY idx_flow_geo_country_covering "
                    "WHERE timestamp_ns > ? AND geo_dst_country IS NOT NULL AND geo_dst_country != '' "
                    "GROUP BY geo_dst_country ORDER BY cnt DESC LIMIT 20",
                    (cutoff_ns,),
                ).fetchall()
                cities = rdb.execute(
                    "SELECT geo_dst_country, geo_dst_city, COUNT(*) as cnt "
                    "FROM flow_events INDEXED BY idx_flow_geo_city_covering "
                    "WHERE timestamp_ns > ? AND geo_dst_city IS NOT NULL AND geo_dst_city != '' "
                    "GROUP BY geo_dst_country, geo_dst_city ORDER BY cnt DESC LIMIT 20",
                    (cutoff_ns,),
                ).fetchall()
                result = {
                    "countries": [
                        {"country": r[0], "count": r[1], "bytes": r[2] or 0}
                        for r in countries
                    ],
                    "cities": [
                        {"country": r[0], "city": r[1], "count": r[2]} for r in cities
                    ],
                }
                self._cache.put(cache_key, result)
                return result
            except sqlite3.Error as e:
                logger.error("Flow geo stats failed: %s", e)
                return {"countries": [], "cities": []}

    def get_flow_asn_breakdown(self, hours: int = 24) -> List[Dict]:
        """Top destination ASN organizations.  Cached 5 s."""
        cache_key = f"flow_asn:{hours}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        with self._read_pool.connection() as rdb:
            try:
                rows = rdb.execute(
                    "SELECT asn_dst_org, asn_dst_network_type, COUNT(*) as cnt, "
                    "SUM(COALESCE(bytes_tx,0)+COALESCE(bytes_rx,0)) as total_bytes "
                    "FROM flow_events INDEXED BY idx_flow_asn_covering "
                    "WHERE timestamp_ns > ? AND asn_dst_org IS NOT NULL AND asn_dst_org != '' "
                    "GROUP BY asn_dst_org ORDER BY cnt DESC LIMIT 20",
                    (cutoff_ns,),
                ).fetchall()
                result = [
                    {
                        "org": r[0],
                        "network_type": r[1] or "unknown",
                        "count": r[2],
                        "bytes": r[3] or 0,
                    }
                    for r in rows
                ]
                self._cache.put(cache_key, result)
                return result
            except sqlite3.Error as e:
                logger.error("Flow ASN breakdown failed: %s", e)
                return []

    def get_flow_geo_points(self, hours: int = 24, limit: int = 500) -> List[Dict]:
        """Lat/lon points for world map visualization.  Cached 5 s."""
        cache_key = f"flow_geopts:{hours}:{limit}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        with self._read_pool.connection() as rdb:
            try:
                rows = rdb.execute(
                    "SELECT geo_dst_latitude, geo_dst_longitude, geo_dst_country, geo_dst_city, "
                    "COUNT(*) as cnt, SUM(COALESCE(bytes_tx,0)+COALESCE(bytes_rx,0)) as total_bytes, "
                    "asn_dst_org, MAX(CASE WHEN threat_intel_match=1 THEN 1 ELSE 0 END) as threat "
                    "FROM flow_events INDEXED BY idx_flow_geopoints_covering "
                    "WHERE timestamp_ns > ? "
                    "AND geo_dst_latitude IS NOT NULL AND geo_dst_latitude != 0 "
                    "GROUP BY geo_dst_latitude, geo_dst_longitude "
                    "ORDER BY cnt DESC LIMIT ?",
                    (cutoff_ns, limit),
                ).fetchall()
                result = [
                    {
                        "lat": r[0],
                        "lon": r[1],
                        "country": r[2],
                        "city": r[3],
                        "count": r[4],
                        "bytes": r[5] or 0,
                        "asn_org": r[6],
                        "threat": bool(r[7]),
                    }
                    for r in rows
                ]
                self._cache.put(cache_key, result)
                return result
            except sqlite3.Error as e:
                logger.error("Flow geo points failed: %s", e)
                return []

    def get_flow_top_destinations(self, hours: int = 24, limit: int = 20) -> List[Dict]:
        """Top destination IPs with enrichment.  Cached 5 s."""
        cache_key = f"flow_topdst:{hours}:{limit}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        with self._read_pool.connection() as rdb:
            try:
                rows = rdb.execute(
                    "SELECT dst_ip, dst_port, protocol, geo_dst_country, geo_dst_city, "
                    "asn_dst_org, asn_dst_network_type, "
                    "COUNT(*) as cnt, SUM(COALESCE(bytes_tx,0)) as tx, SUM(COALESCE(bytes_rx,0)) as rx, "
                    "MAX(CASE WHEN threat_intel_match=1 THEN 1 ELSE 0 END) as threat "
                    "FROM flow_events INDEXED BY idx_flow_topdst_covering "
                    "WHERE timestamp_ns > ? "
                    "GROUP BY dst_ip ORDER BY cnt DESC LIMIT ?",
                    (cutoff_ns, limit),
                ).fetchall()
                result = [
                    {
                        "dst_ip": r[0],
                        "dst_port": r[1],
                        "protocol": r[2],
                        "country": r[3],
                        "city": r[4],
                        "asn_org": r[5],
                        "network_type": r[6] or "unknown",
                        "flows": r[7],
                        "bytes_tx": r[8] or 0,
                        "bytes_rx": r[9] or 0,
                        "threat": bool(r[10]),
                    }
                    for r in rows
                ]
                self._cache.put(cache_key, result)
                return result
            except sqlite3.Error as e:
                logger.error("Flow top destinations failed: %s", e)
                return []

    def get_flow_by_process(self, hours: int = 24, limit: int = 20) -> List[Dict]:
        """Network usage grouped by process.  Cached 5 s."""
        cache_key = f"flow_byproc:{hours}:{limit}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        with self._read_pool.connection() as rdb:
            try:
                rows = rdb.execute(
                    "SELECT process_name, COUNT(*) as cnt, "
                    "SUM(COALESCE(bytes_tx,0)) as tx, SUM(COALESCE(bytes_rx,0)) as rx, "
                    "COUNT(DISTINCT dst_ip) as unique_dsts "
                    "FROM flow_events INDEXED BY idx_flow_byprocess_covering "
                    "WHERE timestamp_ns > ? AND process_name IS NOT NULL AND process_name != '' "
                    "GROUP BY process_name ORDER BY cnt DESC LIMIT ?",
                    (cutoff_ns, limit),
                ).fetchall()
                result = [
                    {
                        "process": r[0],
                        "flows": r[1],
                        "bytes_tx": r[2] or 0,
                        "bytes_rx": r[3] or 0,
                        "unique_destinations": r[4],
                    }
                    for r in rows
                ]
                self._cache.put(cache_key, result)
                return result
            except sqlite3.Error as e:
                logger.error("Flow by process failed: %s", e)
                return []

    # ── File Integrity ──

    def get_fim_stats(self, hours: int = 24) -> Dict[str, Any]:
        """File integrity monitoring summary.

        Optimized: uses covering index idx_fim_stats_covering
        (timestamp_ns, change_type, risk_score) for index-only scan on
        the main aggregate, and idx_fim_extension_covering for the
        GROUP BY.  Results cached for 5 s.
        """
        cache_key = f"fim_stats:{hours}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        with self._read_pool.connection() as rdb:
            try:
                row = rdb.execute(
                    """SELECT COUNT(*),
                       SUM(CASE WHEN change_type='created' THEN 1 ELSE 0 END),
                       SUM(CASE WHEN change_type='modified' THEN 1 ELSE 0 END),
                       SUM(CASE WHEN change_type='deleted' THEN 1 ELSE 0 END),
                       SUM(CASE WHEN risk_score > 0.3 THEN 1 ELSE 0 END)
                    FROM fim_events WHERE timestamp_ns > ?""",
                    (cutoff_ns,),
                ).fetchone()
                ext_rows = rdb.execute(
                    "SELECT file_extension, COUNT(*) FROM fim_events WHERE timestamp_ns > ? "
                    "AND file_extension IS NOT NULL GROUP BY file_extension ORDER BY COUNT(*) DESC LIMIT 15",
                    (cutoff_ns,),
                ).fetchall()
                result = {
                    "total_changes": row[0] or 0,
                    "created": row[1] or 0,
                    "modified": row[2] or 0,
                    "deleted": row[3] or 0,
                    "high_risk": row[4] or 0,
                    "by_extension": {r[0]: r[1] for r in ext_rows if r[0]},
                }
                self._cache.put(cache_key, result, ttl=30)
                return result
            except sqlite3.Error as e:
                logger.error("FIM stats failed: %s", e)
                return {"total_changes": 0}

    def get_fim_critical_changes(
        self, hours: int = 24, min_risk: float = 0.3, limit: int = 100
    ) -> List[Dict]:
        """High-risk file changes."""
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        with self._lock:
            try:
                rows = self.db.execute(
                    """SELECT path, change_type, old_hash, new_hash, risk_score,
                       patterns_matched, file_extension, timestamp_dt, event_type
                    FROM fim_events WHERE timestamp_ns > ? AND risk_score >= ?
                    ORDER BY risk_score DESC LIMIT ?""",
                    (cutoff_ns, min_risk, limit),
                ).fetchall()
                return [
                    {
                        "path": r[0],
                        "change_type": r[1],
                        "old_hash": r[2],
                        "new_hash": r[3],
                        "risk_score": r[4] or 0,
                        "patterns_matched": r[5],
                        "extension": r[6],
                        "timestamp": r[7],
                        "event_type": r[8],
                    }
                    for r in rows
                ]
            except sqlite3.Error as e:
                logger.error("FIM critical changes failed: %s", e)
                return []

    def get_fim_directory_summary(self, hours: int = 24, limit: int = 50) -> List[Dict]:
        """File changes grouped by parent directory."""
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        with self._lock:
            try:
                # Group by directory (everything up to last /)
                rows = self.db.execute(
                    """SELECT
                       CASE WHEN INSTR(path, '/') > 0
                            THEN SUBSTR(path, 1, LENGTH(path) - LENGTH(REPLACE(RTRIM(path, REPLACE(path, '/', '')), '', '')))
                            ELSE '/' END as dir,
                       COUNT(*) as cnt, ROUND(AVG(COALESCE(risk_score, 0)), 3) as avg_risk,
                       SUM(CASE WHEN risk_score > 0.3 THEN 1 ELSE 0 END) as risky
                    FROM fim_events WHERE timestamp_ns > ?
                    GROUP BY dir ORDER BY cnt DESC LIMIT ?""",
                    (cutoff_ns, limit),
                ).fetchall()
                return [
                    {
                        "directory": r[0],
                        "count": r[1],
                        "avg_risk": r[2],
                        "high_risk_count": r[3] or 0,
                    }
                    for r in rows
                ]
            except sqlite3.Error as e:
                logger.error("FIM directory summary failed: %s", e)
                return []

    def get_fim_timeline(self, hours: int = 24) -> List[Dict]:
        """Hourly FIM event counts by change type."""
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        with self._lock:
            try:
                rows = self.db.execute(
                    """SELECT SUBSTR(timestamp_dt, 1, 13) as hour,
                       SUM(CASE WHEN change_type='created' THEN 1 ELSE 0 END) as created,
                       SUM(CASE WHEN change_type='modified' THEN 1 ELSE 0 END) as modified,
                       SUM(CASE WHEN change_type='deleted' THEN 1 ELSE 0 END) as deleted,
                       COUNT(*) as total
                    FROM fim_events WHERE timestamp_ns > ?
                    GROUP BY hour ORDER BY hour""",
                    (cutoff_ns,),
                ).fetchall()
                return [
                    {
                        "hour": r[0],
                        "created": r[1],
                        "modified": r[2],
                        "deleted": r[3],
                        "total": r[4],
                    }
                    for r in rows
                ]
            except sqlite3.Error as e:
                logger.error("FIM timeline failed: %s", e)
                return []

    # ── Persistence Landscape ──

    def get_persistence_stats(self, hours: int = 24) -> Dict[str, Any]:
        """Persistence mechanism summary.

        Optimized: single pass over the covering index
        idx_posture_persistence (timestamp_ns, risk_score) for the
        totals, plus dedicated covering indexes for the two GROUP BY
        queries.  Results cached for 5 s.
        """
        cache_key = f"persistence_stats:{hours}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        with self._read_pool.connection() as rdb:
            try:
                row = rdb.execute(
                    "SELECT COUNT(*), SUM(CASE WHEN risk_score > 0.3 THEN 1 ELSE 0 END) "
                    "FROM persistence_events WHERE timestamp_ns > ?",
                    (cutoff_ns,),
                ).fetchone()
                mech_rows = rdb.execute(
                    "SELECT mechanism, COUNT(*) FROM persistence_events "
                    "INDEXED BY idx_persistence_mechanism_covering "
                    "WHERE timestamp_ns > ? "
                    "GROUP BY mechanism ORDER BY COUNT(*) DESC",
                    (cutoff_ns,),
                ).fetchall()
                ct_rows = rdb.execute(
                    "SELECT change_type, COUNT(*) FROM persistence_events "
                    "INDEXED BY idx_persistence_changetype_covering "
                    "WHERE timestamp_ns > ? "
                    "GROUP BY change_type ORDER BY COUNT(*) DESC",
                    (cutoff_ns,),
                ).fetchall()
                result = {
                    "total_entries": row[0] or 0,
                    "high_risk": row[1] or 0,
                    "by_mechanism": {r[0]: r[1] for r in mech_rows if r[0]},
                    "by_change_type": {r[0]: r[1] for r in ct_rows if r[0]},
                }
                self._cache.put(cache_key, result, ttl=30)
                return result
            except sqlite3.Error as e:
                logger.error("Persistence stats failed: %s", e)
                return {"total_entries": 0}

    def get_persistence_inventory(
        self, mechanism: Optional[str] = None, limit: int = 200
    ) -> List[Dict]:
        """Persistence entries, optionally filtered by mechanism."""
        with self._lock:
            try:
                if mechanism:
                    rows = self.db.execute(
                        """SELECT mechanism, entry_id, path, command, user, change_type,
                           risk_score, timestamp_dt, event_type
                        FROM persistence_events WHERE mechanism = ?
                        ORDER BY timestamp_ns DESC LIMIT ?""",
                        (mechanism, limit),
                    ).fetchall()
                else:
                    rows = self.db.execute(
                        """SELECT mechanism, entry_id, path, command, user, change_type,
                           risk_score, timestamp_dt, event_type
                        FROM persistence_events
                        ORDER BY timestamp_ns DESC LIMIT ?""",
                        (limit,),
                    ).fetchall()
                return [
                    {
                        "mechanism": r[0],
                        "entry_id": r[1],
                        "path": r[2],
                        "command": r[3],
                        "user": r[4],
                        "change_type": r[5],
                        "risk_score": r[6] or 0,
                        "timestamp": r[7],
                        "event_type": r[8],
                    }
                    for r in rows
                ]
            except sqlite3.Error as e:
                logger.error("Persistence inventory failed: %s", e)
                return []

    def get_persistence_changes(self, hours: int = 24) -> List[Dict]:
        """Recent persistence modifications."""
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        with self._lock:
            try:
                rows = self.db.execute(
                    """SELECT SUBSTR(timestamp_dt, 1, 13) as hour, mechanism,
                       COUNT(*) as cnt
                    FROM persistence_events WHERE timestamp_ns > ?
                    GROUP BY hour, mechanism ORDER BY hour""",
                    (cutoff_ns,),
                ).fetchall()
                return [{"hour": r[0], "mechanism": r[1], "count": r[2]} for r in rows]
            except sqlite3.Error as e:
                logger.error("Persistence changes failed: %s", e)
                return []

    # ── Auth / Audit ──

    def get_audit_stats(self, hours: int = 24) -> Dict[str, Any]:
        """Kernel audit / auth event summary."""
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        with self._lock:
            try:
                row = self.db.execute(
                    "SELECT COUNT(*), SUM(CASE WHEN risk_score > 0.5 THEN 1 ELSE 0 END) "
                    "FROM audit_events WHERE timestamp_ns > ?",
                    (cutoff_ns,),
                ).fetchone()
                type_rows = self.db.execute(
                    "SELECT event_type, COUNT(*) FROM audit_events WHERE timestamp_ns > ? "
                    "GROUP BY event_type ORDER BY COUNT(*) DESC",
                    (cutoff_ns,),
                ).fetchall()
                return {
                    "total_events": row[0] or 0,
                    "high_risk": row[1] or 0,
                    "by_event_type": {r[0]: r[1] for r in type_rows if r[0]},
                }
            except sqlite3.Error as e:
                logger.error("Audit stats failed: %s", e)
                return {"total_events": 0}

    def get_audit_high_risk(
        self, hours: int = 24, min_risk: float = 0.5, limit: int = 100
    ) -> List[Dict]:
        """High-risk audit events."""
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        with self._lock:
            try:
                rows = self.db.execute(
                    """SELECT event_type, exe, comm, cmdline, pid, uid, risk_score,
                       reason, mitre_techniques, timestamp_dt
                    FROM audit_events WHERE timestamp_ns > ? AND risk_score >= ?
                    ORDER BY risk_score DESC LIMIT ?""",
                    (cutoff_ns, min_risk, limit),
                ).fetchall()
                return [
                    {
                        "event_type": r[0],
                        "exe": r[1],
                        "comm": r[2],
                        "cmdline": r[3],
                        "pid": r[4],
                        "uid": r[5],
                        "risk_score": r[6] or 0,
                        "reason": r[7],
                        "mitre_techniques": r[8],
                        "timestamp": r[9],
                    }
                    for r in rows
                ]
            except sqlite3.Error as e:
                logger.error("Audit high risk failed: %s", e)
                return []

    # ── Observation Domains (P3) ──

    def get_observation_domain_stats(self, hours: int = 24) -> Dict[str, Any]:
        """Per-domain counts for observation_events.

        Optimized: uses covering index idx_observation_domain_ts_covering
        (timestamp_ns, domain) for an index-only GROUP BY scan.
        Results cached for 5 s.
        """
        cache_key = f"observation_domain_stats:{hours}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        with self._read_pool.connection() as rdb:
            try:
                rows = rdb.execute(
                    "SELECT domain, COUNT(*) FROM observation_events "
                    "INDEXED BY idx_observation_domain_ts_covering "
                    "WHERE timestamp_ns > ? "
                    "GROUP BY domain ORDER BY COUNT(*) DESC",
                    (cutoff_ns,),
                ).fetchall()
                total = sum(r[1] for r in rows)
                result = {
                    "total": total,
                    "by_domain": {r[0]: r[1] for r in rows if r[0]},
                }
                self._cache.put(cache_key, result, ttl=30)  # summary view — 30s TTL
                return result
            except sqlite3.Error as e:
                logger.error("Observation domain stats failed: %s", e)
                return {"total": 0, "by_domain": {}}

    def get_observations_by_domain(
        self, domain: str, hours: int = 24, limit: int = 100, offset: int = 0
    ) -> Dict[str, Any]:
        """Paginated observations for a specific domain."""
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        with self._lock:
            try:
                total = self.db.execute(
                    "SELECT COUNT(*) FROM observation_events WHERE domain = ? AND timestamp_ns > ?",
                    (domain, cutoff_ns),
                ).fetchone()[0]
                rows = self.db.execute(
                    """SELECT timestamp_dt, domain, event_type, attributes, risk_score,
                       collection_agent
                    FROM observation_events WHERE domain = ? AND timestamp_ns > ?
                    ORDER BY timestamp_ns DESC LIMIT ? OFFSET ?""",
                    (domain, cutoff_ns, limit, offset),
                ).fetchall()
                results = []
                for r in rows:
                    attrs = {}
                    try:
                        attrs = json.loads(r[3]) if r[3] else {}
                    except (json.JSONDecodeError, TypeError):
                        attrs = {"raw": r[3]}
                    results.append(
                        {
                            "timestamp": r[0],
                            "domain": r[1],
                            "event_type": r[2],
                            "attributes": attrs,
                            "risk_score": r[4] or 0,
                            "collection_agent": r[5],
                        }
                    )
                return {
                    "results": results,
                    "total_count": total,
                    "offset": offset,
                    "has_more": (offset + limit) < total,
                }
            except sqlite3.Error as e:
                logger.error("Observations by domain failed: %s", e)
                return {"results": [], "total_count": 0, "offset": 0, "has_more": False}

    def search_observations(
        self,
        query: str = "",
        domain: Optional[str] = None,
        hours: int = 24,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """Search across observation_events attributes."""
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        where = ["timestamp_ns > ?"]
        params: list = [cutoff_ns]
        if domain:
            where.append("domain = ?")
            params.append(domain)
        if query:
            where.append("attributes LIKE ?")
            params.append(f"%{query}%")
        where_sql = " AND ".join(where)
        with self._lock:
            try:
                total = self.db.execute(
                    f"SELECT COUNT(*) FROM observation_events WHERE {where_sql}", params
                ).fetchone()[0]
                rows = self.db.execute(
                    f"SELECT timestamp_dt, domain, event_type, attributes, risk_score, collection_agent "
                    f"FROM observation_events WHERE {where_sql} ORDER BY timestamp_ns DESC LIMIT ?",
                    params + [limit],
                ).fetchall()
                results = []
                for r in rows:
                    attrs = {}
                    try:
                        attrs = json.loads(r[3]) if r[3] else {}
                    except (json.JSONDecodeError, TypeError):
                        attrs = {"raw": r[3]}
                    results.append(
                        {
                            "timestamp": r[0],
                            "domain": r[1],
                            "event_type": r[2],
                            "attributes": attrs,
                            "risk_score": r[4] or 0,
                            "collection_agent": r[5],
                        }
                    )
                return {
                    "results": results,
                    "total_count": total,
                    "has_more": total > limit,
                }
            except sqlite3.Error as e:
                logger.error("Observation search failed: %s", e)
                return {"results": [], "total_count": 0, "has_more": False}

    def close(self) -> None:
        """Close database connection."""
        self.db.close()
