"""Schema definition and migration mixin for TelemetryStore."""

from __future__ import annotations

import logging
import sqlite3

logger = logging.getLogger("TelemetryStore")

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

-- Dashboard performance: composite indexes for filtered + sorted queries
-- These cover the hot paths: /live/threats, /agents/deep-overview, /agents/activity
CREATE INDEX IF NOT EXISTS idx_security_ts_risk ON security_events(timestamp_ns DESC, risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_security_ts_agent ON security_events(timestamp_ns DESC, collection_agent);
CREATE INDEX IF NOT EXISTS idx_security_ts_category ON security_events(timestamp_ns DESC, event_category);
CREATE INDEX IF NOT EXISTS idx_process_ts_agent ON process_events(timestamp_ns DESC, collection_agent);
CREATE INDEX IF NOT EXISTS idx_process_ts_anomaly ON process_events(timestamp_ns DESC, anomaly_score DESC);
CREATE INDEX IF NOT EXISTS idx_flow_ts_threat ON flow_events(timestamp_ns DESC, threat_score DESC);
CREATE INDEX IF NOT EXISTS idx_flow_ts_src ON flow_events(timestamp_ns DESC, src_ip);
CREATE INDEX IF NOT EXISTS idx_flow_ts_dst ON flow_events(timestamp_ns DESC, dst_ip);
CREATE INDEX IF NOT EXISTS idx_dns_ts_risk ON dns_events(timestamp_ns DESC, risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_dns_ts_agent ON dns_events(timestamp_ns DESC, collection_agent);
CREATE INDEX IF NOT EXISTS idx_persistence_ts_risk ON persistence_events(timestamp_ns DESC, risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_persistence_ts_agent ON persistence_events(timestamp_ns DESC, collection_agent);
CREATE INDEX IF NOT EXISTS idx_peripheral_ts_agent ON peripheral_events(timestamp_ns DESC, collection_agent);
CREATE INDEX IF NOT EXISTS idx_audit_ts_risk ON audit_events(timestamp_ns DESC, risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_fim_ts_risk ON fim_events(timestamp_ns DESC, risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_fim_ts_agent ON fim_events(timestamp_ns DESC, collection_agent);
CREATE INDEX IF NOT EXISTS idx_observation_ts_domain ON observation_events(timestamp_ns DESC, domain);

-- ══════════════════════════════════════════════════════════════════════
-- Unified Snapshot Dedup (Layer 1)
--
-- Single baseline table for ALL snapshot-producing agents.  Each row
-- tracks the last-known content hash for a (table_name, dedup_key)
-- pair.  When an insert arrives with the same hash, it is suppressed.
--
-- Dedup keys per table:
--   fim_events          → device_id|path
--   persistence_events  → device_id|mechanism|entry_id
--   process_events      → device_id|pid|exe
--   peripheral_events   → device_id|peripheral_device_id
--   observation_events  → device_id|domain|fingerprint
-- ══════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS _snapshot_baseline (
    table_name   TEXT NOT NULL,   -- e.g. 'fim_events', 'process_events'
    dedup_key    TEXT NOT NULL,   -- pipe-delimited composite key
    content_hash TEXT,            -- hash of the mutable content fields
    updated_ns   INTEGER NOT NULL,
    PRIMARY KEY (table_name, dedup_key)
) WITHOUT ROWID;

-- Keep legacy tables so migration 012 doesn't break on existing DBs.
-- New code only reads/writes _snapshot_baseline.
CREATE TABLE IF NOT EXISTS _fim_baseline (
    device_id TEXT NOT NULL, path TEXT NOT NULL, content_hash TEXT,
    mtime TEXT, size INTEGER, updated_ns INTEGER NOT NULL,
    PRIMARY KEY (device_id, path)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS _persistence_baseline (
    device_id TEXT NOT NULL, mechanism TEXT NOT NULL, entry_id TEXT NOT NULL,
    content_hash TEXT, command TEXT, updated_ns INTEGER NOT NULL,
    PRIMARY KEY (device_id, mechanism, entry_id)
) WITHOUT ROWID;

-- ══════════════════════════════════════════════════════════════════════
-- Telemetry Receipt Ledger (completeness verification)
--
-- Tracks every event through 4 pipeline checkpoints:
--   1. emitted_ns   — agent created the event (set by queue_adapter)
--   2. queued_ns    — event entered the local queue
--   3. wal_ns       — WAL processor accepted the envelope
--   4. persisted_ns — TelemetryStore committed to domain table
--
-- IGRIS reconciliation: compare counts at each boundary per source_agent.
-- Any delta means events were lost, misrouted, or quarantined.
-- ══════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS telemetry_receipts (
    event_id      TEXT NOT NULL,
    source_agent  TEXT NOT NULL,
    device_id     TEXT,
    emitted_ns    INTEGER,
    queued_ns     INTEGER,
    wal_ns        INTEGER,
    persisted_ns  INTEGER,
    dest_table    TEXT,           -- which domain table received the event
    quality_state TEXT,           -- valid/degraded/invalid/quarantined
    PRIMARY KEY (event_id, source_agent)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_receipts_agent
    ON telemetry_receipts(source_agent, emitted_ns DESC);
CREATE INDEX IF NOT EXISTS idx_receipts_gaps
    ON telemetry_receipts(source_agent)
    WHERE persisted_ns IS NULL;  -- partial index for incomplete receipts

-- ══════════════════════════════════════════════════════════════════════
-- Process Genealogy (durable spawn chain)
--
-- Records every observed process with full ancestry.  Fed by:
--   1. MacOSProcessAgent — each collection cycle snapshots live processes
--   2. RealtimeSensor    — kqueue NOTE_EXIT events capture exits
--
-- Unlike process_events (which is a time-series of observations),
-- genealogy is a durable record that survives process exit.  Each PID
-- gets one row updated over time; the spawn chain is built by joining
-- on ppid.
-- ══════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS process_genealogy (
    device_id     TEXT NOT NULL,
    pid           INTEGER NOT NULL,
    ppid          INTEGER,
    name          TEXT,
    exe           TEXT,
    cmdline       TEXT,           -- JSON array
    username      TEXT,
    parent_name   TEXT,
    create_time   REAL,           -- Unix epoch
    exit_time_ns  INTEGER,        -- kqueue NOTE_EXIT timestamp
    exit_status   INTEGER,
    code_signing  TEXT,           -- signed/unsigned/tampered/unknown
    is_alive      BOOLEAN DEFAULT 1,
    first_seen_ns INTEGER NOT NULL,
    last_seen_ns  INTEGER NOT NULL,
    process_guid  TEXT,           -- stable GUID for cross-agent correlation
    PRIMARY KEY (device_id, pid, first_seen_ns)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_genealogy_alive
    ON process_genealogy(device_id, is_alive)
    WHERE is_alive = 1;
CREATE INDEX IF NOT EXISTS idx_genealogy_ppid
    ON process_genealogy(device_id, ppid, first_seen_ns DESC);
CREATE INDEX IF NOT EXISTS idx_genealogy_guid
    ON process_genealogy(process_guid);

-- Dashboard rollup table (Layer 2: pre-computed aggregations)
CREATE TABLE IF NOT EXISTS dashboard_rollups (
    rollup_type TEXT NOT NULL,   -- 'events_by_domain', 'threats_by_severity', etc.
    bucket_key  TEXT NOT NULL,   -- 'fim', 'CRITICAL', 'T1070', agent_id, etc.
    bucket_hour TEXT NOT NULL,   -- '2026-03-13T02' (hourly bucket)
    value       INTEGER NOT NULL DEFAULT 0,
    updated_ns  INTEGER NOT NULL,
    PRIMARY KEY (rollup_type, bucket_key, bucket_hour)
) WITHOUT ROWID;
"""


_HOUR_FMT = "%Y-%m-%dT%H"


class SchemaMixin:
    """Schema migration methods for TelemetryStore."""

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

            # Typed feature columns extracted from raw_attributes_json
            # for ML training — avoids JSON parsing at query time
            self._ensure_column("security_events", "exe", "TEXT")
            self._ensure_column("security_events", "cmdline", "TEXT")
            self._ensure_column("security_events", "parent_name", "TEXT")
            self._ensure_column("security_events", "ppid", "INTEGER")
            self._ensure_column("security_events", "process_name", "TEXT")
            self._ensure_column("security_events", "remote_ip", "TEXT")
            self._ensure_column("security_events", "remote_port", "INTEGER")
            self._ensure_column("security_events", "bytes_out", "INTEGER")
            self._ensure_column("security_events", "bytes_in", "INTEGER")
            self._ensure_column("security_events", "trust_disposition", "TEXT")
            self._ensure_column("security_events", "domain", "TEXT")
            self._ensure_column("security_events", "path", "TEXT")
            self._ensure_column("security_events", "sha256", "TEXT")
            self._ensure_column("security_events", "kill_chain_stage", "TEXT")
            self._ensure_column("security_events", "stages_hit", "INTEGER")
            self._ensure_column(
                "security_events", "composite_score", "REAL DEFAULT 0.0"
            )
            # Additional enrichment columns
            self._ensure_column("security_events", "geo_src_city", "TEXT")
            self._ensure_column("security_events", "geo_src_latitude", "REAL")
            self._ensure_column("security_events", "geo_src_longitude", "REAL")
            self._ensure_column("security_events", "asn_src_number", "INTEGER")
            self._ensure_column("security_events", "asn_src_network_type", "TEXT")
            self._ensure_column("security_events", "threat_source", "TEXT")
            self._ensure_column("security_events", "threat_severity", "TEXT")
            self._ensure_column("security_events", "label_source", "TEXT")

            # Mandate v1.0: additional mandatory columns
            self._ensure_column("security_events", "pid", "INTEGER")
            self._ensure_column("security_events", "username", "TEXT")
            self._ensure_column("security_events", "probe_name", "TEXT")
            self._ensure_column("security_events", "detection_source", "TEXT")
            self._ensure_column("security_events", "mitre_tactics", "TEXT")
            self._ensure_column("security_events", "local_port", "INTEGER")
            self._ensure_column("security_events", "protocol", "TEXT")
            self._ensure_column("security_events", "connection_state", "TEXT")
            self._ensure_column("security_events", "file_name", "TEXT")
            self._ensure_column("security_events", "file_extension", "TEXT")
            self._ensure_column("security_events", "file_owner", "TEXT")
            self._ensure_column("security_events", "file_mtime", "REAL")
            self._ensure_column("security_events", "file_permissions", "TEXT")
            self._ensure_column("security_events", "agent_version", "TEXT")

            # Mandate v1.0: rejected_events table for WAL gate audit
            self.db.execute(
                """
                CREATE TABLE IF NOT EXISTS rejected_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp_ns INTEGER,
                    device_id TEXT,
                    event_category TEXT,
                    collection_agent TEXT,
                    rejection_code TEXT NOT NULL,
                    raw_attributes_json TEXT,
                    created_at TEXT DEFAULT (datetime('now'))
                )
            """
            )
            self.db.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_rejected_code
                ON rejected_events(rejection_code)
            """
            )

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
