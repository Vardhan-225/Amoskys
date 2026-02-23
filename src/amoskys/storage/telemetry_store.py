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
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("TelemetryStore")

# Database schema for permanent storage
SCHEMA = """
-- Enable WAL mode for better concurrency
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA cache_size=-64000;  -- 64MB cache

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
    agent_version TEXT
);

CREATE INDEX IF NOT EXISTS idx_security_timestamp ON security_events(timestamp_ns DESC);
CREATE INDEX IF NOT EXISTS idx_security_risk ON security_events(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_security_classification ON security_events(final_classification);

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
    agent_version TEXT
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

    -- Collection
    collection_agent TEXT,
    agent_version TEXT
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
    agent_version TEXT
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

    -- Security context
    risk_score REAL DEFAULT 0.0,
    confidence REAL DEFAULT 0.0,
    mitre_techniques TEXT,     -- JSON array
    reason TEXT,
    patterns_matched TEXT,     -- JSON array of matched patterns

    -- Collection
    collection_agent TEXT,
    agent_version TEXT
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
    envelope_bytes BLOB NOT NULL,
    quarantined_at TEXT NOT NULL,
    source TEXT DEFAULT 'wal_processor'
);
CREATE INDEX IF NOT EXISTS idx_dead_letter_ts ON wal_dead_letter(quarantined_at DESC);
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

        logger.info(f"Initialized TelemetryStore at {db_path}")

    def insert_process_event(self, event_data: dict[str, Any]) -> Optional[int]:
        """Insert a process event

        Args:
            event_data: Dictionary with process event fields

        Returns:
            Row ID of inserted event, or None if failed
        """
        cursor = self.db.execute(
            """
            INSERT OR REPLACE INTO process_events (
                timestamp_ns, timestamp_dt, device_id, pid, ppid, exe, cmdline,
                username, cpu_percent, memory_percent, num_threads, num_fds,
                user_type, process_category, is_suspicious, anomaly_score,
                confidence_score, collection_agent, agent_version
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            ),
        )
        self.db.commit()
        return cursor.lastrowid

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
                    requires_investigation, collection_agent, agent_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                ),
            )
            self.db.commit()
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
                    is_suspicious, threat_score
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                ),
            )
            self.db.commit()
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
                    serial_number, manufacturer, connection_status, previous_status,
                    mount_point, files_transferred, bytes_transferred,
                    is_authorized, risk_score, confidence_score, threat_indicators,
                    collection_agent, agent_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                ),
            )
            self.db.commit()
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
                    collection_agent, agent_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                ),
            )
            self.db.commit()
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
                    reason, collection_agent, agent_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    event_data.get("collection_agent"),
                    event_data.get("agent_version"),
                ),
            )
            self.db.commit()
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
                    collection_agent, agent_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                ),
            )
            self.db.commit()
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
                    file_extension, owner_uid, owner_gid,
                    risk_score, confidence, mitre_techniques, reason,
                    patterns_matched, collection_agent, agent_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    event_data.get("risk_score", 0.0),
                    event_data.get("confidence", 0.0),
                    json.dumps(event_data.get("mitre_techniques", [])),
                    event_data.get("reason"),
                    json.dumps(event_data.get("patterns_matched", [])),
                    event_data.get("collection_agent"),
                    event_data.get("agent_version"),
                ),
            )
            self.db.commit()
            return cursor.lastrowid
        except sqlite3.Error as e:
            logger.error("Failed to insert FIM event: %s", e)
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
            self.db.commit()
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
            self.db.commit()
            return cursor.lastrowid
        except sqlite3.Error as e:
            logger.error("Failed to insert metrics timeseries: %s", e)
            return None

    def get_recent_security_events(
        self,
        limit: int = 50,
        hours: int = 24,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Query security_events with time window and optional filter.

        Args:
            limit: Maximum events to return.
            hours: Time window in hours.
            severity: Optional filter on final_classification.

        Returns:
            List of event dicts.
        """
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        params: list = [cutoff_ns]
        query = "SELECT * FROM security_events WHERE timestamp_ns > ?"

        if severity:
            query += " AND final_classification = ?"
            params.append(severity)

        query += " ORDER BY timestamp_ns DESC LIMIT ?"
        params.append(limit)

        try:
            cursor = self.db.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error("Failed to query security events: %s", e)
            return []

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
        """Calculate threat score from real security_events.

        Returns:
            Dict with threat_score (0-100), threat_level, event_count.
        """
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)

        try:
            cursor = self.db.execute(
                """SELECT
                       COUNT(*) as cnt,
                       COALESCE(AVG(risk_score), 0) as avg_risk,
                       COALESCE(MAX(risk_score), 0) as max_risk,
                       COALESCE(SUM(CASE WHEN risk_score > 0.7 THEN 1 ELSE 0 END), 0) as critical_count
                   FROM security_events
                   WHERE timestamp_ns > ?""",
                (cutoff_ns,),
            )
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
            cursor = self.db.execute(
                "SELECT mitre_techniques, event_category, COUNT(*) as cnt "
                "FROM security_events WHERE mitre_techniques IS NOT NULL "
                "GROUP BY mitre_techniques, event_category"
            )
            coverage: Dict[str, Dict] = {}
            for row in cursor.fetchall():
                try:
                    techniques = json.loads(row[0]) if row[0] else []
                except (json.JSONDecodeError, TypeError):
                    continue
                if not isinstance(techniques, list):
                    continue
                for tech in techniques:
                    if tech not in coverage:
                        coverage[tech] = {"count": 0, "categories": {}}
                    coverage[tech]["count"] += row[2]
                    cat = row[1] or "unknown"
                    coverage[tech]["categories"][cat] = (
                        coverage[tech]["categories"].get(cat, 0) + row[2]
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
            self.db.commit()
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
            self.db.commit()
            return True
        except sqlite3.Error as e:
            logger.error("Failed to update incident: %s", e)
            return False

    def get_incidents(
        self, status: Optional[str] = None, limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Get incidents with optional status filter."""
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

    def close(self) -> None:
        """Close database connection."""
        self.db.close()
