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

import logging
import sqlite3
from pathlib import Path
from typing import Any, Optional

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

    requires_investigation BOOLEAN DEFAULT 0
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

        # Create schema
        self.db.executescript(SCHEMA)
        self.db.commit()

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

    def close(self) -> None:
        """Close database connection"""
        self.db.close()
