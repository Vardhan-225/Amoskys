"""Telemetry Bridge — connects the dashboard to telemetry data.

Two modes:
  1. Local mode (agent running on this machine): reads data/telemetry.db directly
  2. Fleet mode (presentation server): syncs data from ops server into a local
     cache DB, then TelemetryStore reads from that cache

The bridge auto-detects which mode to use:
  - If data/telemetry.db exists → local mode (agent is running here)
  - If AMOSKYS_OPS_SERVER is set → fleet mode (sync from ops server)
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from amoskys.storage.telemetry_store import TelemetryStore

logger = logging.getLogger(__name__)

_telemetry_store: Optional["TelemetryStore"] = None
_sync_started = False

# Resolve paths
_DATA_DIR = Path(__file__).resolve().parents[3] / "data"
_DB_PATH = _DATA_DIR / "telemetry.db"
_CACHE_DB_PATH = _DATA_DIR / "fleet_cache.db"
_OPS_SERVER = os.getenv("AMOSKYS_OPS_SERVER", "").rstrip("/")


def get_telemetry_store() -> Optional["TelemetryStore"]:
    """Get or create a TelemetryStore instance.

    Auto-detects local vs fleet mode:
      - Local: agent telemetry.db exists → use directly
      - Fleet: ops server configured → sync from ops into cache DB
    """
    global _telemetry_store, _sync_started

    if _telemetry_store is not None:
        return _telemetry_store

    # Mode 1: Local telemetry.db (agent running on this machine)
    if _DB_PATH.exists():
        try:
            from amoskys.storage.telemetry_store import TelemetryStore

            _telemetry_store = TelemetryStore(db_path=str(_DB_PATH))
            logger.info("Telemetry bridge: LOCAL mode (%s)", _DB_PATH)
            return _telemetry_store
        except Exception:
            logger.exception("Failed to initialize local TelemetryStore")

    # Mode 2: Fleet mode — sync from ops server
    if _OPS_SERVER and not _sync_started:
        _sync_started = True
        _start_fleet_sync()

    # Try the cache DB (populated by fleet sync)
    if _CACHE_DB_PATH.exists():
        try:
            from amoskys.storage.telemetry_store import TelemetryStore

            _telemetry_store = TelemetryStore(db_path=str(_CACHE_DB_PATH))
            logger.info("Telemetry bridge: FLEET mode (cache=%s)", _CACHE_DB_PATH)
            return _telemetry_store
        except Exception:
            logger.exception("Failed to initialize fleet cache TelemetryStore")

    logger.debug("Telemetry bridge: no data source available")
    return None


def _start_fleet_sync():
    """Start a background thread that syncs telemetry from the ops server."""
    def sync_loop():
        logger.info("Fleet sync started: %s → %s", _OPS_SERVER, _CACHE_DB_PATH)
        while True:
            try:
                _sync_from_ops()
            except Exception as e:
                logger.warning("Fleet sync error: %s", e)
            time.sleep(30)  # Sync every 30 seconds

    t = threading.Thread(target=sync_loop, name="fleet-sync", daemon=True)
    t.start()


def _sync_from_ops():
    """Fetch events from ops server and insert into local cache DB."""
    import requests

    _DATA_DIR.mkdir(parents=True, exist_ok=True)

    # Fetch all events from ops server
    try:
        resp = requests.get(
            f"{_OPS_SERVER}/api/v1/events",
            params={"limit": 500},
            timeout=10,
            verify=False,
        )
        if resp.status_code != 200:
            return
        data = resp.json()
        events = data.get("events", [])
    except Exception as e:
        logger.debug("Fleet sync fetch failed: %s", e)
        return

    if not events:
        return

    # Insert into cache DB using TelemetryStore schema
    db = sqlite3.connect(str(_CACHE_DB_PATH), timeout=5)
    db.execute("PRAGMA journal_mode=WAL")

    # Create security_events table if not exists (matches TelemetryStore schema)
    db.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp_ns INTEGER NOT NULL,
            timestamp_dt TEXT NOT NULL,
            device_id TEXT NOT NULL,
            event_category TEXT,
            event_action TEXT,
            event_outcome TEXT,
            risk_score REAL,
            confidence REAL,
            mitre_techniques TEXT,
            geometric_score REAL,
            temporal_score REAL,
            behavioral_score REAL,
            final_classification TEXT,
            description TEXT,
            indicators TEXT,
            requires_investigation BOOLEAN DEFAULT 0,
            collection_agent TEXT,
            agent_version TEXT,
            enrichment_status TEXT DEFAULT 'raw',
            threat_intel_match BOOLEAN DEFAULT 0,
            geo_src_country TEXT,
            asn_src_org TEXT,
            event_timestamp_ns INTEGER,
            event_id TEXT,
            remote_ip TEXT,
            remote_port TEXT,
            process_name TEXT,
            pid TEXT,
            exe TEXT,
            cmdline TEXT,
            username TEXT,
            protocol TEXT,
            domain TEXT,
            path TEXT,
            sha256 TEXT,
            probe_name TEXT,
            detection_source TEXT,
            geo_src_city TEXT,
            geo_src_latitude TEXT,
            geo_src_longitude TEXT,
            asn_src_number TEXT,
            asn_src_network_type TEXT
        )
    """)
    db.execute("CREATE INDEX IF NOT EXISTS idx_se_ts ON security_events(timestamp_ns)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_se_device ON security_events(device_id)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_se_risk ON security_events(risk_score)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_se_category ON security_events(event_category)")

    # Also create rollups table that some dashboard queries need
    db.execute("""
        CREATE TABLE IF NOT EXISTS dashboard_rollups (
            key TEXT PRIMARY KEY,
            value_json TEXT NOT NULL,
            updated_at REAL NOT NULL
        )
    """)

    # Insert events (skip duplicates by checking source_id)
    inserted = 0
    for e in events:
        ts_ns = e.get("timestamp_ns") or int(time.time() * 1e9)
        ts_dt = e.get("timestamp_dt") or ""
        try:
            db.execute("""
                INSERT OR IGNORE INTO security_events
                (timestamp_ns, timestamp_dt, device_id, event_category, event_action,
                 event_outcome, risk_score, confidence, mitre_techniques,
                 collection_agent, enrichment_status, threat_intel_match,
                 geo_src_country, asn_src_org, event_timestamp_ns, event_id,
                 remote_ip, process_name, pid, username, domain, path, sha256,
                 probe_name, detection_source, description)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                ts_ns, ts_dt, e.get("device_id", ""),
                e.get("event_category"), e.get("event_action"), e.get("event_outcome"),
                e.get("risk_score"), e.get("confidence"), e.get("mitre_techniques"),
                e.get("collection_agent"), e.get("enrichment_status"),
                e.get("threat_intel_match"), e.get("geo_src_country"),
                e.get("asn_src_org"), e.get("event_timestamp_ns"), e.get("event_id"),
                e.get("remote_ip"), e.get("process_name"), e.get("pid"),
                e.get("username"), e.get("domain"), e.get("path"), e.get("sha256"),
                e.get("probe_name"), e.get("detection_source"), e.get("description"),
            ))
            inserted += 1
        except Exception:
            pass

    db.commit()
    db.close()

    if inserted > 0:
        # Reset the TelemetryStore singleton so it picks up new data
        global _telemetry_store
        _telemetry_store = None
        logger.info("Fleet sync: %d events synced from ops server", inserted)
