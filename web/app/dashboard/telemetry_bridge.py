"""Telemetry Bridge — connects the dashboard to telemetry data.

Two modes:
  1. Local mode (agent running on this machine): reads data/telemetry.db directly
  2. Fleet mode (presentation server): syncs data from ops server into a local
     cache DB, then TelemetryStore reads from that cache in readonly mode

The bridge auto-detects which mode to use:
  - If data/telemetry.db exists → local mode (agent is running here)
  - If AMOSKYS_OPS_SERVER is set → fleet mode (sync from ops server)
"""

from __future__ import annotations

import logging
import os
import sqlite3
import ssl
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager
from urllib3.util.ssl_ import create_urllib3_context

if TYPE_CHECKING:
    from amoskys.storage.telemetry_store import TelemetryStore

logger = logging.getLogger(__name__)

_telemetry_store: Optional["TelemetryStore"] = None
_store_lock = threading.Lock()
_sync_started = False

# Resolve paths
_REPO_ROOT = Path(__file__).resolve().parents[3]
_DATA_DIR = _REPO_ROOT / "data"
_DB_PATH = _DATA_DIR / "telemetry.db"
_CACHE_DB_PATH = _DATA_DIR / "fleet_cache.db"
_OPS_SERVER = os.getenv("AMOSKYS_OPS_SERVER", "").rstrip("/")


def _resolve_ca_bundle() -> Optional[str]:
    """Resolve the pinned ops CA bundle path.

    Order of resolution:
      1. AMOSKYS_CA_BUNDLE env var (operator override)
      2. Packaged deploy/certs/ops-ca.pem under the repo root

    Returns the path as a string if it exists, else None (caller falls back
    to an unverified connection so a missing cert never hard-breaks sync).
    """
    env_path = os.getenv("AMOSKYS_CA_BUNDLE", "").strip()
    if env_path:
        if Path(env_path).is_file():
            return env_path
        logger.warning(
            "AMOSKYS_CA_BUNDLE set to %s but file not found; "
            "falling back to packaged CA",
            env_path,
        )
    packaged = _REPO_ROOT / "deploy" / "certs" / "ops-ca.pem"
    if packaged.is_file():
        return str(packaged)
    return None


class _PinnedCAAdapter(HTTPAdapter):
    """requests adapter that pins TLS to the ops self-signed CA.

    The ops cert (CN=ops.amoskys.com) is self-signed and carries NO
    subjectAltName, so RFC 6125 hostname matching cannot succeed. We require
    the chain to validate against the pinned CA (CERT_REQUIRED — full MITM
    protection) but suppress the SAN/hostname match. A wrong or absent CA is
    still rejected.
    """

    def __init__(self, ca_bundle: str, *args: Any, **kwargs: Any) -> None:
        self._ca_bundle = ca_bundle
        super().__init__(*args, **kwargs)

    def init_poolmanager(  # type: ignore[override]
        self, connections: int, maxsize: int, block: bool = False, **kwargs: Any
    ) -> None:
        ctx = create_urllib3_context()
        ctx.load_verify_locations(cafile=self._ca_bundle)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED
        self.poolmanager = PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            ssl_context=ctx,
            assert_hostname=False,
            **kwargs,
        )


def get_telemetry_store() -> Optional["TelemetryStore"]:
    """Get or create a TelemetryStore instance.

    Auto-detects local vs fleet mode:
      - Local: agent telemetry.db exists → use directly
      - Fleet: ops server configured → sync from ops into cache DB (readonly)
    """
    global _telemetry_store, _sync_started

    # Fast path: already initialised
    if _telemetry_store is not None:
        return _telemetry_store

    with _store_lock:
        # Double-check under lock
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
        if _OPS_SERVER:
            cache_exists = _CACHE_DB_PATH.exists()

            if not _sync_started:
                _sync_started = True
                # NEVER block the request thread on sync — it takes 30-60s
                # and freezes the gunicorn worker. Always start background sync.
                _start_fleet_sync()

            # Try the cache DB (populated by fleet sync)
            if cache_exists:
                try:
                    from amoskys.storage.telemetry_store import TelemetryStore

                    _telemetry_store = TelemetryStore(
                        db_path=str(_CACHE_DB_PATH), readonly=True
                    )
                    logger.info(
                        "Telemetry bridge: FLEET mode (cache=%s)", _CACHE_DB_PATH
                    )
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
            time.sleep(60)  # Sync every 60 seconds
            try:
                _sync_from_ops()
            except Exception as e:
                logger.warning("Fleet sync error: %s", e)

    t = threading.Thread(target=sync_loop, name="fleet-sync", daemon=True)
    t.start()


def _sync_from_ops():
    """Fetch event tables from ops server and REPLACE local cache.

    Uses truncate-and-replace strategy to prevent unbounded growth.
    Each sync replaces the cache with the latest events within the time window.
    """
    import requests

    _DATA_DIR.mkdir(parents=True, exist_ok=True)

    # Fetch bulk export from ops server (6h window — keeps cache small
    # for the t2.micro presentation server with 914MB RAM)
    # Pin TLS verification to the ops self-signed CA (CN=ops.amoskys.com).
    # Missing CA → WARNING + unverified fallback so sync never hard-breaks.
    _ca_bundle = _resolve_ca_bundle()
    _session = requests.Session()
    if _ca_bundle:
        _session.mount("https://", _PinnedCAAdapter(_ca_bundle))
    else:
        logger.warning(
            "Ops CA bundle not found (set AMOSKYS_CA_BUNDLE or ship "
            "deploy/certs/ops-ca.pem); fleet sync using UNVERIFIED TLS"
        )
        _session.verify = False
    try:
        resp = _session.get(
            f"{_OPS_SERVER}/api/v1/bulk-export",
            params={"hours": 6},
            timeout=60,
        )
        if resp.status_code != 200:
            logger.debug("Fleet sync: ops returned %d", resp.status_code)
            return
        bulk = resp.json()
    except Exception as e:
        logger.debug("Fleet sync fetch failed: %s", e)
        return

    # Initialize cache DB with TelemetryStore schema
    db = sqlite3.connect(str(_CACHE_DB_PATH), timeout=10)
    # Row factory so migration helpers can read PRAGMA results by name;
    # the rest of this module indexes rows positionally, which sqlite3.Row
    # also supports.
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=NORMAL")

    # Use the real TelemetryStore schema to create all tables
    try:
        from amoskys.storage._ts_schema import SCHEMA

        db.executescript(SCHEMA)
    except Exception:
        # Fallback: create minimal tables
        _create_minimal_schema(db)

    # Carry the BRAIN'S verdict through the sync. The dynamic INSERT only writes
    # columns that already exist in the table, so composite_score / risk_score_raw
    # / last_scored (present in the ops bulk export after re-scoring) are silently
    # dropped unless the columns exist here. Add them idempotently so the web can
    # read the calibrated score instead of the agent's raw risk_score.
    for _col, _typ in (
        ("composite_score", "REAL"),
        ("risk_score_raw", "REAL"),
        ("last_scored", "INTEGER"),
    ):
        try:
            db.execute(f"ALTER TABLE security_events ADD COLUMN {_col} {_typ}")
        except Exception:
            pass  # column already exists

    # The raw SCHEMA above is frozen at CREATE time, but the ops server's
    # store carries every column added by _migrate_convergence_schema()
    # (quality lineage, MITRE provenance, typed feature columns, ...).
    # _upsert_rows() filters INSERTs to columns that exist in the cache,
    # so without this step those fields are silently dropped. Run the
    # store's own convergence migration against the cache connection —
    # SchemaMixin only issues idempotent DDL on self.db (no threads,
    # pools, or side services, unlike a writable TelemetryStore).
    try:
        from amoskys.storage._ts_schema import SchemaMixin

        _migrator = SchemaMixin.__new__(SchemaMixin)
        _migrator.db = db
        _migrator._migrate_convergence_schema()
    except Exception:
        logger.warning(
            "Fleet cache convergence migration failed — syncing with "
            "existing cache schema",
            exc_info=True,
        )

    # Truncate and replace each table (prevents unbounded growth)
    total = 0
    for table_name, rows in bulk.items():
        if not rows:
            continue
        if table_name == "devices":
            # Device inventory is upserted (not truncated) so devices that
            # missed the current export window keep their metadata.
            total += _upsert_devices(db, rows)
            continue
        try:
            db.execute(f"DELETE FROM {table_name}")
        except Exception:
            pass
        inserted = _upsert_rows(db, table_name, rows)
        total += inserted

    # Compact the database periodically
    try:
        page_count = db.execute("PRAGMA page_count").fetchone()[0]
        free_pages = db.execute("PRAGMA freelist_count").fetchone()[0]
        if free_pages > page_count * 0.3:  # >30% free space
            db.execute("VACUUM")
    except Exception:
        pass

    db.commit()
    db.close()

    if total > 0:
        # Invalidate cached store so next request picks up fresh data
        global _telemetry_store
        with _store_lock:
            old = _telemetry_store
            _telemetry_store = None
            # Close old store's connections gracefully
            if old is not None:
                try:
                    old._read_pool.close()
                    old.db.close()
                except Exception:
                    pass
        logger.info(
            "Fleet sync: %d total rows synced across %d tables", total, len(bulk)
        )


def _upsert_rows(db: sqlite3.Connection, table: str, rows: list) -> int:
    """Insert rows into a table, skipping duplicates.

    Handles schema mismatches between ops server (simple columns) and
    TelemetryStore (full schema with NOT NULL constraints) by providing
    defaults for required columns that the ops server doesn't send.
    """
    if not rows:
        return 0

    # Column renames: ops server → fleet_cache TelemetryStore schema
    _COLUMN_MAP = {
        "event_timestamp_ns": "timestamp_ns",
        "raw_attributes_json": "attributes",
        "record_type": "query_type",
    }

    # Apply column renames to all rows
    if any(k in rows[0] for k in _COLUMN_MAP):
        for row in rows:
            for old_key, new_key in _COLUMN_MAP.items():
                if old_key in row and new_key not in row:
                    row[new_key] = row.pop(old_key)
            # Generate timestamp_dt from timestamp_ns if missing
            if "timestamp_ns" in row and "timestamp_dt" not in row:
                try:
                    from datetime import datetime, timezone

                    ts = row["timestamp_ns"] / 1e9
                    row["timestamp_dt"] = datetime.fromtimestamp(
                        ts, tz=timezone.utc
                    ).isoformat()
                except Exception:
                    pass

    # Get existing columns and their NOT NULL constraints
    try:
        cursor = db.execute(f"PRAGMA table_info({table})")
        col_info = cursor.fetchall()
        existing_cols = {r[1] for r in col_info}
        # Map of NOT NULL columns → default values (skip 'id' which is autoincrement)
        notnull_cols = {r[1] for r in col_info if r[3] == 1 and r[1] != "id"}
    except Exception:
        return 0

    if not existing_cols:
        return 0

    # Default values for NOT NULL columns the ops server doesn't send
    _NOT_NULL_DEFAULTS = {
        "event_type": "unknown",
        "syscall": "unknown",
        "host": "",
    }

    inserted = 0
    dropped_keys: set = set()
    for row in rows:
        # Filter to columns that exist, skip 'id' (auto-increment)
        cols = [k for k in row.keys() if k in existing_cols and k != "id"]
        # Track ops keys the cache schema can't hold so drift is visible
        dropped_keys |= set(row) - existing_cols
        if not cols:
            continue
        vals = [row[k] for k in cols]

        # Fill in NOT NULL columns that are missing from the ops server row
        col_set = set(cols)
        for nn_col in notnull_cols:
            if nn_col not in col_set:
                default = _NOT_NULL_DEFAULTS.get(nn_col, "")
                cols.append(nn_col)
                vals.append(default)

        placeholders = ",".join(["?"] * len(cols))
        col_names = ",".join(cols)
        try:
            cur = db.execute(
                f"INSERT OR IGNORE INTO {table} ({col_names}) VALUES ({placeholders})",
                vals,
            )
            # Honest accounting: OR IGNORE reports 0 rows for skipped
            # duplicates/constraint failures; don't count those as synced.
            inserted += max(cur.rowcount, 0)
        except Exception:
            pass

    if dropped_keys:
        logger.info(
            "Fleet sync: %s dropped %d key(s) not in cache schema "
            "(schema drift?): %s",
            table,
            len(dropped_keys),
            sorted(dropped_keys)[:10],
        )

    return inserted


# Device inventory columns mirrored from the ops command-center export.
_DEVICE_COLUMNS = (
    "device_id",
    "hostname",
    "os",
    "os_version",
    "arch",
    "agent_version",
    "status",
    "last_seen",
    "first_seen",
    "org_id",
)


def _upsert_devices(db: sqlite3.Connection, rows: list) -> int:
    """Upsert device inventory rows from the ops bulk export.

    The ops server is adding a 'devices' table to the bulk export; older
    ops builds simply omit it (callers only reach here when it is present).
    Unlike event tables, devices are keyed by device_id and updated in
    place — no truncate — so inventory survives partial export windows.
    """
    if not rows:
        return 0

    try:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS devices (
                device_id TEXT PRIMARY KEY,
                hostname TEXT,
                os TEXT,
                os_version TEXT,
                arch TEXT,
                agent_version TEXT,
                status TEXT,
                last_seen REAL,
                first_seen REAL,
                org_id TEXT
            )
            """
        )
    except Exception:
        logger.debug("Fleet sync: devices table create failed", exc_info=True)
        return 0

    upserted = 0
    for row in rows:
        if not isinstance(row, dict) or not row.get("device_id"):
            continue
        cols = [c for c in _DEVICE_COLUMNS if c in row]
        placeholders = ",".join(["?"] * len(cols))
        assignments = ",".join(
            f"{c}=excluded.{c}" for c in cols if c != "device_id"
        )
        conflict = (
            f"DO UPDATE SET {assignments}" if assignments else "DO NOTHING"
        )
        try:
            cur = db.execute(
                f"INSERT INTO devices ({','.join(cols)}) "
                f"VALUES ({placeholders}) "
                f"ON CONFLICT(device_id) {conflict}",
                [row[c] for c in cols],
            )
            upserted += max(cur.rowcount, 0)
        except Exception:
            logger.debug(
                "Fleet sync: devices upsert failed for %s",
                row.get("device_id"),
                exc_info=True,
            )
    return upserted


def _create_minimal_schema(db: sqlite3.Connection):
    """Create minimal tables if TelemetryStore schema import fails."""
    tables = {
        "security_events": """
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp_ns INTEGER, timestamp_dt TEXT,
                device_id TEXT, event_category TEXT, event_action TEXT, event_outcome TEXT,
                risk_score REAL, confidence REAL, mitre_techniques TEXT,
                collection_agent TEXT, description TEXT, process_name TEXT, remote_ip TEXT,
                pid TEXT, username TEXT, domain TEXT, path TEXT, sha256 TEXT,
                probe_name TEXT, detection_source TEXT, enrichment_status TEXT,
                geo_src_country TEXT, asn_src_org TEXT, event_timestamp_ns INTEGER, event_id TEXT
            )""",
        "process_events": """
            CREATE TABLE IF NOT EXISTS process_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp_ns INTEGER, timestamp_dt TEXT,
                device_id TEXT, pid TEXT, exe TEXT, cmdline TEXT, ppid TEXT,
                username TEXT, name TEXT, parent_name TEXT, status TEXT,
                cpu_percent REAL, memory_percent REAL, collection_agent TEXT
            )""",
        "flow_events": """
            CREATE TABLE IF NOT EXISTS flow_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp_ns INTEGER, timestamp_dt TEXT,
                device_id TEXT, src_ip TEXT, dst_ip TEXT, src_port INTEGER, dst_port INTEGER,
                protocol TEXT, bytes_tx INTEGER, bytes_rx INTEGER, pid TEXT,
                process_name TEXT, geo_dst_latitude REAL, geo_dst_longitude REAL,
                geo_dst_country TEXT, geo_dst_city TEXT, asn_dst_org TEXT,
                threat_intel_match BOOLEAN, collection_agent TEXT
            )""",
        "dns_events": """
            CREATE TABLE IF NOT EXISTS dns_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp_ns INTEGER, timestamp_dt TEXT,
                device_id TEXT, domain TEXT, record_type TEXT, response_code TEXT,
                risk_score REAL, process_name TEXT, collection_agent TEXT
            )""",
        "persistence_events": """
            CREATE TABLE IF NOT EXISTS persistence_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp_ns INTEGER, timestamp_dt TEXT,
                device_id TEXT, mechanism TEXT, path TEXT, change_type TEXT,
                label TEXT, sha256 TEXT, risk_score REAL, collection_agent TEXT
            )""",
        "audit_events": """
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp_ns INTEGER, timestamp_dt TEXT,
                device_id TEXT, event_type TEXT, username TEXT, process_name TEXT,
                risk_score REAL, collection_agent TEXT, description TEXT
            )""",
        "fim_events": """
            CREATE TABLE IF NOT EXISTS fim_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp_ns INTEGER, timestamp_dt TEXT,
                device_id TEXT, path TEXT, change_type TEXT, risk_score REAL,
                old_hash TEXT, new_hash TEXT, collection_agent TEXT
            )""",
        "peripheral_events": """
            CREATE TABLE IF NOT EXISTS peripheral_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp_ns INTEGER, timestamp_dt TEXT,
                device_id TEXT, device_type TEXT, vendor TEXT, product TEXT,
                serial TEXT, action TEXT, risk_score REAL, collection_agent TEXT
            )""",
        "observation_events": """
            CREATE TABLE IF NOT EXISTS observation_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp_ns INTEGER, timestamp_dt TEXT,
                device_id TEXT, domain TEXT, observation_type TEXT, summary TEXT,
                risk_score REAL, collection_agent TEXT
            )""",
        "dashboard_rollups": """
            CREATE TABLE IF NOT EXISTS dashboard_rollups (
                key TEXT PRIMARY KEY, value_json TEXT NOT NULL, updated_at REAL NOT NULL
            )""",
    }
    for sql in tables.values():
        try:
            db.execute(sql)
        except Exception:
            pass
