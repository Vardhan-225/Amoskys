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

import json
import logging
import os
import re
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

_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_SCHEMA_DRIFT_TABLE = "schema_drift_events"
_SCHEMA_DRIFT_SOURCE = "fleet_sync"

_EVENT_TABLES = (
    "security_events",
    "process_events",
    "flow_events",
    "dns_events",
    "audit_events",
    "persistence_events",
    "fim_events",
    "peripheral_events",
    "observation_events",
)

_BASE_EVENT_CONTRACT_COLUMNS = {
    "org_id": "TEXT",
    "source_id": "TEXT",
    "received_at": "REAL",
    "event_id": "TEXT",
    "quality_state": "TEXT DEFAULT 'valid'",
    "training_exclude": "BOOLEAN DEFAULT 0",
    "contract_violation_code": "TEXT DEFAULT 'NONE'",
    "missing_fields": "TEXT",
    "raw_attributes_json": "TEXT",
    "verdict": "TEXT",
}

_CACHE_CONTRACT_COLUMNS = {
    table: dict(_BASE_EVENT_CONTRACT_COLUMNS) for table in _EVENT_TABLES
}
_CACHE_CONTRACT_COLUMNS["security_events"].update(
    {
        "final_classification": "TEXT",
        "geometric_score": "REAL",
        "temporal_score": "REAL",
        "behavioral_score": "REAL",
        "composite_score": "REAL",
        "risk_score_raw": "REAL",
        "last_scored": "INTEGER",
    }
)
_CACHE_CONTRACT_COLUMNS["process_events"].update(
    {
        "name": "TEXT",
        "parent_name": "TEXT",
        "status": "TEXT",
    }
)


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
    the chain to validate against the pinned CA (CERT_REQUIRED) but suppress
    the SAN/hostname match. Because hostname matching is off, the trust store
    is the ONLY thing distinguishing the ops server from an attacker — so it
    must hold that one CA and nothing else; see cert_verify() below.
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

    def cert_verify(  # type: ignore[override]
        self, conn: Any, url: str, verify: Any, cert: Any
    ) -> None:
        """Force the pinned bundle; never let certifi's roots in.

        The pin above was silently defeated. requests defaults verify=True, so
        HTTPAdapter.cert_verify() sets conn.ca_certs to certifi's public root
        bundle, and urllib3's ssl_wrap_socket() then merges that INTO the
        context created above via load_verify_locations(). Measured in this
        venv (requests 2.32.5 / urllib3 2.6.3 / certifi cacert.pem): the
        context goes from 1 trusted CA to 138 — 137 public roots. Combined
        with check_hostname=False and assert_hostname=False (which skips
        urllib3's _match_hostname entirely), ANY publicly-trusted cert for ANY
        domain validated as "the ops server" — i.e. no MITM protection at all,
        the opposite of what the class name claims. Passing our bundle as
        `verify` keeps the context at exactly the one pinned CA.
        """
        super().cert_verify(conn, url, self._ca_bundle, cert)


def _is_safe_identifier(value: str) -> bool:
    return bool(_IDENTIFIER_RE.fullmatch(str(value or "")))


def _quote_identifier(value: str) -> str:
    if not _is_safe_identifier(value):
        raise ValueError(f"unsafe sqlite identifier: {value!r}")
    return f'"{value}"'


def _table_exists(db: sqlite3.Connection, table: str) -> bool:
    try:
        row = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
            (table,),
        ).fetchone()
        return bool(row)
    except Exception:
        return False


def _get_table_columns(db: sqlite3.Connection, table: str) -> set[str]:
    if not _is_safe_identifier(table):
        return set()
    try:
        cursor = db.execute(f"PRAGMA table_info({_quote_identifier(table)})")
        return {r[1] for r in cursor.fetchall()}
    except Exception:
        return set()


def _ensure_schema_drift_table(db: sqlite3.Connection) -> None:
    db.execute(
        f"""
        CREATE TABLE IF NOT EXISTS {_SCHEMA_DRIFT_TABLE} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            detected_at REAL NOT NULL,
            table_name TEXT NOT NULL,
            column_name TEXT NOT NULL,
            action TEXT NOT NULL,
            reason TEXT,
            column_type TEXT,
            sample_value TEXT,
            source TEXT NOT NULL DEFAULT '{_SCHEMA_DRIFT_SOURCE}'
        )
        """
    )
    db.execute(
        f"""
        CREATE INDEX IF NOT EXISTS idx_schema_drift_recent
        ON {_SCHEMA_DRIFT_TABLE}(detected_at DESC, action)
        """
    )


def _sample_for_column(rows: list, column: str) -> Any:
    for row in rows:
        if isinstance(row, dict) and row.get(column) is not None:
            return row[column]
    return None


def _serialize_sample(value: Any) -> Optional[str]:
    if value is None:
        return None
    try:
        if isinstance(value, (dict, list, tuple)):
            text = json.dumps(value, sort_keys=True)
        else:
            text = str(value)
    except Exception:
        text = repr(value)
    return text[:500]


def _normalize_sql_value(value: Any) -> Any:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, sort_keys=True)
    if value is None or isinstance(value, (str, int, float, bytes)):
        return value
    return str(value)


def _infer_sqlite_type(value: Any) -> str:
    if isinstance(value, bool):
        return "BOOLEAN"
    if isinstance(value, int) and not isinstance(value, bool):
        return "INTEGER"
    if isinstance(value, float):
        return "REAL"
    if isinstance(value, bytes):
        return "BLOB"
    return "TEXT"


def _record_schema_drift(
    db: sqlite3.Connection,
    table: str,
    column: str,
    action: str,
    reason: str,
    *,
    column_type: Optional[str] = None,
    sample_value: Any = None,
) -> None:
    try:
        _ensure_schema_drift_table(db)
        db.execute(
            f"""
            INSERT INTO {_SCHEMA_DRIFT_TABLE}
                (detected_at, table_name, column_name, action, reason,
                 column_type, sample_value, source)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                time.time(),
                str(table),
                str(column),
                action,
                reason,
                column_type,
                _serialize_sample(sample_value),
                _SCHEMA_DRIFT_SOURCE,
            ),
        )
    except Exception:
        logger.debug(
            "Fleet sync: failed to record schema drift for %s.%s",
            table,
            column,
            exc_info=True,
        )


def _add_cache_column(
    db: sqlite3.Connection,
    table: str,
    column: str,
    ddl_type: str,
    *,
    reason: str,
    sample_value: Any = None,
) -> bool:
    if column == "id":
        _record_schema_drift(
            db,
            table,
            column,
            "dropped",
            "id is cache-owned autoincrement metadata",
            column_type=ddl_type,
            sample_value=sample_value,
        )
        return False
    if not _is_safe_identifier(table) or not _is_safe_identifier(column):
        _record_schema_drift(
            db,
            table,
            column,
            "dropped",
            "unsafe table or column identifier",
            column_type=ddl_type,
            sample_value=sample_value,
        )
        return False
    if not _table_exists(db, table):
        _record_schema_drift(
            db,
            table,
            column,
            "failed",
            "target table does not exist in fleet cache",
            column_type=ddl_type,
            sample_value=sample_value,
        )
        return False

    try:
        db.execute(
            f"ALTER TABLE {_quote_identifier(table)} "
            f"ADD COLUMN {_quote_identifier(column)} {ddl_type}"
        )
        _record_schema_drift(
            db,
            table,
            column,
            "added",
            reason,
            column_type=ddl_type,
            sample_value=sample_value,
        )
        logger.info(
            "Fleet sync: added cache column %s.%s (%s)",
            table,
            column,
            ddl_type,
        )
        return True
    except sqlite3.OperationalError as exc:
        # Concurrent syncs or legacy DBs can race an idempotent add.
        if "duplicate column name" in str(exc).lower():
            return True
        _record_schema_drift(
            db,
            table,
            column,
            "failed",
            f"ALTER TABLE failed: {exc}",
            column_type=ddl_type,
            sample_value=sample_value,
        )
        return False
    except Exception as exc:
        _record_schema_drift(
            db,
            table,
            column,
            "failed",
            f"ALTER TABLE failed: {exc}",
            column_type=ddl_type,
            sample_value=sample_value,
        )
        return False


def _ensure_fleet_cache_contract(db: sqlite3.Connection) -> None:
    """Ensure fleet-only lineage/verdict columns survive ops→web sync."""
    try:
        _ensure_schema_drift_table(db)
    except Exception:
        logger.debug("Fleet sync: schema drift table create failed", exc_info=True)
        return

    for table, required_columns in _CACHE_CONTRACT_COLUMNS.items():
        existing_cols = _get_table_columns(db, table)
        if not existing_cols:
            continue
        for column, ddl_type in required_columns.items():
            if column in existing_cols:
                continue
            if _add_cache_column(
                db,
                table,
                column,
                ddl_type,
                reason="fleet cache contract column missing",
            ):
                existing_cols.add(column)


def _ensure_incoming_columns(
    db: sqlite3.Connection,
    table: str,
    rows: list,
    existing_cols: set[str],
) -> tuple[set[str], set[str]]:
    """Auto-add safe ops export columns before row filtering drops evidence."""
    incoming_cols: set[str] = set()
    for row in rows:
        if isinstance(row, dict):
            incoming_cols.update(row.keys())

    recorded_unstorable: set[str] = set()
    for column in sorted(incoming_cols - existing_cols):
        if column == "id":
            continue
        sample = _sample_for_column(rows, column)
        ddl_type = _infer_sqlite_type(sample)
        if _add_cache_column(
            db,
            table,
            column,
            ddl_type,
            reason="ops export column missing from fleet cache",
            sample_value=sample,
        ):
            existing_cols.add(column)
        else:
            recorded_unstorable.add(column)

    return existing_cols, recorded_unstorable


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
            # WARNING, not debug: the web app configures logging at
            # LOG_LEVEL=INFO by default (web/app/__init__.py), so every one of
            # these was discarded before it reached a handler. A fleet sync
            # that has been failing for months looked exactly like one that
            # had nothing to do — which is how the cache went stale silently.
            logger.warning("Fleet sync: ops returned %d", resp.status_code)
            return
        bulk = resp.json()
    except Exception as e:
        logger.warning("Fleet sync fetch failed: %s", e)
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

    _ensure_fleet_cache_contract(db)

    # Truncate and replace each table (prevents unbounded growth).
    #
    # Stage-then-swap, because the old sequence could not fail safely: DELETE
    # and the refill ran with no transaction boundary, and _upsert_rows()
    # swallows every per-row exception (its `except Exception: pass`) and just
    # returns 0. A table whose rows the cache schema rejected was therefore
    # emptied, refilled with nothing, and committed — the sync silently wiped
    # the cache and the dashboard then read a fleet with zero events, which is
    # indistinguishable from a quiet fleet. Measured A/B against a temp cache
    # holding 25 security_events, then handed one export the schema rejects:
    # before, security_events went 25 → 0 with nothing logged at all; after,
    # it stays at 25 and two WARNINGs name the table that failed.
    #
    # One outer transaction means readers on other connections keep seeing the
    # previous contents for the whole sync and only ever observe the complete
    # swap; a SAVEPOINT per table means a table that fails validation is rolled
    # back to what it held before instead of being left empty, and one bad
    # table cannot take the others down with it.
    total = 0
    failed_tables: list[str] = []
    try:
        # Land the schema/contract work above first: it writes drift rows, so
        # sqlite3 already has an implicit transaction open and BEGIN would
        # raise "cannot start a transaction within a transaction".
        db.commit()
        db.execute("BEGIN IMMEDIATE")
        for table_name, rows in bulk.items():
            if not rows:
                continue
            if table_name == "devices":
                # Device inventory is upserted (not truncated) so devices that
                # missed the current export window keep their metadata.
                total += _upsert_devices(db, rows)
                continue
            if not _is_safe_identifier(table_name):
                _record_schema_drift(
                    db,
                    table_name,
                    "*",
                    "dropped",
                    "unsafe table identifier in ops bulk export",
                )
                continue
            db.execute("SAVEPOINT fleet_sync_table")
            try:
                db.execute(f"DELETE FROM {_quote_identifier(table_name)}")
                inserted = _upsert_rows(db, table_name, rows)
                if inserted == 0:
                    # The export carried rows but none landed — missing table,
                    # or every INSERT hit a constraint. Committing the DELETE
                    # on this path is exactly what emptied the cache.
                    raise RuntimeError(f"0 of {len(rows)} exported rows accepted")
                db.execute("RELEASE SAVEPOINT fleet_sync_table")
                total += inserted
            except Exception as e:
                db.execute("ROLLBACK TO SAVEPOINT fleet_sync_table")
                db.execute("RELEASE SAVEPOINT fleet_sync_table")
                failed_tables.append(table_name)
                # The rollback also discards the drift rows _upsert_rows()
                # wrote inside the savepoint — and those are the
                # 'dropped'/'failed' rows routes_observatory treats as
                # blocking (_SCHEMA_DRIFT_BLOCKING_ACTIONS). Measured: an
                # export whose columns the cache rejects left 0 drift rows for
                # the table that failed, while the same unstorable column on a
                # table that succeeded left 1 — i.e. the evidence vanished
                # precisely when it mattered. Re-record one table-level row
                # outside the savepoint so the Observatory still sees it.
                _record_schema_drift(
                    db,
                    table_name,
                    "*",
                    "failed",
                    f"table not replaced by fleet sync: {e}",
                )
                logger.warning(
                    "Fleet sync: %s NOT replaced (%s); previous cached rows kept",
                    table_name,
                    e,
                )
        db.commit()
    except Exception as e:
        # Nothing below the loop can un-truncate the cache, so roll the whole
        # swap back and leave the last good snapshot in place.
        db.rollback()
        logger.warning(
            "Fleet sync aborted; cache left at its previous contents: %s",
            e,
            exc_info=True,
        )
        db.close()
        return

    if failed_tables:
        logger.warning(
            "Fleet sync: %d table(s) kept their previous contents instead of "
            "being replaced: %s",
            len(failed_tables),
            ", ".join(sorted(failed_tables)),
        )

    # Compact the database periodically. Must run AFTER the commit above —
    # sqlite refuses to "VACUUM from within a transaction", and the swap now
    # holds one for its whole duration.
    try:
        page_count = db.execute("PRAGMA page_count").fetchone()[0]
        free_pages = db.execute("PRAGMA freelist_count").fetchone()[0]
        if free_pages > page_count * 0.3:  # >30% free space
            db.execute("VACUUM")
    except Exception:
        pass

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
    if not _is_safe_identifier(table):
        _record_schema_drift(
            db,
            table,
            "*",
            "dropped",
            "unsafe table identifier in row upsert",
        )
        return 0

    # Column renames: ops server → fleet_cache TelemetryStore schema
    _COLUMN_MAP = {
        "event_timestamp_ns": "timestamp_ns",
        "record_type": "query_type",
    }
    _TABLE_COLUMN_MAP = {
        # Generic observations store payloads in attributes; typed tables keep
        # raw_attributes_json so lossless payload lineage round-trips.
        "observation_events": {"raw_attributes_json": "attributes"},
    }
    column_map = {**_COLUMN_MAP, **_TABLE_COLUMN_MAP.get(table, {})}

    # Apply column renames to all rows
    for row in rows:
        if not isinstance(row, dict):
            continue
        for old_key, new_key in column_map.items():
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
        cursor = db.execute(f"PRAGMA table_info({_quote_identifier(table)})")
        col_info = cursor.fetchall()
        existing_cols = {r[1] for r in col_info}
        # Map of NOT NULL columns → default values (skip 'id' which is autoincrement)
        notnull_cols = {r[1] for r in col_info if r[3] == 1 and r[1] != "id"}
    except Exception:
        _record_schema_drift(
            db,
            table,
            "*",
            "failed",
            "could not inspect fleet cache table schema",
        )
        return 0

    if not existing_cols:
        _record_schema_drift(
            db,
            table,
            "*",
            "failed",
            "target table missing from fleet cache schema",
        )
        return 0

    existing_cols, recorded_unstorable = _ensure_incoming_columns(
        db, table, rows, existing_cols
    )

    # Default values for NOT NULL columns the ops server doesn't send
    _NOT_NULL_DEFAULTS = {
        "event_type": "unknown",
        "syscall": "unknown",
        "host": "",
    }

    inserted = 0
    dropped_keys: set = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        # Filter to columns that exist, skip 'id' (auto-increment)
        cols = [k for k in row.keys() if k in existing_cols and k != "id"]
        # Track ops keys the cache schema can't hold so drift is visible
        dropped_keys |= {
            k
            for k in set(row) - existing_cols
            if k != "id" and k not in recorded_unstorable
        }
        if not cols:
            continue
        vals = [_normalize_sql_value(row[k]) for k in cols]

        # Fill in NOT NULL columns that are missing from the ops server row
        col_set = set(cols)
        for nn_col in notnull_cols:
            if nn_col not in col_set:
                default = _NOT_NULL_DEFAULTS.get(nn_col, "")
                cols.append(nn_col)
                vals.append(default)

        placeholders = ",".join(["?"] * len(cols))
        col_names = ",".join(_quote_identifier(c) for c in cols)
        try:
            cur = db.execute(
                f"INSERT OR IGNORE INTO {_quote_identifier(table)} "
                f"({col_names}) VALUES ({placeholders})",
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
        for column in sorted(dropped_keys):
            _record_schema_drift(
                db,
                table,
                column,
                "dropped",
                "column remained unstorable after safe auto-add attempt",
                sample_value=_sample_for_column(rows, column),
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
        assignments = ",".join(f"{c}=excluded.{c}" for c in cols if c != "device_id")
        conflict = f"DO UPDATE SET {assignments}" if assignments else "DO NOTHING"
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
