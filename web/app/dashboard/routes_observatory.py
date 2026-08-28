"""Observatory API routes for the AMOSKYS Dashboard.

Extracted from __init__.py — contains posture, signals, incidents,
DNS, network, FIM, persistence, audit, and observation domain endpoints.
"""

import json
import logging
import os
import re
import sqlite3
import time
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path

from flask import jsonify, request

from amoskys.observability.blindness import (
    list_blindness_events,
    summarize_blindness_events,
)
from amoskys.observability.esf_authorization import inspect_esf_authorization

from ..api.rate_limiter import require_rate_limit
from ..middleware import require_login
from . import dashboard_bp
from .route_helpers import _get_store, _parse_indicators, _parse_json_list, _parse_mitre

logger = logging.getLogger("web.app.dashboard")

_MSG_DB_UNAVAILABLE = "Database unavailable"
_THREAT_INTEL_STALE_DAYS = 3.0
_SCHEMA_DRIFT_TABLE = "schema_drift_events"
_SCHEMA_DRIFT_BLOCKING_ACTIONS = {"dropped", "failed"}
_NETWORK_SCHEMA_COLUMNS = {
    "timestamp_ns",
    "device_id",
    "dst_ip",
    "dst_port",
    "protocol",
    "bytes_tx",
    "bytes_rx",
    "process_name",
    "geo_dst_country",
    "geo_dst_city",
    "geo_dst_latitude",
    "geo_dst_longitude",
    "asn_dst_org",
    "asn_dst_network_type",
    "threat_intel_match",
    "collection_agent",
}


# ═══════════════════════════════════════════════════════════════════════════════
# Helper functions — used only within this module
# ═══════════════════════════════════════════════════════════════════════════════


def _normalize_replay_event(row, source="security"):
    """Flatten an event row into the contract expected by timeline replay."""
    event = dict(row)
    indicators = _parse_indicators(event.get("indicators"))
    event["indicators"] = indicators
    event["mitre_techniques"] = _parse_mitre(event.get("mitre_techniques"))
    event["source"] = source
    event.setdefault("event_type", event.get("event_category") or source)
    event.setdefault(
        "agent_id",
        event.get("collection_agent")
        or event.get("agent_id")
        or event.get("device_id"),
    )

    indicator_aliases = {
        "source_ip": ("source_ip", "src_ip"),
        "dest_ip": ("dest_ip", "dst_ip", "remote_ip"),
        "process_name": ("process_name", "process", "exe"),
        "file_path": ("file_path", "path", "target_path"),
    }
    for target_key, aliases in indicator_aliases.items():
        if event.get(target_key):
            continue
        for alias in aliases:
            value = indicators.get(alias)
            if value:
                event[target_key] = value
                break

    return event


def _expand_signal_event_ids(store, signal_ids):
    """Resolve signal IDs to contributing numeric security event row IDs."""
    if not signal_ids:
        return []

    placeholders = ",".join("?" for _ in signal_ids)
    try:
        rows = store.db.execute(
            f"SELECT contributing_event_ids FROM signals WHERE signal_id IN ({placeholders})",
            list(signal_ids),
        ).fetchall()
    except Exception:
        return []

    event_ids = []
    for row in rows:
        payload = (
            row[0]
            if not isinstance(row, sqlite3.Row)
            else row["contributing_event_ids"]
        )
        for event_id in _parse_json_list(payload):
            if isinstance(event_id, int):
                event_ids.append(event_id)
            elif isinstance(event_id, str) and event_id.isdigit():
                event_ids.append(int(event_id))
    return event_ids


def _load_incident_replay_events(store, incident):
    """Resolve linked incident evidence into flat replay events."""
    source_event_ids = _parse_json_list(incident.get("source_event_ids"))
    signal_ids = _parse_json_list(incident.get("signal_ids"))

    numeric_ids = []
    string_event_ids = []

    for event_ref in source_event_ids:
        if isinstance(event_ref, int):
            numeric_ids.append(event_ref)
        elif isinstance(event_ref, str):
            if event_ref.isdigit():
                numeric_ids.append(int(event_ref))
            elif event_ref:
                string_event_ids.append(event_ref)

    numeric_ids.extend(_expand_signal_event_ids(store, signal_ids))

    clauses = []
    params = []
    if numeric_ids:
        unique_numeric_ids = list(dict.fromkeys(numeric_ids))
        clauses.append(f"id IN ({','.join('?' for _ in unique_numeric_ids)})")
        params.extend(unique_numeric_ids)
    if string_event_ids:
        unique_string_ids = list(dict.fromkeys(string_event_ids))
        clauses.append(f"event_id IN ({','.join('?' for _ in unique_string_ids)})")
        params.extend(unique_string_ids)

    if not clauses:
        return []

    try:
        cursor = store.db.execute(
            "SELECT * FROM security_events WHERE "
            + " OR ".join(clauses)
            + " ORDER BY timestamp_ns ASC",
            params,
        )
        rows = [dict(row) for row in cursor.fetchall()]
    except Exception:
        logger.exception("Failed to resolve incident-linked security events")
        return []

    deduped = []
    seen = set()
    for row in rows:
        key = row.get("id") or row.get("event_id")
        if key in seen:
            continue
        seen.add(key)
        deduped.append(_normalize_replay_event(row, source="security"))
    return deduped


def _table_columns(db, table):
    try:
        return {row[1] for row in db.execute(f"PRAGMA table_info({table})")}
    except Exception:
        return set()


def _health_status(status, message, **extra):
    payload = {"status": status, "message": message}
    payload.update(extra)
    return payload


def _iso_age_days(value):
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - parsed).total_seconds() / 86400


def _intel_corpus_size():
    """Number of UNEXPIRED indicators available to the matcher, or None.

    Deliberately counts only unexpired rows: this feed had 1,155 rows on disk
    and zero of them live, because every row shared one expires_at that passed
    on 2026-07-01. A plain COUNT(*) would have reported a healthy 1,155 and
    reproduced the exact failure this check exists to prevent.

    Returns None when the corpus genuinely cannot be determined from here (no
    configured DB), so the caller can say "unverified" instead of inventing a
    number in either direction.
    """
    path = (os.getenv("AMOSKYS_THREAT_INTEL_DB") or "").strip()
    if not path or not os.path.isabs(path) or not os.path.exists(path):
        return None
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=2)
        try:
            row = conn.execute(
                "SELECT COUNT(*) FROM indicators "
                "WHERE expires_at IS NULL OR expires_at > ?",
                (datetime.now(timezone.utc).isoformat(),),
            ).fetchone()
            return int(row[0] or 0) if row else 0
        finally:
            conn.close()
    except Exception:
        return None


def _threat_intel_evidence_from_data(store, hours=24):
    """Did intel actually RUN on the telemetry being displayed?

    The local env var answers "is this box configured", which on a
    presentation server is the wrong question: threat-intel matching happens at
    the ENDPOINT, at scoring time, and arrives here already decided in the
    threat_intel_match column. A fleet view that reports its own missing config
    as fleet-wide degradation is describing the viewer, not the sensors.

    The data answers the right question, because the column distinguishes three
    states rather than two:
        NULL -> enrichment never ran; genuinely blind
        0    -> it ran and found nothing; a real negative
        1    -> it ran and matched

    Measured here when this was written: 8,128 of 8,128 flows carried 0, not
    NULL — intel had run on every single one while the card said "0 indicators,
    degraded".

    Returns (checked, matched, total) or None when it cannot be determined.
    """
    try:
        with store._read_pool.connection() as rdb:
            cutoff = int((time.time() - hours * 3600) * 1e9)
            row = rdb.execute(
                """SELECT COUNT(*),
                          SUM(CASE WHEN threat_intel_match IS NOT NULL THEN 1 ELSE 0 END),
                          SUM(CASE WHEN threat_intel_match = 1 THEN 1 ELSE 0 END)
                   FROM flow_events WHERE timestamp_ns > ?""",
                (cutoff,),
            ).fetchone()
        if not row or not row[0]:
            return None
        return (int(row[1] or 0), int(row[2] or 0), int(row[0]))
    except Exception:
        return None


def _threat_intel_health(store=None):
    """Report threat-intel feed health.

    Prefers evidence from the telemetry itself over this host's configuration —
    see _threat_intel_evidence_from_data for why. Falls back to inspecting the
    local DB when the data cannot answer (no flows, or the column absent).
    """
    if store is not None:
        ev = _threat_intel_evidence_from_data(store)
        if ev is not None:
            checked, matched, total = ev
            if checked >= total and total > 0:
                # "It ran" is NOT "it was armed". An enricher with zero
                # unexpired indicators still executes on every flow and still
                # returns a verdict — one that is arithmetically forced to be
                # negative. Reporting that as healthy is how a feed that
                # expired wholesale on 2026-07-01 kept a green badge for 52
                # days while 22,366 flows went past unexamined.
                #
                # A zero-match run only certifies the sensor if the corpus
                # could have produced a match. matched > 0 proves that
                # directly. Otherwise the corpus size has to be established
                # independently, and if it cannot be, the honest answer is
                # "unverified" — not "healthy".
                # Softened deliberately. The first version of this check
                # demanded a known non-empty corpus before saying healthy,
                # which would have flagged every correctly-armed FLEET server
                # as degraded: AMOSKYS_THREAT_INTEL_DB is intentionally unset
                # there, so corpus is None, and preferring local config over
                # fleet data is the exact mistake this function was written to
                # stop making.
                #
                # It is safe to trust the data now, because the writers were
                # fixed to stop defaulting to False: an UNARMED enricher writes
                # NULL, so it lands in the checked == 0 branch below and never
                # reaches here. Reaching this line means an armed enricher
                # returned a verdict on every flow. corpus is therefore only
                # used to CONTRADICT that, never to confirm it.
                corpus = _intel_corpus_size()
                if corpus is None or corpus > 0 or matched > 0:
                    return _health_status(
                        "healthy",
                        (
                            f"Intel evaluated at the collector on {checked:,} of "
                            f"{total:,} flows — {matched:,} matched"
                        ),
                        configured=True,
                        indicators=corpus,
                        source="collector",
                    )
                return _health_status(
                    "degraded",
                    (
                        f"Intel ran on {checked:,} of {total:,} flows and matched "
                        f"nothing, but the indicator feed is empty or fully "
                        f"expired — a zero-match result here is arithmetic, not "
                        f"evidence. Refresh the feed "
                        f"(scripts/update_threat_intel.py)."
                    ),
                    configured=True,
                    indicators=corpus,
                    source="collector",
                )
            if checked > 0:
                return _health_status(
                    "degraded",
                    (
                        f"Intel evaluated on only {checked:,} of {total:,} flows "
                        f"— the rest arrived unchecked"
                    ),
                    configured=True,
                    indicators=None,
                    source="collector",
                )
            return _health_status(
                "degraded",
                (
                    f"No intel verdict on any of {total:,} flows — the collector "
                    f"is not running threat-intel enrichment"
                ),
                configured=False,
                indicators=0,
                source="collector",
            )

    path = (os.getenv("AMOSKYS_THREAT_INTEL_DB") or "").strip()
    if not path:
        return _health_status(
            "degraded",
            "AMOSKYS_THREAT_INTEL_DB is not set",
            configured=False,
            indicators=0,
            db_path="",
        )
    if not os.path.isabs(path):
        return _health_status(
            "degraded",
            "AMOSKYS_THREAT_INTEL_DB is not absolute",
            configured=False,
            indicators=0,
            db_path=path,
        )
    if not os.path.exists(path):
        return _health_status(
            "degraded",
            "Threat-intel DB file is missing",
            configured=False,
            indicators=0,
            db_path=path,
        )

    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=2)
        try:
            row = conn.execute("SELECT COUNT(*) FROM indicators").fetchone()
            indicators = int(row[0] or 0) if row else 0
            added = conn.execute("SELECT MAX(added_at) FROM indicators").fetchone()
            updated_at = added[0] if added and added[0] else None
            age_days = _iso_age_days(updated_at) if updated_at else None
        finally:
            conn.close()
    except Exception:
        return _health_status(
            "degraded",
            "Threat-intel DB could not be read",
            configured=True,
            indicators=0,
            db_path=path,
        )

    if indicators <= 0:
        return _health_status(
            "degraded",
            "Threat-intel DB has 0 indicators",
            configured=True,
            indicators=0,
            db_path=path,
            updated_at=updated_at,
            age_days=age_days,
        )
    if age_days is None:
        return _health_status(
            "degraded",
            "Threat-intel feed freshness is unknown",
            configured=True,
            indicators=indicators,
            db_path=path,
            updated_at=updated_at,
            age_days=age_days,
        )
    if age_days > _THREAT_INTEL_STALE_DAYS:
        return _health_status(
            "degraded",
            f"Threat-intel feed is stale ({age_days:.1f} days old)",
            configured=True,
            indicators=indicators,
            db_path=path,
            updated_at=updated_at,
            age_days=round(age_days, 1),
        )
    return _health_status(
        "healthy",
        "Threat-intel feed loaded",
        configured=True,
        indicators=indicators,
        db_path=path,
        updated_at=updated_at,
        age_days=round(age_days, 1),
    )


def _coverage_status(label, total, covered):
    pct = round((covered / total) * 100, 1) if total else 0.0
    if total <= 0:
        return _health_status(
            "unknown",
            f"No flows to evaluate {label}",
            covered=covered,
            total=total,
            coverage_pct=pct,
        )
    if covered > 0:
        return _health_status(
            "healthy",
            f"{label} present on {pct}% of recent flows",
            covered=covered,
            total=total,
            coverage_pct=pct,
        )
    return _health_status(
        "degraded",
        f"No recent flows carry {label}",
        covered=covered,
        total=total,
        coverage_pct=pct,
    )


def _schema_health(db, missing_cols, hours):
    """Report network schema health plus recent fleet sync drift incidents."""
    events = []
    blocking_events = []
    added_count = 0
    cutoff = time.time() - max(int(hours or 24), 1) * 3600

    try:
        exists = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
            (_SCHEMA_DRIFT_TABLE,),
        ).fetchone()
        if exists:
            rows = db.execute(
                f"""
                SELECT detected_at, table_name, column_name, action, reason,
                       column_type, sample_value
                FROM {_SCHEMA_DRIFT_TABLE}
                WHERE detected_at >= ?
                ORDER BY detected_at DESC
                LIMIT 25
                """,
                (cutoff,),
            ).fetchall()
            for row in rows:
                event = {
                    "detected_at": float(row[0] or 0),
                    "table": row[1],
                    "column": row[2],
                    "action": row[3],
                    "reason": row[4],
                    "column_type": row[5],
                    "sample_value": row[6],
                }
                events.append(event)
                if event["action"] in _SCHEMA_DRIFT_BLOCKING_ACTIONS:
                    blocking_events.append(event)
                elif event["action"] == "added":
                    added_count += 1
    except Exception:
        return _health_status(
            "degraded",
            "Schema drift ledger could not be inspected",
            missing_columns=missing_cols,
            drift_events=[],
            drift_blocking_count=0,
            drift_added_count=0,
        )

    if missing_cols and blocking_events:
        message = "Network schema is missing columns and fleet sync dropped evidence"
    elif missing_cols:
        message = "Network schema is missing dashboard columns"
    elif blocking_events:
        message = "Fleet sync dropped or failed to store incoming columns"
    elif added_count:
        message = "Fleet sync auto-healed schema drift"
    else:
        message = "Network schema has required dashboard columns"

    return _health_status(
        "degraded" if missing_cols or blocking_events else "healthy",
        message,
        missing_columns=missing_cols,
        drift_events=events,
        drift_blocking_count=len(blocking_events),
        drift_added_count=added_count,
    )


def _blindness_db_paths():
    """DB candidates that may contain the canonical blindness ledger."""
    root = Path(__file__).resolve().parents[3]
    candidates = [
        os.getenv("MCP_FLEET_DB", ""),
        os.getenv("CC_DB_PATH", ""),
        "server/fleet.db",
        "data/fleet.db",
        "data/fleet_cache.db",
        str(root / "server" / "fleet.db"),
        str(root / "data" / "fleet.db"),
        str(root / "data" / "fleet_cache.db"),
    ]
    try:
        from amoskys.mcp.config import cfg as mcp_cfg

        candidates.insert(0, mcp_cfg.fleet_db)
    except Exception:
        pass

    resolved = []
    seen = set()
    for candidate in candidates:
        if not candidate:
            continue
        path = Path(candidate)
        if not path.is_absolute():
            path = root / path
        key = str(path.resolve(strict=False))
        if key not in seen and path.exists():
            seen.add(key)
            resolved.append(path)
    return resolved


def _collect_blindness_health(store=None, hours=24, device_id=None):
    """Read active blindness events across dashboard and command ledgers."""
    cutoff = time.time() - max(int(hours or 24), 1) * 3600
    events_by_key = {}

    def add_events(events, db_source):
        for event in events:
            event = dict(event)
            event["db_source"] = db_source
            key = event.get("event_key") or (
                f"{db_source}:{event.get('sensor')}:{event.get('kind')}:"
                f"{event.get('device_id')}:{event.get('last_seen')}"
            )
            existing = events_by_key.get(key)
            if not existing or float(event.get("last_seen") or 0) > float(
                existing.get("last_seen") or 0
            ):
                events_by_key[key] = event

    if store is not None and getattr(store, "db", None) is not None:
        add_events(
            list_blindness_events(
                store.db,
                since=cutoff,
                device_id=device_id,
                limit=50,
            ),
            "telemetry_store",
        )

    for path in _blindness_db_paths():
        try:
            conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=2)
            conn.row_factory = sqlite3.Row
            try:
                add_events(
                    list_blindness_events(
                        conn,
                        since=cutoff,
                        device_id=device_id,
                        limit=50,
                    ),
                    str(path),
                )
            finally:
                conn.close()
        except Exception:
            continue

    esf_event = inspect_esf_authorization(device_id=device_id)
    if esf_event:
        add_events([esf_event], "local_esf_authorization_probe")

    events = sorted(
        events_by_key.values(),
        key=lambda event: float(event.get("last_seen") or 0),
        reverse=True,
    )[:50]
    summary = summarize_blindness_events(events)
    summary.update(
        {
            "checked_at": time.time(),
            "hours": hours,
            "device_id": device_id,
        }
    )
    return summary


def _flatten_incident_timeline_entries(entries):
    """Flatten TelemetryStore incident timeline entries for replay."""
    flattened = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        data = entry.get("data") if isinstance(entry.get("data"), dict) else {}
        if data.get("_collapsed"):
            continue
        base = dict(data)
        if "timestamp_ns" not in base and entry.get("ts") is not None:
            base["timestamp_ns"] = entry.get("ts")
        flattened.append(
            _normalize_replay_event(base, source=str(entry.get("source") or "unknown"))
        )
    return flattened


# ═══════════════════════════════════════════════════════════════════════════════
# Observatory API Endpoints — Wire observability pipeline data to dashboard
# ═══════════════════════════════════════════════════════════════════════════════


# ── Device Posture ──


@dashboard_bp.route("/api/posture/summary")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def posture_summary():
    """Device posture — Nerve Signal Model (v1).

    Returns posture_score (0-100) computed via signal classification,
    time-decay, and tanh mapping.  Backwards compatible: includes
    domain breakdown, total_events, security_detections.
    """
    store = _get_store()
    if not store:
        return jsonify({"status": "error", "message": _MSG_DB_UNAVAILABLE})
    hours = request.args.get("hours", 24, type=int)
    device_id = request.args.get("device_id") or None
    return jsonify(store.compute_nerve_posture(hours, device_id=device_id))


@dashboard_bp.route("/api/posture/timeline")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def posture_timeline():
    """Unified cross-domain event timeline."""
    store = _get_store()
    if not store:
        return jsonify([])
    hours = request.args.get("hours", 24, type=int)
    limit = request.args.get("limit", 200, type=int)
    device_id = request.args.get("device_id") or None
    return jsonify(
        store.get_cross_domain_timeline(hours, min(limit, 500), device_id=device_id)
    )


# ── Signals (Directive 3) ──


@dashboard_bp.route("/api/signals")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def list_signals():
    """List signals with optional status filter."""
    store = _get_store()
    if not store:
        return jsonify([])
    status = request.args.get("status")
    limit = request.args.get("limit", 50, type=int)
    return jsonify(store.get_signals(status=status, limit=min(limit, 200)))


@dashboard_bp.route("/api/signals", methods=["POST"])
@require_login
def create_signal_api():
    """Manually create a signal (analyst-initiated)."""
    store = _get_store()
    if not store:
        return jsonify({"status": "error", "message": _MSG_DB_UNAVAILABLE}), 500
    data = request.get_json(silent=True) or {}
    required = ("device_id", "signal_type", "trigger_summary")
    for field in required:
        if not data.get(field):
            return (
                jsonify({"status": "error", "message": f"Missing: {field}"}),
                400,
            )
    signal_id = store.create_signal(
        device_id=data["device_id"],
        signal_type=data.get("signal_type", "manual"),
        trigger_summary=data["trigger_summary"],
        contributing_event_ids=data.get("contributing_event_ids", []),
        risk_score=data.get("risk_score", 0.5),
    )
    return jsonify({"status": "ok", "signal_id": signal_id}), 201


@dashboard_bp.route("/api/signals/<signal_id>/promote", methods=["POST"])
@require_login
def promote_signal(signal_id):
    """Promote a signal to an incident."""
    store = _get_store()
    if not store:
        return jsonify({"status": "error", "message": _MSG_DB_UNAVAILABLE}), 500
    incident_id = store.promote_signal(signal_id)
    if incident_id:
        return jsonify({"status": "ok", "incident_id": incident_id})
    return jsonify({"status": "error", "message": "Signal not found or not open"}), 404


@dashboard_bp.route("/api/signals/<signal_id>/dismiss", methods=["POST"])
@require_login
def dismiss_signal(signal_id):
    """Dismiss a signal with reason."""
    store = _get_store()
    if not store:
        return jsonify({"status": "error", "message": _MSG_DB_UNAVAILABLE}), 500
    data = request.get_json(silent=True) or {}
    ok = store.dismiss_signal(
        signal_id,
        dismissed_by=data.get("dismissed_by", "analyst"),
        reason=data.get("reason", ""),
    )
    if ok:
        return jsonify({"status": "ok"})
    return jsonify({"status": "error", "message": "Signal not found or not open"}), 404


@dashboard_bp.route("/api/incidents/<int:incident_id>/timeline")
@require_login
@require_rate_limit(max_requests=30, window_seconds=60)
def incident_timeline(incident_id):
    """Get cross-agent investigation timeline for an incident."""
    store = _get_store()
    if not store:
        return jsonify([])
    incident = store.get_incident(incident_id)
    if not incident:
        return jsonify({"status": "error", "message": "Incident not found"}), 404

    evidence_events = _load_incident_replay_events(store, incident)
    if evidence_events:
        return jsonify(evidence_events)

    device_id = incident.get("device_id") or incident.get("assignee", "")
    # Use incident time window or default to last 24h
    end_ns = int(time.time() * 1e9)
    start_ns = end_ns - int(24 * 3600 * 1e9)
    if incident.get("created_at"):
        try:
            from datetime import datetime as _dt

            created = _dt.fromisoformat(incident["created_at"].replace("Z", "+00:00"))
            start_ns = int(created.timestamp() * 1e9) - int(3600 * 1e9)  # 1h before
        except (ValueError, TypeError):
            pass
    # Extract device_id from title/description (fusion incidents embed it)
    # Format: "[rule] DESCRIPTION on DEVICE_ID: ..."
    if not device_id:
        for field in ("title", "description"):
            text = incident.get(field, "")
            m = re.search(r" on ([A-Za-z0-9._-]+\.local)\b", text)
            if not m:
                m = re.search(r" on ([A-Za-z0-9._-]+):", text)
            if m:
                device_id = m.group(1)
                break
    # Fallback: try device_id from linked security events
    if not device_id:
        try:
            event_ids = json.loads(incident.get("source_event_ids", "[]"))
            if event_ids:
                # source_event_ids may be probe string IDs, try integer lookup first
                row = store.db.execute(
                    "SELECT device_id FROM security_events WHERE id = ?",
                    (event_ids[0],),
                ).fetchone()
                if row:
                    device_id = row[0]
        except Exception:
            pass
    if not device_id:
        return jsonify([])
    timeline = store.build_incident_timeline(device_id, start_ns, end_ns)
    return jsonify(_flatten_incident_timeline_entries(timeline))


# ── DNS Intelligence ──


def _store_unavailable(payload_shape):
    """The answer when there is no store to ask.

    These endpoints used to return a *successful* empty result — HTTP 200 with
    ``[]`` or ``{"total_queries": 0}``. The DNS page read that as evidence and
    printed "DNS resolution patterns appear healthy with no anomalous activity
    detected." over a store it had never reached. Zero queries observed is not a
    clean bill; on a live machine it is itself an alarm.

    503 is the honest code: the service is fine, the thing behind it is not, and
    the client's existing failure paths already say so out loud. The body keeps
    the caller's expected shape so anything that ignores the status still gets a
    structure it can iterate rather than a TypeError.
    """
    if isinstance(payload_shape, dict):
        body = {"available": False, "error": "telemetry store unavailable"}
        body.update(payload_shape)
        return jsonify(body), 503
    # List endpoints: the shape is an array, so the flag rides in the header.
    response = jsonify([])
    response.status_code = 503
    response.headers["X-Amoskys-Unavailable"] = "telemetry store unavailable"
    return response


@dashboard_bp.route("/api/dns/stats")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def dns_stats():
    """DNS query analytics."""
    store = _get_store()
    if not store:
        return _store_unavailable({"total_queries": None})
    hours = request.args.get("hours", 24, type=int)
    device_id = request.args.get("device_id") or None
    stats = store.get_dns_stats(hours, device_id=device_id)
    # JS expects 'response_codes' (not 'by_response_code') and 'nxdomain_count'
    rc = stats.pop("by_response_code", {})
    stats["response_codes"] = rc
    stats.setdefault("nxdomain_count", rc.get("NXDOMAIN", 0))
    return jsonify(stats)


@dashboard_bp.route("/api/dns/top-domains")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def dns_top_domains():
    """Top queried domains."""
    store = _get_store()
    if not store:
        return _store_unavailable([])
    hours = request.args.get("hours", 24, type=int)
    limit = request.args.get("limit", 20, type=int)
    device_id = request.args.get("device_id") or None
    return jsonify(
        store.get_dns_top_domains(hours, min(limit, 100), device_id=device_id)
    )


@dashboard_bp.route("/api/dns/dga")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def dns_dga():
    """DGA suspect domains."""
    store = _get_store()
    if not store:
        return _store_unavailable([])
    hours = request.args.get("hours", 24, type=int)
    min_score = request.args.get("min_score", 0.5, type=float)
    limit = request.args.get("limit", 50, type=int)
    device_id = request.args.get("device_id") or None
    return jsonify(
        store.get_dns_dga_suspects(
            hours, min_score, min(limit, 200), device_id=device_id
        )
    )


@dashboard_bp.route("/api/dns/beaconing")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def dns_beaconing():
    """Beaconing domain detection."""
    store = _get_store()
    if not store:
        return _store_unavailable([])
    hours = request.args.get("hours", 24, type=int)
    limit = request.args.get("limit", 50, type=int)
    device_id = request.args.get("device_id") or None
    return jsonify(store.get_dns_beaconing(hours, min(limit, 200), device_id=device_id))


@dashboard_bp.route("/api/dns/timeline")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def dns_timeline():
    """DNS query timeline."""
    store = _get_store()
    if not store:
        return _store_unavailable([])
    hours = request.args.get("hours", 24, type=int)
    device_id = request.args.get("device_id") or None
    return jsonify(store.get_dns_timeline(hours, device_id=device_id))


@dashboard_bp.route("/api/dns/recent")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def dns_recent():
    """Recent DNS events with search."""
    store = _get_store()
    if not store:
        return _store_unavailable({"results": [], "total_count": None})
    hours = request.args.get("hours", 24, type=int)
    limit = request.args.get("limit", 100, type=int)
    offset = request.args.get("offset", 0, type=int)
    search = request.args.get("search", "")
    device_id = request.args.get("device_id") or None
    return jsonify(
        store.search_events(
            search, "dns_events", hours, min(limit, 500), offset, device_id=device_id
        )
    )


# ── Network Intelligence ──


@dashboard_bp.route("/api/network/stats")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def network_flow_stats():
    """Network flow summary."""
    store = _get_store()
    if not store:
        # Was a bare {"total_flows": 0}. The Network Intelligence page turns
        # that into "No network flows recorded from <device> in the past 24
        # hours" — i.e. an unreachable telemetry store was reported to the
        # operator as a clean network. Say "unavailable" so the UI can show
        # the visibility gap instead of a false all-clear.
        return jsonify(
            {
                "available": False,
                "error": "telemetry_store_unavailable",
                "total_flows": 0,
            }
        )
    hours = request.args.get("hours", 24, type=int)
    device_id = request.args.get("device_id") or None
    stats = store.get_flow_stats(hours, device_id=device_id)

    # Whether the byte counters are populated at all. Without this the page
    # renders an unmeasured field as a confident "0 B" — measured live, 99.64%
    # of flows carry bytes_tx = bytes_rx = 0 as literal zeros, so almost every
    # volume figure on the network page was a measurement that never happened.
    try:
        from . import insight_service

        db_path = insight_service.resolve_db_path()
        if db_path:
            db = insight_service._connect(db_path)
            try:
                stats["byte_accounting"] = insight_service.byte_accounting(
                    db, device_id=device_id
                )
            finally:
                db.close()
    except Exception:  # pragma: no cover - never break the page over this
        logger.debug("byte accounting unavailable", exc_info=True)
    return jsonify(stats)


@dashboard_bp.route("/api/network/visibility-health")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def network_visibility_health():
    """Health contract behind the Network Intelligence clean/unknown verdict."""
    store = _get_store()
    hours = request.args.get("hours", 24, type=int)
    device_id = request.args.get("device_id") or None
    blindness = _collect_blindness_health(store, hours, device_id)
    if not store:
        return jsonify(
            {
                "overall": "degraded",
                "sensor": _health_status("degraded", _MSG_DB_UNAVAILABLE),
                "schema": _health_status(
                    "unknown",
                    "flow_events schema could not be inspected",
                    missing_columns=sorted(_NETWORK_SCHEMA_COLUMNS),
                ),
                "geoip": _coverage_status("GeoIP", 0, 0),
                "asn": _coverage_status("ASN", 0, 0),
                "threat_intel": _threat_intel_health(store),
                "blindness": blindness,
                "quality": {},
            }
        )

    cutoff_ns = int((time.time() - hours * 3600) * 1e9)
    cols = _table_columns(store.db, "flow_events")
    missing_cols = sorted(_NETWORK_SCHEMA_COLUMNS - cols)
    schema = _schema_health(store.db, missing_cols, hours)

    if "timestamp_ns" not in cols:
        return jsonify(
            {
                "overall": "degraded",
                "sensor": _health_status(
                    "degraded", "flow_events has no timestamp_ns column"
                ),
                "schema": schema,
                "geoip": _coverage_status("GeoIP", 0, 0),
                "asn": _coverage_status("ASN", 0, 0),
                "threat_intel": _threat_intel_health(store),
                "blindness": blindness,
                "quality": {},
            }
        )

    where = "timestamp_ns > ?"
    params = [cutoff_ns]
    if device_id and "device_id" in cols:
        where += " AND device_id = ?"
        params.append(device_id)

    def scalar(sql, values=None):
        try:
            row = store.db.execute(sql, values or ()).fetchone()
            return row[0] if row else None
        except Exception:
            return None

    total = int(scalar(f"SELECT COUNT(*) FROM flow_events WHERE {where}", params) or 0)
    latest_ns = scalar(
        f"SELECT MAX(timestamp_ns) FROM flow_events WHERE {where}", params
    )
    latest_age_s = None
    if latest_ns:
        latest_age_s = max(0.0, round(time.time() - (int(latest_ns) / 1e9), 1))

    if total <= 0:
        sensor = _health_status(
            "unknown",
            "No network flows in the selected window",
            total_flows=0,
            latest_ns=latest_ns,
            latest_age_s=latest_age_s,
        )
    elif latest_age_s is not None and latest_age_s <= 600:
        sensor = _health_status(
            "healthy",
            "Network telemetry is fresh",
            total_flows=total,
            latest_ns=latest_ns,
            latest_age_s=latest_age_s,
        )
    else:
        sensor = _health_status(
            "degraded",
            "Network telemetry is stale",
            total_flows=total,
            latest_ns=latest_ns,
            latest_age_s=latest_age_s,
        )

    geo_count = 0
    if {"geo_dst_country", "geo_dst_latitude"} & cols:
        geo_parts = []
        if "geo_dst_country" in cols:
            geo_parts.append("(geo_dst_country IS NOT NULL AND geo_dst_country != '')")
        if "geo_dst_latitude" in cols:
            geo_parts.append("(geo_dst_latitude IS NOT NULL AND geo_dst_latitude != 0)")
        geo_count = int(
            scalar(
                f"SELECT COUNT(*) FROM flow_events WHERE {where} AND ({' OR '.join(geo_parts)})",
                params,
            )
            or 0
        )

    asn_count = 0
    if "asn_dst_org" in cols:
        asn_count = int(
            scalar(
                f"SELECT COUNT(*) FROM flow_events WHERE {where} "
                "AND asn_dst_org IS NOT NULL AND asn_dst_org != ''",
                params,
            )
            or 0
        )

    quality = {}
    if "quality_state" in cols:
        try:
            rows = store.db.execute(
                f"SELECT COALESCE(quality_state, 'valid'), COUNT(*) "
                f"FROM flow_events WHERE {where} GROUP BY 1",
                params,
            ).fetchall()
            quality = {str(r[0] or "valid"): int(r[1] or 0) for r in rows}
        except Exception:
            quality = {}

    agents = []
    if "collection_agent" in cols:
        try:
            rows = store.db.execute(
                f"SELECT collection_agent, COUNT(*) FROM flow_events WHERE {where} "
                "AND collection_agent IS NOT NULL AND collection_agent != '' "
                "GROUP BY collection_agent ORDER BY COUNT(*) DESC LIMIT 5",
                params,
            ).fetchall()
            agents = [{"name": r[0], "count": int(r[1] or 0)} for r in rows]
        except Exception:
            agents = []

    threat_intel = _threat_intel_health(store)
    geoip = _coverage_status("GeoIP", total, geo_count)
    asn = _coverage_status("ASN", total, asn_count)
    blockers = [
        sensor["status"] == "degraded",
        schema["status"] == "degraded",
        threat_intel["status"] == "degraded",
        blindness["status"] in ("degraded", "blind", "unauthorized"),
    ]
    if blindness["status"] in ("blind", "unauthorized"):
        overall = "blind"
    else:
        overall = (
            "degraded" if any(blockers) else ("unknown" if total <= 0 else "healthy")
        )

    return jsonify(
        {
            "overall": overall,
            "sensor": sensor,
            "schema": schema,
            "geoip": geoip,
            "asn": asn,
            "threat_intel": threat_intel,
            "blindness": blindness,
            "quality": quality,
            "agents": agents,
            "checked_at": time.time(),
            "hours": hours,
            "device_id": device_id,
        }
    )


@dashboard_bp.route("/api/health/blindness")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def health_blindness():
    """Canonical active blindness stream across dashboard and command ledgers."""
    hours = request.args.get("hours", 24, type=int)
    device_id = request.args.get("device_id") or None
    return jsonify(_collect_blindness_health(_get_store(), hours, device_id))


@dashboard_bp.route("/api/network/geo")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def network_geo():
    """GeoIP destination aggregation."""
    store = _get_store()
    if not store:
        return jsonify({"countries": [], "cities": []})
    hours = request.args.get("hours", 24, type=int)
    device_id = request.args.get("device_id") or None
    return jsonify(store.get_flow_geo_stats(hours, device_id=device_id))


@dashboard_bp.route("/api/network/asn")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def network_asn():
    """ASN breakdown."""
    store = _get_store()
    if not store:
        return jsonify([])
    hours = request.args.get("hours", 24, type=int)
    device_id = request.args.get("device_id") or None
    return jsonify(store.get_flow_asn_breakdown(hours, device_id=device_id))


@dashboard_bp.route("/api/network/device-location")
@require_login
@require_rate_limit(max_requests=10, window_seconds=60)
def network_device_location():
    """Get device location via GeoIP on the device's public IP.

    In fleet mode, gets the public_ip from the ops server device record
    and resolves it with local GeoIP databases.
    """
    import os as _os

    device_id = request.args.get("device_id") or None

    # Fleet mode: get public IP from ops server, then GeoIP it locally
    if _os.environ.get("AMOSKYS_OPS_SERVER"):
        try:
            from .routes_command_center import _ops_get

            data = _ops_get("/api/v1/devices")
            if data and data.get("devices"):
                devices = data["devices"]
                if device_id:
                    devices = [d for d in devices if d.get("device_id") == device_id]
                public_ip = devices[0].get("public_ip") if devices else None
                if public_ip:
                    geo = _geoip_lookup(public_ip)
                    if geo:
                        return jsonify(geo)
        except Exception:
            pass

    # Local mode: try flow_events source geo
    store = _get_store()
    if store:
        try:
            dev_sql = " AND device_id = ?" if device_id else ""
            dev_params: tuple = (device_id,) if device_id else ()
            row = store.db.execute(
                f"""SELECT geo_src_latitude, geo_src_longitude, geo_src_city,
                          geo_src_country, asn_src_org, src_ip
                   FROM flow_events
                   WHERE geo_src_latitude IS NOT NULL AND geo_src_latitude != ''{dev_sql}
                   ORDER BY timestamp_ns DESC LIMIT 1""",
                dev_params,
            ).fetchone()
            if row and row[0]:
                return jsonify(
                    {
                        "lat": float(row[0]),
                        "lon": float(row[1]),
                        "city": row[2] or "",
                        "country": row[3] or "",
                        "org": row[4] or "",
                        "ip": row[5] or "",
                    }
                )
        except Exception:
            pass

    return jsonify({"lat": 0, "lon": 0, "city": "Unknown", "country": ""})


def _geoip_lookup(ip: str):
    """Resolve an IP to lat/lon/city/country using local GeoIP databases."""
    try:
        from amoskys.enrichment.geoip import GeoIPEnricher

        enricher = GeoIPEnricher()
        result = enricher.lookup(ip)
        if result and result.get("latitude"):
            return {
                "lat": result["latitude"],
                "lon": result["longitude"],
                "city": result.get("city", ""),
                "country": result.get("country_code", ""),
                "region": result.get("region", ""),
                "org": result.get("org", ""),
                "ip": ip,
            }
    except Exception:
        pass
    # Fallback: try ipinfo.io for the specific device IP (not the server's IP)
    try:
        import requests

        resp = requests.get(f"https://ipinfo.io/{ip}/json", timeout=3)
        if resp.ok:
            d = resp.json()
            loc = d.get("loc", "0,0").split(",")
            return {
                "lat": float(loc[0]),
                "lon": float(loc[1]),
                "city": d.get("city", ""),
                "country": d.get("country", ""),
                "region": d.get("region", ""),
                "org": d.get("org", ""),
                "ip": ip,
            }
    except Exception:
        pass
    return None


@dashboard_bp.route("/api/network/geo-points")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def network_geo_points():
    """Lat/lon points for world map, with country centroid fallback."""
    store = _get_store()
    if not store:
        return jsonify([])
    hours = request.args.get("hours", 24, type=int)
    limit = request.args.get("limit", 500, type=int)
    device_id = request.args.get("device_id") or None
    points = store.get_flow_geo_points(hours, min(limit, 1000), device_id=device_id)

    # Also grab flows that have country but no lat/lon — use centroid
    try:
        import time

        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        dev_sql = "AND device_id = ? " if device_id else ""
        dev_params: tuple = (device_id,) if device_id else ()
        rows = store.db.execute(
            "SELECT geo_dst_country, COUNT(*) as cnt, "
            "SUM(COALESCE(bytes_tx,0)+COALESCE(bytes_rx,0)) as total_bytes, "
            "asn_dst_org, MAX(CASE WHEN threat_intel_match=1 THEN 1 ELSE 0 END) as threat "
            "FROM flow_events WHERE timestamp_ns > ? "
            f"{dev_sql}"
            "AND (geo_dst_latitude IS NULL OR geo_dst_latitude = 0) "
            "AND geo_dst_country IS NOT NULL AND geo_dst_country != '' "
            "GROUP BY geo_dst_country ORDER BY cnt DESC LIMIT 50",
            (cutoff_ns, *dev_params),
        ).fetchall()
        for r in rows:
            centroid = _COUNTRY_CENTROIDS.get(r[0])
            if centroid:
                points.append(
                    {
                        "lat": centroid[0],
                        "lon": centroid[1],
                        "country": r[0],
                        "city": "",
                        "count": r[1],
                        "bytes": r[2] or 0,
                        "asn_org": r[3] or "",
                        "threat": bool(r[4]),
                    }
                )
    except Exception:
        pass

    return jsonify(points)


# Country centroids for flows with country but no lat/lon
_COUNTRY_CENTROIDS = {
    "US": (39.8, -98.5),
    "GB": (51.5, -0.1),
    "DE": (51.2, 10.4),
    "FR": (46.2, 2.2),
    "JP": (35.7, 139.7),
    "AU": (-25.3, 133.8),
    "NL": (52.1, 5.3),
    "IE": (53.1, -7.7),
    "CA": (56.1, -106.3),
    "BR": (-14.2, -51.9),
    "IN": (20.6, 78.9),
    "SG": (1.4, 103.8),
    "KR": (35.9, 127.8),
    "SE": (60.1, 18.6),
    "CH": (46.8, 8.2),
    "IT": (41.9, 12.6),
    "ES": (40.5, -3.7),
    "RU": (61.5, 105.3),
    "CN": (35.9, 104.2),
    "HK": (22.3, 114.2),
    "ZA": (-30.6, 22.9),
    "MX": (23.6, -102.6),
    "AR": (-38.4, -63.6),
    "CL": (-35.7, -71.5),
    "PL": (51.9, 19.1),
    "NO": (60.5, 8.5),
    "FI": (61.9, 25.7),
    "DK": (56.3, 9.5),
    "AT": (47.5, 14.6),
    "BE": (50.5, 4.5),
    "PT": (39.4, -8.2),
    "CZ": (49.8, 15.5),
    "RO": (45.9, 25.0),
    "IL": (31.0, 34.8),
    "TW": (23.7, 121.0),
    "NZ": (-40.9, 174.9),
    "TH": (15.9, 100.9),
    "MY": (4.2, 101.9),
    "PH": (12.9, 121.8),
    "ID": (-0.8, 113.9),
    "VN": (14.1, 108.3),
    "AE": (23.4, 53.8),
    "SA": (23.9, 45.1),
    "NG": (9.1, 8.7),
    "EG": (26.8, 30.8),
    "CO": (4.6, -74.3),
    "UA": (48.4, 31.2),
    "TR": (39.0, 35.2),
}


@dashboard_bp.route("/api/network/top-destinations")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def network_top_destinations():
    """Top destination IPs."""
    store = _get_store()
    if not store:
        return jsonify([])
    hours = request.args.get("hours", 24, type=int)
    limit = request.args.get("limit", 20, type=int)
    device_id = request.args.get("device_id") or None
    return jsonify(
        store.get_flow_top_destinations(hours, min(limit, 100), device_id=device_id)
    )


@dashboard_bp.route("/api/network/by-process")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def network_by_process():
    """Network usage by process."""
    store = _get_store()
    if not store:
        return jsonify([])
    hours = request.args.get("hours", 24, type=int)
    limit = request.args.get("limit", 20, type=int)
    device_id = request.args.get("device_id") or None
    return jsonify(
        store.get_flow_by_process(hours, min(limit, 100), device_id=device_id)
    )


@dashboard_bp.route("/api/network/connection-story/ask", methods=["POST"])
@require_login
@require_rate_limit(max_requests=10, window_seconds=60)
def network_connection_story_ask():
    """Hand ONE connection to IGRIS, with the evidence already assembled.

    The chat widget can already answer questions about the fleet, but a person
    looking at a line on the globe should not have to describe what they are
    looking at. The context is built HERE, server-side, from the same story the
    page is showing — so IGRIS is answering about the connection in front of the
    user rather than about whatever the browser managed to phrase, and a client
    cannot invent facts for it to reason over.

    The question stays the user's; only the evidence is supplied.
    """
    data = request.get_json(silent=True) or {}
    dst_ip = (data.get("dst_ip") or "").strip()
    question = (data.get("question") or "").strip()
    hours = int(data.get("hours") or 24)
    device_id = data.get("device_id") or None
    if not dst_ip:
        return jsonify({"status": "error", "message": "dst_ip required"}), 400

    store = _get_store()
    if not store:
        return (
            jsonify(
                {
                    "status": "error",
                    "message": "The telemetry store is unreachable, so there is "
                    "no evidence to hand IGRIS. This is not a clean bill.",
                }
            ),
            503,
        )
    hours = max(1, min(hours, 24 * 14))
    try:
        story = store.get_connection_story(dst_ip, hours=hours, device_id=device_id)
    except Exception:
        logger.warning("connection story failed for %s", dst_ip, exc_info=True)
        return jsonify({"status": "error", "message": "story_query_failed"}), 500

    if not story.get("found"):
        return (
            jsonify(
                {
                    "status": "error",
                    "message": "No flows to that destination in this window, so "
                    "there is nothing to explain yet.",
                }
            ),
            404,
        )

    context = _story_as_prompt(story, dst_ip, hours)
    ask = question or (
        "Explain this connection to me in plain language: why does it exist, "
        "is it expected on my machine, and is there anything here I should act on?"
    )

    from .routes_igris import _get_igris_chat

    chat = _get_igris_chat()
    if chat is None:
        return (
            jsonify(
                {
                    "status": "error",
                    "message": "IGRIS is unavailable on this server "
                    "(ANTHROPIC_API_KEY is not configured).",
                    "context": context,
                }
            ),
            503,
        )
    try:
        answer = chat.chat(f"{context}\n\nThe person asks: {ask}")
        return jsonify(
            {
                "status": "success",
                "response": answer,
                "evidence": chat.get_last_evidence(),
                "context_sent": context,
                "dst_ip": dst_ip,
            }
        )
    except Exception as e:
        logger.error("connection-story ask failed: %s", e)
        return jsonify({"status": "error", "message": str(e)}), 500


def _story_as_prompt(story: dict, dst_ip: str, hours: int) -> str:
    """Flatten the assembled story into facts IGRIS can reason over.

    Deliberately states what is MISSING as well as what is known — an unmeasured
    byte counter and a genuinely idle connection look identical in a number, and
    an analyst told "0 B" without that distinction will draw the wrong
    conclusion just as readily as a person would.
    """
    what = story.get("what") or {}
    where = story.get("where") or {}
    why = story.get("why") or {}
    who = story.get("who") or []

    lines = [
        "You are being asked about ONE outbound destination from the user's Mac.",
        "Here is everything AMOSKYS holds about it. Do not look up anything else "
        "unless it is needed to answer.",
        "",
        f"DESTINATION: {dst_ip}",
        f"WINDOW: last {hours}h",
        f"WHERE: {where.get('city') or 'unknown city'}, "
        f"{where.get('country') or 'unknown country'} — "
        f"owned by {where.get('asn_org') or 'an unattributed network'}",
        f"CONNECTIONS: {what.get('flows') or 0}",
        f"PORTS: {', '.join(str(p.get('port')) for p in (what.get('ports') or [])[:6]) or 'unknown'}",
        f"FIRST SEEN: {what.get('first_seen') or 'unknown'} · LAST SEEN: {what.get('last_seen') or 'unknown'}",
    ]

    measured = what.get("bytes_measured")
    if measured is False:
        lines.append(
            "VOLUME: NOT MEASURED. The byte counters are not populated for these "
            "flows, so treat any zero as missing data — do NOT tell the user this "
            "connection moved no data."
        )
    else:
        lines.append(f"VOLUME: {what.get('bytes') or 0} bytes")

    if who:
        lines.append("WHICH PROCESSES OPENED IT:")
        for p in who[:5]:
            chain = " <- ".join(a.get("name", "?") for a in (p.get("ancestry") or []))
            lines.append(
                f"  - {p.get('name') or '?'}"
                + (f" (ancestry: {chain})" if chain else "")
                + f" · code signing: {p.get('code_signing') or 'unknown'}"
            )
    else:
        lines.append(
            "WHICH PROCESSES OPENED IT: not attributable from the data on this tier."
        )

    if why:
        lines.append("CORROBORATION LEDGER (why AMOSKYS rated it as it did):")
        for key, value in why.items():
            lines.append(f"  - {key}: {value}")

    lines += [
        "",
        "Answer in plain language for the owner of the machine, not an analyst. "
        "Be specific about what this counterparty is and what normally talks to "
        "it. If the evidence does not support a conclusion, say so rather than "
        "guessing, and never describe unmeasured volume as zero traffic.",
    ]
    return "\n".join(lines)


@dashboard_bp.route("/api/network/connection-story")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def network_connection_story():
    """Assemble ONE destination into a narrative a human can act on.

    The rest of this page reports aggregates — bars by country, by ASN, by
    process. Aggregates tell you the shape of the traffic and nothing about
    whether any of it matters. This assembles the four things an analyst
    actually asks about a single destination, from tables that already hold
    them and were simply never joined:

        WHAT   flow_events        volume, ports, protocol, first/last seen
        WHO    process_genealogy  the process AND its ancestry + code signing
        WHERE  flow_events        geo city/country + the ASN org that OWNS it
        WHY    the corroboration ledger, below

    The ledger is the point. Every other security console shows a verdict.
    This shows the EVIDENCE FOR the verdict, including — deliberately — the
    evidence that is missing. AMOSKYS caps an uncorroborated attack category
    at "suspicious" rather than escalating it (scoring.py's corroboration
    gate), and an operator who cannot see WHY a thing was capped has no reason
    to trust either the cap or the escalation. So the response says, in as many
    words, "I would rate this higher but nothing independent supports it."

    Note on naming: macOS masks DNS names in the unified log as
    <mask.hash: 'xxx'>, so the resolved domain genuinely is not recoverable
    here. The ASN organisation is the naming layer instead — and it is the
    better one, because "Anthropic, PBC" identifies the counterparty where a
    domain only labels it.
    """
    store = _get_store()
    if not store:
        return jsonify({"available": False, "error": "telemetry_store_unavailable"})

    dst_ip = (request.args.get("dst_ip") or "").strip()
    if not dst_ip:
        return jsonify({"available": False, "error": "dst_ip required"}), 400
    # Clamped both ends: a negative or absurd window is a full-table scan.
    hours = max(1, min(request.args.get("hours", 24, type=int) or 24, 24 * 14))
    device_id = request.args.get("device_id") or None

    try:
        story = store.get_connection_story(dst_ip, hours=hours, device_id=device_id)
    except Exception:
        logger.warning("connection story failed for %s", dst_ip, exc_info=True)
        return jsonify({"available": False, "error": "story_query_failed"})
    return jsonify(story)


@dashboard_bp.route("/api/network/flows")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def network_flows():
    """Recent flow events with search."""
    store = _get_store()
    if not store:
        return jsonify({"results": [], "total_count": 0})
    hours = request.args.get("hours", 24, type=int)
    limit = request.args.get("limit", 100, type=int)
    offset = request.args.get("offset", 0, type=int)
    search = request.args.get("search", "")
    device_id = request.args.get("device_id") or None
    return jsonify(
        store.search_events(
            search, "flow_events", hours, min(limit, 500), offset, device_id=device_id
        )
    )


# ── File Integrity ──


@dashboard_bp.route("/api/fim/stats")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def fim_stats():
    """File integrity monitoring summary."""
    store = _get_store()
    if not store:
        return jsonify({"total_changes": 0})
    hours = request.args.get("hours", 24, type=int)
    device_id = request.args.get("device_id") or None
    stats = store.get_fim_stats(hours, device_id=device_id)
    # JS expects 'total' (not 'total_changes')
    stats["total"] = stats.get("total_changes", 0)
    return jsonify(stats)


@dashboard_bp.route("/api/fim/critical")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def fim_critical():
    """High-risk file changes."""
    store = _get_store()
    if not store:
        return jsonify([])
    hours = request.args.get("hours", 24, type=int)
    min_risk = request.args.get("min_risk", 0.3, type=float)
    limit = request.args.get("limit", 100, type=int)
    device_id = request.args.get("device_id") or None
    return jsonify(
        store.get_fim_critical_changes(
            hours, min_risk, min(limit, 500), device_id=device_id
        )
    )


@dashboard_bp.route("/api/fim/directories")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def fim_directories():
    """File changes by directory."""
    store = _get_store()
    if not store:
        return jsonify([])
    hours = request.args.get("hours", 24, type=int)
    device_id = request.args.get("device_id") or None
    return jsonify(store.get_fim_directory_summary(hours, device_id=device_id))


@dashboard_bp.route("/api/fim/timeline")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def fim_timeline():
    """FIM event timeline."""
    store = _get_store()
    if not store:
        return jsonify([])
    hours = request.args.get("hours", 24, type=int)
    device_id = request.args.get("device_id") or None
    return jsonify(store.get_fim_timeline(hours, device_id=device_id))


@dashboard_bp.route("/api/fim/recent")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def fim_recent():
    """Recent FIM events with search."""
    store = _get_store()
    if not store:
        return jsonify({"results": [], "total_count": 0})
    hours = request.args.get("hours", 24, type=int)
    limit = request.args.get("limit", 100, type=int)
    offset = request.args.get("offset", 0, type=int)
    search = request.args.get("search", "")
    device_id = request.args.get("device_id") or None
    return jsonify(
        store.search_events(
            search, "fim_events", hours, min(limit, 500), offset, device_id=device_id
        )
    )


# ── Persistence Landscape ──


@dashboard_bp.route("/api/persistence/stats")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def persistence_stats():
    """Persistence mechanism summary."""
    store = _get_store()
    if not store:
        return jsonify({"total_entries": 0})
    hours = request.args.get("hours", 24, type=int)
    device_id = request.args.get("device_id") or None
    stats = store.get_persistence_stats(hours, device_id=device_id)
    # JS expects 'mechanism_counts' (not 'by_mechanism'),
    # 'change_type_counts' (not 'by_change_type'), and 'total_changes'
    stats["mechanism_counts"] = stats.pop("by_mechanism", {})
    stats["change_type_counts"] = stats.pop("by_change_type", {})
    stats.setdefault("total_changes", sum(stats["change_type_counts"].values()))
    return jsonify(stats)


@dashboard_bp.route("/api/persistence/inventory")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def persistence_inventory():
    """Persistence entry inventory."""
    store = _get_store()
    if not store:
        return jsonify([])
    mechanism = request.args.get("mechanism")
    limit = request.args.get("limit", 200, type=int)
    device_id = request.args.get("device_id") or None
    entries = store.get_persistence_inventory(
        mechanism, min(limit, 500), device_id=device_id
    )
    # JS expects {inventory: [...]} or {entries: [...]}, not a flat list
    return jsonify({"inventory": entries})


@dashboard_bp.route("/api/persistence/changes")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def persistence_changes():
    """Persistence modification timeline."""
    store = _get_store()
    if not store:
        return jsonify([])
    hours = request.args.get("hours", 24, type=int)
    device_id = request.args.get("device_id") or None
    raw = store.get_persistence_changes(hours, device_id=device_id)
    # JS expects {buckets: [{label, mechanisms: {mech: count}}, ...]}
    # Store returns flat [{hour, mechanism, count}, ...]
    buckets_map = OrderedDict()
    for row in raw:
        h = row.get("hour", "")
        if h not in buckets_map:
            buckets_map[h] = {"label": h, "mechanisms": {}}
        buckets_map[h]["mechanisms"][row.get("mechanism", "")] = row.get("count", 0)
    return jsonify({"buckets": list(buckets_map.values())})


# ── Auth / Audit ──


@dashboard_bp.route("/api/audit/stats")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def audit_stats():
    """Kernel audit / auth summary."""
    store = _get_store()
    if not store:
        return jsonify({"total_events": 0})
    hours = request.args.get("hours", 24, type=int)
    device_id = request.args.get("device_id") or None
    return jsonify(store.get_audit_stats(hours, device_id=device_id))


@dashboard_bp.route("/api/audit/high-risk")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def audit_high_risk():
    """High-risk audit events."""
    store = _get_store()
    if not store:
        return jsonify([])
    hours = request.args.get("hours", 24, type=int)
    min_risk = request.args.get("min_risk", 0.5, type=float)
    limit = request.args.get("limit", 100, type=int)
    device_id = request.args.get("device_id") or None
    return jsonify(
        store.get_audit_high_risk(hours, min_risk, min(limit, 500), device_id=device_id)
    )


@dashboard_bp.route("/api/audit/recent")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def audit_recent():
    """Recent audit events with search."""
    store = _get_store()
    if not store:
        return jsonify({"results": [], "total_count": 0})
    hours = request.args.get("hours", 24, type=int)
    limit = request.args.get("limit", 100, type=int)
    offset = request.args.get("offset", 0, type=int)
    search = request.args.get("search", "")
    device_id = request.args.get("device_id") or None
    return jsonify(
        store.search_events(
            search, "audit_events", hours, min(limit, 500), offset, device_id=device_id
        )
    )


# ── Observation Domains ──


@dashboard_bp.route("/api/observations/stats")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def observation_stats():
    """Per-domain observation counts."""
    store = _get_store()
    if not store:
        return jsonify({"total": 0, "by_domain": {}})
    hours = request.args.get("hours", 24, type=int)
    device_id = request.args.get("device_id") or None
    return jsonify(store.get_observation_domain_stats(hours, device_id=device_id))


@dashboard_bp.route("/api/observations/<domain>")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def observation_by_domain(domain):
    """Paginated observations for a domain."""
    store = _get_store()
    if not store:
        return jsonify({"results": [], "total_count": 0})
    hours = request.args.get("hours", 24, type=int)
    limit = request.args.get("limit", 100, type=int)
    offset = request.args.get("offset", 0, type=int)
    device_id = request.args.get("device_id") or None
    return jsonify(
        store.get_observations_by_domain(
            domain, hours, min(limit, 500), offset, device_id=device_id
        )
    )


@dashboard_bp.route("/api/observations/search")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def observation_search():
    """Search observation attributes."""
    store = _get_store()
    if not store:
        return jsonify({"results": [], "total_count": 0})
    query = request.args.get("query", "")
    domain = request.args.get("domain")
    hours = request.args.get("hours", 24, type=int)
    limit = request.args.get("limit", 100, type=int)
    device_id = request.args.get("device_id") or None
    return jsonify(
        store.search_observations(
            query, domain, hours, min(limit, 500), device_id=device_id
        )
    )
