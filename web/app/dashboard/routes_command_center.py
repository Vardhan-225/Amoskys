"""Command Center routes — multi-device fleet management.

Provides the Command Center page and API endpoints that query the
fleet database (server/fleet.db or remote Command Center server).
"""

import json
import logging
import os
import sqlite3
import time
from pathlib import Path

from flask import jsonify, render_template, request

from ..middleware import get_current_user, require_login
from . import dashboard_bp

logger = logging.getLogger("web.dashboard.command_center")

# ── Fleet DB access ────────────────────────────────────────────────

# The fleet DB can be:
#   1. Local file (when running Command Center on the same machine)
#   2. Remote API (when Command Center is on a separate server)
# For now, support local file. Remote API can be added later.

_FLEET_DB_PATH = os.getenv(
    "CC_DB_PATH",
    os.path.join(os.getenv("AMOSKYS_DATA", "data"), "fleet.db"),
)

# Also check server/fleet.db as fallback
_FLEET_DB_CANDIDATES = [
    _FLEET_DB_PATH,
    "server/fleet.db",
    "data/fleet.db",
]


def _get_fleet_db() -> sqlite3.Connection | None:
    """Get a read-only connection to the fleet database."""
    for path in _FLEET_DB_CANDIDATES:
        if Path(path).exists():
            try:
                db = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5.0)
                db.row_factory = sqlite3.Row
                return db
            except Exception as e:
                logger.debug("Cannot open fleet DB %s: %s", path, e)
    return None


# ── Pages ──────────────────────────────────────────────────────────

@dashboard_bp.route("/command-center")
@require_login
def command_center_page():
    """Command Center — multi-device fleet view."""
    user = get_current_user()
    embed = request.args.get("embed") == "1"
    return render_template(
        "dashboard/command-center.html",
        user=user,
        embed=embed,
    )


# ── API Endpoints ──────────────────────────────────────────────────

@dashboard_bp.route("/api/command-center/status")
@require_login
def cc_fleet_status():
    """Fleet-wide posture summary for Command Center."""
    db = _get_fleet_db()
    if db is None:
        return jsonify({
            "available": False,
            "message": "Fleet database not found. Start the Command Center server or set AMOSKYS_SERVER on agents to begin shipping telemetry.",
        })

    try:
        now = time.time()

        # Device counts
        total = db.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        online = db.execute(
            "SELECT COUNT(*) FROM devices WHERE last_seen > ?", (now - 300,)
        ).fetchone()[0]

        # Event stats (last 24h)
        day_ago_ns = int((now - 86400) * 1e9)
        total_events = db.execute(
            "SELECT COUNT(*) FROM security_events WHERE timestamp_ns > ?",
            (day_ago_ns,),
        ).fetchone()[0]

        critical = db.execute(
            "SELECT COUNT(*) FROM security_events WHERE timestamp_ns > ? AND risk_score >= 0.8",
            (day_ago_ns,),
        ).fetchone()[0]

        high = db.execute(
            "SELECT COUNT(*) FROM security_events WHERE timestamp_ns > ? AND risk_score >= 0.6 AND risk_score < 0.8",
            (day_ago_ns,),
        ).fetchone()[0]

        # Top categories
        top_categories = db.execute(
            """SELECT event_category, COUNT(*) as cnt, AVG(risk_score) as avg_risk
               FROM security_events
               WHERE timestamp_ns > ? AND risk_score > 0
               GROUP BY event_category
               ORDER BY cnt DESC LIMIT 10""",
            (day_ago_ns,),
        ).fetchall()

        # Top MITRE techniques
        mitre_rows = db.execute(
            """SELECT mitre_techniques FROM security_events
               WHERE timestamp_ns > ? AND mitre_techniques IS NOT NULL
               AND mitre_techniques != '[]'""",
            (day_ago_ns,),
        ).fetchall()

        technique_counts: dict[str, int] = {}
        for row in mitre_rows:
            try:
                raw = row[0]
                techniques = json.loads(raw)
                if isinstance(techniques, str):
                    techniques = json.loads(techniques)
                if isinstance(techniques, list):
                    for t in techniques:
                        if isinstance(t, str) and t.startswith("T"):
                            technique_counts[t] = technique_counts.get(t, 0) + 1
            except (json.JSONDecodeError, TypeError):
                pass

        top_techniques = sorted(technique_counts.items(), key=lambda x: -x[1])[:10]

        # Per-device summary
        device_rows = db.execute(
            """SELECT d.device_id, d.hostname, d.os, d.os_version, d.arch,
                      d.agent_version, d.status, d.last_seen, d.first_seen,
                      COUNT(se.id) as event_count,
                      COALESCE(MAX(se.risk_score), 0) as max_risk,
                      SUM(CASE WHEN se.risk_score >= 0.8 THEN 1 ELSE 0 END) as critical_count,
                      SUM(CASE WHEN se.risk_score >= 0.6 AND se.risk_score < 0.8 THEN 1 ELSE 0 END) as high_count
               FROM devices d
               LEFT JOIN security_events se ON d.device_id = se.device_id
                    AND se.timestamp_ns > ?
               GROUP BY d.device_id
               ORDER BY max_risk DESC""",
            (day_ago_ns,),
        ).fetchall()

        devices = []
        for r in device_rows:
            status = "online" if r["last_seen"] and r["last_seen"] > now - 300 else "offline"
            devices.append({
                "device_id": r["device_id"],
                "hostname": r["hostname"] or r["device_id"][:12],
                "os": r["os"],
                "os_version": r["os_version"],
                "arch": r["arch"],
                "agent_version": r["agent_version"],
                "status": status,
                "last_seen": r["last_seen"],
                "first_seen": r["first_seen"],
                "event_count": r["event_count"] or 0,
                "max_risk": r["max_risk"] or 0,
                "critical_count": r["critical_count"] or 0,
                "high_count": r["high_count"] or 0,
            })

        db.close()

        return jsonify({
            "available": True,
            "fleet": {
                "total_devices": total,
                "online": online,
                "offline": total - online,
            },
            "last_24h": {
                "total_events": total_events,
                "critical": critical,
                "high": high,
            },
            "top_categories": [
                {"category": r[0], "count": r[1], "avg_risk": round(r[2], 3)}
                for r in top_categories
            ],
            "top_mitre_techniques": [
                {"technique": t, "count": c} for t, c in top_techniques
            ],
            "devices": devices,
        })

    except Exception as e:
        logger.error("Command Center status failed: %s", e)
        if db:
            db.close()
        return jsonify({"available": False, "message": str(e)})


@dashboard_bp.route("/api/command-center/device/<device_id>/events")
@require_login
def cc_device_events(device_id):
    """Recent security events for a specific device."""
    db = _get_fleet_db()
    if db is None:
        return jsonify({"events": [], "message": "Fleet database not available"})

    try:
        limit = min(request.args.get("limit", 50, type=int), 200)
        min_risk = request.args.get("min_risk", 0.0, type=float)

        rows = db.execute(
            """SELECT id, timestamp_dt, event_category, risk_score,
                      confidence, description, collection_agent, mitre_techniques,
                      process_name, remote_ip, username, domain, path,
                      detection_source, probe_name, geo_src_country, asn_src_org
               FROM security_events
               WHERE device_id = ? AND risk_score >= ?
               ORDER BY timestamp_ns DESC LIMIT ?""",
            (device_id, min_risk, limit),
        ).fetchall()

        events = []
        for r in rows:
            mitre = []
            try:
                raw = r["mitre_techniques"]
                if raw:
                    parsed = json.loads(raw)
                    if isinstance(parsed, str):
                        parsed = json.loads(parsed)
                    mitre = [t for t in parsed if isinstance(t, str) and t.startswith("T")]
            except (json.JSONDecodeError, TypeError):
                pass

            events.append({
                "id": r["id"],
                "timestamp": r["timestamp_dt"],
                "category": r["event_category"],
                "risk_score": r["risk_score"],
                "confidence": r["confidence"],
                "description": r["description"],
                "agent": r["collection_agent"],
                "mitre": mitre,
                "process": r["process_name"],
                "remote_ip": r["remote_ip"],
                "username": r["username"],
                "domain": r["domain"],
                "path": r["path"],
                "detection_source": r["detection_source"],
                "probe": r["probe_name"],
                "geo_country": r["geo_src_country"],
                "asn_org": r["asn_src_org"],
            })

        db.close()
        return jsonify({"events": events, "count": len(events)})

    except Exception as e:
        logger.error("Device events query failed: %s", e)
        if db:
            db.close()
        return jsonify({"events": [], "message": str(e)})
