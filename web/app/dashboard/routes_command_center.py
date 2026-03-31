"""Command Center routes — multi-device fleet management.

Provides the Command Center page and API endpoints that proxy
to the operations server (ops.amoskys.com) for fleet data.

Architecture:
    Browser → amoskys.com (this) → ops server (fleet.db)
    The presentation server never touches telemetry data directly.
"""

import json
import logging
import os
import sqlite3
import time
from pathlib import Path

import requests as http_client

from flask import jsonify, render_template, request

from ..middleware import get_current_user, require_login
from . import dashboard_bp

logger = logging.getLogger("web.dashboard.command_center")

# ── Ops Server connection ──────────────────────────────────────────

OPS_SERVER_URL = os.getenv("AMOSKYS_OPS_SERVER", "https://18.223.110.15").rstrip("/")
OPS_TIMEOUT = (5, 15)  # (connect, read) seconds


def _ops_get(path: str, params: dict | None = None) -> dict | None:
    """Fetch data from the ops server API."""
    try:
        resp = http_client.get(
            f"{OPS_SERVER_URL}{path}",
            params=params,
            timeout=OPS_TIMEOUT,
            verify=False,  # Self-signed cert on ops server
        )
        if resp.status_code == 200:
            return resp.json()
        logger.warning("Ops server %s returned %d", path, resp.status_code)
    except http_client.ConnectionError:
        logger.debug("Ops server unreachable: %s", OPS_SERVER_URL)
    except Exception as e:
        logger.warning("Ops server error: %s", e)
    return None


def _get_fleet_db() -> sqlite3.Connection | None:
    """Fallback: try local fleet.db if ops server is unreachable."""
    candidates = [
        os.getenv("CC_DB_PATH", ""),
        "server/fleet.db",
        "data/fleet.db",
    ]
    for path in candidates:
        if path and Path(path).exists():
            try:
                db = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5.0)
                db.row_factory = sqlite3.Row
                return db
            except Exception:
                pass
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


@dashboard_bp.route("/device/<device_id>")
@require_login
def device_detail_page(device_id):
    """Device detail — telemetry view for a single device."""
    user = get_current_user()
    return render_template(
        "dashboard/device-detail.html",
        user=user,
        device_id=device_id,
    )


# Per-device advanced pages — same templates, scoped to one device
@dashboard_bp.route("/device/<device_id>/cortex")
@require_login
def device_cortex(device_id):
    user = get_current_user()
    return render_template("dashboard/cortex.html", user=user, device_id=device_id)


@dashboard_bp.route("/device/<device_id>/observatory")
@require_login
def device_observatory(device_id):
    user = get_current_user()
    return render_template("dashboard/observatory.html", user=user, device_id=device_id)


@dashboard_bp.route("/device/<device_id>/intelligence")
@require_login
def device_intelligence(device_id):
    user = get_current_user()
    return render_template("dashboard/intelligence.html", user=user, device_id=device_id)


@dashboard_bp.route("/device/<device_id>/threats")
@require_login
def device_threats(device_id):
    user = get_current_user()
    return render_template("dashboard/threats.html", user=user, device_id=device_id)


@dashboard_bp.route("/device/<device_id>/igris")
@require_login
def device_igris(device_id):
    user = get_current_user()
    return render_template("dashboard/igris.html", user=user, device_id=device_id)


@dashboard_bp.route("/device/<device_id>/guardian")
@require_login
def device_guardian(device_id):
    user = get_current_user()
    return render_template("dashboard/guardian.html", user=user, device_id=device_id)


@dashboard_bp.route("/api/command-center/device/<device_id>/detail")
@require_login
def cc_device_detail(device_id):
    """Full device info + recent events — proxied from ops."""
    data = _ops_get(f"/api/v1/devices/{device_id}")
    if data:
        return jsonify({"available": True, **data})

    return jsonify({"available": False, "message": "Device not found or ops server unreachable"})


@dashboard_bp.route("/api/command-center/device/<device_id>/telemetry")
@require_login
def cc_device_telemetry(device_id):
    """Full Cortex-style telemetry — proxied from ops."""
    data = _ops_get(f"/api/v1/devices/{device_id}/telemetry")
    if data:
        return jsonify(data)

    return jsonify({"error": "Device not found or ops server unreachable"}), 404


# ── API Endpoints ──────────────────────────────────────────────────

@dashboard_bp.route("/api/command-center/status")
@require_login
def cc_fleet_status():
    """Fleet-wide posture summary — proxied from ops server."""
    # Try ops server first
    data = _ops_get("/api/v1/fleet/status")
    if data is not None:
        data["available"] = True
        return jsonify(data)

    # Fallback to local fleet.db
    db = _get_fleet_db()
    if db is None:
        return jsonify({
            "available": False,
            "message": "Operations server unreachable. Agents may still be shipping — check back in a moment.",
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
    """Recent security events for a specific device — proxied from ops."""
    # Try ops server
    limit = request.args.get("limit", 50, type=int)
    min_risk = request.args.get("min_risk", 0.0, type=float)
    data = _ops_get(f"/api/v1/devices/{device_id}", {"limit": limit})
    if data and "recent_events" in data:
        return jsonify({"events": data["recent_events"], "count": len(data["recent_events"])})

    # Fallback to local
    db = _get_fleet_db()
    if db is None:
        return jsonify({"events": [], "message": "Operations server unreachable"})

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


@dashboard_bp.route("/api/command-center/live-feed")
@require_login
def cc_live_feed():
    """Live event feed — proxied from ops server."""
    limit = request.args.get("limit", 30, type=int)
    after_id = request.args.get("after", 0, type=int)
    params = {"limit": limit}
    if after_id > 0:
        params["min_risk"] = 0.01

    data = _ops_get("/api/v1/events", params)
    if data and "events" in data:
        # Transform to match the feed format
        events = []
        for e in data["events"][:limit]:
            events.append({
                "id": e.get("id", 0),
                "timestamp": e.get("timestamp_dt", ""),
                "category": e.get("event_category", ""),
                "risk_score": e.get("risk_score", 0),
                "agent": e.get("collection_agent", ""),
                "process": e.get("process_name", ""),
                "hostname": e.get("device_id", "")[:12],
                "device_id": e.get("device_id", ""),
            })
        return jsonify({"events": events})

    # Fallback to local
    db = _get_fleet_db()
    if db is None:
        return jsonify({"events": []})

    try:
        limit = min(request.args.get("limit", 30, type=int), 100)
        after_id = request.args.get("after", 0, type=int)

        query = """SELECT se.id, se.timestamp_dt, se.event_category, se.risk_score,
                          se.collection_agent, se.process_name, se.mitre_techniques,
                          se.description, d.hostname, d.device_id
                   FROM security_events se
                   JOIN devices d ON se.device_id = d.device_id
                   WHERE se.risk_score > 0"""
        params: list = []

        if after_id > 0:
            query += " AND se.id > ?"
            params.append(after_id)

        query += " ORDER BY se.id DESC LIMIT ?"
        params.append(limit)

        rows = db.execute(query, params).fetchall()

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
                "agent": r["collection_agent"],
                "process": r["process_name"],
                "mitre": mitre,
                "description": r["description"],
                "hostname": r["hostname"] or r["device_id"][:12],
                "device_id": r["device_id"],
            })

        db.close()
        return jsonify({"events": events})

    except Exception as e:
        logger.error("Live feed query failed: %s", e)
        if db:
            db.close()
        return jsonify({"events": []})
