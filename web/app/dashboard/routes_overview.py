"""Overview page API — the 'Am I safe?' landing page.

Aggregates fleet status, posture score, IGRIS signals, MITRE coverage,
event trends, and agent health into a single JSON response.
"""

import json
import logging
import os
import sqlite3
import time
from pathlib import Path

from flask import jsonify, request

from ..middleware import get_current_user, require_login
from . import dashboard_bp

logger = logging.getLogger("web.dashboard.overview")


def _get_fleet_db() -> sqlite3.Connection | None:
    """Try local fleet.db for overview data."""
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


def _compute_posture(critical: int, high: int, medium: int = 0) -> dict:
    """Compute fleet posture score and label from threat counts."""
    if critical == 0 and high == 0:
        score = 100
        label = "All Clear"
        color = "#00ff88"
    elif critical == 0 and high <= 3:
        score = max(70, 90 - high * 5)
        label = "Guarded"
        color = "#f0ad4e"
    elif critical <= 5:
        score = max(30, 60 - critical * 5 - high * 2)
        label = "Needs Attention"
        color = "#f0ad4e"
    else:
        score = max(5, 25 - critical)
        label = "Critical"
        color = "#ff3366"
    return {"score": score, "label": label, "color": color}


@dashboard_bp.route("/api/overview")
@require_login
def overview_data():
    """Aggregated overview data for the landing page."""
    db = _get_fleet_db()
    if db is None:
        return jsonify({
            "available": False,
            "message": "No data source available",
            "posture": _compute_posture(0, 0),
            "fleet": {"total_devices": 0, "online": 0, "offline": 0},
            "last_24h": {"total_events": 0, "critical": 0, "high": 0},
            "previous_24h": {"total_events": 0, "critical": 0, "high": 0},
            "top_mitre_techniques": [],
            "top_categories": [],
            "devices": [],
            "needs_attention": [],
            "signals": {"active": 0, "items": []},
            "agents": {"total": 0, "healthy": 0},
        })

    try:
        now = time.time()
        day_ago_ns = int((now - 86400) * 1e9)
        two_days_ago_ns = int((now - 172800) * 1e9)

        # ── Fleet counts ──
        total = db.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        online = db.execute(
            "SELECT COUNT(*) FROM devices WHERE last_seen > ?", (now - 300,)
        ).fetchone()[0]

        # ── Event stats (last 24h) ──
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

        # ── Previous 24h (for trend arrows) ──
        prev_events = db.execute(
            "SELECT COUNT(*) FROM security_events WHERE timestamp_ns > ? AND timestamp_ns <= ?",
            (two_days_ago_ns, day_ago_ns),
        ).fetchone()[0]
        prev_critical = db.execute(
            "SELECT COUNT(*) FROM security_events WHERE timestamp_ns > ? AND timestamp_ns <= ? AND risk_score >= 0.8",
            (two_days_ago_ns, day_ago_ns),
        ).fetchone()[0]

        # ── MITRE techniques (24h) ──
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
        top_techniques = sorted(technique_counts.items(), key=lambda x: -x[1])[:12]
        unique_technique_count = len(technique_counts)

        # ── Top categories (24h) ──
        top_categories = db.execute(
            """SELECT event_category, COUNT(*) as cnt, AVG(risk_score) as avg_risk
               FROM security_events
               WHERE timestamp_ns > ? AND risk_score > 0
               GROUP BY event_category
               ORDER BY cnt DESC LIMIT 8""",
            (day_ago_ns,),
        ).fetchall()

        # ── Per-device summary ──
        device_rows = db.execute(
            """SELECT d.device_id, d.hostname, d.os, d.os_version,
                      d.agent_version, d.last_seen,
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
            cr = r["critical_count"] or 0
            hi = r["high_count"] or 0
            devices.append({
                "device_id": r["device_id"],
                "hostname": r["hostname"] or r["device_id"][:12],
                "os": r["os"],
                "os_version": r["os_version"],
                "agent_version": r["agent_version"],
                "status": status,
                "last_seen": r["last_seen"],
                "event_count": r["event_count"] or 0,
                "max_risk": r["max_risk"] or 0,
                "critical_count": cr,
                "high_count": hi,
                "posture": _compute_posture(cr, hi),
            })

        # ── Needs Attention items ──
        needs_attention = []
        if critical > 0:
            needs_attention.append({
                "severity": "critical",
                "text": f"{critical} critical event{'s' if critical != 1 else ''} in the last 24h",
                "action": "Review immediately",
                "link": "/dashboard/threats",
            })
        if high > 0:
            needs_attention.append({
                "severity": "high",
                "text": f"{high} high-risk event{'s' if high != 1 else ''} detected",
                "action": "Worth investigating",
                "link": "/dashboard/threats",
            })

        # Check for offline devices
        offline_count = total - online
        if offline_count > 0 and total > 0:
            needs_attention.append({
                "severity": "medium" if offline_count < total else "high",
                "text": f"{offline_count} device{'s' if offline_count != 1 else ''} offline",
                "action": "Check connectivity",
                "link": "/dashboard/devices",
            })

        # ── IGRIS signals ──
        signals = {"active": 0, "items": []}
        try:
            from amoskys.igris import get_igris
            igris = get_igris()
            sigs = igris.get_signals(limit=10)
            active_sigs = [s for s in sigs if not s.get("cleared")]
            signals["active"] = len(active_sigs)
            signals["items"] = [
                {
                    "id": s.get("id", ""),
                    "agent": s.get("subsystem", ""),
                    "message": s.get("reason", s.get("signal_type", "")),
                    "severity": s.get("severity", "medium"),
                }
                for s in active_sigs[:5]
            ]
            if signals["active"] > 0:
                needs_attention.append({
                    "severity": "medium",
                    "text": f"{signals['active']} active IGRIS signal{'s' if signals['active'] != 1 else ''}",
                    "action": "Review anomalies",
                    "link": "/dashboard/igris",
                })
        except Exception:
            pass

        # ── Agent health (best-effort) ──
        agents = {"total": 0, "healthy": 0}
        try:
            from .agent_discovery import AGENT_CATALOG, detect_agent_status
            agents["total"] = len(AGENT_CATALOG)
            agents["healthy"] = sum(
                1 for cfg in AGENT_CATALOG.values()
                if detect_agent_status(cfg)["health"] == "online"
            )
        except Exception:
            pass

        # ── Compute fleet posture ──
        posture = _compute_posture(critical, high)

        db.close()

        return jsonify({
            "available": True,
            "posture": posture,
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
            "previous_24h": {
                "total_events": prev_events,
                "critical": prev_critical,
                "high": 0,
            },
            "mitre": {
                "unique_techniques": unique_technique_count,
                "top": [{"technique": t, "count": c} for t, c in top_techniques],
            },
            "top_categories": [
                {"category": r[0], "count": r[1], "avg_risk": round(r[2], 3)}
                for r in top_categories
            ],
            "devices": devices,
            "needs_attention": needs_attention,
            "signals": signals,
            "agents": agents,
        })

    except Exception as e:
        logger.error("Overview data failed: %s", e)
        if db:
            db.close()
        return jsonify({"available": False, "message": str(e)})
