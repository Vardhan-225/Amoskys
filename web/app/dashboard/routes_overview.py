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

from ..middleware import get_current_org_id, get_current_user, require_login
from . import dashboard_bp

logger = logging.getLogger("web.dashboard.overview")


def _get_fleet_db() -> sqlite3.Connection | None:
    """Try local fleet.db for overview data (needs devices + security_events)."""
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


def _get_flow_db() -> sqlite3.Connection | None:
    """Try any DB that has flow_events with geo data (fleet.db or fleet_cache.db)."""
    candidates = [
        os.getenv("CC_DB_PATH", ""),
        "server/fleet.db",
        "data/fleet.db",
        "data/fleet_cache.db",
    ]
    for path in candidates:
        if path and Path(path).exists():
            try:
                db = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5.0)
                db.row_factory = sqlite3.Row
                # Verify flow_events table exists
                db.execute("SELECT 1 FROM flow_events LIMIT 1")
                return db
            except Exception:
                try:
                    db.close()
                except Exception:
                    pass
    return None


@dashboard_bp.route("/api/overview/geo-points")
@require_login
def overview_geo_points():
    """Geo points for the overview globe — aggregated from fleet flow_events."""
    db = _get_flow_db()
    if db is None:
        return jsonify([])
    try:
        hours = request.args.get("hours", 24, type=int)
        limit = request.args.get("limit", 300, type=int)
        cutoff_ns = int((time.time() - hours * 3600) * 1e9)
        rows = db.execute(
            """SELECT geo_dst_latitude as lat, geo_dst_longitude as lon,
                      geo_dst_country as country, geo_dst_city as city,
                      asn_dst_org as asn_org,
                      SUM(COALESCE(bytes_tx,0)+COALESCE(bytes_rx,0)) as bytes,
                      COUNT(*) as count,
                      MAX(CASE WHEN threat_intel_match=1 THEN 1 ELSE 0 END) as threat
               FROM flow_events
               WHERE timestamp_ns > ? AND geo_dst_latitude IS NOT NULL AND geo_dst_latitude != 0
               GROUP BY ROUND(geo_dst_latitude,1), ROUND(geo_dst_longitude,1)
               ORDER BY count DESC LIMIT ?""",
            (cutoff_ns, min(limit, 500)),
        ).fetchall()
        points = [
            {
                "lat": r[0], "lon": r[1], "country": r[2] or "",
                "city": r[3] or "", "asn_org": r[4] or "",
                "bytes": r[5] or 0, "count": r[6], "threat": bool(r[7]),
            }
            for r in rows
        ]
        db.close()
        return jsonify(points)
    except Exception as e:
        logger.debug("Overview geo-points failed: %s", e)
        if db:
            db.close()
        return jsonify([])


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

        # ── Org scoping: regular users see only their org's data ──
        user = get_current_user()
        is_admin = user and user.role and user.role.value == "admin"
        org_id = get_current_org_id()

        # Build WHERE clause fragments for org isolation
        if is_admin:
            dev_org_clause = ""
            dev_org_params: tuple = ()
            evt_org_clause = ""
            evt_org_params: tuple = ()
        elif org_id:
            dev_org_clause = " AND org_id = ?"
            dev_org_params = (org_id,)
            evt_org_clause = " AND org_id = ?"
            evt_org_params = (org_id,)
        else:
            # No org → see nothing (safety default)
            dev_org_clause = " AND org_id = ?"
            dev_org_params = ("__none__",)
            evt_org_clause = " AND org_id = ?"
            evt_org_params = ("__none__",)

        # ── Fleet counts ──
        total = db.execute(
            "SELECT COUNT(*) FROM devices WHERE 1=1" + dev_org_clause,
            dev_org_params,
        ).fetchone()[0]
        online = db.execute(
            "SELECT COUNT(*) FROM devices WHERE last_seen > ?" + dev_org_clause,
            (now - 300,) + dev_org_params,
        ).fetchone()[0]

        # ── Event stats (last 24h) ──
        total_events = db.execute(
            "SELECT COUNT(*) FROM security_events WHERE timestamp_ns > ?" + evt_org_clause,
            (day_ago_ns,) + evt_org_params,
        ).fetchone()[0]
        critical = db.execute(
            "SELECT COUNT(*) FROM security_events WHERE timestamp_ns > ? AND risk_score >= 0.8" + evt_org_clause,
            (day_ago_ns,) + evt_org_params,
        ).fetchone()[0]
        high = db.execute(
            "SELECT COUNT(*) FROM security_events WHERE timestamp_ns > ? AND risk_score >= 0.6 AND risk_score < 0.8" + evt_org_clause,
            (day_ago_ns,) + evt_org_params,
        ).fetchone()[0]

        # ── Previous 24h (for trend arrows) ──
        prev_events = db.execute(
            "SELECT COUNT(*) FROM security_events WHERE timestamp_ns > ? AND timestamp_ns <= ?" + evt_org_clause,
            (two_days_ago_ns, day_ago_ns) + evt_org_params,
        ).fetchone()[0]
        prev_critical = db.execute(
            "SELECT COUNT(*) FROM security_events WHERE timestamp_ns > ? AND timestamp_ns <= ? AND risk_score >= 0.8" + evt_org_clause,
            (two_days_ago_ns, day_ago_ns) + evt_org_params,
        ).fetchone()[0]

        # ── MITRE techniques (24h) ──
        mitre_rows = db.execute(
            """SELECT mitre_techniques FROM security_events
               WHERE timestamp_ns > ? AND mitre_techniques IS NOT NULL
               AND mitre_techniques != '[]'""" + evt_org_clause,
            (day_ago_ns,) + evt_org_params,
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
               WHERE timestamp_ns > ? AND risk_score > 0""" + evt_org_clause + """
               GROUP BY event_category
               ORDER BY cnt DESC LIMIT 8""",
            (day_ago_ns,) + evt_org_params,
        ).fetchall()

        # ── Per-device summary ──
        dev_where = "WHERE 1=1" + dev_org_clause
        device_rows = db.execute(
            f"""SELECT d.device_id, d.hostname, d.os, d.os_version,
                      d.agent_version, d.last_seen,
                      COUNT(se.id) as event_count,
                      COALESCE(MAX(se.risk_score), 0) as max_risk,
                      SUM(CASE WHEN se.risk_score >= 0.8 THEN 1 ELSE 0 END) as critical_count,
                      SUM(CASE WHEN se.risk_score >= 0.6 AND se.risk_score < 0.8 THEN 1 ELSE 0 END) as high_count
               FROM devices d
               LEFT JOIN security_events se ON d.device_id = se.device_id
                    AND se.timestamp_ns > ?
               {dev_where}
               GROUP BY d.device_id
               ORDER BY max_risk DESC""",
            (day_ago_ns,) + dev_org_params,
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


# ── Investigation Context Endpoint ─────────────────────────────────


@dashboard_bp.route("/api/investigation/<int:incident_id>/context")
@require_login
def investigation_context(incident_id):
    """Full evidence package for the investigation page.

    Combines: incident metadata, timeline, story narrative,
    event explanations, and MITRE mapping into a single response.
    """
    from .telemetry_bridge import get_telemetry_store

    store = get_telemetry_store()
    if store is None:
        return jsonify({"status": "error", "message": "Database unavailable"}), 500

    # 1. Get incident
    incident = store.get_incident(incident_id)
    if not incident:
        return jsonify({"status": "error", "message": "Incident not found"}), 404

    result: dict = {
        "status": "success",
        "incident": incident,
        "narrative": None,
        "timeline": [],
        "explanations": [],
        "mitre_techniques": [],
        "kill_chain_stages": [],
        "scoring": None,
    }

    # 2. Try to build attack story
    try:
        from amoskys.intel.story_engine import StoryEngine

        engine = StoryEngine()
        story = engine.build_story_for_incident(str(incident_id))
        if story:
            result["narrative"] = {
                "story_id": story.story_id,
                "pattern_name": story.pattern_name,
                "pattern_label": story.pattern_label,
                "severity": story.severity,
                "confidence": story.confidence,
                "techniques": story.techniques,
                "affected_assets": story.affected_assets,
                "duration_seconds": story.duration_seconds,
                "raw_event_count": story.raw_event_count,
                "kill_chain": [
                    {
                        "stage": s.stage,
                        "techniques": s.techniques,
                        "technique_names": s.technique_names,
                        "summary": s.summary,
                        "first_seen": s.first_seen,
                        "last_seen": s.last_seen,
                        "event_count": len(s.events),
                    }
                    for s in story.kill_chain
                ],
            }
    except Exception as e:
        logger.debug("StoryEngine unavailable: %s", e)

    # 3. Build timeline
    try:
        import re as _re

        device_id = incident.get("device_id", "")
        end_ns = int(time.time() * 1e9)
        start_ns = end_ns - int(24 * 3600 * 1e9)
        if incident.get("created_at"):
            try:
                from datetime import datetime, timezone as _tz

                created = datetime.fromisoformat(
                    incident["created_at"].replace("Z", "+00:00")
                )
                start_ns = int(created.timestamp() * 1e9) - int(3600 * 1e9)
            except (ValueError, TypeError):
                pass
        if not device_id:
            for field in ("title", "description"):
                text = incident.get(field, "")
                m = _re.search(r" on ([A-Za-z0-9._-]+)", text)
                if m:
                    device_id = m.group(1)
                    break
        if device_id:
            raw_timeline = store.build_incident_timeline(device_id, start_ns, end_ns)
            if raw_timeline:
                result["timeline"] = [
                    {
                        "ts": e.get("ts") or e.get("timestamp_ns"),
                        "source": e.get("source") or e.get("agent") or e.get("table"),
                        "significance": e.get("significance", 1),
                        "category": e.get("event_category", ""),
                        "risk_score": e.get("risk_score", 0),
                        "description": e.get("description", ""),
                        "process_name": e.get("process_name", ""),
                        "remote_ip": e.get("remote_ip", ""),
                        "mitre": e.get("mitre_techniques", []),
                    }
                    for e in raw_timeline[:500]
                ]
    except Exception as e:
        logger.debug("Timeline build failed: %s", e)

    # 4. Explain top events
    try:
        from amoskys.intel.explanation import EventExplainer

        explainer = EventExplainer()
        source_ids = json.loads(incident.get("source_event_ids", "[]"))
        for eid in source_ids[:10]:
            event = store.get_event(eid)
            if event:
                explanation = explainer.explain_event(event)
                explanation["event_id"] = eid
                result["explanations"].append(explanation)
    except Exception as e:
        logger.debug("EventExplainer unavailable: %s", e)

    # 5. Extract MITRE techniques
    techniques = set()
    for field in ("tactics", "techniques"):
        val = incident.get(field)
        if val:
            try:
                parsed = json.loads(val) if isinstance(val, str) else val
                if isinstance(parsed, list):
                    techniques.update(t for t in parsed if isinstance(t, str))
            except (json.JSONDecodeError, TypeError):
                pass
    result["mitre_techniques"] = sorted(techniques)

    return jsonify(result)
