"""Health summary route for the Cortex Dashboard."""

import json as _json
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import jsonify

from ..api.rate_limiter import require_rate_limit
from ..middleware import require_login
from . import dashboard_bp
from .agent_discovery import AGENT_CATALOG, detect_agent_status, get_platform_name


# ── Dashboard-authenticated health summary (avoids health API auth issues) ──
@dashboard_bp.route("/api/health-summary")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def health_summary():
    """System health summary for Cortex Command Center.

    Returns agent counts, health score, threat level, and event statistics
    using dashboard session auth (same as all other dashboard endpoints).
    """
    now = datetime.now(timezone.utc)
    project_root = Path(__file__).parent.parent.parent.parent

    # ── Agent counts (process detection + heartbeat fallback) ──
    agents_status = {}
    agents_details = []
    heartbeat_dir = project_root / "data" / "heartbeats"

    for agent_id, agent_config in AGENT_CATALOG.items():
        status = detect_agent_status(agent_config)
        if status["health"] == "online":
            agents_status[agent_id] = "running"
        elif status["health"] == "incompatible":
            agents_status[agent_id] = "incompatible"
        else:
            # Fallback: check heartbeat file (agent may not be a visible process)
            hb_name = agent_id.replace("_agent", "").replace("_", "")
            hb_candidates = [
                heartbeat_dir / f"{agent_id.replace('_agent', '')}.json",
                heartbeat_dir / f"{hb_name}.json",
                heartbeat_dir / f"{agent_id}.json",
            ]
            for hb_path in hb_candidates:
                if hb_path.exists():
                    try:
                        hb = _json.loads(hb_path.read_text())
                        hb_ts = hb.get("timestamp", "")
                        if hb_ts:
                            hb_dt = datetime.fromisoformat(hb_ts.replace("Z", "+00:00"))
                            age = (now - hb_dt).total_seconds()
                            if age < 600:  # Heartbeat within 10 minutes
                                agents_status[agent_id] = "running"
                                break
                    except Exception:
                        pass
            if agent_id not in agents_status:
                agents_status[agent_id] = "stopped"

        agents_details.append(
            {
                "id": agent_id,
                "name": agent_config["name"],
                "type": agent_config["type"],
                "status": agents_status[agent_id],
                "critical": agent_config.get("critical", False),
                "color": agent_config.get("color", "#00ff88"),
            }
        )

    agents_online = sum(1 for s in agents_status.values() if s == "running")
    agents_total = len([a for a in agents_status.values() if a != "incompatible"])

    # ── Event count (prefer pre-computed rollups, fall back to raw COUNT) ──
    events_24h = 0
    try:
        from .telemetry_bridge import get_telemetry_store

        _ev_store = get_telemetry_store()
        if _ev_store:
            rollup_counts = _ev_store.get_rollup_event_counts(hours=24)
            if rollup_counts:
                events_24h = sum(rollup_counts.values())
    except Exception:
        pass
    if events_24h == 0:
        # Fallback: direct COUNT queries (cold start before first rollup cycle)
        telemetry_db = project_root / "data" / "telemetry.db"
        if telemetry_db.exists():
            try:
                conn = sqlite3.connect(str(telemetry_db))
                cutoff_ns = int((now - timedelta(hours=24)).timestamp() * 1_000_000_000)
                for table in [
                    "security_events",
                    "process_events",
                    "flow_events",
                    "dns_events",
                    "persistence_events",
                    "fim_events",
                    "peripheral_events",
                    "audit_events",
                    "observation_events",
                ]:
                    try:
                        row = conn.execute(
                            f"SELECT COUNT(*) FROM {table} WHERE timestamp_ns > ?",
                            (cutoff_ns,),
                        ).fetchone()
                        events_24h += row[0]
                    except sqlite3.OperationalError:
                        pass
                conn.close()
            except Exception:
                pass

    # ── Threat level — unified from posture (risk-based) + fusion (incident-based) ──
    # Posture provides continuous risk assessment; fusion provides confirmed incidents.
    # Use the worse of the two so the dashboard never underreports.
    posture_threat = "clear"
    posture_score = 100.0
    posture_model = "legacy"
    try:
        from .telemetry_bridge import get_telemetry_store

        _store = get_telemetry_store()
        if _store:
            _posture = _store.compute_nerve_posture(hours=24)
            posture_threat = _posture.get("threat_level", "clear")
            posture_score = _posture.get("posture_score", 100.0)
            posture_model = _posture.get("model", "nerve_signal_v1")
    except Exception:
        pass

    fusion_threat = "clear"
    fusion_db = project_root / "data" / "intel" / "fusion.db"
    if fusion_db.exists():
        try:
            conn = sqlite3.connect(str(fusion_db))
            cutoff = (now - timedelta(hours=1)).isoformat()
            try:
                row = conn.execute(
                    """SELECT severity FROM incidents
                       WHERE created_at > ?
                       ORDER BY CASE severity
                         WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
                         WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5
                       END LIMIT 1""",
                    (cutoff,),
                ).fetchone()
                if row:
                    fusion_threat = row[0]
            except sqlite3.OperationalError:
                pass
            conn.close()
        except Exception:
            pass

    # Severity ordering for comparison (includes Nerve Signal levels)
    _THREAT_ORDER = {
        "clear": 0,
        "low": 1,
        "guarded": 2,
        "medium": 2,
        "elevated": 3,
        "high": 4,
        "critical": 5,
    }
    threat_level = max(
        [posture_threat.lower(), fusion_threat.lower()],
        key=lambda t: _THREAT_ORDER.get(t, 0),
    ).upper()

    # ── Data freshness — how stale is the data? ──
    data_age_seconds = None
    last_event_time = None
    try:
        telemetry_db = project_root / "data" / "telemetry.db"
        if telemetry_db.exists():
            conn = sqlite3.connect(str(telemetry_db), timeout=2)
            row = conn.execute(
                "SELECT MAX(event_timestamp_ns) FROM security_events"
            ).fetchone()
            if row and row[0]:
                last_event_time = row[0]
            if not last_event_time:
                row = conn.execute(
                    "SELECT MAX(timestamp_ns) FROM observation_events"
                ).fetchone()
                if row and row[0]:
                    last_event_time = row[0]
            conn.close()
            if last_event_time:
                data_age_seconds = round(
                    time.time() - (last_event_time / 1_000_000_000), 1
                )
    except Exception:
        pass

    # ── Health score — operational health (are agents running and collecting?) ──
    infra_ok = agents_online > 0 or events_24h > 0
    agent_score = (agents_online / max(agents_total, 1)) * 40
    infra_score = 40 if infra_ok else 0
    activity_score = 20 if events_24h > 0 else 10
    health_score = int(agent_score + infra_score + activity_score)

    freshness = "live"
    if data_age_seconds is None:
        freshness = "no_data"
    elif data_age_seconds > 300:
        freshness = "stale"
    elif data_age_seconds > 60:
        freshness = "delayed"

    return jsonify(
        {
            "status": "success",
            "timestamp": now.isoformat(),
            "platform": get_platform_name(),
            "agents": agents_status,
            "agents_details": agents_details,
            "agents_summary": {
                "online": agents_online,
                "total": agents_total,
                "coverage_percent": round(
                    (agents_online / max(agents_total, 1)) * 100, 1
                ),
            },
            "threat_level": threat_level,
            "posture_score": posture_score,
            "posture_model": posture_model,
            "events_last_24h": events_24h,
            "health_score": health_score,
            "health_status": (
                "healthy"
                if health_score >= 70
                else "degraded" if health_score >= 40 else "critical"
            ),
            "data_freshness": {
                "age_seconds": data_age_seconds,
                "status": freshness,
                "label": (
                    f"data as of {int(data_age_seconds)}s ago"
                    if data_age_seconds is not None
                    else "no data yet"
                ),
            },
        }
    )
