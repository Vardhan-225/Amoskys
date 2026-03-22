"""SOMA / Fusion / Explain / Feedback API routes.

Extracted from dashboard __init__.py — all endpoints related to:
- FusionEngine risk & incidents  (/api/fusion/*)
- SOMA overview, agents, status, mode  (/api/soma/*)
- Agent trust  (/api/agents/trust)
- Event & incident explanation  (/api/explain/*)
- Analyst feedback loop  (/api/feedback*)
"""

import json
import logging
import os
import time

from flask import jsonify, request

from ..api.rate_limiter import require_rate_limit
from ..middleware import get_current_user, require_login
from . import dashboard_bp
from .route_helpers import (
    _get_store,
    _normalize_agent_id,
    _parse_indicators,
    _parse_mitre,
)

logger = logging.getLogger(__name__)

_MSG_DB_UNAVAILABLE = "Database unavailable"
_MSG_FUSION_UNAVAILABLE = "Fusion engine not available"


# ── Helpers ───────────────────────────────────────────────────────────


def _get_fusion_engine():
    """Get a FusionEngine instance for read-only queries."""
    from pathlib import Path

    fusion_db = Path("data/intel/fusion.db")
    if not fusion_db.exists():
        return None
    try:
        from amoskys.intel.fusion_engine import FusionEngine

        return FusionEngine(db_path=str(fusion_db))
    except Exception:
        return None


_classification_cache = {"data": None, "ts": 0}


def _get_classification_stats(store):
    """Compute signal/noise distribution from composite scores.

    Uses SQL aggregation to classify events without fetching rows into Python.
    Cached for 30 seconds to avoid repeated full-table scans.
    """
    classification = {"legitimate": 0, "suspicious": 0, "malicious": 0}
    total = 0
    if store is None:
        return classification, total

    now = time.time()
    if _classification_cache["data"] and (now - _classification_cache["ts"]) < 30:
        cached = _classification_cache["data"]
        return cached[0], cached[1]

    try:
        row = store.db.execute(
            """
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN composite >= 0.70 THEN 1 ELSE 0 END) AS malicious,
                SUM(CASE WHEN composite >= 0.40 AND composite < 0.70 THEN 1 ELSE 0 END) AS suspicious,
                SUM(CASE WHEN composite < 0.40 THEN 1 ELSE 0 END) AS legitimate
            FROM (
                SELECT
                    CASE
                        WHEN geometric_score > 0.001
                        THEN 0.35*geometric_score + 0.25*temporal_score
                             + 0.40*behavioral_score
                        ELSE 0.38*temporal_score + 0.62*behavioral_score
                    END AS composite
                FROM security_events
                WHERE geometric_score IS NOT NULL
                ORDER BY timestamp_ns DESC LIMIT 100000
            )
            """
        ).fetchone()
        if row:
            total = row[0] or 0
            classification["malicious"] = row[1] or 0
            classification["suspicious"] = row[2] or 0
            classification["legitimate"] = row[3] or 0
        _classification_cache["data"] = (classification, total)
        _classification_cache["ts"] = now
    except Exception:
        pass
    return classification, total


def _get_agent_explanations(engine):
    """Get AMRDR agent reliability explanations from FusionEngine."""
    if engine is None:
        return []
    try:
        from amoskys.intel.explanation import AgentExplainer

        explainer = AgentExplainer()
        return [
            explainer.explain_agent(aid, engine.reliability_tracker.get_state(aid))
            for aid in engine.reliability_tracker.list_agents()
        ]
    except Exception:
        return []


# ── Fusion Routes ─────────────────────────────────────────────────────


@dashboard_bp.route("/api/fusion/risk", methods=["GET"])
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def fusion_device_risk():
    """Get device risk snapshot from FusionEngine correlation.

    Query params:
        device_id: Optional device ID filter (defaults to all devices)
    """
    engine = _get_fusion_engine()
    if engine is None:
        return jsonify(
            {"status": "success", "risk": None, "message": _MSG_FUSION_UNAVAILABLE}
        )

    device_id = request.args.get("device_id")
    try:
        if device_id:
            risk = engine.get_device_risk(device_id)
            return jsonify({"status": "success", "risk": risk})
        else:
            risks = []
            for row in engine.db.execute(
                "SELECT * FROM device_risk ORDER BY score DESC"
            ).fetchall():
                risks.append(
                    {
                        "device_id": row[0],
                        "score": row[1],
                        "level": row[2],
                        "reason_tags": json.loads(row[3]),
                        "supporting_events": json.loads(row[4]),
                        "metadata": json.loads(row[5]),
                        "updated_at": row[6],
                    }
                )
            return jsonify({"status": "success", "risks": risks})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@dashboard_bp.route("/api/fusion/incidents", methods=["GET"])
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def fusion_incidents():
    """Get correlated incidents from FusionEngine with full AMRDR detail.

    Query params:
        severity: Optional severity filter (CRITICAL, HIGH, MEDIUM, LOW, INFO)
        device_id: Optional device ID filter
        limit: Max results (default 50)
    """
    engine = _get_fusion_engine()
    if engine is None:
        return jsonify(
            {"status": "success", "incidents": [], "message": _MSG_FUSION_UNAVAILABLE}
        )

    try:
        limit = min(int(request.args.get("limit", 50)), 200)
    except (ValueError, TypeError):
        return jsonify({"status": "error", "message": "Invalid limit parameter"}), 400

    device_id = request.args.get("device_id")
    severity_filter = request.args.get("severity")

    try:
        incidents = engine.get_recent_incidents(device_id=device_id, limit=limit)
        if severity_filter:
            incidents = [i for i in incidents if i["severity"] == severity_filter]
        return jsonify(
            {
                "status": "success",
                "incidents": incidents,
                "total": len(incidents),
            }
        )
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ── SOMA Routes ───────────────────────────────────────────────────────


@dashboard_bp.route("/api/soma/overview", methods=["GET"])
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def soma_overview():
    """Full SOMA dashboard data: pipeline, classification, agents, learning."""
    from .telemetry_bridge import get_telemetry_store

    store = get_telemetry_store()
    engine = _get_fusion_engine()

    pipeline_stages = [
        {"name": "Agents", "status": "active"},
        {"name": "WAL Processor", "status": "active"},
        {"name": "Enrichment", "status": "active"},
        {"name": "Scoring Engine", "status": "active"},
        {"name": "FusionEngine", "status": "active" if engine else "inactive"},
        {"name": "Incidents", "status": "active"},
    ]

    classification, events_processed = _get_classification_stats(store)
    agents = _get_agent_explanations(engine)

    total_flagged = classification["suspicious"] + classification["malicious"]
    confirmed_malicious = classification["malicious"]
    if confirmed_malicious > 0:
        fp_rate = round(classification["suspicious"] / total_flagged, 3)
    elif total_flagged > 0:
        fp_rate = None  # No confirmed threats yet — FP rate not meaningful
    else:
        fp_rate = 0.0

    # Read brain metrics for learning context
    brain_metrics = {}
    try:
        brain_path = os.path.join("data", "intel", "models", "brain_metrics.json")
        if os.path.exists(brain_path):
            with open(brain_path) as bf:
                brain_metrics = json.load(bf)
    except Exception:
        pass

    gbc = brain_metrics.get("gradient_boost", {})
    embedder = brain_metrics.get("embedder", {})
    high_trust = brain_metrics.get("high_trust_label_count", 0)

    return jsonify(
        {
            "status": "success",
            "pipeline": {
                "stages": pipeline_stages,
                "events_processed": events_processed,
            },
            "classification": classification,
            "agents": agents,
            "learning": {
                "total_feedback": 0,
                "fp_rate": fp_rate,
                "confirmed_malicious": confirmed_malicious,
                "total_flagged": total_flagged,
                "calibrations": [],
                "gbc_status": gbc.get("status", "cold_start"),
                "gbc_reason": gbc.get("reason"),
                "high_trust_labels": high_trust,
                "gbc_label_threshold": 50,
                "embedder_status": embedder.get("status", "cold_start"),
                "embedder_vocab_size": embedder.get("vocab_size", 0),
                "embedder_dim": embedder.get("embedding_dim", 0),
                "embedder_variance": embedder.get("explained_variance"),
            },
        }
    )


@dashboard_bp.route("/api/soma/agents", methods=["GET"])
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def soma_agents():
    """Get agent reliability states from AMRDR."""
    engine = _get_fusion_engine()
    if engine is None:
        return jsonify({"status": "success", "agents": []})

    try:
        from amoskys.intel.explanation import AgentExplainer

        explainer = AgentExplainer()
        agents = []
        for agent_id in engine.reliability_tracker.list_agents():
            state = engine.reliability_tracker.get_state(agent_id)
            agents.append(explainer.explain_agent(agent_id, state))
        return jsonify({"status": "success", "agents": agents})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@dashboard_bp.route("/api/agents/trust", methods=["GET"])
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def agent_trust():
    """Get cross-validated agent trust scores from AMRDR.

    Returns trust data from TelemetryStore's reliability tracker which
    performs cross-validation (FIM<->process, network<->DNS, auth<->process).
    """
    store = _get_store()
    if not store or not getattr(store, "_reliability", None):
        return jsonify({"status": "success", "agents": [], "source": "unavailable"})
    try:
        tracker = store._reliability
        agents = []
        weights = tracker.get_fusion_weights()
        for agent_id in sorted(tracker.list_agents()):
            state = tracker.get_state(agent_id)
            agents.append(
                {
                    "agent_id": agent_id,
                    "alpha": round(state.alpha, 2),
                    "beta": round(state.beta, 2),
                    "reliability_score": round(state.reliability_score, 3),
                    "fusion_weight": round(weights.get(agent_id, 1.0), 3),
                    "tier": state.tier.name,
                    "drift_type": state.drift_type.name,
                }
            )
        return jsonify(
            {"status": "success", "agents": agents, "source": "cross_validation"}
        )
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@dashboard_bp.route("/api/soma/status", methods=["GET"])
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def soma_baseline_status():
    """Get SOMA baseline learning/detection status + IGRIS tactical memory."""
    result = {"status": "success"}

    # Strategic SOMA (ML models)
    try:
        from amoskys.intel.scoring import ScoringEngine

        scorer = ScoringEngine()
        device_id = request.args.get("device_id")
        result["baseline"] = scorer.get_baseline_status(device_id)
    except Exception as e:
        result["baseline"] = {"error": str(e)}

    # Strategic SOMA brain status
    try:
        from amoskys.intel.soma_brain import SomaBrain

        brain = SomaBrain()
        result["brain"] = brain.status()
    except Exception:
        result["brain"] = {"status": "unavailable"}

    # Tactical SOMA (IGRIS observations)
    try:
        import sqlite3 as _sqlite3

        mem_db = os.path.join("data", "igris", "memory.db")
        if os.path.exists(mem_db):
            conn = _sqlite3.connect(mem_db, timeout=2)
            conn.row_factory = _sqlite3.Row

            total = conn.execute("SELECT COUNT(*) FROM soma_observations").fetchone()[0]
            known = conn.execute(
                "SELECT COUNT(*) FROM soma_observations WHERE seen_count > 3"
            ).fetchone()[0]
            novel = conn.execute(
                "SELECT COUNT(*) FROM soma_observations WHERE seen_count = 1"
            ).fetchone()[0]
            top_patterns = [
                dict(r)
                for r in conn.execute(
                    "SELECT event_category, process_name, seen_count, risk_score "
                    "FROM soma_observations ORDER BY seen_count DESC LIMIT 10"
                ).fetchall()
            ]
            recent_novel = [
                dict(r)
                for r in conn.execute(
                    "SELECT event_category, process_name, path, risk_score "
                    "FROM soma_observations WHERE seen_count = 1 "
                    "ORDER BY risk_score DESC LIMIT 5"
                ).fetchall()
            ]
            conn.close()
            result["tactical_memory"] = {
                "total_patterns": total,
                "known_patterns": known,
                "novel_patterns": novel,
                "learning_progress": round(known / max(total, 1) * 100, 1),
                "top_patterns": top_patterns,
                "recent_novel": recent_novel,
            }
    except Exception:
        result["tactical_memory"] = {"status": "unavailable"}

    return jsonify(result)


@dashboard_bp.route("/api/soma/mode", methods=["POST"])
@require_login
@require_rate_limit(max_requests=10, window_seconds=60)
def soma_set_mode():
    """Manually override SOMA baseline mode (learning/detection).

    Body: {
        "mode": "learning" | "detection",
        "device_id": optional str,
        "learning_hours": optional int (default 24, for learning mode)
    }
    """
    try:
        data = request.get_json(silent=True) or {}
        mode = data.get("mode", "").strip().lower()
        if mode not in ("learning", "detection"):
            return (
                jsonify(
                    {
                        "status": "error",
                        "message": "mode must be 'learning' or 'detection'",
                    }
                ),
                400,
            )

        device_id = data.get("device_id")
        learning_hours = min(int(data.get("learning_hours", 24)), 168)

        from amoskys.intel.scoring import ScoringEngine

        scorer = ScoringEngine(
            learning_hours=learning_hours if mode == "learning" else 0
        )
        success = scorer.set_baseline_mode(mode, device_id)
        if not success and mode == "learning":
            # No baselines exist yet — will be created on next event ingestion
            return jsonify(
                {
                    "status": "success",
                    "mode": mode,
                    "device_id": device_id,
                    "message": f"Learning mode activated ({learning_hours}h). Baselines will be created on next event ingestion.",
                }
            )

        return jsonify({"status": "success", "mode": mode, "device_id": device_id})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ── Explain Routes ────────────────────────────────────────────────────


@dashboard_bp.route("/api/explain/event/<int:event_id>", methods=["GET"])
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def explain_event(event_id):
    """Explain why a security event was classified the way it was."""
    from .telemetry_bridge import get_telemetry_store

    store = get_telemetry_store()
    if store is None:
        return jsonify({"status": "error", "message": _MSG_DB_UNAVAILABLE}), 500

    source_table = request.args.get("source", "security")

    # Map source to table names
    _TABLE_MAP = {
        "security": "security_events",
        "fim": "fim_events",
        "persistence": "persistence_events",
        "flow": "flow_events",
        "process": "process_events",
    }

    try:
        # Try specified table first, then fall back through all tables
        tables_to_try = [_TABLE_MAP.get(source_table, "security_events")]
        tables_to_try += [t for t in _TABLE_MAP.values() if t != tables_to_try[0]]

        row = None
        used_table = None
        for tbl in tables_to_try:
            try:
                row = store.db.execute(
                    f"SELECT * FROM {tbl} WHERE id = ?", (event_id,)
                ).fetchone()
                if row:
                    used_table = tbl
                    break
            except Exception:
                continue

        if not row:
            return jsonify({"status": "error", "message": "Event not found"}), 404

        columns = [
            desc[0]
            for desc in store.db.execute(
                f"SELECT * FROM {used_table} LIMIT 0"
            ).description
        ]
        event_dict = dict(zip(columns, row))

        # Normalize column names for non-security tables
        if used_table != "security_events":
            if "event_type" in event_dict and "event_category" not in event_dict:
                event_dict["event_category"] = event_dict["event_type"]
            if "anomaly_score" in event_dict and "risk_score" not in event_dict:
                event_dict["risk_score"] = event_dict["anomaly_score"]
            if "threat_score" in event_dict and "risk_score" not in event_dict:
                event_dict["risk_score"] = event_dict["threat_score"]
            if "confidence_score" in event_dict and "confidence" not in event_dict:
                event_dict["confidence"] = event_dict["confidence_score"]
            if "reason" in event_dict and "description" not in event_dict:
                event_dict["description"] = event_dict["reason"]

        # Parse JSON fields with null-safe defaults
        event_dict["mitre_techniques"] = _parse_mitre(
            event_dict.get("mitre_techniques")
        )
        event_dict["indicators"] = _parse_indicators(event_dict.get("indicators"))

        # Ensure indicators has meaningful content for the explainer
        if not event_dict.get("indicators"):
            event_dict["indicators"] = {
                "note": "No indicator data recorded for this event"
            }

        from amoskys.intel.explanation import EventExplainer

        explainer = EventExplainer()
        explanation = explainer.explain_event(event_dict)
        return jsonify({"status": "success", "explanation": explanation})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@dashboard_bp.route("/api/explain/incident/<incident_id>", methods=["GET"])
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def explain_incident(incident_id):
    """Explain an incident with narrative, confidence, and TP/FP indicators."""
    engine = _get_fusion_engine()
    if engine is None:
        return jsonify({"status": "error", "message": _MSG_FUSION_UNAVAILABLE}), 500

    try:
        incidents = engine.get_recent_incidents(limit=500)
        incident = next(
            (inc for inc in incidents if inc.get("incident_id") == incident_id),
            None,
        )
        if incident is None:
            return jsonify({"status": "error", "message": "Incident not found"}), 404

        # Fetch contributing events for richer explanation
        from .telemetry_bridge import get_telemetry_store

        events = []
        event_ids = incident.get("event_ids", [])
        if isinstance(event_ids, str):
            try:
                event_ids = json.loads(event_ids)
            except (json.JSONDecodeError, TypeError):
                event_ids = []
        store = get_telemetry_store()
        if store and event_ids:
            try:
                placeholders = ",".join("?" for _ in event_ids)
                rows = store.db.execute(
                    f"SELECT * FROM security_events WHERE id IN ({placeholders})",
                    event_ids,
                ).fetchall()
                cols = [
                    d[0]
                    for d in store.db.execute(
                        "SELECT * FROM security_events LIMIT 0"
                    ).description
                ]
                events = [dict(zip(cols, row)) for row in rows]
            except Exception:
                pass  # Proceed without events — explainer handles None

        from amoskys.intel.explanation import IncidentExplainer

        explainer = IncidentExplainer()
        explanation = explainer.explain_incident(incident, events or None)
        return jsonify({"status": "success", "explanation": explanation})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ── Feedback Routes ───────────────────────────────────────────────────


@dashboard_bp.route("/api/feedback", methods=["POST"])
@require_login
@require_rate_limit(max_requests=20, window_seconds=60)
def submit_feedback():
    """Record analyst triage decision for AMRDR learning.

    Body: {"incident_id": str, "verdict": "confirmed"|"dismissed"}
    """
    engine = _get_fusion_engine()
    if engine is None:
        return jsonify({"status": "error", "message": _MSG_FUSION_UNAVAILABLE}), 500

    data = request.get_json(silent=True) or {}
    incident_id = data.get("incident_id")
    verdict = data.get("verdict")

    if not incident_id or verdict not in ("confirmed", "dismissed"):
        return (
            jsonify(
                {
                    "status": "error",
                    "message": "Required: incident_id and verdict (confirmed|dismissed)",
                }
            ),
            400,
        )

    try:
        user = get_current_user()
        if isinstance(user, dict):
            analyst = user.get("username") or user.get("email") or "unknown"
        elif user:
            analyst = getattr(user, "email", "unknown")
        else:
            analyst = "unknown"
        result = engine.provide_incident_feedback(
            incident_id=incident_id,
            is_confirmed=(verdict == "confirmed"),
            analyst=analyst,
        )
        if result:
            return jsonify({"status": "success", "message": "Feedback recorded"})
        return jsonify({"status": "error", "message": "Incident not found"}), 404
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@dashboard_bp.route("/api/feedback/stats", methods=["GET"])
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def feedback_stats():
    """Get learning metrics: feedback counts, FP rates, reliability trends."""
    from .telemetry_bridge import get_telemetry_store

    engine = _get_fusion_engine()
    store = get_telemetry_store()

    stats = {
        "total_feedback": 0,
        "fp_rate": 0.0,
        "agent_reliability": {},
    }

    if engine:
        try:
            for agent_id in engine.reliability_tracker.list_agents():
                state = engine.reliability_tracker.get_state(agent_id)
                stats["agent_reliability"][agent_id] = {
                    "reliability": round(state.reliability_score, 3),
                    "tier": state.tier.name if state.tier else "NOMINAL",
                    "weight": round(state.fusion_weight, 3),
                }
        except Exception:
            pass

    if store:
        try:
            # Limit to last 7 days for performance on large tables
            cutoff_ns = int((time.time() - 7 * 24 * 3600) * 1e9)
            row = store.db.execute(
                "SELECT "
                "  SUM(CASE WHEN final_classification = 'suspicious' THEN 1 ELSE 0 END), "
                "  SUM(CASE WHEN final_classification != 'legitimate' THEN 1 ELSE 0 END) "
                "FROM security_events WHERE timestamp_ns > ?",
                (cutoff_ns,),
            ).fetchone()
            if row:
                suspicious = row[0] or 0
                flagged = row[1] or 0
                if flagged > 0:
                    stats["fp_rate"] = round(suspicious / flagged, 3)
        except Exception:
            pass

    return jsonify({"status": "success", "stats": stats})
