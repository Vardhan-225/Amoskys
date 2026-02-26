"""
AMRDR Reliability API — Agent reliability status, fusion weights, and feedback.

Endpoints:
    GET  /api/reliability/status/<agent_id>  — Agent reliability state
    GET  /api/reliability/weights             — All fusion weights
    POST /api/reliability/feedback            — Submit analyst ground truth
    GET  /api/reliability/drifts              — Recent drift alerts
"""

import json
import logging
from typing import Any, Dict

from flask import Blueprint, jsonify, request

logger = logging.getLogger(__name__)

reliability_bp = Blueprint("reliability", __name__, url_prefix="/reliability")

# Module-level references — set by register_reliability_deps()
_reliability_tracker = None
_fusion_engine = None


def register_reliability_deps(reliability_tracker, fusion_engine=None):
    """Register runtime dependencies for the reliability API.

    Called during app initialization to inject the tracker and engine
    without circular imports.

    Args:
        reliability_tracker: ReliabilityTracker instance
        fusion_engine: Optional FusionEngine instance (for feedback)
    """
    global _reliability_tracker, _fusion_engine
    _reliability_tracker = reliability_tracker
    _fusion_engine = fusion_engine
    logger.info(
        "Reliability API deps registered: tracker=%s, engine=%s",
        type(reliability_tracker).__name__,
        type(fusion_engine).__name__ if fusion_engine else "None",
    )


@reliability_bp.route("/status/<agent_id>", methods=["GET"])
def get_agent_status(agent_id: str):
    """Get reliability state for a specific agent.

    Returns:
        JSON with alpha, beta, fusion_weight, drift_type, tier, score.
    """
    if _reliability_tracker is None:
        return jsonify({"error": "Reliability tracker not initialized"}), 503

    state = _reliability_tracker.get_state(agent_id)

    return jsonify(
        {
            "agent_id": state.agent_id,
            "alpha": state.alpha,
            "beta": state.beta,
            "reliability_score": state.alpha / (state.alpha + state.beta),
            "fusion_weight": state.fusion_weight,
            "drift_type": state.drift_type.value,
            "recalibration_tier": state.tier.value,
            "last_update_ns": state.last_update_ns,
        }
    )


@reliability_bp.route("/weights", methods=["GET"])
def get_fusion_weights():
    """Get all agent fusion weights.

    Returns:
        JSON dict mapping agent_id → weight.
    """
    if _reliability_tracker is None:
        return jsonify({"error": "Reliability tracker not initialized"}), 503

    weights = _reliability_tracker.get_fusion_weights()

    return jsonify(
        {
            "weights": weights,
            "agent_count": len(weights),
        }
    )


@reliability_bp.route("/feedback", methods=["POST"])
def submit_feedback():
    """Submit analyst ground truth feedback for an incident.

    Request body:
        {
            "incident_id": "INC-...",
            "is_confirmed": true/false,
            "analyst": "analyst_name" (optional)
        }

    Returns:
        JSON confirmation.
    """
    if _fusion_engine is None:
        return jsonify({"error": "Fusion engine not initialized"}), 503

    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body required"}), 400

    incident_id = data.get("incident_id")
    is_confirmed = data.get("is_confirmed")
    analyst = data.get("analyst", "api_user")

    if not incident_id:
        return jsonify({"error": "incident_id required"}), 400
    if is_confirmed is None:
        return jsonify({"error": "is_confirmed required"}), 400

    success = _fusion_engine.provide_incident_feedback(
        incident_id=incident_id,
        is_confirmed=bool(is_confirmed),
        analyst=analyst,
    )

    if not success:
        return jsonify({"error": f"Incident {incident_id} not found"}), 404

    return jsonify(
        {
            "status": "ok",
            "incident_id": incident_id,
            "is_confirmed": is_confirmed,
            "analyst": analyst,
        }
    )


@reliability_bp.route("/drifts", methods=["GET"])
def get_drift_alerts():
    """Get recent drift alerts across all agents.

    Query params:
        limit: Max alerts to return (default 50)

    Returns:
        JSON list of agents with active drift.
    """
    if _reliability_tracker is None:
        return jsonify({"error": "Reliability tracker not initialized"}), 503

    drifts = []
    for agent_id in _reliability_tracker.list_agents():
        state = _reliability_tracker.get_state(agent_id)
        if state.drift_type.value != "none":
            drifts.append(
                {
                    "agent_id": agent_id,
                    "drift_type": state.drift_type.value,
                    "recalibration_tier": state.tier.value,
                    "fusion_weight": state.fusion_weight,
                    "reliability_score": state.alpha / (state.alpha + state.beta),
                    "alpha": state.alpha,
                    "beta": state.beta,
                }
            )

    # Also fetch drift incidents from fusion engine if available
    drift_incidents = []
    if _fusion_engine is not None:
        try:
            recent = _fusion_engine.get_recent_incidents(limit=50)
            drift_incidents = [
                inc for inc in recent if inc.get("rule_name") == "AMRDR_DRIFT"
            ]
        except Exception as e:
            logger.error(f"Failed to fetch drift incidents: {e}")

    return jsonify(
        {
            "active_drifts": drifts,
            "drift_incident_count": len(drift_incidents),
            "recent_drift_incidents": drift_incidents[:10],
        }
    )
