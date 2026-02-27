"""
AMRDR Reliability API — Agent reliability status, fusion weights, and feedback.

Endpoints:
    GET  /api/reliability/status              — All agents reliability state
    GET  /api/reliability/status/<agent_id>   — Single agent reliability state
    GET  /api/reliability/weights             — All fusion weights
    POST /api/reliability/feedback            — Submit analyst ground truth / actions
    GET  /api/reliability/drifts              — Recent drift alerts
"""

import logging
from typing import Any, Dict

from flask import Blueprint, jsonify, request

logger = logging.getLogger(__name__)

reliability_bp = Blueprint("reliability", __name__, url_prefix="/reliability")

# Module-level references — set by register_reliability_deps() or auto-initialized
_reliability_tracker = None
_fusion_engine = None

# Known agent IDs to seed the tracker with (from AGENT_CATALOG)
_KNOWN_AGENTS = [
    "auth_agent",
    "dns_agent",
    "fim_agent",
    "flow_agent",
    "kernel_audit_agent",
    "peripheral_agent",
    "persistence_agent",
    "proc_agent",
    "protocol_collectors",
    "device_discovery",
]


def _get_tracker():
    """Get or auto-initialize the reliability tracker.

    Falls back to NoOpReliabilityTracker if register_reliability_deps()
    was never called. Seeds known agents so the dashboard isn't empty.
    """
    global _reliability_tracker
    if _reliability_tracker is None:
        from amoskys.intel.reliability import NoOpReliabilityTracker

        _reliability_tracker = NoOpReliabilityTracker()
        # Seed known agents so the dashboard shows all agents immediately
        for agent_id in _KNOWN_AGENTS:
            _reliability_tracker.get_state(agent_id)
        logger.info(
            "Auto-initialized NoOpReliabilityTracker with %d agents",
            len(_KNOWN_AGENTS),
        )
    return _reliability_tracker


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


def _drift_state_label(drift_type) -> str:
    """Map DriftType enum to frontend-friendly label."""
    val = drift_type.value
    if val == "abrupt":
        return "ALERT"
    if val == "gradual":
        return "WARNING"
    return "STABLE"


def _agent_state_to_dict(state) -> Dict[str, Any]:
    """Convert a ReliabilityState to the JSON dict the frontend expects."""
    return {
        "agent_id": state.agent_id,
        "alpha": state.alpha,
        "beta": state.beta,
        "reliability_score": state.alpha / max(state.alpha + state.beta, 1e-9),
        "weight": state.fusion_weight,
        "fusion_weight": state.fusion_weight,
        "drift_type": state.drift_type.value,
        "drift_state": _drift_state_label(state.drift_type),
        "recalibration_tier": state.tier.value,
        "last_update_ns": state.last_update_ns,
    }


@reliability_bp.route("/status", methods=["GET"])
def get_all_agents_status():
    """Get reliability state for ALL tracked agents.

    Returns:
        JSON with {agents: [...]}, one entry per tracked agent.
    """
    tracker = _get_tracker()
    agents = []
    for agent_id in tracker.list_agents():
        state = tracker.get_state(agent_id)
        agents.append(_agent_state_to_dict(state))

    return jsonify({"agents": agents})


@reliability_bp.route("/status/<agent_id>", methods=["GET"])
def get_agent_status(agent_id: str):
    """Get reliability state for a specific agent.

    Returns:
        JSON with alpha, beta, fusion_weight, drift_type, tier, score.
    """
    tracker = _get_tracker()
    state = tracker.get_state(agent_id)
    return jsonify(_agent_state_to_dict(state))


@reliability_bp.route("/weights", methods=["GET"])
def get_fusion_weights():
    """Get all agent fusion weights.

    Returns:
        JSON dict mapping agent_id -> weight.
    """
    tracker = _get_tracker()
    weights = tracker.get_fusion_weights()

    return jsonify(
        {
            "weights": weights,
            "agent_count": len(weights),
        }
    )


@reliability_bp.route("/feedback", methods=["POST"])
def submit_feedback():
    """Submit analyst feedback for an agent event or action.

    Supports two schemas:
      1. Frontend schema: {agent_id, event_id, action}
         action: "confirm" | "dismiss" | "quarantine" | "restore"
      2. Fusion engine schema: {incident_id, is_confirmed, analyst}

    Returns:
        JSON confirmation.
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body required"}), 400

    tracker = _get_tracker()

    # Schema 1: Frontend feedback (agent_id + action)
    agent_id = data.get("agent_id")
    action = data.get("action")
    if agent_id and action:
        if action == "confirm":
            tracker.update(agent_id, ground_truth_match=True)
            return jsonify(
                {"status": "ok", "message": f"Agent {agent_id} confirmed (TP)."}
            )
        elif action == "dismiss":
            tracker.update(agent_id, ground_truth_match=False)
            return jsonify(
                {"status": "ok", "message": f"Agent {agent_id} dismissed (FP)."}
            )
        elif action == "quarantine":
            state = tracker.get_state(agent_id)
            state.fusion_weight = 0.0
            from amoskys.intel.reliability import RecalibrationTier

            state.tier = RecalibrationTier.QUARANTINE
            return jsonify(
                {"status": "ok", "message": f"Agent {agent_id} quarantined."}
            )
        elif action == "restore":
            state = tracker.get_state(agent_id)
            state.fusion_weight = state.reliability_score
            from amoskys.intel.reliability import DriftType, RecalibrationTier

            state.tier = RecalibrationTier.NOMINAL
            state.drift_type = DriftType.NONE
            return jsonify(
                {"status": "ok", "message": f"Agent {agent_id} restored."}
            )
        else:
            return jsonify({"error": f"Unknown action: {action}"}), 400

    # Schema 2: Fusion engine feedback (incident_id + is_confirmed)
    incident_id = data.get("incident_id")
    is_confirmed = data.get("is_confirmed")
    analyst = data.get("analyst", "api_user")

    if incident_id is not None and is_confirmed is not None:
        if _fusion_engine is None:
            return jsonify(
                {"status": "ok", "message": "Feedback recorded (fusion engine offline)."}
            )
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

    return jsonify({"error": "Provide {agent_id, action} or {incident_id, is_confirmed}"}), 400


@reliability_bp.route("/drifts", methods=["GET"])
def get_drift_alerts():
    """Get recent drift alerts across all agents.

    Returns:
        JSON with {drifts: [...], drift_incident_count, recent_drift_incidents}.
    """
    tracker = _get_tracker()
    drifts = []
    for agent_id in tracker.list_agents():
        state = tracker.get_state(agent_id)
        if state.drift_type.value != "none":
            drifts.append(
                {
                    "agent_id": agent_id,
                    "drift_type": state.drift_type.value,
                    "drift_state": (
                        "ALERT"
                        if state.drift_type.value == "abrupt"
                        else "WARNING"
                    ),
                    "detector": state.drift_type.value,
                    "weight": state.fusion_weight,
                    "recalibration_tier": state.tier.value,
                    "reliability_score": state.alpha / max(state.alpha + state.beta, 1e-9),
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
            logger.error("Failed to fetch drift incidents: %s", e)

    return jsonify(
        {
            "drifts": drifts,
            "active_drifts": drifts,
            "drift_incident_count": len(drift_incidents),
            "recent_drift_incidents": drift_incidents[:10],
        }
    )
