"""
SOMA Brain API — Status, metrics, feature importances, training control

Endpoints:
  GET  /api/soma/brain          → Brain status + model metrics
  GET  /api/soma/brain/features → Top feature importances
  POST /api/soma/brain/train    → Force immediate training cycle
  GET  /api/soma/brain/history  → Training history (last 20 cycles)
"""

import json
import logging
import os

from flask import Blueprint, jsonify, request

logger = logging.getLogger(__name__)

soma_brain_bp = Blueprint("soma_brain", __name__, url_prefix="/soma/brain")

_MODEL_DIR = "data/intel/models"


@soma_brain_bp.route("", methods=["GET"])
def brain_status():
    """Brain status, model metrics, training count."""
    metrics_path = os.path.join(_MODEL_DIR, "brain_metrics.json")
    cal_path = os.path.join(_MODEL_DIR, "if_calibration.json")
    log_path = os.path.join(_MODEL_DIR, "auto_calibrator_log.json")

    metrics = {}
    if os.path.exists(metrics_path):
        try:
            with open(metrics_path) as f:
                metrics = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.warning("Failed to load brain metrics from %s: %s", metrics_path, e)

    calibration = {}
    if os.path.exists(cal_path):
        try:
            with open(cal_path) as f:
                calibration = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.warning("Failed to load calibration from %s: %s", cal_path, e)

    calibrator_adjustments = 0
    if os.path.exists(log_path):
        try:
            with open(log_path) as f:
                log = json.load(f)
                calibrator_adjustments = len(log) if isinstance(log, list) else 0
        except (json.JSONDecodeError, IOError) as e:
            logger.warning("Failed to load calibrator log from %s: %s", log_path, e)

    # Check which models exist
    models_available = {
        "isolation_forest": os.path.exists(
            os.path.join(_MODEL_DIR, "isolation_forest.joblib")
        ),
        "gradient_boost": os.path.exists(
            os.path.join(_MODEL_DIR, "gradient_boost.joblib")
        ),
        "event_embedder": os.path.exists(
            os.path.join(_MODEL_DIR, "event_embedder.joblib")
        ),
    }

    return jsonify(
        {
            "status": "success",
            "brain": {
                "latest_metrics": metrics,
                "if_calibration": calibration,
                "models_available": models_available,
                "calibrator_adjustments": calibrator_adjustments,
            },
        }
    )


@soma_brain_bp.route("/features", methods=["GET"])
def brain_features():
    """Top feature importances from GBC model (if trained)."""
    metrics_path = os.path.join(_MODEL_DIR, "brain_metrics.json")

    if not os.path.exists(metrics_path):
        return jsonify(
            {"status": "success", "features": [], "message": "No training data yet"}
        )

    try:
        with open(metrics_path) as f:
            metrics = json.load(f)
    except (json.JSONDecodeError, IOError):
        return jsonify({"status": "error", "message": "Could not read metrics"}), 500

    gbc = metrics.get("gradient_boost", {})
    features = gbc.get("top_features", [])

    # Also load feature columns for context
    fc_path = os.path.join(_MODEL_DIR, "feature_columns.joblib")
    all_features = []
    if os.path.exists(fc_path):
        try:
            import joblib

            all_features = joblib.load(fc_path)
        except Exception as e:
            logger.warning("Failed to load feature columns from %s: %s", fc_path, e)

    return jsonify(
        {
            "status": "success",
            "features": features,
            "all_feature_names": all_features,
            "gbc_status": gbc.get("status", "unknown"),
        }
    )


@soma_brain_bp.route("/train", methods=["POST"])
def brain_train():
    """Force an immediate training cycle."""
    try:
        from amoskys.intel.soma_brain import SomaBrain

        db_path = (
            request.json.get("db_path", "data/telemetry.db")
            if request.json
            else "data/telemetry.db"
        )
        brain = SomaBrain(telemetry_db_path=db_path)
        metrics = brain.train_once()
        return jsonify({"status": "success", "metrics": metrics})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@soma_brain_bp.route("/history", methods=["GET"])
def brain_history():
    """Training history (last 20 cycles)."""
    history_path = os.path.join(_MODEL_DIR, "training_history.json")

    if not os.path.exists(history_path):
        return jsonify(
            {"status": "success", "history": [], "message": "No training history yet"}
        )

    try:
        with open(history_path) as f:
            history = json.load(f)
    except (json.JSONDecodeError, IOError):
        return jsonify({"status": "error", "message": "Could not read history"}), 500

    # Return last 20 entries
    limit = int(request.args.get("limit", 20))
    return jsonify(
        {
            "status": "success",
            "history": history[-limit:],
            "total_cycles": len(history),
        }
    )
