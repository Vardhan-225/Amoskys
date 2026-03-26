"""
SOMA Brain API — Status, metrics, feature importances, training control

Endpoints:
  GET  /api/soma/brain          -> Brain status + model metrics + live DB observations
  GET  /api/soma/brain/features -> Top feature importances (GBC model or DB-derived)
  POST /api/soma/brain/train    -> Force immediate training cycle
  GET  /api/soma/brain/history  -> Training history (last 20 cycles)

All endpoints query the real soma_observations table in data/igris/memory.db
for live observation counts, classification breakdowns, and top patterns.
"""

import json
import logging
import os
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

from flask import Blueprint, jsonify, request

logger = logging.getLogger(__name__)

soma_brain_bp = Blueprint("soma_brain", __name__, url_prefix="/soma/brain")

_MODEL_DIR = "data/intel/models"
_MEMORY_DB = os.path.join("data", "igris", "memory.db")


# ── Helpers ───────────────────────────────────────────────────────────


def _get_memory_conn():
    """Open a read-only connection to the IGRIS memory database."""
    if not os.path.exists(_MEMORY_DB):
        return None
    try:
        conn = sqlite3.connect(_MEMORY_DB, timeout=2)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only = ON")
        return conn
    except Exception as exc:
        logger.warning("Could not open memory.db: %s", exc)
        return None


def _query_observation_stats(conn):
    """Aggregate observation counts by classification from soma_observations.

    is_normal values: 1 = NORMAL, 0 = ANOMALY, -1 = UNKNOWN (unclassified)
    """
    row = conn.execute(
        """
        SELECT
            COUNT(*)                                        AS total,
            SUM(CASE WHEN is_normal = 1  THEN 1 ELSE 0 END) AS normal_count,
            SUM(CASE WHEN is_normal = 0  THEN 1 ELSE 0 END) AS anomaly_count,
            SUM(CASE WHEN is_normal = -1 THEN 1 ELSE 0 END) AS unknown_count,
            MIN(first_seen)                                  AS earliest,
            MAX(last_seen)                                   AS latest
        FROM soma_observations
        """
    ).fetchone()

    total = row["total"] or 0
    anomaly_count = row["anomaly_count"] or 0

    return {
        "total_observations": total,
        "normal_count": row["normal_count"] or 0,
        "anomaly_count": anomaly_count,
        "unknown_count": row["unknown_count"] or 0,
        "anomaly_rate": round(anomaly_count / max(total, 1), 4),
        "first_seen": row["earliest"],
        "last_seen": row["latest"],
    }


def _query_top_anomalies(conn, limit=10):
    """Top ANOMALY observations ordered by risk_score descending."""
    rows = conn.execute(
        """
        SELECT event_category, process_name, path, risk_score,
               seen_count, last_seen
        FROM soma_observations
        WHERE is_normal = 0
        ORDER BY risk_score DESC, seen_count DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]


def _query_top_normal(conn, limit=10):
    """Most-seen NORMAL patterns — the machine's deeply familiar baseline."""
    rows = conn.execute(
        """
        SELECT event_category, process_name, path, risk_score,
               seen_count, last_seen
        FROM soma_observations
        WHERE is_normal = 1
        ORDER BY seen_count DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]


def _load_json(path):
    """Safely load a JSON file, returning {} on any error."""
    if not os.path.exists(path):
        return {}
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as exc:
        logger.warning("Failed to load %s: %s", path, exc)
        return {}


# ── Endpoints ─────────────────────────────────────────────────────────


@soma_brain_bp.route("", methods=["GET"])
def brain_status():
    """Brain status: ML model metrics + live SOMA observation statistics.

    Merges two data sources:
      1. data/intel/models/*.json — trained model metrics, calibration, history
      2. data/igris/memory.db    — live observation counts and top patterns
    """
    metrics = _load_json(os.path.join(_MODEL_DIR, "brain_metrics.json"))
    calibration = _load_json(os.path.join(_MODEL_DIR, "if_calibration.json"))

    # Calibrator adjustment count
    calibrator_adjustments = 0
    cal_log = _load_json(os.path.join(_MODEL_DIR, "auto_calibrator_log.json"))
    if isinstance(cal_log, list):
        calibrator_adjustments = len(cal_log)

    # Which model files exist on disk
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

    # Determine model_status from what's actually available
    any_model = any(models_available.values())
    model_status = "trained" if any_model else "untrained"

    # Live observation data from memory.db
    obs_stats = {}
    top_anomalies = []
    top_normal = []
    conn = _get_memory_conn()
    if conn:
        try:
            obs_stats = _query_observation_stats(conn)
            top_anomalies = _query_top_anomalies(conn, limit=10)
            top_normal = _query_top_normal(conn, limit=10)
        except Exception as exc:
            logger.warning("SOMA observation query failed: %s", exc)
        finally:
            conn.close()

    # Last training time from metrics or history
    last_training_time = metrics.get("started_at")
    if not last_training_time:
        history = _load_json(os.path.join(_MODEL_DIR, "training_history.json"))
        if isinstance(history, list) and history:
            last_training_time = history[-1].get("started_at")

    return jsonify(
        {
            "status": "success",
            "brain": {
                "latest_metrics": metrics,
                "if_calibration": calibration,
                "models_available": models_available,
                "calibrator_adjustments": calibrator_adjustments,
                # Live SOMA observation data
                "model_status": model_status,
                "last_training_time": last_training_time,
                "observations": obs_stats,
                "top_anomalies": top_anomalies,
                "top_normal": top_normal,
            },
        }
    )


@soma_brain_bp.route("/features", methods=["GET"])
def brain_features():
    """Top feature importances from GBC model, with DB-derived fallback.

    Priority:
      1. GBC model top_features from brain_metrics.json (if GBC was trained)
      2. Derived from soma_observations — event_category distribution as a
         proxy for which features matter most to the observation engine.
    """
    metrics = _load_json(os.path.join(_MODEL_DIR, "brain_metrics.json"))
    gbc = metrics.get("gradient_boost", {})
    features = gbc.get("top_features", [])

    # Load feature column names for context
    fc_path = os.path.join(_MODEL_DIR, "feature_columns.joblib")
    all_features = []
    if os.path.exists(fc_path):
        try:
            import joblib

            all_features = joblib.load(fc_path)
        except Exception as exc:
            logger.warning("Failed to load feature columns: %s", exc)

    # If GBC features are available, return them directly
    if features:
        return jsonify(
            {
                "status": "success",
                "features": features,
                "all_feature_names": all_features,
                "gbc_status": gbc.get("status", "unknown"),
                "source": "gradient_boost",
            }
        )

    # Fallback: derive feature-importance proxy from observation distribution
    conn = _get_memory_conn()
    if conn:
        try:
            rows = conn.execute(
                """
                SELECT event_category,
                       SUM(seen_count)  AS total_seen,
                       COUNT(*)         AS pattern_count,
                       AVG(risk_score)  AS avg_risk
                FROM soma_observations
                GROUP BY event_category
                ORDER BY total_seen DESC
                LIMIT 15
                """
            ).fetchall()

            if rows:
                total_seen_all = sum(r["total_seen"] for r in rows) or 1
                features = [
                    {
                        "feature": r["event_category"],
                        "importance": round(r["total_seen"] / total_seen_all, 4),
                        "pattern_count": r["pattern_count"],
                        "avg_risk": round(r["avg_risk"], 4),
                    }
                    for r in rows
                ]
        except Exception as exc:
            logger.warning("Feature derivation from DB failed: %s", exc)
        finally:
            conn.close()

    return jsonify(
        {
            "status": "success",
            "features": features,
            "all_feature_names": all_features,
            "gbc_status": gbc.get("status", "unknown"),
            "source": "soma_observations" if features else "none",
        }
    )


@soma_brain_bp.route("/train", methods=["POST"])
def brain_train():
    """Force an immediate SomaBrain training cycle.

    Instantiates a fresh SomaBrain, runs one synchronous training pass,
    and returns the resulting metrics dict. Training writes updated model
    files to data/intel/models/ and appends to training_history.json.
    """
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
    except Exception as exc:
        logger.error("SOMA brain training failed: %s", exc, exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500


@soma_brain_bp.route("/history", methods=["GET"])
def brain_history():
    """Training history with live observation context.

    Returns the last N training cycles from training_history.json,
    enriched with current observation counts from memory.db.
    """
    history_path = os.path.join(_MODEL_DIR, "training_history.json")
    history_data = _load_json(history_path)

    # training_history.json is a list of cycle dicts
    if not isinstance(history_data, list):
        history_data = []

    try:
        limit = min(int(request.args.get("limit", 20)), 100)
    except (ValueError, TypeError):
        limit = 20

    # Enrich with current observation snapshot
    obs_snapshot = {}
    conn = _get_memory_conn()
    if conn:
        try:
            obs_snapshot = _query_observation_stats(conn)
        except Exception:
            pass
        finally:
            conn.close()

    return jsonify(
        {
            "status": "success",
            "history": history_data[-limit:],
            "total_cycles": len(history_data),
            "current_observations": obs_snapshot,
        }
    )
