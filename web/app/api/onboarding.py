"""
AMOSKYS User Onboarding API

Handles first-time user setup: account type selection, platform detection,
and setup completion tracking.
"""

import logging
import os
import platform

from flask import Blueprint, g, jsonify, request

logger = logging.getLogger(__name__)

from ..middleware import get_current_user, require_login

onboarding_bp = Blueprint("onboarding", __name__, url_prefix="/onboarding")


@onboarding_bp.route("/status", methods=["GET"])
@require_login
def onboarding_status():
    """Check if current user has completed onboarding."""
    user = get_current_user()
    return jsonify(
        {
            "status": "success",
            "setup_completed": getattr(user, "setup_completed", True),
            "account_type": getattr(user, "account_type", None),
            "device_os": getattr(user, "device_os", None),
        }
    )


@onboarding_bp.route("/profile", methods=["POST"])
@require_login
def onboarding_profile():
    """Save account type and device OS during onboarding."""
    from amoskys.db.web_db import get_web_session_context

    user = get_current_user()
    data = request.get_json(silent=True) or {}

    account_type = data.get("account_type")
    device_os = data.get("device_os")

    if account_type and account_type not in ("enterprise", "individual"):
        return (
            jsonify({"status": "error", "message": "Invalid account_type"}),
            400,
        )

    if device_os and device_os not in ("macos", "linux", "windows"):
        return (
            jsonify({"status": "error", "message": "Invalid device_os"}),
            400,
        )

    try:
        with get_web_session_context() as db:
            from amoskys.auth.models import User

            db_user = db.query(User).filter(User.id == user.id).first()
            if not db_user:
                return jsonify({"status": "error", "message": "User not found"}), 404

            if account_type:
                db_user.account_type = account_type
            if device_os:
                db_user.device_os = device_os
            db.commit()

        return jsonify(
            {
                "status": "success",
                "account_type": account_type,
                "device_os": device_os,
            }
        )
    except Exception as e:
        logger.exception("Failed to save onboarding profile for user %s", user.id)
        return jsonify({"status": "error", "message": str(e)}), 500


@onboarding_bp.route("/complete", methods=["POST"])
@require_login
def onboarding_complete():
    """Mark onboarding as completed for current user."""
    from amoskys.db.web_db import get_web_session_context

    user = get_current_user()

    try:
        with get_web_session_context() as db:
            from amoskys.auth.models import User

            db_user = db.query(User).filter(User.id == user.id).first()
            if not db_user:
                return jsonify({"status": "error", "message": "User not found"}), 404

            db_user.setup_completed = True
            db.commit()

        return jsonify({"status": "success", "setup_completed": True})
    except Exception as e:
        logger.exception("Failed to complete onboarding for user %s", user.id)
        return jsonify({"status": "error", "message": str(e)}), 500


@onboarding_bp.route("/preflight", methods=["GET"])
@require_login
def onboarding_preflight():
    """Auto-detect platform and check if agent signing key exists."""
    # Detect OS from server-side (where agents will run)
    system = platform.system().lower()
    if system == "darwin":
        detected_os = "macos"
    elif system == "linux":
        detected_os = "linux"
    elif system == "windows":
        detected_os = "windows"
    else:
        detected_os = system

    # Check if Ed25519 key exists
    key_exists = os.path.exists("certs/agent.ed25519")

    return jsonify(
        {
            "status": "success",
            "detected_os": detected_os,
            "key_exists": key_exists,
            "platform_details": {
                "system": platform.system(),
                "release": platform.release(),
                "machine": platform.machine(),
            },
        }
    )
