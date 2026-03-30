"""Deployment routes — agent provisioning tokens & deployed-agent management."""

import os
from datetime import datetime, timezone

from flask import Response, jsonify, request

from ..api.rate_limiter import require_rate_limit
from ..middleware import get_current_user, require_login
from . import dashboard_bp

# Operations server URL — where agents ship telemetry
OPS_SERVER_URL = os.getenv("AMOSKYS_OPS_SERVER", "https://ops.amoskys.com")


@dashboard_bp.route("/api/agents/deploy/token", methods=["POST"])
@require_login
@require_rate_limit(max_requests=20, window_seconds=60)
def deploy_create_token():
    """Create a deployment token for agent provisioning."""
    from amoskys.agents.distribution import AgentDistributionService
    from amoskys.db.web_db import get_web_session_context

    user = get_current_user()
    data = request.get_json(silent=True) or {}
    label = data.get("label", "My Device")
    platform = data.get("platform", "macos")

    try:
        with get_web_session_context() as db:
            service = AgentDistributionService(db)
            result = service.create_deployment_token(
                user_id=user.id,
                label=label,
                platform=platform,
            )
            if result.success:
                return jsonify(
                    {
                        "status": "success",
                        "token": result.token,
                        "token_id": result.token_id,
                    }
                )
            return (
                jsonify(
                    {
                        "status": "error",
                        "message": result.error or "Failed to create token",
                    }
                ),
                400,
            )
    except Exception as e:
        return (
            jsonify(
                {
                    "status": "error",
                    "message": str(e),
                }
            ),
            500,
        )


@dashboard_bp.route("/api/agents/deploy/tokens", methods=["GET"])
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def deploy_list_tokens():
    """List deployment tokens for the current user."""
    from amoskys.agents.distribution import AgentDistributionService
    from amoskys.db.web_db import get_web_session_context

    user = get_current_user()

    try:
        with get_web_session_context() as db:
            service = AgentDistributionService(db)
            result = service.list_user_tokens(user.id)
            if result.success:
                tokens = [
                    {
                        "id": t.id,
                        "label": t.label,
                        "platform": t.platform,
                        "is_consumed": t.is_consumed,
                        "expires_at": t.expires_at,
                        "created_at": t.created_at,
                        "consumed_by_agent_id": t.consumed_by_agent_id,
                    }
                    for t in result.tokens
                ]
                return jsonify(
                    {
                        "status": "success",
                        "tokens": tokens,
                        "total": result.total,
                        "active_count": result.active_count,
                        "consumed_count": result.consumed_count,
                    }
                )
            return jsonify({"status": "error", "message": result.error}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@dashboard_bp.route("/api/agents/deploy/tokens/<token_id>/revoke", methods=["POST"])
@require_login
@require_rate_limit(max_requests=20, window_seconds=60)
def deploy_revoke_token(token_id):
    """Revoke a deployment token."""
    from amoskys.agents.distribution import AgentDistributionService
    from amoskys.db.web_db import get_web_session_context

    user = get_current_user()

    try:
        with get_web_session_context() as db:
            service = AgentDistributionService(db)
            ok = service.revoke_token(user.id, token_id)
            if ok:
                return jsonify({"status": "success"})
            return jsonify({"status": "error", "message": "Token not found"}), 404
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@dashboard_bp.route("/api/agents/deploy/agents", methods=["GET"])
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def deploy_list_agents():
    """List deployed agents for the current user."""
    from amoskys.agents.distribution import AgentDistributionService
    from amoskys.db.web_db import get_web_session_context

    user = get_current_user()

    try:
        with get_web_session_context() as db:
            service = AgentDistributionService(db)
            result = service.list_user_agents(user.id)
            if result.success:
                agents = [
                    {
                        "id": a.id,
                        "hostname": a.hostname,
                        "ip_address": a.ip_address,
                        "platform": a.platform,
                        "version": a.version,
                        "status": a.status,
                        "capabilities": a.capabilities,
                        "last_heartbeat_at": a.last_heartbeat_at,
                        "created_at": a.created_at,
                        "heartbeat_count": a.heartbeat_count,
                    }
                    for a in result.agents
                ]
                return jsonify(
                    {
                        "status": "success",
                        "agents": agents,
                        "total": result.total,
                        "by_status": result.by_status,
                    }
                )
            return jsonify({"status": "error", "message": result.error}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@dashboard_bp.route("/api/agents/deploy/agents/<agent_id>/revoke", methods=["POST"])
@require_login
@require_rate_limit(max_requests=20, window_seconds=60)
def deploy_revoke_agent(agent_id):
    """Revoke a deployed agent."""
    from amoskys.agents.distribution import AgentDistributionService
    from amoskys.db.web_db import get_web_session_context

    user = get_current_user()

    try:
        with get_web_session_context() as db:
            service = AgentDistributionService(db)
            ok = service.revoke_agent(user.id, agent_id)
            if ok:
                return jsonify({"status": "success"})
            return jsonify({"status": "error", "message": "Agent not found"}), 404
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@dashboard_bp.route("/api/agents/deploy/stats", methods=["GET"])
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def deploy_stats():
    """Get deployment statistics for the current user."""
    from amoskys.agents.distribution import AgentDistributionService
    from amoskys.db.web_db import get_web_session_context

    user = get_current_user()

    try:
        with get_web_session_context() as db:
            service = AgentDistributionService(db)
            stats = service.get_user_stats(user.id)
            return jsonify(
                {
                    "status": "success",
                    "stats": stats,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ── Quick Deploy ───────────────────────────────────────────────────


@dashboard_bp.route("/api/agents/deploy/quick", methods=["POST"])
@require_login
@require_rate_limit(max_requests=10, window_seconds=60)
def deploy_quick():
    """One-step deploy: generates token + returns install command.

    Returns the complete install one-liner the user can paste into Terminal.
    No manual token copying. No env var editing.
    """
    from amoskys.agents.distribution import AgentDistributionService
    from amoskys.db.web_db import get_web_session_context

    user = get_current_user()
    data = request.get_json(silent=True) or {}
    label = data.get("label", "My Device")
    platform = data.get("platform", "macos")

    try:
        with get_web_session_context() as db:
            service = AgentDistributionService(db)
            result = service.create_deployment_token(
                user_id=user.id,
                label=label,
                platform=platform,
            )
            if not result.success:
                return jsonify({
                    "status": "error",
                    "message": result.error or "Failed to create token",
                }), 400

            token = result.token
            server = OPS_SERVER_URL

            # Build platform-specific install command
            if platform in ("macos", "linux"):
                install_cmd = (
                    f"curl -fsSL https://amoskys.com/deploy/install.sh "
                    f"| sudo bash -s -- --token={token} --server={server}"
                )
            else:
                install_cmd = f"# Download from https://amoskys.com/deploy/{platform}"

            return jsonify({
                "status": "success",
                "token": token,
                "token_id": result.token_id,
                "install_command": install_cmd,
                "ops_server": server,
                "platform": platform,
                "label": label,
            })

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@dashboard_bp.route("/api/agents/deploy/install.sh", methods=["GET"])
def serve_install_script():
    """Serve the install script for curl-pipe-bash deployment (public, no auth)."""
    from pathlib import Path

    script_candidates = [
        Path(__file__).parent.parent.parent.parent / "deploy" / "macos" / "install.sh",
        Path("/opt/amoskys/deploy/macos/install.sh"),
    ]

    for path in script_candidates:
        if path.exists():
            content = path.read_text()
            return Response(content, mimetype="text/x-shellscript")

    return Response("# Install script not found\nexit 1", mimetype="text/x-shellscript", status=404)
