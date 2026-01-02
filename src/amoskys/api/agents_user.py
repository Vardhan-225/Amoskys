"""
AMOSKYS User Agent Management API

Flask Blueprint for user-facing agent management:
- GET /api/user/agents - List user's agents
- POST /api/user/agents/token - Create deployment token
- DELETE /api/user/agents/token/<id> - Revoke token
- DELETE /api/user/agents/<id> - Revoke agent
- GET /api/user/agents/stats - Get agent statistics
- POST /api/agents/register - Agent registration (uses token auth)
- POST /api/agents/heartbeat - Agent heartbeat

These are USER endpoints (session auth), not agent endpoints (token auth).
"""

from __future__ import annotations

import os
from dataclasses import asdict
from functools import wraps
from typing import Any

from flask import Blueprint, g, jsonify, make_response, request

from amoskys.api.security import rate_limit_auth
from amoskys.common.logging import get_logger
from amoskys.db import get_session_context

__all__ = ["agents_user_bp"]

logger = get_logger(__name__)


def get_distribution_service(db):
    """Lazy import of AgentDistributionService to avoid circular imports."""
    from amoskys.agents.distribution import AgentDistributionService

    return AgentDistributionService(db)


# Check dev mode
DEV_MODE = os.environ.get("FLASK_DEBUG", "").lower() == "true"

agents_user_bp = Blueprint("agents_user", __name__)

# Cookie settings
SESSION_COOKIE_NAME = "amoskys_session"

# Error message constants
ERR_BODY_REQUIRED = "Request body required"


# =============================================================================
# Auth Decorator
# =============================================================================


def require_user_auth(f):
    """Decorator to require valid user session for endpoint."""
    from amoskys.auth import AuthService

    @wraps(f)
    def decorated(*args: Any, **kwargs: Any):
        session_token = request.cookies.get(SESSION_COOKIE_NAME)
        if not session_token:
            return (
                jsonify(
                    {"error": "Authentication required", "error_code": "NO_SESSION"}
                ),
                401,
            )

        with get_session_context() as db:
            auth = AuthService(db)
            result = auth.validate_and_refresh_session(
                token=session_token,
                ip_address=request.headers.get("X-Forwarded-For", request.remote_addr),
                user_agent=request.headers.get("User-Agent"),
            )

            if not result.is_valid:
                response = make_response(
                    jsonify({"error": result.error, "error_code": result.error_code}),
                    401,
                )
                response.delete_cookie(SESSION_COOKIE_NAME)
                return response

            # Store user info in Flask's g object
            g.current_user = result.user
            g.current_session = result.session

            return f(*args, **kwargs)

    return decorated


# =============================================================================
# User Agent Endpoints
# =============================================================================


@agents_user_bp.route("/api/user/agents", methods=["GET"])
@rate_limit_auth("30 per minute")
@require_user_auth
def list_agents():
    """List all agents for the authenticated user."""
    user = g.current_user

    with get_session_context() as db:
        service = get_distribution_service(db)
        result = service.list_user_agents(user.id)

        if not result.success:
            return jsonify({"error": result.error}), 500

        return jsonify(
            {
                "success": True,
                "agents": [asdict(a) for a in result.agents],
                "total": result.total,
                "by_status": result.by_status,
            }
        )


@agents_user_bp.route("/api/user/agents/tokens", methods=["GET"])
@rate_limit_auth("30 per minute")
@require_user_auth
def list_tokens():
    """List all deployment tokens for the authenticated user."""
    user = g.current_user

    with get_session_context() as db:
        service = get_distribution_service(db)
        result = service.list_user_tokens(user.id)

        if not result.success:
            return jsonify({"error": result.error}), 500

        return jsonify(
            {
                "success": True,
                "tokens": [asdict(t) for t in result.tokens],
                "total": result.total,
                "active_count": result.active_count,
                "consumed_count": result.consumed_count,
            }
        )


@agents_user_bp.route("/api/user/agents/token", methods=["POST"])
@rate_limit_auth("10 per minute")
@require_user_auth
def create_token():
    """Create a new agent deployment token."""
    user = g.current_user
    data = request.get_json()

    if not data:
        return jsonify({"error": ERR_BODY_REQUIRED}), 400

    # Validate required fields
    label = data.get("label")
    platform = data.get("platform")

    if not label:
        return (
            jsonify({"error": "Label is required", "error_code": "MISSING_LABEL"}),
            400,
        )
    if not platform:
        return (
            jsonify(
                {"error": "Platform is required", "error_code": "MISSING_PLATFORM"}
            ),
            400,
        )

    with get_session_context() as db:
        service = get_distribution_service(db)
        result = service.create_deployment_token(
            user_id=user.id,
            label=label,
            platform=platform,
            description=data.get("description"),
            expires_in_days=data.get("expires_in_days"),
        )

        if not result.success:
            return (
                jsonify(
                    {
                        "error": result.error,
                        "error_code": result.error_code,
                    }
                ),
                400,
            )

        # IMPORTANT: Token is shown ONCE
        return (
            jsonify(
                {
                    "success": True,
                    "token": result.token,  # Plaintext - show once!
                    "token_id": result.token_id,
                    "message": "Save this token! It will only be shown once.",
                }
            ),
            201,
        )


@agents_user_bp.route("/api/user/agents/token/<token_id>", methods=["DELETE"])
@rate_limit_auth("10 per minute")
@require_user_auth
def revoke_token(token_id: str):
    """Revoke a deployment token."""
    user = g.current_user

    with get_session_context() as db:
        service = get_distribution_service(db)
        success = service.revoke_token(user.id, token_id)

        if not success:
            return jsonify({"error": "Token not found or already revoked"}), 404

        return jsonify({"success": True, "message": "Token revoked"})


@agents_user_bp.route("/api/user/agents/<agent_id>", methods=["DELETE"])
@rate_limit_auth("10 per minute")
@require_user_auth
def revoke_agent(agent_id: str):
    """Revoke an agent."""
    user = g.current_user

    with get_session_context() as db:
        service = get_distribution_service(db)
        success = service.revoke_agent(user.id, agent_id)

        if not success:
            return jsonify({"error": "Agent not found or already revoked"}), 404

        return jsonify({"success": True, "message": "Agent revoked"})


@agents_user_bp.route("/api/user/agents/stats", methods=["GET"])
@rate_limit_auth("30 per minute")
@require_user_auth
def get_stats():
    """Get agent statistics for the authenticated user."""
    user = g.current_user

    with get_session_context() as db:
        service = get_distribution_service(db)
        stats = service.get_user_stats(user.id)

        return jsonify(
            {
                "success": True,
                **stats,
            }
        )


# =============================================================================
# Agent-Facing Endpoints (Token Auth)
# =============================================================================


@agents_user_bp.route("/api/agents/register", methods=["POST"])
def agent_register():
    """
    Register a new agent using a deployment token.

    This is called by the agent during first-time setup.
    Token auth, not session auth.
    """
    data = request.get_json()

    if not data:
        return jsonify({"error": ERR_BODY_REQUIRED}), 400

    token = data.get("token")
    hostname = data.get("hostname")

    if not token:
        return jsonify({"error": "Deployment token required"}), 400
    if not hostname:
        return jsonify({"error": "Hostname required"}), 400

    with get_session_context() as db:
        service = get_distribution_service(db)
        result = service.register_agent(
            token=token,
            hostname=hostname,
            ip_address=request.headers.get("X-Forwarded-For", request.remote_addr),
            platform=data.get("platform"),
            version=data.get("version", "1.0.0"),
            capabilities=data.get("capabilities"),
            metadata=data.get("metadata"),
        )

        if not result.success:
            return (
                jsonify(
                    {
                        "error": result.error,
                        "error_code": result.error_code,
                    }
                ),
                400,
            )

        return (
            jsonify(
                {
                    "success": True,
                    "agent_id": result.agent_id,
                    "agent_info": result.agent_info,
                    "message": "Agent registered successfully",
                }
            ),
            201,
        )


@agents_user_bp.route("/api/agents/heartbeat", methods=["POST"])
def agent_heartbeat():
    """
    Record agent heartbeat.

    Called periodically by agents to report health.
    """
    data = request.get_json()

    if not data:
        return jsonify({"error": ERR_BODY_REQUIRED}), 400

    agent_id = data.get("agent_id")
    if not agent_id:
        return jsonify({"error": "Agent ID required"}), 400

    with get_session_context() as db:
        service = get_distribution_service(db)
        success = service.record_heartbeat(
            agent_id=agent_id,
            ip_address=request.headers.get("X-Forwarded-For", request.remote_addr),
            metadata=data.get("metadata"),
        )

        if not success:
            return jsonify({"error": "Agent not found or revoked"}), 404

        return jsonify(
            {
                "success": True,
                "message": "Heartbeat recorded",
            }
        )


# =============================================================================
# Download Package Info
# =============================================================================


@agents_user_bp.route("/api/user/agents/package-info", methods=["GET"])
@rate_limit_auth("30 per minute")
@require_user_auth
def get_package_info():
    """
    Get information about available agent packages.

    Returns download URLs and instructions for each platform.
    """
    # Base URL for downloads (would be CDN in production)
    base_url = os.environ.get("AMOSKYS_AGENT_DOWNLOAD_URL", "/downloads/agents")

    return jsonify(
        {
            "success": True,
            "version": "1.0.0",
            "packages": {
                "windows": {
                    "name": "AMOSKYS Agent for Windows",
                    "filename": "amoskys-agent-windows-1.0.0.exe",
                    "url": f"{base_url}/amoskys-agent-windows-1.0.0.exe",
                    "size_mb": 45,
                    "sha256": "pending",  # Would be actual hash
                    "requirements": "Windows 10 or later, .NET 6 Runtime",
                    "instructions": [
                        "1. Download the installer",
                        "2. Run as Administrator",
                        "3. Enter your deployment token when prompted",
                        "4. Agent will start automatically",
                    ],
                },
                "linux": {
                    "name": "AMOSKYS Agent for Linux",
                    "filename": "amoskys-agent-linux-1.0.0.tar.gz",
                    "url": f"{base_url}/amoskys-agent-linux-1.0.0.tar.gz",
                    "size_mb": 35,
                    "sha256": "pending",
                    "requirements": "Linux kernel 4.0+, glibc 2.17+",
                    "instructions": [
                        "1. Download and extract the archive",
                        "2. Run: sudo ./install.sh",
                        "3. Configure with: amoskys-agent config --token YOUR_TOKEN",
                        "4. Start with: sudo systemctl start amoskys-agent",
                    ],
                },
                "macos": {
                    "name": "AMOSKYS Agent for macOS",
                    "filename": "amoskys-agent-macos-1.0.0.pkg",
                    "url": f"{base_url}/amoskys-agent-macos-1.0.0.pkg",
                    "size_mb": 40,
                    "sha256": "pending",
                    "requirements": "macOS 11 (Big Sur) or later",
                    "instructions": [
                        "1. Download the package",
                        "2. Open and follow the installer",
                        "3. Grant Full Disk Access in System Preferences",
                        "4. Configure with your deployment token",
                    ],
                },
                "docker": {
                    "name": "AMOSKYS Agent Docker Image",
                    "image": "amoskys/agent:1.0.0",
                    "url": "docker pull amoskys/agent:1.0.0",
                    "size_mb": 150,
                    "sha256": "pending",
                    "requirements": "Docker 20.10+",
                    "instructions": [
                        "1. Pull the image: docker pull amoskys/agent:1.0.0",
                        "2. Run: docker run -d -e AMOSKYS_TOKEN=YOUR_TOKEN amoskys/agent:1.0.0",
                        "3. For Kubernetes, use our Helm chart",
                    ],
                },
            },
        }
    )
