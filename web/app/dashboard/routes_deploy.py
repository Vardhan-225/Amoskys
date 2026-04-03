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


@dashboard_bp.route("/api/agents/deploy/download", methods=["POST"])
@require_login
@require_rate_limit(max_requests=5, window_seconds=60)
def deploy_download_pkg():
    """Download a .zip containing signed .pkg + personalized config.

    Creates a .zip on the fly with:
      - AMOSKYS.pkg (signed + notarized, Gatekeeper-trusted)
      - .amoskys-config (deployment token + ops server URL)

    macOS auto-extracts the .zip. User double-clicks the .pkg.
    postinstall finds .amoskys-config in the same folder. Done.
    """
    import io
    import zipfile
    from pathlib import Path

    from amoskys.agents.distribution import AgentDistributionService
    from amoskys.db.web_db import get_web_session_context

    user = get_current_user()
    data = request.get_json(silent=True) or {}
    label = data.get("label", "My Mac")
    platform = data.get("platform", "macos")

    # Find the signed .pkg
    pkg_candidates = [
        Path("/var/www/amoskys-static/AMOSKYS.pkg"),
        Path("/opt/amoskys/dist/AMOSKYS-0.9.1-beta.pkg"),
        Path(__file__).parent.parent.parent.parent / "dist" / "AMOSKYS-0.9.1-beta-signed.pkg",
        Path(__file__).parent.parent.parent.parent / "dist" / "AMOSKYS-0.9.1-beta.pkg",
    ]
    pkg_path = None
    for p in pkg_candidates:
        if p.exists():
            pkg_path = p
            break

    if not pkg_path:
        return jsonify({"status": "error", "message": "Installer package not found"}), 500

    # Generate deployment token
    try:
        with get_web_session_context() as db:
            service = AgentDistributionService(db)
            result = service.create_deployment_token(
                user_id=user.id,
                label=label,
                platform=platform,
            )
            if not result.success:
                return jsonify({"status": "error", "message": result.error}), 400
            token = result.token
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

    # Build .amoskys-config — includes org_id so ops server can link device to user's org
    org_id = getattr(user, "org_id", "") or ""
    config_content = f"token={token}\nserver={OPS_SERVER_URL}\norg_id={org_id}\n"

    # Create .zip: signed .pkg + config
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_STORED) as zf:
        zf.write(pkg_path, "AMOSKYS-Install/AMOSKYS.pkg")
        zf.writestr("AMOSKYS-Install/.amoskys-config", config_content)

    zip_buffer.seek(0)
    zip_bytes = zip_buffer.getvalue()

    return Response(
        zip_bytes,
        mimetype="application/zip",
        headers={
            "Content-Disposition": "attachment; filename=AMOSKYS-Install.zip",
            "Content-Length": str(len(zip_bytes)),
        },
    )


# In-memory store for pending downloads (short-lived, <10 min)
import time
_pending_downloads: dict = {}


def _cleanup_downloads():
    """Remove download records older than 10 minutes."""
    cutoff = time.time() - 600
    expired = [k for k, v in _pending_downloads.items() if v["created"] < cutoff]
    for k in expired:
        del _pending_downloads[k]


@dashboard_bp.route("/api/agents/deploy/config/<download_id>", methods=["GET"])
def deploy_get_config(download_id):
    """Return token + server URL for a download ID.

    Called by the .pkg postinstall script during installation OR
    downloaded as a .amoskys-config file by the browser.
    The download ID is short-lived (10 min).
    """
    record = _pending_downloads.get(download_id)
    if not record:
        return jsonify({"error": "Download expired or not found"}), 404

    content = f"token={record['token']}\nserver={record['server']}\n"

    # If requested as a file download (browser), serve as attachment
    if request.args.get("download") == "1":
        return Response(
            content,
            mimetype="application/octet-stream",
            headers={
                "Content-Disposition": "attachment; filename=.amoskys-config",
            },
        )

    # Otherwise return as plain text (for postinstall curl)
    # Consume the record on plain-text fetch (postinstall is the final consumer)
    _pending_downloads.pop(download_id, None)
    return Response(content, mimetype="text/plain")
