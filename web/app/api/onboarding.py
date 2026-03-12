"""
AMOSKYS User Onboarding API

Handles first-time user setup: account type selection, platform detection,
coverage marketplace selection, and setup completion tracking.
"""

import json as json_mod
import logging
import os
import platform
import secrets
import textwrap

from flask import Blueprint, Response, g, jsonify, request

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


# ── Platform-to-darwin mapping for agent registry lookup ──
_OS_TO_PLATFORM = {"macos": "darwin", "linux": "linux", "windows": "windows"}


@onboarding_bp.route("/catalog", methods=["GET"])
@require_login
def onboarding_catalog():
    """Return agent catalog filtered by platform for marketplace display.

    Query params:
        platform: "macos", "linux", or "windows" (default: auto-detect)
    """
    from amoskys.agents import AGENT_REGISTRY

    requested_os = request.args.get("platform", "macos")
    plat = _OS_TO_PLATFORM.get(requested_os, requested_os)

    catalog = []
    for agent_id, meta in AGENT_REGISTRY.items():
        if plat in meta.get("platforms", []):
            catalog.append(
                {
                    "id": agent_id,
                    "name": meta["name"],
                    "description": meta["description"],
                    "probes": meta.get("probes", 0),
                    "platforms": meta["platforms"],
                    "category": meta.get("category", "endpoint"),
                    "icon": meta.get("icon", "cpu"),
                }
            )

    bundles = {
        "essential": {
            "name": "Essential Security",
            "description": "Core endpoint monitoring — processes, auth, files, network, persistence",
            "agents": ["proc", "auth", "persistence", "fim", "flow"],
            "icon": "shield",
        },
        "advanced": {
            "name": "Advanced Defense",
            "description": "Essential + DNS, HTTP inspection, application logs, peripherals",
            "agents": [
                "proc",
                "auth",
                "persistence",
                "fim",
                "flow",
                "dns",
                "http_inspector",
                "applog",
                "peripheral",
            ],
            "icon": "zap",
        },
        "full": {
            "name": "Full Coverage",
            "description": "Complete threat landscape — all available agents for your platform",
            "agents": [a["id"] for a in catalog],
            "icon": "maximize",
        },
    }

    total_probes = sum(a["probes"] for a in catalog)

    return jsonify(
        {
            "status": "success",
            "catalog": catalog,
            "bundles": bundles,
            "total_agents": len(catalog),
            "total_probes": total_probes,
        }
    )


@onboarding_bp.route("/coverage", methods=["POST"])
@require_login
def onboarding_coverage():
    """Save selected coverage modules for the current user."""
    from amoskys.db.web_db import get_web_session_context

    user = get_current_user()
    data = request.get_json(silent=True) or {}
    selected = data.get("selected_agents", [])

    if not isinstance(selected, list):
        return (
            jsonify({"status": "error", "message": "selected_agents must be a list"}),
            400,
        )

    try:
        with get_web_session_context() as db:
            from amoskys.auth.models import User

            db_user = db.query(User).filter(User.id == user.id).first()
            if not db_user:
                return jsonify({"status": "error", "message": "User not found"}), 404

            db_user.selected_coverage = json_mod.dumps(selected)
            db.commit()

        return jsonify(
            {
                "status": "success",
                "selected_agents": selected,
                "count": len(selected),
            }
        )
    except Exception as e:
        logger.exception("Failed to save coverage for user %s", user.id)
        return jsonify({"status": "error", "message": str(e)}), 500


@onboarding_bp.route("/bootstrap.sh", methods=["GET"])
@require_login
def onboarding_bootstrap():
    """Generate a personalized bootstrap script for agent deployment.

    The script installs AMOSKYS, writes the user's config, and starts the agent.
    Intended to be downloaded or piped:  curl ... | bash
    """
    user = get_current_user()
    plat = getattr(user, "device_os", "macos") or "macos"
    coverage_json = getattr(user, "selected_coverage", None) or "[]"
    try:
        agents = json_mod.loads(coverage_json)
    except (json_mod.JSONDecodeError, TypeError):
        agents = ["proc", "auth", "persistence", "fim", "flow"]

    enrollment_token = secrets.token_urlsafe(32)
    agents_yaml = "\n".join(f"  - {a}" for a in agents)

    script = textwrap.dedent(
        f"""\
        #!/usr/bin/env bash
        # ═══════════════════════════════════════════════════════════
        #  AMOSKYS Agent Bootstrap Script
        #  Platform: {plat}
        #  Agents:   {len(agents)} selected
        #  Generated for: {getattr(user, 'email', 'user')}
        # ═══════════════════════════════════════════════════════════
        set -euo pipefail

        CYAN="\\033[36m"; GREEN="\\033[32m"; RED="\\033[31m"; RESET="\\033[0m"
        info()  {{ echo -e "${{CYAN}}[AMOSKYS]${{RESET}} $1"; }}
        ok()    {{ echo -e "${{GREEN}}[  OK  ]${{RESET}} $1"; }}
        fail()  {{ echo -e "${{RED}}[FAIL]${{RESET}} $1"; exit 1; }}

        info "Starting AMOSKYS agent deployment..."

        # ── Step 1: Check Python ──
        if ! command -v python3 &>/dev/null; then
            fail "Python 3 is required. Install it first: https://python.org"
        fi
        PYVER=$(python3 -c 'import sys; print(f"{{sys.version_info.major}}.{{sys.version_info.minor}}")')
        ok "Python $PYVER detected"

        # ── Step 2: Install AMOSKYS ──
        info "Installing AMOSKYS agent..."
        python3 -m pip install --upgrade --quiet amoskys 2>/dev/null || {{
            info "pip install failed, trying with --user flag..."
            python3 -m pip install --upgrade --quiet --user amoskys || fail "Could not install amoskys package"
        }}
        ok "AMOSKYS installed"

        # ── Step 3: Write configuration ──
        AMOSKYS_DIR="${{HOME}}/.amoskys"
        mkdir -p "$AMOSKYS_DIR"
        cat > "$AMOSKYS_DIR/config.yml" << 'AMOSKYS_CONFIG'
        # AMOSKYS Agent Configuration
        # Generated by setup wizard — edit anytime
        platform: {plat}
        signing: ed25519
        enrollment_token: {enrollment_token}
        agents:
        {agents_yaml}
        AMOSKYS_CONFIG
        ok "Configuration written to $AMOSKYS_DIR/config.yml"

        # ── Step 4: Start agent ──
        info "Starting AMOSKYS agent..."
        if command -v amoskys-agent &>/dev/null; then
            amoskys-agent start --config "$AMOSKYS_DIR/config.yml" --daemon
            ok "Agent started in daemon mode"
        else
            info "Agent binary not in PATH — starting via Python module..."
            python3 -m amoskys.launcher --config "$AMOSKYS_DIR/config.yml" &
            ok "Agent started (PID: $!)"
        fi

        echo ""
        info "═══════════════════════════════════════════════"
        ok   "AMOSKYS agent deployed successfully!"
        info "  Platform:  {plat}"
        info "  Agents:    {len(agents)} active"
        info "  Config:    $AMOSKYS_DIR/config.yml"
        info "  Dashboard: http://localhost:5000/dashboard/cortex"
        info "═══════════════════════════════════════════════"
    """
    )

    # Dedent the heredoc content (the indented YAML inside cat)
    script = script.replace(
        "        # AMOSKYS Agent Configuration", "# AMOSKYS Agent Configuration"
    )
    script = script.replace(
        "        # Generated by setup wizard", "# Generated by setup wizard"
    )
    script = script.replace("        platform:", "platform:")
    script = script.replace("        signing:", "signing:")
    script = script.replace("        enrollment_token:", "enrollment_token:")
    script = script.replace("        agents:", "agents:")
    for a in agents:
        script = script.replace(f"          - {a}", f"  - {a}")
    script = script.replace("        AMOSKYS_CONFIG", "AMOSKYS_CONFIG")

    return Response(
        script,
        mimetype="text/x-shellscript",
        headers={
            "Content-Disposition": "attachment; filename=amoskys-install.sh",
        },
    )


@onboarding_bp.route("/config.yml", methods=["GET"])
@require_login
def onboarding_config():
    """Download the user's agent configuration as a YAML file."""
    user = get_current_user()
    plat = getattr(user, "device_os", "macos") or "macos"
    coverage_json = getattr(user, "selected_coverage", None) or "[]"
    try:
        agents = json_mod.loads(coverage_json)
    except (json_mod.JSONDecodeError, TypeError):
        agents = ["proc", "auth", "persistence", "fim", "flow"]

    agents_yaml = "\n".join(f"  - {a}" for a in agents)

    config = textwrap.dedent(
        f"""\
        # AMOSKYS Agent Configuration
        # Generated by setup wizard — edit anytime
        #
        # Docs: https://docs.amoskys.com/configuration
        # Dashboard: http://localhost:5000/dashboard/cortex

        platform: {plat}
        signing: ed25519

        # Selected coverage modules ({len(agents)} agents)
        agents:
        {agents_yaml}

        # Collection settings
        collection:
          interval: 30          # seconds between collection cycles
          batch_size: 100       # events per batch
          wal_path: data/wal/   # write-ahead log directory

        # Enrichment pipeline
        enrichment:
          geoip: true
          asn: true
          threat_intel: true
          mitre_mapping: true

        # Detection engines
        detection:
          sigma: true           # stateless field-matching rules
          yara: false           # file-scanning (requires YARA library)

        # Storage
        storage:
          path: data/telemetry.db
          retention_days: 90
    """
    )

    return Response(
        config,
        mimetype="text/yaml",
        headers={
            "Content-Disposition": "attachment; filename=amoskys-config.yml",
        },
    )
