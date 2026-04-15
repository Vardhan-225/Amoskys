"""Dashboard page routes — template renders with no business logic."""

from flask import redirect, render_template, request, url_for

from ..middleware import get_current_user, require_login
from . import dashboard_bp

_DEVICES_URL = "/dashboard/devices"


@dashboard_bp.route("/")
@require_login
def dashboard_home():
    """Landing page — overview (or setup if first login)."""
    user = get_current_user()
    if user and not user.setup_completed:
        return redirect("/dashboard/setup")
    return render_template("dashboard/overview.html", user=user)


@dashboard_bp.route("/devices")
@require_login
def devices_page():
    """Device list — fleet inventory."""
    user = get_current_user()
    return render_template("dashboard/devices.html", user=user)


@dashboard_bp.route("/setup")
@require_login
def setup_page():
    """IGRIS onboarding — first-time setup wizard."""
    user = get_current_user()
    if user and user.setup_completed:
        return redirect("/dashboard")
    return render_template("dashboard/setup.html", user=user)


@dashboard_bp.route("/api/setup/complete", methods=["POST"])
@require_login
def setup_complete():
    """Mark setup as completed for the current user."""
    from flask import jsonify
    from amoskys.db.web_db import get_web_session_context
    from amoskys.auth.models import User

    user = get_current_user()
    if not user:
        return jsonify({"error": "Not authenticated"}), 401

    try:
        with get_web_session_context() as db:
            db_user = db.query(User).filter_by(id=user.id).first()
            if db_user:
                db_user.setup_completed = True
        return jsonify({"status": "ok"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@dashboard_bp.route("/cortex")
@require_login
def cortex_redirect():
    """Cortex without device context — redirect to device list."""
    return redirect(_DEVICES_URL)


@dashboard_bp.route("/device/<device_id>/cortex")
@require_login
def cortex_dashboard(device_id):
    """AMOSKYS Cortex Dashboard — scoped to a single device."""
    user = get_current_user()
    return render_template("dashboard/cortex.html", user=user, device_id=device_id)


@dashboard_bp.route("/agents")
@require_login
def agent_management():
    """Agent Management Dashboard - Neural Network Status"""
    user = get_current_user()
    return render_template("dashboard/agents.html", user=user)


@dashboard_bp.route("/agent-monitor")
@require_login
def agent_monitor():
    """Agent Monitor - Deep single-agent telemetry viewer"""
    user = get_current_user()
    return render_template("dashboard/agent-monitor.html", user=user)


@dashboard_bp.route("/event-stream")
@require_login
def event_stream():
    """Event Stream — live firehose of all telemetry events"""
    user = get_current_user()
    return render_template("dashboard/event-stream.html", user=user)


@dashboard_bp.route("/probe-explorer")
@require_login
def probe_explorer():
    """Probe Explorer - Deep inspection of all micro-probes"""
    user = get_current_user()
    return render_template("dashboard/probe-explorer.html", user=user)


@dashboard_bp.route("/system")
@require_login
def system_monitoring():
    """System Health Monitoring - Platform Vitals"""
    user = get_current_user()
    return render_template("dashboard/system.html", user=user)


@dashboard_bp.route("/processes")
@require_login
def processes_redirect():
    """Processes without device context — redirect to device list."""
    return redirect(_DEVICES_URL)


@dashboard_bp.route("/device/<device_id>/processes")
@require_login
def process_telemetry(device_id):
    """Process Telemetry — scoped to a single device."""
    user = get_current_user()
    return render_template("dashboard/processes.html", user=user, device_id=device_id)


@dashboard_bp.route("/peripherals")
@require_login
def peripherals_redirect():
    """Peripherals without device context — redirect to device list."""
    return redirect(_DEVICES_URL)


@dashboard_bp.route("/device/<device_id>/peripherals")
@require_login
def peripheral_monitoring(device_id):
    """Peripheral Monitoring — scoped to a single device."""
    user = get_current_user()
    return render_template("dashboard/peripherals.html", user=user, device_id=device_id)


@dashboard_bp.route("/database")
@require_login
def database_manager():
    """Database Manager - Zero-Trust Data Management"""
    user = get_current_user()
    return render_template("dashboard/database_manager.html", user=user)


@dashboard_bp.route("/my-agents")
@require_login
def my_agents():
    """User Agent Management - Deploy and Monitor Your Agents"""
    user = get_current_user()
    return render_template("dashboard/my-agents.html", user=user)


@dashboard_bp.route("/deploy")
@require_login
def deploy_agent():
    """Agent Deployment Portal - Download and Deploy"""
    user = get_current_user()
    return render_template("dashboard/deploy.html", user=user)


@dashboard_bp.route("/mitre")
@require_login
def mitre_coverage():
    """MITRE ATT&CK Coverage Heatmap"""
    user = get_current_user()
    return render_template("dashboard/mitre.html", user=user)


@dashboard_bp.route("/hunt")
@require_login
def threat_hunting():
    """Log Search / Threat Hunting Console"""
    user = get_current_user()
    return render_template("dashboard/hunt.html", user=user)


@dashboard_bp.route("/incidents")
@require_login
def incident_management():
    """Incident Management Dashboard"""
    user = get_current_user()
    return render_template("dashboard/incidents.html", user=user)


@dashboard_bp.route("/correlation")
@require_login
def correlation_dashboard():
    """SOMA Correlation — FusionEngine incidents, device risk, MITRE coverage"""
    user = get_current_user()
    return render_template("dashboard/correlation.html", user=user)


@dashboard_bp.route("/soma")
@require_login
def soma_dashboard():
    """SOMA — Architecture, scoring, agent reliability, learning"""
    user = get_current_user()
    return render_template("dashboard/soma.html", user=user)


@dashboard_bp.route("/soma/brain")
@require_login
def soma_brain_dashboard():
    """Redirect to unified SOMA Intelligence page (ML Models section)."""
    return redirect(url_for("dashboard.soma_dashboard") + "#ml-models")


@dashboard_bp.route("/network")
@require_login
def network_redirect():
    """Network without device context — redirect to device list."""
    return redirect(_DEVICES_URL)


@dashboard_bp.route("/device/<device_id>/network")
@require_login
def network_topology(device_id):
    """Network Topology Map — scoped to a single device."""
    user = get_current_user()
    return render_template("dashboard/network.html", user=user, device_id=device_id)


@dashboard_bp.route("/threat-feed")
@require_login
def threat_feed():
    """Live Threat Feed - Full-page threat analysis and triage"""
    user = get_current_user()
    return render_template("dashboard/threat-feed.html", user=user)


@dashboard_bp.route("/reliability")
@require_login
def reliability_dashboard():
    """Agent Reliability (AMRDR) - Drift detection and trust weights"""
    user = get_current_user()
    return render_template("dashboard/reliability.html", user=user)


@dashboard_bp.route("/igris")
@require_login
def igris_dashboard():
    """IGRIS — Autonomous Supervisory Intelligence Layer"""
    user = get_current_user()
    return render_template("dashboard/igris.html", user=user)


@dashboard_bp.route("/guardian")
@require_login
def guardian_dashboard():
    """Guardian C2 — Command & Control Terminal"""
    user = get_current_user()
    return render_template("dashboard/guardian.html", user=user)


# ── Observatory Pages ──
# Each page supports an optional device_id via query param (?device_id=xxx)
# or via device-scoped route (/device/<id>/posture).


@dashboard_bp.route("/posture")
@require_login
def posture_redirect():
    """Posture without device context — redirect to device list."""
    return redirect(_DEVICES_URL)


@dashboard_bp.route("/device/<device_id>/posture")
@require_login
def device_posture(device_id):
    """Device Posture — scoped to a single device."""
    user = get_current_user()
    return render_template("dashboard/posture.html", user=user, device_id=device_id)


@dashboard_bp.route("/dns")
@require_login
def dns_redirect():
    """DNS without device context — redirect to device list."""
    return redirect(_DEVICES_URL)


@dashboard_bp.route("/device/<device_id>/dns")
@require_login
def dns_intelligence(device_id):
    """DNS Intelligence — scoped to a single device."""
    user = get_current_user()
    return render_template("dashboard/dns-intelligence.html", user=user, device_id=device_id)


@dashboard_bp.route("/file-integrity")
@require_login
def file_integrity_redirect():
    """FIM without device context — redirect to device list."""
    return redirect(_DEVICES_URL)


@dashboard_bp.route("/device/<device_id>/file-integrity")
@require_login
def file_integrity(device_id):
    """File Integrity Monitor — scoped to a single device."""
    user = get_current_user()
    return render_template("dashboard/file-integrity.html", user=user, device_id=device_id)


@dashboard_bp.route("/persistence")
@require_login
def persistence_redirect():
    """Persistence without device context — redirect to device list."""
    return redirect(_DEVICES_URL)


@dashboard_bp.route("/device/<device_id>/persistence")
@require_login
def persistence_landscape(device_id):
    """Persistence Landscape — scoped to a single device."""
    user = get_current_user()
    return render_template("dashboard/persistence-landscape.html", user=user, device_id=device_id)


@dashboard_bp.route("/auth")
@require_login
def auth_redirect():
    """Auth without device context — redirect to device list."""
    return redirect(_DEVICES_URL)


@dashboard_bp.route("/device/<device_id>/auth")
@require_login
def auth_observatory(device_id):
    """Auth & Access — scoped to a single device."""
    user = get_current_user()
    return render_template("dashboard/auth-observatory.html", user=user, device_id=device_id)


@dashboard_bp.route("/timeline-replay")
@require_login
def timeline_redirect():
    """Timeline without device context — redirect to device list."""
    return redirect(_DEVICES_URL)


@dashboard_bp.route("/device/<device_id>/timeline-replay")
@require_login
def timeline_replay(device_id):
    """Threat Timeline Replay — scoped to a single device."""
    user = get_current_user()
    return render_template("dashboard/timeline-replay.html", user=user, device_id=device_id)


@dashboard_bp.route("/observations")
@require_login
def observations_redirect():
    """Observations without device context — redirect to device list."""
    return redirect(_DEVICES_URL)


@dashboard_bp.route("/device/<device_id>/observations")
@require_login
def observation_domains(device_id):
    """Observation Domains — scoped to a single device."""
    user = get_current_user()
    return render_template("dashboard/observations.html", user=user, device_id=device_id)


# ── Consolidated Views (v3 Architecture) ──


@dashboard_bp.route("/threats")
@require_login
def threats_consolidated():
    """Threats — Consolidated: Feed, MITRE, Hunt, Incidents, Correlation"""
    user = get_current_user()
    return render_template("dashboard/threats.html", user=user)


@dashboard_bp.route("/observatory")
@require_login
def observatory_redirect():
    """Observatory without device context — redirect to device list."""
    return redirect(_DEVICES_URL)


@dashboard_bp.route("/device/<device_id>/observatory")
@require_login
def observatory_consolidated(device_id):
    """Observatory — All domain monitoring scoped to a single device."""
    user = get_current_user()
    return render_template("dashboard/observatory.html", user=user, device_id=device_id)


@dashboard_bp.route("/intelligence")
@require_login
def intelligence_consolidated():
    """Intelligence — SOMA + INADS + Scoring + Fusion + AMRDR"""
    user = get_current_user()
    return render_template("dashboard/intelligence.html", user=user)


@dashboard_bp.route("/fleet")
@require_login
def fleet_consolidated():
    """Fleet — Agent management, deploy, reliability"""
    user = get_current_user()
    return render_template("dashboard/fleet.html", user=user)


@dashboard_bp.route("/settings")
@require_login
def settings_page():
    """Settings — account, team, advanced"""
    user = get_current_user()
    return render_template("dashboard/settings.html", user=user)
