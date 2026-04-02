"""Dashboard page routes — template renders with no business logic."""

from flask import redirect, render_template, request, url_for

from ..middleware import get_current_user, require_login
from . import dashboard_bp


@dashboard_bp.route("/")
@require_login
def dashboard_home():
    """Landing page — security overview."""
    user = get_current_user()
    return render_template("dashboard/overview.html", user=user)


@dashboard_bp.route("/devices")
@require_login
def devices_page():
    """Devices list — just the devices."""
    user = get_current_user()
    return render_template("dashboard/devices.html", user=user)


@dashboard_bp.route("/cortex")
@require_login
def cortex_dashboard():
    """AMOSKYS Cortex Dashboard - Advanced View (power users)"""
    user = get_current_user()
    return render_template("dashboard/cortex.html", user=user)


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
def process_telemetry():
    """Process Telemetry Dashboard - Mac Process Monitoring"""
    user = get_current_user()
    return render_template("dashboard/processes.html", user=user)


@dashboard_bp.route("/peripherals")
@require_login
def peripheral_monitoring():
    """Peripheral Monitoring Dashboard - USB/Bluetooth Device Tracking"""
    user = get_current_user()
    return render_template("dashboard/peripherals.html", user=user)


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
def network_topology():
    """Network Topology Map"""
    user = get_current_user()
    return render_template("dashboard/network.html", user=user)


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


@dashboard_bp.route("/posture")
@require_login
def device_posture():
    """Device Posture — Single-screen device health overview"""
    user = get_current_user()
    return render_template("dashboard/posture.html", user=user)


@dashboard_bp.route("/dns")
@require_login
def dns_intelligence():
    """DNS Intelligence — DGA detection, beaconing, query analysis"""
    user = get_current_user()
    return render_template("dashboard/dns-intelligence.html", user=user)


@dashboard_bp.route("/file-integrity")
@require_login
def file_integrity():
    """File Integrity Monitor — Change tracking and risk analysis"""
    user = get_current_user()
    return render_template("dashboard/file-integrity.html", user=user)


@dashboard_bp.route("/persistence")
@require_login
def persistence_landscape():
    """Persistence Landscape — Autostart mechanism monitoring"""
    user = get_current_user()
    return render_template("dashboard/persistence-landscape.html", user=user)


@dashboard_bp.route("/auth")
@require_login
def auth_observatory():
    """Auth & Access — Login patterns and privilege escalation"""
    user = get_current_user()
    return render_template("dashboard/auth-observatory.html", user=user)


@dashboard_bp.route("/timeline-replay")
@require_login
def timeline_replay():
    """Threat Timeline Replay — step-by-step attack reconstruction"""
    user = get_current_user()
    return render_template("dashboard/timeline-replay.html", user=user)


@dashboard_bp.route("/observations")
@require_login
def observation_domains():
    """Observation Domains — P3 domain exploration"""
    user = get_current_user()
    return render_template("dashboard/observations.html", user=user)


# ── Consolidated Views (v3 Architecture) ──


@dashboard_bp.route("/threats")
@require_login
def threats_consolidated():
    """Threats — Consolidated: Feed, MITRE, Hunt, Incidents, Correlation"""
    user = get_current_user()
    return render_template("dashboard/threats.html", user=user)


@dashboard_bp.route("/observatory")
@require_login
def observatory_consolidated():
    """Observatory — All domain monitoring in one tabbed view"""
    user = get_current_user()
    return render_template("dashboard/observatory.html", user=user)


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
