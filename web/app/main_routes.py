"""
AMOSKYS Neural Security Command Platform
Flask Routes and Views
"""

from datetime import datetime, timezone

from flask import Blueprint, current_app, jsonify, render_template, send_from_directory

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def landing():
    """AMOSKYS Public Landing Page"""
    return render_template("landing.html")


@main_bp.route("/about")
def about():
    """About AMOSKYS page"""
    return render_template("about.html")


@main_bp.route("/how-it-works")
def how_it_works():
    """How AMOSKYS Works page - Biological architecture explained"""
    return render_template("how-it-works.html")


@main_bp.route("/docs")
def documentation():
    """AMOSKYS Documentation landing page"""
    return render_template("docs.html")


@main_bp.route("/terms")
def terms():
    """Terms of Service page"""
    return render_template("terms.html")


@main_bp.route("/privacy")
def privacy():
    """Privacy Policy page"""
    return render_template("privacy.html")


@main_bp.route("/command")
def command():
    """AMOSKYS Neural Security Command Interface"""
    return render_template("index.html")


@main_bp.route("/api-access")
def api_access():
    """API Access and Documentation Page"""
    return render_template("api_access.html")


@main_bp.route("/status")
def status():
    """System status endpoint for monitoring"""
    return jsonify(
        {
            "status": "OPERATIONAL",
            "platform": "AMOSKYS Neural Security Command",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": "1.0.0-alpha",
            "components": {
                "web_interface": "ACTIVE",
                "neural_core": "STANDBY",
                "event_bus": "READY",
            },
        }
    )


@main_bp.route("/health")
def health():
    """Health check endpoint for load balancer"""
    return jsonify({"status": "healthy"}), 200


@main_bp.route("/robots.txt")
def robots():
    """Serve robots.txt from static directory"""
    return send_from_directory(current_app.static_folder, "robots.txt")


@main_bp.route("/favicon.ico")
def favicon():
    """Serve favicon from static images"""
    return send_from_directory(
        current_app.static_folder + "/images",
        "favicon-32x32.png",
        mimetype="image/png",
    )


@main_bp.route("/deploy/install.sh", methods=["GET"])
def deploy_install_script():
    """Serve AMOSKYS install script (public, no auth).

    Usage: curl -fsSL https://amoskys.com/deploy/install.sh | sudo bash -s -- --token=... --server=...
    """
    from pathlib import Path

    from flask import Response

    # Look for install.sh relative to project root (2 levels up from web/app/)
    project_root = Path(__file__).parent.parent.parent
    script_candidates = [
        project_root / "deploy" / "macos" / "install.sh",
        Path("/opt/amoskys/deploy/macos/install.sh"),
        Path("/Library/Amoskys/deploy/install.sh"),
    ]

    for path in script_candidates:
        if path.exists():
            return Response(path.read_text(), mimetype="text/x-shellscript")

    return Response("# Install script not found\nexit 1", mimetype="text/x-shellscript", status=404)
