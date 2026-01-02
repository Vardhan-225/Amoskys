"""
AMOSKYS Neural Security Command Platform
Flask Routes and Views
"""

from flask import Blueprint, render_template, jsonify
from datetime import datetime, timezone

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
