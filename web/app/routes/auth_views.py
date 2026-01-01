"""
AMOSKYS Authentication View Routes

Flask routes for rendering authentication templates.
These are NOT API endpoints - they serve HTML pages.

The actual authentication logic is handled by:
- /api/auth/* endpoints in amoskys.api.auth
- AuthService in amoskys.auth.service
"""

from flask import Blueprint, redirect, render_template, request, url_for

auth_views_bp = Blueprint("auth_views", __name__, url_prefix="/auth")


@auth_views_bp.route("/login")
def login():
    """Render login page."""
    # If user is already authenticated, redirect to dashboard
    session_token = request.cookies.get("amoskys_session")
    if session_token:
        # We could validate the session here, but for now just redirect
        # The dashboard will handle invalid sessions
        return redirect("/dashboard")
    
    return render_template("auth/login.html")


@auth_views_bp.route("/signup")
def signup():
    """Render signup page."""
    session_token = request.cookies.get("amoskys_session")
    if session_token:
        return redirect("/dashboard")
    
    return render_template("auth/signup.html")


@auth_views_bp.route("/forgot-password")
def forgot_password():
    """Render forgot password page."""
    return render_template("auth/forgot-password.html")


@auth_views_bp.route("/reset-password")
def reset_password():
    """Render reset password page."""
    # Token should be in query params
    token = request.args.get("token")
    if not token:
        # Redirect to forgot password if no token
        return redirect("/auth/forgot-password")
    
    return render_template("auth/reset-password.html")


@auth_views_bp.route("/verify-email")
def verify_email():
    """Render email verification page."""
    # Token should be in query params
    return render_template("auth/verify-email.html")


@auth_views_bp.route("/verify-pending")
def verify_pending():
    """Render verification pending page."""
    return render_template("auth/verify-pending.html")


@auth_views_bp.route("/resend-verification")
def resend_verification():
    """Render resend verification page."""
    # Email should be in query params
    email = request.args.get("email", "")
    return render_template("auth/resend-verification.html", email=email)


@auth_views_bp.route("/logout")
def logout():
    """
    Handle logout via GET request (for links/buttons).
    
    This is a convenience route that redirects to login after logout.
    For programmatic logout, use POST /api/auth/logout instead.
    """
    # The actual logout is handled by JavaScript calling the API
    # This route just provides a destination after logout
    return redirect("/auth/login?logged_out=1")
