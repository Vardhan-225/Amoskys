"""
AMOSKYS Authentication View Routes

Flask routes for rendering authentication templates.
These are NOT API endpoints - they serve HTML pages.

The actual authentication logic is handled by:
- /api/auth/* endpoints in amoskys.api.auth
- AuthService in amoskys.auth.service
"""

import logging

from flask import Blueprint, make_response, redirect, render_template, request

from amoskys.auth import AuthService
from amoskys.db.web_db import get_web_session_context

logger = logging.getLogger(__name__)

auth_views_bp = Blueprint("auth_views", __name__, url_prefix="/auth")

SESSION_COOKIE_NAME = "amoskys_session"


def _session_is_valid(token: str) -> bool:
    """Check if a session token is still valid. Returns False on any error."""
    try:
        client_info = {
            "ip_address": request.headers.get("X-Forwarded-For", request.remote_addr),
            "user_agent": request.headers.get("User-Agent"),
        }
        with get_web_session_context() as db:
            auth = AuthService(db)
            result = auth.validate_and_refresh_session(token=token, **client_info)
            return result.is_valid
    except Exception:
        logger.debug("Session validation failed during auth view check", exc_info=True)
        return False


def _clear_session_and_render(template: str):
    """Render a template while clearing the stale session cookie."""
    resp = make_response(render_template(template))
    resp.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return resp


@auth_views_bp.route("/login", methods=["GET", "POST"])
def login():
    """Render login page."""
    session_token = request.cookies.get(SESSION_COOKIE_NAME)
    if session_token:
        if _session_is_valid(session_token):
            return redirect("/dashboard")
        logger.info("Cleared invalid session cookie on login page")
        return _clear_session_and_render("auth/login.html")

    return render_template("auth/login.html")


@auth_views_bp.route("/signup", methods=["GET", "POST"])
def signup():
    """Render signup page."""
    session_token = request.cookies.get(SESSION_COOKIE_NAME)
    if session_token:
        if _session_is_valid(session_token):
            return redirect("/dashboard")
        logger.info("Cleared invalid session cookie on signup page")
        return _clear_session_and_render("auth/signup.html")

    return render_template("auth/signup.html")


@auth_views_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    """Render forgot password page."""
    # Both GET and POST serve the page - form uses JS
    return render_template("auth/forgot-password.html")


@auth_views_bp.route("/reset-password", methods=["GET", "POST"])
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


@auth_views_bp.route("/setup", methods=["GET"])
def setup():
    """Redirect to the new onboarding flow."""
    from flask import redirect

    return redirect("/dashboard/setup")


@auth_views_bp.route("/logout")
def logout():
    """
    Handle logout via GET request (for links/buttons).

    Invalidates the session server-side and clears the cookie — a plain
    redirect here left the session alive, so "logout" links didn't log out.
    """
    session_token = request.cookies.get(SESSION_COOKIE_NAME)
    if session_token:
        try:
            client_info = {
                "ip_address": request.headers.get(
                    "X-Forwarded-For", request.remote_addr
                ),
                "user_agent": request.headers.get("User-Agent", ""),
            }
            with get_web_session_context() as db:
                AuthService(db).logout(
                    session_token=session_token,
                    ip_address=client_info["ip_address"],
                    user_agent=client_info["user_agent"],
                )
        except Exception:
            logger.warning("GET /auth/logout: server-side invalidation failed", exc_info=True)

    response = make_response(redirect("/auth/login?logged_out=1"))
    response.set_cookie(
        SESSION_COOKIE_NAME,
        "",
        httponly=True,
        secure=request.is_secure,
        samesite="Lax",
        max_age=0,
    )
    return response
