"""
Authentication Middleware for Flask Routes

Provides decorators and utilities for protecting routes with session authentication.

Usage:
    from app.middleware import require_login

    @app.route('/dashboard')
    @require_login
    def dashboard():
        return render_template('dashboard.html')

    @app.route('/api/data')
    @require_login
    def api_data():
        user = get_current_user()
        return jsonify({'user_id': user.id})
"""

from functools import wraps
from typing import Optional

from flask import request, redirect, url_for, flash, g, jsonify

from amoskys.auth import AuthService, User
from amoskys.db.web_db import get_web_session_context
from amoskys.common.logging import get_logger

logger = get_logger(__name__)

# Session cookie name (must match what's set in auth API)
SESSION_COOKIE_NAME = "amoskys_session"


def get_current_user() -> Optional[User]:
    """
    Get the currently authenticated user from the request context.

    This is only available after the require_login decorator has run.

    Returns:
        User object if authenticated, None otherwise
    """
    return g.get("current_user", None)


def require_login(f):
    """
    Decorator to require authentication for a route.

    For HTML routes: Redirects to login page if not authenticated
    For API routes: Returns 401 JSON error if not authenticated

    The authenticated user is stored in g.current_user and can be
    accessed via get_current_user().

    Usage:
        @app.route('/dashboard')
        @require_login
        def dashboard():
            user = get_current_user()
            return render_template('dashboard.html', user=user)
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if session cookie exists
        session_token = request.cookies.get(SESSION_COOKIE_NAME)

        if not session_token:
            logger.debug("No session cookie found - redirecting to login")

            # Check if this is an API request
            is_api_request = request.path.startswith("/api/") or request.is_json

            if is_api_request:
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": "Authentication required",
                            "error_code": "NO_SESSION",
                        }
                    ),
                    401,
                )
            else:
                # Store the page they were trying to access
                next_url = request.url
                flash("Please log in to access this page.", "warning")
                return redirect(url_for("auth_views.login", next=next_url))

        # Validate session
        client_info = {
            "ip_address": request.headers.get("X-Forwarded-For", request.remote_addr),
            "user_agent": request.headers.get("User-Agent"),
        }

        try:
            with get_web_session_context() as db:
                auth = AuthService(db)
                result = auth.validate_and_refresh_session(
                    token=session_token, **client_info
                )

                if not result.is_valid:
                    logger.warning(
                        "Invalid session",
                        error=result.error,
                        error_code=result.error_code,
                    )

                    # Check if this is an API request
                    is_api_request = request.path.startswith("/api/") or request.is_json

                    if is_api_request:
                        return (
                            jsonify(
                                {
                                    "success": False,
                                    "error": result.error or "Session expired",
                                    "error_code": result.error_code
                                    or "SESSION_EXPIRED",
                                }
                            ),
                            401,
                        )
                    else:
                        flash(
                            "Your session has expired. Please log in again.", "warning"
                        )
                        return redirect(url_for("auth_views.login", next=request.url))

                # Store user in request context
                g.current_user = result.user
                g.current_session = result.session

                logger.debug(
                    "User authenticated",
                    user_id=result.user.id,
                    email=result.user.email,
                )

        except Exception as e:
            logger.error("Session validation error", error=str(e), exc_info=True)

            # Check if this is an API request
            is_api_request = request.path.startswith("/api/") or request.is_json

            if is_api_request:
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": "Authentication error",
                            "error_code": "AUTH_ERROR",
                        }
                    ),
                    500,
                )
            else:
                flash("An authentication error occurred. Please try again.", "danger")
                return redirect(url_for("auth_views.login"))

        # Call the actual route function
        return f(*args, **kwargs)

    return decorated_function


def require_role(role: str):
    """
    Decorator to require a specific user role for a route.

    Must be used after @require_login decorator.

    Args:
        role: Required role (e.g., 'admin', 'user')

    Usage:
        @app.route('/admin')
        @require_login
        @require_role('admin')
        def admin_panel():
            return render_template('admin.html')
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = get_current_user()

            if not user:
                # This shouldn't happen if @require_login is used correctly
                logger.error("require_role called without authentication")
                return redirect(url_for("auth_views.login"))

            if user.role.value != role:
                logger.warning(
                    "Insufficient permissions",
                    user_id=user.id,
                    required_role=role,
                    user_role=user.role.value,
                )

                is_api_request = request.path.startswith("/api/") or request.is_json

                if is_api_request:
                    return (
                        jsonify(
                            {
                                "success": False,
                                "error": "Insufficient permissions",
                                "error_code": "FORBIDDEN",
                            }
                        ),
                        403,
                    )
                else:
                    flash(
                        "You do not have permission to access this page. Please login with an authorized account.",
                        "danger",
                    )
                    return redirect(url_for("auth_views.login"))

            return f(*args, **kwargs)

        return decorated_function

    return decorator
