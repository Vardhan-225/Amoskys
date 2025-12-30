"""
AMOSKYS Authentication API Endpoints

Flask Blueprint providing REST API for authentication:
- POST /api/auth/signup - Register new user
- POST /api/auth/login - Authenticate user
- POST /api/auth/logout - End current session
- POST /api/auth/logout-all - End all sessions
- GET /api/auth/verify-email - Verify email token
- POST /api/auth/resend-verification - Resend verification email
- POST /api/auth/forgot-password - Request password reset
- POST /api/auth/reset-password - Reset password with token
- POST /api/auth/change-password - Change password (authenticated)
- GET /api/auth/me - Get current user info

Design: Thin JSON wrappers around AuthService business logic.
"""

from __future__ import annotations

from functools import wraps

from flask import Blueprint, jsonify, make_response, request

from amoskys.api.security import rate_limit_auth, rate_limit_strict
from amoskys.auth import AuthService
from amoskys.common.logging import get_logger
from amoskys.db import get_session_context
from amoskys.notifications.email import EmailService

__all__ = ["auth_bp"]

logger = get_logger(__name__)

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")

# Cookie settings
SESSION_COOKIE_NAME = "amoskys_session"
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = True  # Set to False for local dev without HTTPS
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_MAX_AGE = 86400  # 24 hours


def get_client_info():
    """Extract client IP and User-Agent from request."""
    return {
        "ip_address": request.headers.get("X-Forwarded-For", request.remote_addr),
        "user_agent": request.headers.get("User-Agent"),
    }


def require_auth(f):
    """Decorator to require valid session for endpoint."""

    @wraps(f)
    def decorated(*args, **kwargs):
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
                token=session_token, **get_client_info()
            )

            if not result.is_valid:
                response = make_response(
                    jsonify({"error": result.error, "error_code": result.error_code}),
                    401,
                )
                response.delete_cookie(SESSION_COOKIE_NAME)
                return response

            # Attach user and session to request context
            request.current_user = result.user
            request.current_session = result.session

        return f(*args, **kwargs)

    return decorated


# =============================================================================
# Public Endpoints (No Auth Required)
# =============================================================================


@auth_bp.route("/signup", methods=["POST"])
@rate_limit_auth("10 per hour")  # Prevent spam account creation
def signup():
    """Register a new user account."""
    data = request.get_json()

    if not data:
        return (
            jsonify(
                {"error": "Request body required", "error_code": "INVALID_REQUEST"}
            ),
            400,
        )

    email = data.get("email")
    password = data.get("password")
    full_name = data.get("full_name")

    if not email or not password:
        return (
            jsonify(
                {"error": "Email and password required", "error_code": "MISSING_FIELDS"}
            ),
            400,
        )

    with get_session_context() as db:
        auth = AuthService(db)
        result = auth.signup(
            email=email, password=password, full_name=full_name, **get_client_info()
        )

        if result.success and result.verification_token:
            # Send verification email
            try:
                email_service = EmailService()
                email_service.send_verification_email(
                    to_email=email,
                    token=result.verification_token,
                    user_name=full_name or email.split("@")[0],
                )
            except Exception as e:
                # Log but don't fail signup if email fails
                logger.warning(f"Failed to send verification email: {e}")

        status_code = 201 if result.success else 400
        return jsonify(result.to_dict()), status_code


@auth_bp.route("/login", methods=["POST"])
@rate_limit_auth("5 per minute")  # Prevent brute-force attacks
def login():
    """Authenticate user with email and password."""
    data = request.get_json()

    if not data:
        return (
            jsonify(
                {"error": "Request body required", "error_code": "INVALID_REQUEST"}
            ),
            400,
        )

    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return (
            jsonify(
                {"error": "Email and password required", "error_code": "MISSING_FIELDS"}
            ),
            400,
        )

    with get_session_context() as db:
        auth = AuthService(db)
        result = auth.login(email=email, password=password, **get_client_info())

        if result.success and result.session_token:
            response = make_response(jsonify(result.to_dict()))
            response.set_cookie(
                SESSION_COOKIE_NAME,
                result.session_token,
                httponly=SESSION_COOKIE_HTTPONLY,
                secure=SESSION_COOKIE_SECURE,
                samesite=SESSION_COOKIE_SAMESITE,
                max_age=SESSION_COOKIE_MAX_AGE,
            )
            return response

        status_code = 401 if not result.success else 200
        return jsonify(result.to_dict()), status_code


@auth_bp.route("/verify-email", methods=["GET"])
def verify_email():
    """Verify email with token from query parameter."""
    token = request.args.get("token")

    if not token:
        return (
            jsonify({"error": "Token required", "error_code": "MISSING_TOKEN"}),
            400,
        )

    with get_session_context() as db:
        auth = AuthService(db)
        result = auth.verify_email(token=token, **get_client_info())

        status_code = 200 if result.success else 400
        return jsonify(result.to_dict()), status_code


@auth_bp.route("/resend-verification", methods=["POST"])
def resend_verification():
    """Resend verification email."""
    data = request.get_json()
    email = data.get("email") if data else None

    if not email:
        return (
            jsonify({"error": "Email required", "error_code": "MISSING_EMAIL"}),
            400,
        )

    with get_session_context() as db:
        auth = AuthService(db)
        result = auth.resend_verification_email(email=email, **get_client_info())

        if result.success and result.verification_token:
            try:
                email_service = EmailService()
                email_service.send_verification_email(
                    to_email=email,
                    token=result.verification_token,
                )
            except Exception as e:
                logger.warning(f"Failed to send verification email: {e}")

        # Always return success to prevent email enumeration
        return jsonify({"success": True}), 200


@auth_bp.route("/forgot-password", methods=["POST"])
@rate_limit_strict("1 per minute")  # Prevent email enumeration
def forgot_password():
    """Request password reset email."""
    data = request.get_json()
    email = data.get("email") if data else None

    if not email:
        return (
            jsonify({"error": "Email required", "error_code": "MISSING_EMAIL"}),
            400,
        )

    with get_session_context() as db:
        auth = AuthService(db)
        result = auth.request_password_reset(email=email, **get_client_info())

        if result.success and result.reset_token:
            try:
                email_service = EmailService()
                email_service.send_password_reset_email(
                    to_email=email,
                    token=result.reset_token,
                )
            except Exception as e:
                logger.warning(f"Failed to send password reset email: {e}")

        # Always return success to prevent email enumeration
        return jsonify({"success": True}), 200


@auth_bp.route("/reset-password", methods=["POST"])
def reset_password():
    """Reset password with token."""
    data = request.get_json()

    if not data:
        return (
            jsonify(
                {"error": "Request body required", "error_code": "INVALID_REQUEST"}
            ),
            400,
        )

    token = data.get("token")
    new_password = data.get("new_password")

    if not token or not new_password:
        return (
            jsonify(
                {
                    "error": "Token and new_password required",
                    "error_code": "MISSING_FIELDS",
                }
            ),
            400,
        )

    with get_session_context() as db:
        auth = AuthService(db)
        result = auth.reset_password(
            token=token, new_password=new_password, **get_client_info()
        )

        status_code = 200 if result.success else 400
        return jsonify(result.to_dict()), status_code


# =============================================================================
# Protected Endpoints (Auth Required)
# =============================================================================


@auth_bp.route("/logout", methods=["POST"])
@require_auth
def logout():
    """Log out current session."""
    session_token = request.cookies.get(SESSION_COOKIE_NAME)

    with get_session_context() as db:
        auth = AuthService(db)
        result = auth.logout(session_token=session_token, **get_client_info())

        response = make_response(jsonify(result.to_dict()))
        response.delete_cookie(SESSION_COOKIE_NAME)
        return response


@auth_bp.route("/logout-all", methods=["POST"])
@require_auth
def logout_all():
    """Log out all sessions for current user."""
    with get_session_context() as db:
        auth = AuthService(db)
        result = auth.logout_all(user_id=request.current_user.id, **get_client_info())

        response = make_response(jsonify(result.to_dict()))
        response.delete_cookie(SESSION_COOKIE_NAME)
        return response


@auth_bp.route("/change-password", methods=["POST"])
@require_auth
def change_password():
    """Change password for authenticated user."""
    data = request.get_json()

    if not data:
        return (
            jsonify(
                {"error": "Request body required", "error_code": "INVALID_REQUEST"}
            ),
            400,
        )

    current_password = data.get("current_password")
    new_password = data.get("new_password")

    if not current_password or not new_password:
        return (
            jsonify(
                {
                    "error": "current_password and new_password required",
                    "error_code": "MISSING_FIELDS",
                }
            ),
            400,
        )

    with get_session_context() as db:
        auth = AuthService(db)
        result = auth.change_password(
            user_id=request.current_user.id,
            current_password=current_password,
            new_password=new_password,
            **get_client_info(),
        )

        status_code = 200 if result.success else 400
        return jsonify(result.to_dict()), status_code


@auth_bp.route("/me", methods=["GET"])
@require_auth
def get_current_user():
    """Get current authenticated user info."""
    user = request.current_user
    return jsonify(
        {
            "success": True,
            "user": {
                "id": user.id,
                "email": user.email,
                "full_name": user.full_name,
                "role": user.role.value,
                "is_verified": user.is_verified,
                "mfa_enabled": user.mfa_enabled,
                "created_at": user.created_at.isoformat() if user.created_at else None,
                "last_login_at": (
                    user.last_login_at.isoformat() if user.last_login_at else None
                ),
            },
        }
    )
