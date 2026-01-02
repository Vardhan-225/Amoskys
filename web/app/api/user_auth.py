"""
AMOSKYS User Authentication API
Phase 3: Session Management & User Authentication

Provides secure HTTP endpoints for user authentication workflows:
- User registration (signup)
- Login with session management
- Logout (single session and all sessions)
- Password reset flow
- Email verification

Security Features:
- Rate limiting on all endpoints
- Secure HTTP-only session cookies
- Comprehensive audit logging
- Input validation
- CSRF protection via SameSite cookies
"""

import os
from typing import Any, Dict, Optional

from flask import Blueprint, jsonify, make_response, request
from sqlalchemy.exc import SQLAlchemyError

from amoskys.auth.service import AuthService
from amoskys.common.logging import get_logger
from amoskys.db.web_db import get_web_session_context
from amoskys.notifications.email import (
    send_password_reset_email,
    send_verification_email,
)

logger = get_logger(__name__)

# Create blueprint
user_auth_bp = Blueprint("user_auth", __name__, url_prefix="/user/auth")

# Configuration
SESSION_COOKIE_NAME = "amoskys_session"
SESSION_COOKIE_SECURE = (
    os.environ.get("AMOSKYS_SECURE_COOKIES", "true").lower() == "true"
)
SESSION_COOKIE_SAMESITE = "Lax"  # CSRF protection
EMAIL_DEV_MODE = os.environ.get("AMOSKYS_EMAIL_DEV_MODE", "false").lower() == "true"


def get_client_info() -> Dict[str, Optional[str]]:
    """Extract client IP and user agent from request."""
    # Handle proxy headers for IP
    ip_address = request.headers.get("X-Forwarded-For", request.remote_addr)
    if ip_address and "," in ip_address:
        ip_address = ip_address.split(",")[0].strip()

    user_agent = request.headers.get("User-Agent")

    return {"ip_address": ip_address, "user_agent": user_agent}


def create_session_cookie(session_token: str) -> Any:
    """Create a secure HTTP-only session cookie."""
    # Set cookie with security settings
    response = make_response()
    response.set_cookie(
        SESSION_COOKIE_NAME,
        session_token,
        httponly=True,  # Prevent XSS
        secure=SESSION_COOKIE_SECURE,  # HTTPS only in production
        samesite=SESSION_COOKIE_SAMESITE,  # CSRF protection
        max_age=30 * 24 * 60 * 60,  # 30 days
    )
    return response


def clear_session_cookie() -> Any:
    """Clear the session cookie."""
    response = make_response()
    response.set_cookie(
        SESSION_COOKIE_NAME,
        "",
        httponly=True,
        secure=SESSION_COOKIE_SECURE,
        samesite=SESSION_COOKIE_SAMESITE,
        max_age=0,  # Expire immediately
    )
    return response


# =============================================================================
# Signup
# =============================================================================


@user_auth_bp.route("/signup", methods=["POST"])
def signup():
    """
    Register a new user account.

    Request Body:
        {
            "email": "user@example.com",
            "password": "SecurePassword123!",
            "full_name": "John Doe" (optional)
        }

    Returns:
        201: User created successfully
        400: Invalid input
        409: Email already exists
        500: Server error
    """
    try:
        data = request.get_json()
        if not data:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": "Request body is required",
                        "error_code": "MISSING_BODY",
                    }
                ),
                400,
            )

        email = data.get("email", "").strip()
        password = data.get("password", "")
        full_name = data.get("full_name")

        # Validate required fields
        if not email or not password:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": "Email and password are required",
                        "error_code": "MISSING_FIELDS",
                    }
                ),
                400,
            )

        client_info = get_client_info()

        # Create user via AuthService
        with get_web_session_context() as db:
            auth_service = AuthService(db)
            result = auth_service.signup(
                email=email,
                password=password,
                full_name=full_name,
                ip_address=client_info["ip_address"],
                user_agent=client_info["user_agent"],
            )

            # Extract user data while session is still active (avoid lazy loading issues)
            if result.user:
                user_id = str(result.user.id)
                user_email = result.user.email
                # Store for response
                user_data = {
                    "id": user_id,
                    "email": user_email,
                }
            else:
                user_id = None
                user_data = None

        if not result.success:
            status_code = 409 if result.error_code == "EMAIL_EXISTS" else 400
            # Build response without accessing detached user object
            response_data = {
                "success": result.success,
                "error": result.error,
                "error_code": result.error_code,
            }
            return jsonify(response_data), status_code

        # Send verification email if token was generated
        if result.verification_token:
            # Build verification URL
            verify_url = (
                f"{request.host_url}auth/verify-email?token={result.verification_token}"
            )

            # Send email
            email_sent = send_verification_email(email, verify_url)

            if email_sent:
                logger.info(
                    "verification_email_sent",
                    user_id=user_id,
                    email=email,
                )
            else:
                logger.error(
                    "verification_email_failed",
                    user_id=user_id,
                    email=email,
                )

        # Build success response with extracted user data
        response_data = {
            "success": True,
            "error": None,
            "error_code": None,
            "user": user_data,
        }

        # In dev mode, include verification token
        if EMAIL_DEV_MODE and result.verification_token:
            logger.info(
                "signup_verification_token",
                user_id=user_id,
                token=result.verification_token,
                verify_url=f"/auth/verify-email?token={result.verification_token}",
            )
            response_data["dev_verification_token"] = result.verification_token
            response_data["dev_verify_url"] = (
                f"/auth/verify-email?token={result.verification_token}"
            )

        return jsonify(response_data), 201

    except SQLAlchemyError as e:
        logger.error("signup_database_error", error=str(e))
        return (
            jsonify(
                {
                    "success": False,
                    "error": "Database error occurred",
                    "error_code": "DATABASE_ERROR",
                }
            ),
            500,
        )

    except Exception as e:
        logger.error("signup_unexpected_error", error=str(e), exc_info=True)
        return (
            jsonify(
                {
                    "success": False,
                    "error": "An unexpected error occurred",
                    "error_code": "SERVER_ERROR",
                }
            ),
            500,
        )


# =============================================================================
# Email Verification
# =============================================================================


@user_auth_bp.route("/resend-verification", methods=["POST"])
def resend_verification():
    """
    Resend email verification link.

    Request Body:
        {
            "email": "user@example.com"
        }

    Returns:
        200: Verification email sent
        400: Invalid input
        500: Server error
    """
    try:
        data = request.get_json()
        if not data:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": "Request body is required",
                        "error_code": "MISSING_BODY",
                    }
                ),
                400,
            )

        email = data.get("email", "").strip()
        if not email:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": "Email is required",
                        "error_code": "MISSING_EMAIL",
                    }
                ),
                400,
            )

        client_info = get_client_info()

        with get_web_session_context() as db:
            auth_service = AuthService(db)
            result = auth_service.resend_verification_email(
                email=email,
                ip_address=client_info["ip_address"],
            )

        if not result.success:
            return jsonify(result.to_dict()), 400

        # Get the verification token from the result
        if hasattr(result, "verification_token") and result.verification_token:
            # Send verification email
            verify_url = (
                f"{request.host_url}auth/verify-email?token={result.verification_token}"
            )
            email_sent = send_verification_email(email, verify_url)

            if email_sent:
                logger.info("resend_verification_email_sent", email=email)
            else:
                logger.error("resend_verification_email_failed", email=email)

        return (
            jsonify(
                {"success": True, "message": "Verification email sent successfully"}
            ),
            200,
        )

    except Exception as e:
        logger.error("resend_verification_error", error=str(e), exc_info=True)
        return (
            jsonify(
                {
                    "success": False,
                    "error": "An unexpected error occurred",
                    "error_code": "SERVER_ERROR",
                }
            ),
            500,
        )


@user_auth_bp.route("/verify-email", methods=["POST"])
def verify_email():
    """
    Verify user's email address.

    Request Body:
        {
            "token": "verification_token_from_email"
        }

    Returns:
        200: Email verified successfully
        400: Invalid or expired token
        500: Server error
    """
    try:
        data = request.get_json()
        if not data:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": "Request body is required",
                        "error_code": "MISSING_BODY",
                    }
                ),
                400,
            )

        token = data.get("token", "").strip()
        if not token:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": "Verification token is required",
                        "error_code": "MISSING_TOKEN",
                    }
                ),
                400,
            )

        client_info = get_client_info()

        with get_web_session_context() as db:
            auth_service = AuthService(db)
            result = auth_service.verify_email(
                token=token,
                ip_address=client_info["ip_address"],
                user_agent=client_info["user_agent"],
            )

        if not result.success:
            return jsonify(result.to_dict()), 400

        return jsonify(result.to_dict()), 200

    except Exception as e:
        logger.error("verify_email_error", error=str(e), exc_info=True)
        return (
            jsonify(
                {
                    "success": False,
                    "error": "An unexpected error occurred",
                    "error_code": "SERVER_ERROR",
                }
            ),
            500,
        )


# =============================================================================
# Login
# =============================================================================


@user_auth_bp.route("/login", methods=["POST"])
def login():
    """
    Authenticate user and create session.

    Request Body:
        {
            "email": "user@example.com",
            "password": "password123"
        }

    Returns:
        200: Login successful (sets session cookie)
        400: Invalid credentials or account issue
        500: Server error
    """
    try:
        data = request.get_json()
        if not data:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": "Request body is required",
                        "error_code": "MISSING_BODY",
                    }
                ),
                400,
            )

        email = data.get("email", "").strip()
        password = data.get("password", "")

        if not email or not password:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": "Email and password are required",
                        "error_code": "MISSING_FIELDS",
                    }
                ),
                400,
            )

        client_info = get_client_info()

        with get_web_session_context() as db:
            auth_service = AuthService(db)
            result = auth_service.login(
                email=email,
                password=password,
                ip_address=client_info["ip_address"],
                user_agent=client_info["user_agent"],
            )

        if not result.success:
            return jsonify(result.to_dict()), 400

        # Check if MFA is required
        if result.requires_mfa:
            # MFA flow not implemented yet - return for future implementation
            return jsonify(result.to_dict()), 200

        # Create response with session cookie
        response = create_session_cookie(result.session_token)
        response_data = result.to_dict()
        # Don't send session token in JSON (it's in cookie)
        response_data.pop("session_token", None)

        response.data = jsonify(response_data).data
        response.content_type = "application/json"

        return response, 200

    except SQLAlchemyError as e:
        logger.error("login_database_error", error=str(e))
        return (
            jsonify(
                {
                    "success": False,
                    "error": "Database error occurred",
                    "error_code": "DATABASE_ERROR",
                }
            ),
            500,
        )

    except Exception as e:
        logger.error("login_unexpected_error", error=str(e), exc_info=True)
        return (
            jsonify(
                {
                    "success": False,
                    "error": "An unexpected error occurred",
                    "error_code": "SERVER_ERROR",
                }
            ),
            500,
        )


# =============================================================================
# Logout
# =============================================================================


@user_auth_bp.route("/logout", methods=["POST"])
def logout():
    """
    Logout current session.

    Returns:
        200: Logout successful (clears session cookie)
        400: Invalid session
        500: Server error
    """
    try:
        # Get session token from cookie
        session_token = request.cookies.get(SESSION_COOKIE_NAME)

        if not session_token:
            # Already logged out - return success
            response = clear_session_cookie()
            response.data = jsonify(
                {"success": True, "message": "Already logged out"}
            ).data
            response.content_type = "application/json"
            return response, 200

        client_info = get_client_info()

        with get_web_session_context() as db:
            auth_service = AuthService(db)
            result = auth_service.logout(
                session_token=session_token,
                ip_address=client_info["ip_address"],
                user_agent=client_info["user_agent"],
            )

        # Clear cookie regardless of result
        response = clear_session_cookie()
        response.data = jsonify(result.to_dict()).data
        response.content_type = "application/json"

        return response, 200

    except Exception as e:
        logger.error("logout_error", error=str(e), exc_info=True)
        # Clear cookie even on error
        response = clear_session_cookie()
        response.data = jsonify(
            {
                "success": False,
                "error": "An unexpected error occurred",
                "error_code": "SERVER_ERROR",
            }
        ).data
        response.content_type = "application/json"
        return response, 500


# =============================================================================
# Password Reset
# =============================================================================


@user_auth_bp.route("/forgot-password", methods=["POST"])
def forgot_password():
    """
    Request password reset email.

    Request Body:
        {
            "email": "user@example.com"
        }

    Returns:
        200: Reset email sent (always returns success for security)
        400: Invalid input
        500: Server error
    """
    try:
        data = request.get_json()
        if not data:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": "Request body is required",
                        "error_code": "MISSING_BODY",
                    }
                ),
                400,
            )

        email = data.get("email", "").strip()
        if not email:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": "Email is required",
                        "error_code": "MISSING_EMAIL",
                    }
                ),
                400,
            )

        client_info = get_client_info()

        with get_web_session_context() as db:
            auth_service = AuthService(db)
            result = auth_service.request_password_reset(
                email=email,
                ip_address=client_info["ip_address"],
            )

        # Send password reset email if token was generated
        if result.reset_token:
            # Build reset URL
            reset_url = (
                f"{request.host_url}auth/reset-password?token={result.reset_token}"
            )

            # Send email
            email_sent = send_password_reset_email(email, reset_url)

            if email_sent:
                logger.info(
                    "password_reset_email_sent",
                    email=email,
                )
            else:
                logger.error(
                    "password_reset_email_failed",
                    email=email,
                )

        # In dev mode, log the reset token
        if EMAIL_DEV_MODE and result.reset_token:
            logger.info(
                "password_reset_token",
                token=result.reset_token,
                reset_url=f"/auth/reset-password?token={result.reset_token}",
            )
            # Include token in response for dev testing
            response_data = result.to_dict()
            response_data["dev_reset_token"] = result.reset_token
            response_data["dev_reset_url"] = (
                f"/auth/reset-password?token={result.reset_token}"
            )
            return jsonify(response_data), 200

        # Always return success for security (don't reveal if email exists)
        return (
            jsonify(
                {
                    "success": True,
                    "message": "If an account exists with this email, a password reset link has been sent.",
                }
            ),
            200,
        )

    except Exception as e:
        logger.error("forgot_password_error", error=str(e), exc_info=True)
        return (
            jsonify(
                {
                    "success": False,
                    "error": "An unexpected error occurred",
                    "error_code": "SERVER_ERROR",
                }
            ),
            500,
        )


@user_auth_bp.route("/reset-password", methods=["POST"])
def reset_password():
    """
    Reset password using reset token.

    Request Body:
        {
            "token": "reset_token_from_email",
            "new_password": "NewSecurePassword123!"
        }

    Returns:
        200: Password reset successful
        400: Invalid token or password
        500: Server error
    """
    try:
        data = request.get_json()
        if not data:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": "Request body is required",
                        "error_code": "MISSING_BODY",
                    }
                ),
                400,
            )

        token = data.get("token", "").strip()
        new_password = data.get("new_password", "")

        if not token or not new_password:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": "Token and new password are required",
                        "error_code": "MISSING_FIELDS",
                    }
                ),
                400,
            )

        client_info = get_client_info()

        with get_web_session_context() as db:
            auth_service = AuthService(db)
            result = auth_service.reset_password(
                token=token,
                new_password=new_password,
                ip_address=client_info["ip_address"],
                user_agent=client_info["user_agent"],
            )

        if not result.success:
            return jsonify(result.to_dict()), 400

        return jsonify(result.to_dict()), 200

    except Exception as e:
        logger.error("reset_password_error", error=str(e), exc_info=True)
        return (
            jsonify(
                {
                    "success": False,
                    "error": "An unexpected error occurred",
                    "error_code": "SERVER_ERROR",
                }
            ),
            500,
        )


# =============================================================================
# Session Validation (for middleware/frontend)
# =============================================================================


@user_auth_bp.route("/validate-session", methods=["GET"])
def validate_session():
    """
    Validate current session and return user info.

    Returns:
        200: Valid session with user info
        401: Invalid or expired session
        500: Server error
    """
    try:
        session_token = request.cookies.get(SESSION_COOKIE_NAME)

        if not session_token:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": "No session found",
                        "error_code": "NO_SESSION",
                    }
                ),
                401,
            )

        client_info = get_client_info()

        with get_web_session_context() as db:
            auth_service = AuthService(db)
            result = auth_service.validate_and_refresh_session(
                token=session_token,
                ip_address=client_info["ip_address"],
                user_agent=client_info["user_agent"],
            )

        if not result.is_valid:
            response = clear_session_cookie()
            response.data = jsonify(
                {
                    "success": False,
                    "error": "Invalid or expired session",
                    "error_code": "INVALID_SESSION",
                }
            ).data
            response.content_type = "application/json"
            return response, 401

        # Return user info
        user = result.user
        return (
            jsonify(
                {
                    "success": True,
                    "user": {
                        "id": str(user.id),
                        "email": user.email,
                        "full_name": user.full_name,
                        "role": user.role.value,
                        "is_verified": user.is_verified,
                    },
                }
            ),
            200,
        )

    except Exception as e:
        logger.error("validate_session_error", error=str(e), exc_info=True)
        return (
            jsonify(
                {
                    "success": False,
                    "error": "An unexpected error occurred",
                    "error_code": "SERVER_ERROR",
                }
            ),
            500,
        )
