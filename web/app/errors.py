"""
AMOSKYS Unified Error Handlers

Flask error handlers that integrate with the AMOSKYS exception framework
to provide consistent JSON error responses with proper HTTP status codes.

Features:
- Consistent JSON error response format
- Correlation ID propagation
- Automatic sensitive data filtering
- Error logging with full context
- Frontend toast notification support
"""

from typing import Tuple

from flask import Flask, Response, jsonify, request, render_template
from werkzeug.exceptions import HTTPException

from amoskys.common.exceptions import (
    AgentError,
    AmoskysError,
    AuthenticationError,
    AuthorizationError,
    ConfigurationError,
    DatabaseError,
    ErrorCode,
    InternalError,
    RateLimitExceededError,
    ResourceNotFoundError,
    ValidationError,
    wrap_exception,
)
from amoskys.common.logging import get_correlation_id, get_logger

logger = get_logger(__name__)


def _build_error_response(error: AmoskysError, include_debug: bool = False) -> dict:
    """Build standardized error response dictionary.

    Args:
        error: The AMOSKYS error instance
        include_debug: Include debug information (stack traces, etc.)

    Returns:
        Dictionary suitable for JSON serialization
    """
    response = error.to_dict()

    # Add correlation ID from context if not set on error
    if "correlation_id" not in response["error"]:
        correlation_id = get_correlation_id()
        if correlation_id:
            response["error"]["correlation_id"] = correlation_id

    # Add debug info in development mode
    if include_debug and error.cause:
        response["error"]["debug"] = {
            "cause_type": type(error.cause).__name__,
            "cause_message": str(error.cause),
        }

    return response


def _is_api_request() -> bool:
    """Check if the current request is an API request."""
    # Check URL path
    if request.path.startswith("/api/"):
        return True

    # Check Accept header
    accept = request.headers.get("Accept", "")
    if "application/json" in accept:
        return True

    # Check Content-Type for POST/PUT requests
    if request.method in ("POST", "PUT", "PATCH"):
        content_type = request.headers.get("Content-Type", "")
        if "application/json" in content_type:
            return True

    return False


def _get_include_debug(app: Flask) -> bool:
    """Check if debug information should be included in errors."""
    return app.config.get("DEBUG", False) or app.config.get("TESTING", False)


def handle_amoskys_error(error: AmoskysError) -> Tuple[Response, int]:
    """Handle AMOSKYS custom exceptions.

    Logs the error and returns a JSON response with appropriate status code.
    """
    # Log the error
    if error.http_status_code >= 500:
        logger.error(
            f"Server error: {error.message}",
            error_code=error.code.name,
            error_type=type(error).__name__,
            details=error.details,
            exc_info=error.cause is not None,
        )
    elif error.http_status_code >= 400:
        logger.warning(
            f"Client error: {error.message}",
            error_code=error.code.name,
            error_type=type(error).__name__,
            details=error.details,
        )

    # Set correlation ID on error if not already set
    if not error.correlation_id:
        error.correlation_id = get_correlation_id()

    # Build response - import current_app here to avoid circular imports
    from flask import current_app

    include_debug = _get_include_debug(current_app)
    response_data = _build_error_response(error, include_debug=include_debug)

    response = jsonify(response_data)

    # Add correlation ID header
    if error.correlation_id:
        response.headers["X-Correlation-ID"] = error.correlation_id

    # Add Retry-After header for rate limiting
    if isinstance(error, RateLimitExceededError):
        retry_after = error.details.get("retry_after_seconds")
        if retry_after:
            response.headers["Retry-After"] = str(retry_after)

    return response, error.http_status_code


def handle_http_exception(error: HTTPException) -> Tuple[Response, int]:
    """Handle Werkzeug HTTP exceptions.

    Converts standard HTTP exceptions to AMOSKYS JSON format.
    """
    # Map HTTP status to AMOSKYS error code
    status_to_code = {
        400: ErrorCode.VAL_SCHEMA_INVALID,
        401: ErrorCode.AUTH_TOKEN_MISSING,
        403: ErrorCode.AUTHZ_INSUFFICIENT_PERMISSIONS,
        404: ErrorCode.RES_NOT_FOUND,
        405: ErrorCode.VAL_INVALID_FORMAT,
        409: ErrorCode.RES_CONFLICT,
        429: ErrorCode.RES_RATE_LIMITED,
        500: ErrorCode.INTERNAL_ERROR,
        502: ErrorCode.AGENT_COMMUNICATION_ERROR,
        503: ErrorCode.INTERNAL_SERVICE_UNAVAILABLE,
        504: ErrorCode.CONN_TIMEOUT,
    }

    code = status_to_code.get(error.code, ErrorCode.UNKNOWN_ERROR)

    # Create AMOSKYS error wrapper
    amoskys_error = AmoskysError(
        message=error.description or str(error),
        code=code,
        correlation_id=get_correlation_id(),
    )
    amoskys_error.http_status_code = error.code

    logger.warning(
        f"HTTP error: {error.code} {error.name}",
        error_code=code.name,
        path=request.path,
        method=request.method,
    )

    response = jsonify(_build_error_response(amoskys_error))

    if amoskys_error.correlation_id:
        response.headers["X-Correlation-ID"] = amoskys_error.correlation_id

    return response, error.code


def handle_generic_exception(error: Exception) -> Tuple[Response, int]:
    """Handle unexpected exceptions.

    Wraps unknown exceptions in InternalError and logs full details.
    """
    # Log the full exception with traceback
    logger.exception(
        f"Unhandled exception: {type(error).__name__}: {error}",
        error_type=type(error).__name__,
        error_message=str(error),
        path=request.path,
        method=request.method,
    )

    # Wrap in AMOSKYS error (hides internal details from clients)
    amoskys_error = wrap_exception(
        error,
        message="An unexpected error occurred",
        correlation_id=get_correlation_id(),
    )

    # Build response - import current_app here
    from flask import current_app

    include_debug = _get_include_debug(current_app)
    response_data = _build_error_response(amoskys_error, include_debug=include_debug)

    response = jsonify(response_data)

    if amoskys_error.correlation_id:
        response.headers["X-Correlation-ID"] = amoskys_error.correlation_id

    return response, 500


def render_html_error_page(error: HTTPException) -> Tuple[str, int]:
    """Render HTML error page for browser requests.

    Args:
        error: The HTTP exception

    Returns:
        Tuple of (HTML string, status_code)
    """
    # Map status codes to user-friendly titles
    error_titles = {
        400: "Bad Request",
        401: "Unauthorized",
        403: "Access Forbidden",
        404: "Page Not Found",
        405: "Method Not Allowed",
        408: "Request Timeout",
        429: "Too Many Requests",
        500: "Internal Server Error",
        502: "Bad Gateway",
        503: "Service Unavailable",
        504: "Gateway Timeout",
    }

    # Map status codes to user-friendly messages
    error_messages = {
        400: "The request was invalid or cannot be processed. Please check your input and try again.",
        401: "You need to be logged in to access this resource.",
        403: "You don't have permission to access this resource.",
        404: "The page you're looking for doesn't exist or has been moved.",
        405: "The request method is not supported for this resource.",
        408: "The request took too long to process. Please try again.",
        429: "You've made too many requests. Please wait a moment and try again.",
        500: "Something went wrong on our end. Our team has been notified.",
        502: "The gateway received an invalid response. Please try again later.",
        503: "The service is temporarily unavailable. We're working on bringing it back online.",
        504: "The request timed out. Please try again.",
    }

    error_code = error.code
    error_title = error_titles.get(error_code, "Error")
    error_message = error_messages.get(
        error_code, str(error.description or "An error occurred.")
    )

    # Show login button for auth errors
    show_login = error_code in [401, 403]

    correlation_id = get_correlation_id()

    html = render_template(
        "errors/error.html",
        error_code=error_code,
        error_title=error_title,
        error_message=error_message,
        correlation_id=correlation_id,
        show_login=show_login,
    )

    return html, error_code


def register_error_handlers(app: Flask) -> None:
    """Register all error handlers with Flask application.

    Call this function during app initialization to set up
    unified error handling.

    Args:
        app: Flask application instance

    Usage:
        from web.app.errors import register_error_handlers

        app = Flask(__name__)
        register_error_handlers(app)
    """
    # Register AMOSKYS exception handlers
    app.register_error_handler(AmoskysError, handle_amoskys_error)
    app.register_error_handler(AuthenticationError, handle_amoskys_error)
    app.register_error_handler(AuthorizationError, handle_amoskys_error)
    app.register_error_handler(ValidationError, handle_amoskys_error)
    app.register_error_handler(AgentError, handle_amoskys_error)
    app.register_error_handler(ResourceNotFoundError, handle_amoskys_error)
    app.register_error_handler(RateLimitExceededError, handle_amoskys_error)
    app.register_error_handler(DatabaseError, handle_amoskys_error)
    app.register_error_handler(ConfigurationError, handle_amoskys_error)
    app.register_error_handler(InternalError, handle_amoskys_error)

    # Register HTTP exception handler for API requests
    @app.errorhandler(HTTPException)
    def http_exception_handler(error: HTTPException):
        if _is_api_request():
            return handle_http_exception(error)
        # For non-API requests, render custom HTML error page
        return render_html_error_page(error)

    # Register generic exception handler for API requests
    @app.errorhandler(Exception)
    def generic_exception_handler(error: Exception):
        # Don't catch HTTPException here (already handled above)
        if isinstance(error, HTTPException):
            raise error

        if _is_api_request():
            return handle_generic_exception(error)

        # For non-API requests, render 500 error page
        logger.exception(
            f"Unhandled exception in web request: {type(error).__name__}: {error}",
            error_type=type(error).__name__,
            path=request.path,
        )

        correlation_id = get_correlation_id()
        html = render_template(
            "errors/error.html",
            error_code=500,
            error_title="Internal Server Error",
            error_message="Something went wrong on our end. Our team has been notified and is working on it.",
            correlation_id=correlation_id,
            show_login=False,
        )
        return html, 500

    logger.info("Registered AMOSKYS error handlers")


# ============================================================================
# API Response Helpers
# ============================================================================


def api_success(
    data: dict = None, message: str = None, status_code: int = 200
) -> Tuple[Response, int]:
    """Create a successful API response.

    Args:
        data: Response data dictionary
        message: Success message
        status_code: HTTP status code (default 200)

    Returns:
        Tuple of (Response, status_code)
    """
    response_data = {"status": "success"}

    if message:
        response_data["message"] = message

    if data:
        response_data.update(data)

    # Add correlation ID
    correlation_id = get_correlation_id()
    if correlation_id:
        response_data["correlation_id"] = correlation_id

    response = jsonify(response_data)

    if correlation_id:
        response.headers["X-Correlation-ID"] = correlation_id

    return response, status_code


def api_created(
    data: dict = None,
    message: str = "Resource created successfully",
    location: str = None,
) -> Tuple[Response, int]:
    """Create a 201 Created response.

    Args:
        data: Response data
        message: Success message
        location: Location header value (URL of created resource)
    """
    response, _ = api_success(data, message, 201)

    if location:
        response.headers["Location"] = location

    return response, 201


def api_no_content() -> Tuple[str, int]:
    """Create a 204 No Content response."""
    return "", 204


# ============================================================================
# Frontend Toast Notification Helpers
# ============================================================================


def get_toast_notification(error: AmoskysError) -> dict:
    """Generate toast notification data for frontend display.

    Returns a dictionary suitable for frontend toast notification systems.

    Args:
        error: The AMOSKYS error

    Returns:
        Dictionary with toast notification data
    """
    # Map error severity to toast type
    if error.http_status_code >= 500:
        toast_type = "error"
        title = "Server Error"
    elif error.http_status_code == 429:
        toast_type = "warning"
        title = "Rate Limited"
    elif error.http_status_code == 401:
        toast_type = "warning"
        title = "Authentication Required"
    elif error.http_status_code == 403:
        toast_type = "warning"
        title = "Access Denied"
    elif error.http_status_code == 404:
        toast_type = "info"
        title = "Not Found"
    else:
        toast_type = "error"
        title = "Error"

    return {
        "type": toast_type,
        "title": title,
        "message": error.message,
        "code": error.code.name,
        "duration": 5000 if error.http_status_code < 500 else 8000,
        "dismissible": True,
        "hints": error.hints,
    }
