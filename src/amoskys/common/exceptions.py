# filepath: /Users/athanneeru/Downloads/GitHub/Amoskys/src/amoskys/common/exceptions.py
"""
AMOSKYS Unified Exception Hierarchy

World-class error handling framework providing:
- Consistent exception types across all components
- Structured error information for debugging
- HTTP status code mapping for API responses
- Error codes for programmatic handling
- Internationalization-ready error messages

Design Philosophy (Akash Thanneeru + Claude Supremacy):
    Every error tells a story. Our exceptions carry enough context
    to diagnose issues without exposing sensitive information.
    Errors are first-class citizens, not afterthoughts.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class ErrorCode(Enum):
    """Standardized error codes for programmatic handling.

    Format: CATEGORY_SPECIFIC_ERROR
    Ranges:
        1000-1999: Authentication/Authorization
        2000-2999: Validation
        3000-3999: Agent/Connection
        4000-4999: Detection Pipeline
        5000-5999: Resource/Database
        6000-6999: Configuration
        9000-9999: Internal/Unknown
    """

    # Authentication errors (1000-1099)
    AUTH_INVALID_CREDENTIALS = 1001
    AUTH_TOKEN_EXPIRED = 1002
    AUTH_TOKEN_INVALID = 1003
    AUTH_TOKEN_MISSING = 1004
    AUTH_MFA_REQUIRED = 1005
    AUTH_ACCOUNT_LOCKED = 1006
    AUTH_ACCOUNT_DISABLED = 1007
    AUTH_SESSION_EXPIRED = 1008

    # Authorization errors (1100-1199)
    AUTHZ_INSUFFICIENT_PERMISSIONS = 1101
    AUTHZ_RESOURCE_FORBIDDEN = 1102
    AUTHZ_ROLE_REQUIRED = 1103
    AUTHZ_SCOPE_INVALID = 1104

    # Validation errors (2000-2099)
    VAL_MISSING_FIELD = 2001
    VAL_INVALID_FORMAT = 2002
    VAL_OUT_OF_RANGE = 2003
    VAL_CONSTRAINT_VIOLATED = 2004
    VAL_TYPE_MISMATCH = 2005
    VAL_SCHEMA_INVALID = 2006
    VAL_DUPLICATE_VALUE = 2007

    # Agent/Connection errors (3000-3099)
    AGENT_NOT_FOUND = 3001
    AGENT_OFFLINE = 3002
    AGENT_REGISTRATION_FAILED = 3003
    AGENT_HEARTBEAT_TIMEOUT = 3004
    AGENT_VERSION_MISMATCH = 3005
    AGENT_COMMUNICATION_ERROR = 3006
    AGENT_PROTOCOL_ERROR = 3007

    # Connection errors (3100-3199)
    CONN_TIMEOUT = 3101
    CONN_REFUSED = 3102
    CONN_DNS_FAILED = 3103
    CONN_SSL_ERROR = 3104
    CONN_NETWORK_UNREACHABLE = 3105

    # Detection Pipeline errors (4000-4099)
    DETECT_PIPELINE_ERROR = 4001
    DETECT_RULE_PARSE_ERROR = 4002
    DETECT_THRESHOLD_EXCEEDED = 4003
    DETECT_CORRELATION_FAILED = 4004
    DETECT_ENRICHMENT_FAILED = 4005

    # Resource errors (5000-5099)
    RES_NOT_FOUND = 5001
    RES_ALREADY_EXISTS = 5002
    RES_CONFLICT = 5003
    RES_QUOTA_EXCEEDED = 5004
    RES_RATE_LIMITED = 5005

    # Database errors (5100-5199)
    DB_CONNECTION_FAILED = 5101
    DB_QUERY_FAILED = 5102
    DB_INTEGRITY_ERROR = 5103
    DB_TRANSACTION_FAILED = 5104
    DB_MIGRATION_FAILED = 5105

    # Configuration errors (6000-6099)
    CFG_MISSING = 6001
    CFG_INVALID = 6002
    CFG_PARSE_ERROR = 6003
    CFG_ENVIRONMENT_ERROR = 6004

    # Internal errors (9000-9099)
    INTERNAL_ERROR = 9001
    INTERNAL_TIMEOUT = 9002
    INTERNAL_SERVICE_UNAVAILABLE = 9003
    INTERNAL_NOT_IMPLEMENTED = 9004
    UNKNOWN_ERROR = 9999


class AmoskysError(Exception):
    """Base exception class for all AMOSKYS errors.

    Provides:
    - Structured error information
    - HTTP status code mapping
    - Correlation ID for request tracing
    - Timestamp for debugging
    - Safe serialization (no sensitive data exposure)
    """

    http_status_code: int = 500
    default_code: ErrorCode = ErrorCode.INTERNAL_ERROR

    def __init__(
        self,
        message: str,
        code: Optional[ErrorCode] = None,
        details: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
        correlation_id: Optional[str] = None,
        hints: Optional[List[str]] = None,
    ):
        super().__init__(message)
        self.message = message
        self.code = code or self.default_code
        self.details = self._filter_sensitive_data(details or {})
        self.cause = cause
        self.correlation_id = correlation_id
        self.hints = hints or []
        self.timestamp = datetime.now(timezone.utc)

    @staticmethod
    def _filter_sensitive_data(data: Dict[str, Any]) -> Dict[str, Any]:
        """Remove sensitive information from error details."""
        sensitive_keys = {
            "password",
            "secret",
            "token",
            "api_key",
            "apikey",
            "authorization",
            "auth",
            "credential",
            "private_key",
            "secret_key",
            "access_token",
            "refresh_token",
            "ssn",
            "credit_card",
            "card_number",
            "cvv",
            "pin",
        }

        filtered = {}
        for key, value in data.items():
            key_lower = key.lower()
            if any(sensitive in key_lower for sensitive in sensitive_keys):
                filtered[key] = "[REDACTED]"
            elif isinstance(value, dict):
                filtered[key] = AmoskysError._filter_sensitive_data(value)
            else:
                filtered[key] = value
        return filtered

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for JSON serialization."""
        result = {
            "error": {
                "type": self.__class__.__name__,
                "code": self.code.name,
                "code_number": self.code.value,
                "message": self.message,
                "timestamp": self.timestamp.isoformat(),
            }
        }

        if self.details:
            result["error"]["details"] = self.details
        if self.hints:
            result["error"]["hints"] = self.hints
        if self.correlation_id:
            result["error"]["correlation_id"] = self.correlation_id

        return result

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"message={self.message!r}, "
            f"code={self.code.name}, "
            f"correlation_id={self.correlation_id!r})"
        )


# Authentication Errors (HTTP 401)
class AuthenticationError(AmoskysError):
    """Authentication failed - invalid or missing credentials."""

    http_status_code = 401
    default_code = ErrorCode.AUTH_INVALID_CREDENTIALS

    def __init__(
        self,
        message: str = "Authentication failed",
        code: Optional[ErrorCode] = None,
        **kwargs,
    ):
        super().__init__(message, code=code, **kwargs)


class TokenExpiredError(AuthenticationError):
    """Authentication token has expired."""

    default_code = ErrorCode.AUTH_TOKEN_EXPIRED

    def __init__(self, message: str = "Authentication token has expired", **kwargs):
        super().__init__(
            message, hints=["Refresh your token or log in again"], **kwargs
        )


class TokenInvalidError(AuthenticationError):
    """Authentication token is invalid or malformed."""

    default_code = ErrorCode.AUTH_TOKEN_INVALID

    def __init__(self, message: str = "Invalid authentication token", **kwargs):
        super().__init__(message, **kwargs)


class MFARequiredError(AuthenticationError):
    """Multi-factor authentication is required."""

    default_code = ErrorCode.AUTH_MFA_REQUIRED

    def __init__(self, message: str = "Multi-factor authentication required", **kwargs):
        super().__init__(
            message, hints=["Complete MFA verification to continue"], **kwargs
        )


# Authorization Errors (HTTP 403)
class AuthorizationError(AmoskysError):
    """Authorization failed - insufficient permissions."""

    http_status_code = 403
    default_code = ErrorCode.AUTHZ_INSUFFICIENT_PERMISSIONS

    def __init__(
        self,
        message: str = "You don't have permission to perform this action",
        required_permission: Optional[str] = None,
        **kwargs,
    ):
        details = kwargs.pop("details", {})
        if required_permission:
            details["required_permission"] = required_permission
        super().__init__(message, details=details, **kwargs)


class ResourceForbiddenError(AuthorizationError):
    """Access to the specified resource is forbidden."""

    default_code = ErrorCode.AUTHZ_RESOURCE_FORBIDDEN

    def __init__(self, resource: str, message: Optional[str] = None, **kwargs):
        msg = message or f"Access to '{resource}' is forbidden"
        super().__init__(msg, details={"resource": resource}, **kwargs)


# Validation Errors (HTTP 400)
class ValidationError(AmoskysError):
    """Request validation failed."""

    http_status_code = 400
    default_code = ErrorCode.VAL_SCHEMA_INVALID

    def __init__(
        self,
        message: str = "Validation failed",
        field: Optional[str] = None,
        errors: Optional[List[Dict[str, str]]] = None,
        **kwargs,
    ):
        details = kwargs.pop("details", {})
        if field:
            details["field"] = field
        if errors:
            details["errors"] = errors
        super().__init__(message, details=details, **kwargs)


class MissingFieldError(ValidationError):
    """Required field is missing."""

    default_code = ErrorCode.VAL_MISSING_FIELD

    def __init__(self, field: str, **kwargs):
        super().__init__(
            f"Required field '{field}' is missing",
            field=field,
            hints=[f"Include the '{field}' field in your request"],
            **kwargs,
        )


class InvalidFormatError(ValidationError):
    """Field value has invalid format."""

    default_code = ErrorCode.VAL_INVALID_FORMAT

    def __init__(self, field: str, expected_format: str, **kwargs):
        details = kwargs.pop("details", {})
        details["expected_format"] = expected_format
        super().__init__(
            f"Field '{field}' has invalid format",
            field=field,
            details=details,
            hints=[f"Expected format: {expected_format}"],
            **kwargs,
        )


class DuplicateValueError(ValidationError):
    """Value already exists (unique constraint violation)."""

    default_code = ErrorCode.VAL_DUPLICATE_VALUE

    def __init__(self, field: str, value: Optional[str] = None, **kwargs):
        msg = f"A record with this '{field}' already exists"
        super().__init__(msg, field=field, **kwargs)


# Agent/Connection Errors (HTTP 502/503/504)
class AgentError(AmoskysError):
    """Base class for agent-related errors."""

    http_status_code = 502
    default_code = ErrorCode.AGENT_COMMUNICATION_ERROR

    def __init__(self, message: str, agent_id: Optional[str] = None, **kwargs):
        details = kwargs.pop("details", {})
        if agent_id:
            details["agent_id"] = agent_id
        super().__init__(message, details=details, **kwargs)


class AgentNotFoundError(AgentError):
    """Specified agent does not exist."""

    http_status_code = 404
    default_code = ErrorCode.AGENT_NOT_FOUND

    def __init__(self, agent_id: str, **kwargs):
        super().__init__(f"Agent '{agent_id}' not found", agent_id=agent_id, **kwargs)


class AgentOfflineError(AgentError):
    """Agent is not currently connected."""

    http_status_code = 503
    default_code = ErrorCode.AGENT_OFFLINE

    def __init__(self, agent_id: str, last_seen: Optional[str] = None, **kwargs):
        details = kwargs.pop("details", {})
        if last_seen:
            details["last_seen"] = last_seen
        super().__init__(
            f"Agent '{agent_id}' is offline",
            agent_id=agent_id,
            details=details,
            hints=["Check agent status and network connectivity"],
            **kwargs,
        )


class AgentConnectionError(AgentError):
    """Failed to communicate with agent."""

    http_status_code = 502
    default_code = ErrorCode.AGENT_COMMUNICATION_ERROR

    def __init__(self, agent_id: str, reason: Optional[str] = None, **kwargs):
        msg = f"Failed to communicate with agent '{agent_id}'"
        if reason:
            msg += f": {reason}"
        super().__init__(msg, agent_id=agent_id, **kwargs)


class ConnectionTimeoutError(AmoskysError):
    """Connection attempt timed out."""

    http_status_code = 504
    default_code = ErrorCode.CONN_TIMEOUT

    def __init__(self, target: str, timeout_seconds: Optional[float] = None, **kwargs):
        details = kwargs.pop("details", {})
        details["target"] = target
        if timeout_seconds:
            details["timeout_seconds"] = timeout_seconds
        super().__init__(
            f"Connection to '{target}' timed out",
            details=details,
            hints=["Check network connectivity", "Increase timeout if appropriate"],
            **kwargs,
        )


# Detection Pipeline Errors (HTTP 500/503)
class DetectionPipelineError(AmoskysError):
    """Error in the threat detection pipeline."""

    http_status_code = 500
    default_code = ErrorCode.DETECT_PIPELINE_ERROR

    def __init__(
        self,
        message: str,
        stage: Optional[str] = None,
        rule_id: Optional[str] = None,
        **kwargs,
    ):
        details = kwargs.pop("details", {})
        if stage:
            details["pipeline_stage"] = stage
        if rule_id:
            details["rule_id"] = rule_id
        super().__init__(message, details=details, **kwargs)


class RuleParseError(DetectionPipelineError):
    """Failed to parse detection rule."""

    default_code = ErrorCode.DETECT_RULE_PARSE_ERROR

    def __init__(self, rule_id: str, parse_error: str, **kwargs):
        super().__init__(
            f"Failed to parse detection rule '{rule_id}'",
            rule_id=rule_id,
            details={"parse_error": parse_error},
            **kwargs,
        )


# Resource Errors (HTTP 404/409/429)
class ResourceNotFoundError(AmoskysError):
    """Requested resource does not exist."""

    http_status_code = 404
    default_code = ErrorCode.RES_NOT_FOUND

    def __init__(self, resource_type: str, resource_id: str, **kwargs):
        super().__init__(
            f"{resource_type} '{resource_id}' not found",
            details={"resource_type": resource_type, "resource_id": resource_id},
            **kwargs,
        )


class ResourceConflictError(AmoskysError):
    """Resource state conflict (e.g., concurrent modification)."""

    http_status_code = 409
    default_code = ErrorCode.RES_CONFLICT

    def __init__(self, message: str = "Resource conflict", **kwargs):
        super().__init__(message, hints=["Refresh and try again"], **kwargs)


class RateLimitExceededError(AmoskysError):
    """Rate limit exceeded."""

    http_status_code = 429
    default_code = ErrorCode.RES_RATE_LIMITED

    def __init__(
        self,
        message: str = "Rate limit exceeded",
        retry_after: Optional[int] = None,
        **kwargs,
    ):
        details = kwargs.pop("details", {})
        if retry_after:
            details["retry_after_seconds"] = retry_after
        hint = (
            f"Wait {retry_after} seconds before retrying"
            if retry_after
            else "Please wait before retrying"
        )
        super().__init__(message, details=details, hints=[hint], **kwargs)


# Database Errors (HTTP 500/503)
class DatabaseError(AmoskysError):
    """Database operation failed."""

    http_status_code = 500
    default_code = ErrorCode.DB_QUERY_FAILED

    def __init__(self, message: str = "Database operation failed", **kwargs):
        super().__init__(message, **kwargs)


class DatabaseConnectionError(DatabaseError):
    """Failed to connect to database."""

    http_status_code = 503
    default_code = ErrorCode.DB_CONNECTION_FAILED

    def __init__(self, message: str = "Database connection failed", **kwargs):
        super().__init__(message, hints=["Check database connectivity"], **kwargs)


# Configuration Errors (HTTP 500)
class ConfigurationError(AmoskysError):
    """Configuration error."""

    http_status_code = 500
    default_code = ErrorCode.CFG_INVALID

    def __init__(self, message: str, config_key: Optional[str] = None, **kwargs):
        details = kwargs.pop("details", {})
        if config_key:
            details["config_key"] = config_key
        super().__init__(message, details=details, **kwargs)


class ConfigurationMissingError(ConfigurationError):
    """Required configuration is missing."""

    default_code = ErrorCode.CFG_MISSING

    def __init__(self, config_key: str, **kwargs):
        super().__init__(
            f"Required configuration '{config_key}' is missing",
            config_key=config_key,
            hints=[f"Set the '{config_key}' configuration value"],
            **kwargs,
        )


# Internal Errors (HTTP 500/501/503)
class InternalError(AmoskysError):
    """Internal server error."""

    http_status_code = 500
    default_code = ErrorCode.INTERNAL_ERROR

    def __init__(self, message: str = "An internal error occurred", **kwargs):
        super().__init__(message, **kwargs)


class NotImplementedError(AmoskysError):
    """Feature not implemented."""

    http_status_code = 501
    default_code = ErrorCode.INTERNAL_NOT_IMPLEMENTED

    def __init__(self, feature: str, **kwargs):
        super().__init__(
            f"Feature '{feature}' is not yet implemented",
            details={"feature": feature},
            **kwargs,
        )


class ServiceUnavailableError(AmoskysError):
    """Service temporarily unavailable."""

    http_status_code = 503
    default_code = ErrorCode.INTERNAL_SERVICE_UNAVAILABLE

    def __init__(
        self,
        message: str = "Service temporarily unavailable",
        retry_after: Optional[int] = None,
        **kwargs,
    ):
        details = kwargs.pop("details", {})
        if retry_after:
            details["retry_after_seconds"] = retry_after
        super().__init__(message, details=details, **kwargs)


# Convenience Functions
def wrap_exception(
    exc: Exception,
    message: Optional[str] = None,
    code: Optional[ErrorCode] = None,
    correlation_id: Optional[str] = None,
) -> AmoskysError:
    """Wrap a standard exception in an AmoskysError."""
    if isinstance(exc, AmoskysError):
        if correlation_id and not exc.correlation_id:
            exc.correlation_id = correlation_id
        return exc

    return InternalError(
        message=message or str(exc) or "An unexpected error occurred",
        code=code or ErrorCode.UNKNOWN_ERROR,
        cause=exc,
        correlation_id=correlation_id,
    )
