"""
Tests for AMOSKYS Unified Exception Hierarchy

Tests cover:
- Exception creation and attributes
- HTTP status code mapping
- JSON serialization
- Sensitive data filtering
- Error code consistency
"""

from datetime import datetime

import pytest  # noqa: F401 - used for fixtures

from amoskys.common.exceptions import (  # Base classes
    AgentConnectionError,
    AgentError,
    AgentNotFoundError,
    AgentOfflineError,
    AmoskysError,
    AuthenticationError,
    AuthorizationError,
    ConfigurationError,
    ConfigurationMissingError,
    ConnectionTimeoutError,
    DatabaseConnectionError,
    DatabaseError,
    DetectionPipelineError,
    DuplicateValueError,
    ErrorCode,
    InternalError,
    InvalidFormatError,
    MFARequiredError,
    MissingFieldError,
    RateLimitExceededError,
    ResourceConflictError,
    ResourceForbiddenError,
    ResourceNotFoundError,
    RuleParseError,
    ServiceUnavailableError,
    TokenExpiredError,
    TokenInvalidError,
    ValidationError,
    wrap_exception,
)


class TestAmoskysError:
    """Test base AmoskysError class."""

    def test_basic_creation(self):
        """Test basic exception creation."""
        error = AmoskysError("Something went wrong")
        assert error.message == "Something went wrong"
        assert error.code == ErrorCode.INTERNAL_ERROR
        assert error.http_status_code == 500
        assert error.details == {}
        assert error.hints == []
        assert error.cause is None
        assert isinstance(error.timestamp, datetime)

    def test_with_error_code(self):
        """Test exception with specific error code."""
        error = AmoskysError("Validation failed", code=ErrorCode.VAL_MISSING_FIELD)
        assert error.code == ErrorCode.VAL_MISSING_FIELD

    def test_with_details(self):
        """Test exception with details."""
        error = AmoskysError(
            "User not found", details={"user_id": "123", "searched": True}
        )
        assert error.details == {"user_id": "123", "searched": True}

    def test_with_correlation_id(self):
        """Test exception with correlation ID."""
        error = AmoskysError("Error", correlation_id="req-123-abc")
        assert error.correlation_id == "req-123-abc"

    def test_with_hints(self):
        """Test exception with hints."""
        error = AmoskysError(
            "Rate limited", hints=["Wait 60 seconds", "Consider upgrading plan"]
        )
        assert len(error.hints) == 2
        assert "Wait 60 seconds" in error.hints

    def test_with_cause(self):
        """Test exception with cause."""
        original = ValueError("Original error")
        error = AmoskysError("Wrapped error", cause=original)
        assert error.cause is original

    def test_to_dict(self):
        """Test JSON serialization."""
        error = AmoskysError(
            "Test error",
            code=ErrorCode.VAL_MISSING_FIELD,
            details={"field": "email"},
            hints=["Add email field"],
            correlation_id="req-123",
        )

        result = error.to_dict()

        assert "error" in result
        assert result["error"]["type"] == "AmoskysError"
        assert result["error"]["code"] == "VAL_MISSING_FIELD"
        assert result["error"]["code_number"] == 2001
        assert result["error"]["message"] == "Test error"
        assert result["error"]["details"] == {"field": "email"}
        assert result["error"]["hints"] == ["Add email field"]
        assert result["error"]["correlation_id"] == "req-123"
        assert "timestamp" in result["error"]

    def test_sensitive_data_filtering(self):
        """Test that sensitive data is filtered from details."""
        error = AmoskysError(
            "Auth failed",
            details={
                "username": "john",
                "password": "secret123",
                "api_key": "sk-12345",
                "nested": {"token": "jwt-token", "safe_field": "visible"},
            },
        )

        assert error.details["username"] == "john"
        assert error.details["password"] == "[REDACTED]"
        assert error.details["api_key"] == "[REDACTED]"
        assert error.details["nested"]["token"] == "[REDACTED]"
        assert error.details["nested"]["safe_field"] == "visible"

    def test_repr(self):
        """Test string representation."""
        error = AmoskysError(
            "Test error", code=ErrorCode.INTERNAL_ERROR, correlation_id="req-123"
        )
        repr_str = repr(error)
        assert "AmoskysError" in repr_str
        assert "Test error" in repr_str
        assert "INTERNAL_ERROR" in repr_str
        assert "req-123" in repr_str


class TestAuthenticationErrors:
    """Test authentication error classes."""

    def test_authentication_error(self):
        """Test basic authentication error."""
        error = AuthenticationError("Invalid credentials")
        assert error.http_status_code == 401
        assert error.code == ErrorCode.AUTH_INVALID_CREDENTIALS

    def test_token_expired(self):
        """Test token expired error."""
        error = TokenExpiredError()
        assert error.http_status_code == 401
        assert error.code == ErrorCode.AUTH_TOKEN_EXPIRED
        assert "expired" in error.message.lower()
        assert len(error.hints) > 0

    def test_token_invalid(self):
        """Test token invalid error."""
        error = TokenInvalidError()
        assert error.http_status_code == 401
        assert error.code == ErrorCode.AUTH_TOKEN_INVALID

    def test_mfa_required(self):
        """Test MFA required error."""
        error = MFARequiredError()
        assert error.http_status_code == 401
        assert error.code == ErrorCode.AUTH_MFA_REQUIRED
        assert len(error.hints) > 0


class TestAuthorizationErrors:
    """Test authorization error classes."""

    def test_authorization_error(self):
        """Test basic authorization error."""
        error = AuthorizationError("Access denied")
        assert error.http_status_code == 403
        assert error.code == ErrorCode.AUTHZ_INSUFFICIENT_PERMISSIONS

    def test_authorization_with_permission(self):
        """Test authorization error with required permission."""
        error = AuthorizationError(
            "Cannot delete users", required_permission="admin.users.delete"
        )
        assert error.details["required_permission"] == "admin.users.delete"

    def test_resource_forbidden(self):
        """Test resource forbidden error."""
        error = ResourceForbiddenError("/api/admin/settings")
        assert error.http_status_code == 403
        assert error.code == ErrorCode.AUTHZ_RESOURCE_FORBIDDEN
        assert "/api/admin/settings" in error.message


class TestValidationErrors:
    """Test validation error classes."""

    def test_validation_error(self):
        """Test basic validation error."""
        error = ValidationError("Invalid input")
        assert error.http_status_code == 400
        assert error.code == ErrorCode.VAL_SCHEMA_INVALID

    def test_validation_with_field(self):
        """Test validation error with field."""
        error = ValidationError("Invalid email", field="email")
        assert error.details["field"] == "email"

    def test_validation_with_errors_list(self):
        """Test validation error with multiple errors."""
        errors = [
            {"field": "email", "message": "Invalid format"},
            {"field": "age", "message": "Must be positive"},
        ]
        error = ValidationError("Validation failed", errors=errors)
        assert len(error.details["errors"]) == 2

    def test_missing_field(self):
        """Test missing field error."""
        error = MissingFieldError("username")
        assert error.http_status_code == 400
        assert error.code == ErrorCode.VAL_MISSING_FIELD
        assert "username" in error.message
        assert error.details["field"] == "username"
        assert len(error.hints) > 0

    def test_invalid_format(self):
        """Test invalid format error."""
        error = InvalidFormatError("email", "user@example.com")
        assert error.http_status_code == 400
        assert error.code == ErrorCode.VAL_INVALID_FORMAT
        assert "email" in error.message
        assert error.details["expected_format"] == "user@example.com"

    def test_duplicate_value(self):
        """Test duplicate value error."""
        error = DuplicateValueError("email")
        assert error.http_status_code == 400
        assert error.code == ErrorCode.VAL_DUPLICATE_VALUE
        assert "email" in error.message


class TestAgentErrors:
    """Test agent-related error classes."""

    def test_agent_error(self):
        """Test basic agent error."""
        error = AgentError("Connection failed", agent_id="agent-001")
        assert error.http_status_code == 502
        assert error.details["agent_id"] == "agent-001"

    def test_agent_not_found(self):
        """Test agent not found error."""
        error = AgentNotFoundError("agent-001")
        assert error.http_status_code == 404
        assert error.code == ErrorCode.AGENT_NOT_FOUND
        assert "agent-001" in error.message

    def test_agent_offline(self):
        """Test agent offline error."""
        error = AgentOfflineError("agent-001", last_seen="2025-12-30T10:00:00Z")
        assert error.http_status_code == 503
        assert error.code == ErrorCode.AGENT_OFFLINE
        assert error.details["last_seen"] == "2025-12-30T10:00:00Z"
        assert len(error.hints) > 0

    def test_agent_connection_error(self):
        """Test agent connection error."""
        error = AgentConnectionError("agent-001", reason="timeout")
        assert error.http_status_code == 502
        assert error.code == ErrorCode.AGENT_COMMUNICATION_ERROR
        assert "timeout" in error.message

    def test_connection_timeout(self):
        """Test connection timeout error."""
        error = ConnectionTimeoutError("api.example.com", timeout_seconds=30.0)
        assert error.http_status_code == 504
        assert error.code == ErrorCode.CONN_TIMEOUT
        assert error.details["timeout_seconds"] == 30.0


class TestDetectionPipelineErrors:
    """Test detection pipeline error classes."""

    def test_detection_pipeline_error(self):
        """Test basic pipeline error."""
        error = DetectionPipelineError(
            "Pipeline failed", stage="enrichment", rule_id="rule-001"
        )
        assert error.http_status_code == 500
        assert error.details["pipeline_stage"] == "enrichment"
        assert error.details["rule_id"] == "rule-001"

    def test_rule_parse_error(self):
        """Test rule parse error."""
        error = RuleParseError("rule-001", "Syntax error at line 5")
        assert error.code == ErrorCode.DETECT_RULE_PARSE_ERROR
        assert "rule-001" in error.message
        assert error.details["parse_error"] == "Syntax error at line 5"


class TestResourceErrors:
    """Test resource-related error classes."""

    def test_resource_not_found(self):
        """Test resource not found error."""
        error = ResourceNotFoundError("Event", "evt-123")
        assert error.http_status_code == 404
        assert error.code == ErrorCode.RES_NOT_FOUND
        assert "Event" in error.message
        assert "evt-123" in error.message

    def test_resource_conflict(self):
        """Test resource conflict error."""
        error = ResourceConflictError("Concurrent modification")
        assert error.http_status_code == 409
        assert error.code == ErrorCode.RES_CONFLICT

    def test_rate_limit_exceeded(self):
        """Test rate limit exceeded error."""
        error = RateLimitExceededError(retry_after=60)
        assert error.http_status_code == 429
        assert error.code == ErrorCode.RES_RATE_LIMITED
        assert error.details["retry_after_seconds"] == 60


class TestDatabaseErrors:
    """Test database error classes."""

    def test_database_error(self):
        """Test basic database error."""
        error = DatabaseError("Query failed")
        assert error.http_status_code == 500
        assert error.code == ErrorCode.DB_QUERY_FAILED

    def test_database_connection_error(self):
        """Test database connection error."""
        error = DatabaseConnectionError()
        assert error.http_status_code == 503
        assert error.code == ErrorCode.DB_CONNECTION_FAILED


class TestConfigurationErrors:
    """Test configuration error classes."""

    def test_configuration_error(self):
        """Test basic configuration error."""
        error = ConfigurationError("Invalid config", config_key="database.host")
        assert error.http_status_code == 500
        assert error.details["config_key"] == "database.host"

    def test_configuration_missing(self):
        """Test configuration missing error."""
        error = ConfigurationMissingError("SECRET_KEY")
        assert error.code == ErrorCode.CFG_MISSING
        assert "SECRET_KEY" in error.message
        assert len(error.hints) > 0


class TestInternalErrors:
    """Test internal error classes."""

    def test_internal_error(self):
        """Test basic internal error."""
        error = InternalError()
        assert error.http_status_code == 500
        assert error.code == ErrorCode.INTERNAL_ERROR

    def test_service_unavailable(self):
        """Test service unavailable error."""
        error = ServiceUnavailableError(retry_after=300)
        assert error.http_status_code == 503
        assert error.code == ErrorCode.INTERNAL_SERVICE_UNAVAILABLE
        assert error.details["retry_after_seconds"] == 300


class TestWrapException:
    """Test wrap_exception utility function."""

    def test_wrap_standard_exception(self):
        """Test wrapping standard exception."""
        original = ValueError("Invalid value")
        wrapped = wrap_exception(original)

        assert isinstance(wrapped, InternalError)
        assert wrapped.cause is original
        assert "Invalid value" in wrapped.message

    def test_wrap_with_custom_message(self):
        """Test wrapping with custom message."""
        original = KeyError("missing_key")
        wrapped = wrap_exception(original, message="Configuration error")

        assert wrapped.message == "Configuration error"
        assert wrapped.cause is original

    def test_wrap_with_correlation_id(self):
        """Test wrapping with correlation ID."""
        original = RuntimeError("Failed")
        wrapped = wrap_exception(original, correlation_id="req-123")

        assert wrapped.correlation_id == "req-123"

    def test_wrap_amoskys_error_passthrough(self):
        """Test that AmoskysError passes through without re-wrapping."""
        original = ValidationError("Invalid input")
        wrapped = wrap_exception(original)

        assert wrapped is original

    def test_wrap_amoskys_error_updates_correlation_id(self):
        """Test that wrapping updates correlation ID if missing."""
        original = ValidationError("Invalid input")
        wrapped = wrap_exception(original, correlation_id="req-456")

        assert wrapped is original
        assert wrapped.correlation_id == "req-456"


class TestErrorCodes:
    """Test error code consistency."""

    def test_error_code_ranges(self):
        """Test error code value ranges are consistent."""
        auth_codes = [
            ErrorCode.AUTH_INVALID_CREDENTIALS,
            ErrorCode.AUTH_TOKEN_EXPIRED,
            ErrorCode.AUTH_TOKEN_INVALID,
            ErrorCode.AUTH_TOKEN_MISSING,
        ]
        for code in auth_codes:
            assert (
                1000 <= code.value < 2000
            ), f"{code.name} should be in 1000-1999 range"

        val_codes = [
            ErrorCode.VAL_MISSING_FIELD,
            ErrorCode.VAL_INVALID_FORMAT,
            ErrorCode.VAL_SCHEMA_INVALID,
        ]
        for code in val_codes:
            assert (
                2000 <= code.value < 3000
            ), f"{code.name} should be in 2000-2999 range"

    def test_all_error_codes_unique(self):
        """Test that all error codes have unique values."""
        values = [code.value for code in ErrorCode]
        assert len(values) == len(set(values)), "Error codes should have unique values"
