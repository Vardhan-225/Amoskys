"""Tests for amoskys.common.exceptions — Exception hierarchy with to_dict, sensitive filtering.

Covers:
    - ErrorCode enum: values, names
    - AmoskysError: construction, to_dict, repr, sensitive data filtering
    - AuthenticationError and subclasses: TokenExpiredError, TokenInvalidError, MFARequiredError
    - AuthorizationError and subclasses: ResourceForbiddenError
    - ValidationError and subclasses: MissingFieldError, InvalidFormatError, DuplicateValueError
    - AgentError and subclasses: AgentNotFoundError, AgentOfflineError, AgentConnectionError
    - ConnectionTimeoutError
    - DetectionPipelineError and subclasses: RuleParseError
    - ResourceNotFoundError, ResourceConflictError, RateLimitExceededError
    - DatabaseError, DatabaseConnectionError
    - ConfigurationError, ConfigurationMissingError
    - InternalError, NotImplementedError, ServiceUnavailableError
    - wrap_exception: wrapping standard exceptions, passing through AmoskysError
"""

from datetime import datetime, timezone

import pytest

# Import the custom NotImplementedError with a different name to avoid shadowing
from amoskys.common.exceptions import (
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
)
from amoskys.common.exceptions import NotImplementedError as AmoskysNotImplementedError
from amoskys.common.exceptions import (
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

# ---------------------------------------------------------------------------
# ErrorCode
# ---------------------------------------------------------------------------


class TestErrorCode:

    def test_auth_codes_in_1000_range(self):
        assert ErrorCode.AUTH_INVALID_CREDENTIALS.value == 1001
        assert ErrorCode.AUTH_TOKEN_EXPIRED.value == 1002

    def test_validation_codes_in_2000_range(self):
        assert ErrorCode.VAL_MISSING_FIELD.value == 2001
        assert ErrorCode.VAL_INVALID_FORMAT.value == 2002

    def test_agent_codes_in_3000_range(self):
        assert ErrorCode.AGENT_NOT_FOUND.value == 3001

    def test_detection_codes_in_4000_range(self):
        assert ErrorCode.DETECT_PIPELINE_ERROR.value == 4001

    def test_resource_codes_in_5000_range(self):
        assert ErrorCode.RES_NOT_FOUND.value == 5001
        assert ErrorCode.DB_CONNECTION_FAILED.value == 5101

    def test_config_codes_in_6000_range(self):
        assert ErrorCode.CFG_MISSING.value == 6001

    def test_internal_codes_in_9000_range(self):
        assert ErrorCode.INTERNAL_ERROR.value == 9001
        assert ErrorCode.UNKNOWN_ERROR.value == 9999

    def test_all_codes_have_unique_values(self):
        values = [e.value for e in ErrorCode]
        assert len(values) == len(set(values))


# ---------------------------------------------------------------------------
# AmoskysError
# ---------------------------------------------------------------------------


class TestAmoskysError:

    def test_basic_construction(self):
        err = AmoskysError("Something failed")
        assert err.message == "Something failed"
        assert str(err) == "Something failed"
        assert err.code == ErrorCode.INTERNAL_ERROR
        assert err.details == {}
        assert err.cause is None
        assert err.correlation_id is None
        assert err.hints == []
        assert isinstance(err.timestamp, datetime)

    def test_with_code(self):
        err = AmoskysError("fail", code=ErrorCode.AGENT_NOT_FOUND)
        assert err.code == ErrorCode.AGENT_NOT_FOUND

    def test_with_details(self):
        err = AmoskysError("fail", details={"key": "value"})
        assert err.details == {"key": "value"}

    def test_with_cause(self):
        cause = ValueError("root cause")
        err = AmoskysError("fail", cause=cause)
        assert err.cause is cause

    def test_with_correlation_id(self):
        err = AmoskysError("fail", correlation_id="corr-123")
        assert err.correlation_id == "corr-123"

    def test_with_hints(self):
        err = AmoskysError("fail", hints=["Try this", "Or that"])
        assert err.hints == ["Try this", "Or that"]

    def test_to_dict_basic(self):
        err = AmoskysError("fail")
        d = err.to_dict()
        assert "error" in d
        assert d["error"]["type"] == "AmoskysError"
        assert d["error"]["code"] == "INTERNAL_ERROR"
        assert d["error"]["code_number"] == 9001
        assert d["error"]["message"] == "fail"
        assert "timestamp" in d["error"]

    def test_to_dict_with_details(self):
        err = AmoskysError("fail", details={"agent": "proc"})
        d = err.to_dict()
        assert d["error"]["details"] == {"agent": "proc"}

    def test_to_dict_with_hints(self):
        err = AmoskysError("fail", hints=["hint1"])
        d = err.to_dict()
        assert d["error"]["hints"] == ["hint1"]

    def test_to_dict_with_correlation_id(self):
        err = AmoskysError("fail", correlation_id="cid-456")
        d = err.to_dict()
        assert d["error"]["correlation_id"] == "cid-456"

    def test_to_dict_omits_empty_optional_fields(self):
        err = AmoskysError("fail")
        d = err.to_dict()
        assert "details" not in d["error"]
        assert "hints" not in d["error"]
        assert "correlation_id" not in d["error"]

    def test_repr(self):
        err = AmoskysError("fail", correlation_id="cid")
        r = repr(err)
        assert "AmoskysError" in r
        assert "fail" in r
        assert "INTERNAL_ERROR" in r
        assert "cid" in r

    def test_http_status_code_default(self):
        assert AmoskysError.http_status_code == 500

    def test_is_exception(self):
        err = AmoskysError("fail")
        assert isinstance(err, Exception)

    def test_sensitive_data_filtered_in_details(self):
        err = AmoskysError(
            "fail",
            details={
                "username": "admin",
                "password": "s3cret",
                "token": "abc123",
                "safe_field": "visible",
            },
        )
        assert err.details["password"] == "[REDACTED]"
        assert err.details["token"] == "[REDACTED]"
        assert err.details["username"] == "admin"
        assert err.details["safe_field"] == "visible"

    def test_nested_sensitive_data_filtered(self):
        err = AmoskysError(
            "fail",
            details={
                "config": {
                    "api_key": "secret",
                    "host": "localhost",
                }
            },
        )
        assert err.details["config"]["api_key"] == "[REDACTED]"
        assert err.details["config"]["host"] == "localhost"

    def test_filter_sensitive_data_static_method(self):
        result = AmoskysError._filter_sensitive_data(
            {
                "credential": "hidden",
                "name": "visible",
            }
        )
        assert result["credential"] == "[REDACTED]"
        assert result["name"] == "visible"


# ---------------------------------------------------------------------------
# Authentication Errors
# ---------------------------------------------------------------------------


class TestAuthenticationError:

    def test_default_message(self):
        err = AuthenticationError()
        assert err.message == "Authentication failed"

    def test_default_code(self):
        err = AuthenticationError()
        assert err.code == ErrorCode.AUTH_INVALID_CREDENTIALS

    def test_http_status_code(self):
        assert AuthenticationError.http_status_code == 401

    def test_custom_code(self):
        err = AuthenticationError(code=ErrorCode.AUTH_ACCOUNT_LOCKED)
        assert err.code == ErrorCode.AUTH_ACCOUNT_LOCKED

    def test_custom_message(self):
        err = AuthenticationError("Invalid API key")
        assert err.message == "Invalid API key"


class TestTokenExpiredError:

    def test_default_message(self):
        err = TokenExpiredError()
        assert "expired" in err.message.lower()

    def test_default_code(self):
        err = TokenExpiredError()
        assert err.code == ErrorCode.AUTH_TOKEN_EXPIRED

    def test_includes_hint(self):
        err = TokenExpiredError()
        assert len(err.hints) > 0
        assert any("refresh" in h.lower() or "log in" in h.lower() for h in err.hints)


class TestTokenInvalidError:

    def test_default_message(self):
        err = TokenInvalidError()
        assert "invalid" in err.message.lower()

    def test_default_code(self):
        err = TokenInvalidError()
        assert err.code == ErrorCode.AUTH_TOKEN_INVALID


class TestMFARequiredError:

    def test_default_message(self):
        err = MFARequiredError()
        assert "multi-factor" in err.message.lower()

    def test_default_code(self):
        err = MFARequiredError()
        assert err.code == ErrorCode.AUTH_MFA_REQUIRED

    def test_includes_hint(self):
        err = MFARequiredError()
        assert len(err.hints) > 0


# ---------------------------------------------------------------------------
# Authorization Errors
# ---------------------------------------------------------------------------


class TestAuthorizationError:

    def test_default_message(self):
        err = AuthorizationError()
        assert "permission" in err.message.lower()

    def test_http_status_code(self):
        assert AuthorizationError.http_status_code == 403

    def test_default_code(self):
        err = AuthorizationError()
        assert err.code == ErrorCode.AUTHZ_INSUFFICIENT_PERMISSIONS

    def test_required_permission_in_details(self):
        err = AuthorizationError(required_permission="admin:write")
        assert err.details["required_permission"] == "admin:write"

    def test_no_required_permission(self):
        err = AuthorizationError()
        assert "required_permission" not in err.details


class TestResourceForbiddenError:

    def test_default_message_includes_resource(self):
        err = ResourceForbiddenError("/api/admin")
        assert "/api/admin" in err.message

    def test_custom_message(self):
        err = ResourceForbiddenError("/api/admin", message="Custom forbidden")
        assert err.message == "Custom forbidden"

    def test_resource_in_details(self):
        err = ResourceForbiddenError("/secret")
        assert err.details["resource"] == "/secret"

    def test_default_code(self):
        err = ResourceForbiddenError("/api")
        assert err.code == ErrorCode.AUTHZ_RESOURCE_FORBIDDEN


# ---------------------------------------------------------------------------
# Validation Errors
# ---------------------------------------------------------------------------


class TestValidationError:

    def test_default_message(self):
        err = ValidationError()
        assert err.message == "Validation failed"

    def test_http_status_code(self):
        assert ValidationError.http_status_code == 400

    def test_with_field(self):
        err = ValidationError(field="email")
        assert err.details["field"] == "email"

    def test_with_errors_list(self):
        errors = [{"field": "email", "message": "invalid format"}]
        err = ValidationError(errors=errors)
        assert err.details["errors"] == errors

    def test_no_field_no_errors(self):
        err = ValidationError()
        assert "field" not in err.details
        assert "errors" not in err.details


class TestMissingFieldError:

    def test_message_includes_field(self):
        err = MissingFieldError("username")
        assert "username" in err.message

    def test_default_code(self):
        err = MissingFieldError("x")
        assert err.code == ErrorCode.VAL_MISSING_FIELD

    def test_includes_hint(self):
        err = MissingFieldError("email")
        assert any("email" in h for h in err.hints)

    def test_field_in_details(self):
        err = MissingFieldError("name")
        assert err.details["field"] == "name"


class TestInvalidFormatError:

    def test_message_includes_field(self):
        err = InvalidFormatError("email", "user@example.com")
        assert "email" in err.message

    def test_expected_format_in_details(self):
        err = InvalidFormatError("date", "YYYY-MM-DD")
        assert err.details["expected_format"] == "YYYY-MM-DD"

    def test_includes_hint(self):
        err = InvalidFormatError("date", "ISO 8601")
        assert any("ISO 8601" in h for h in err.hints)

    def test_default_code(self):
        err = InvalidFormatError("x", "fmt")
        assert err.code == ErrorCode.VAL_INVALID_FORMAT


class TestDuplicateValueError:

    def test_message_includes_field(self):
        err = DuplicateValueError("email")
        assert "email" in err.message

    def test_default_code(self):
        err = DuplicateValueError("email")
        assert err.code == ErrorCode.VAL_DUPLICATE_VALUE


# ---------------------------------------------------------------------------
# Agent/Connection Errors
# ---------------------------------------------------------------------------


class TestAgentError:

    def test_with_agent_id(self):
        err = AgentError("communication fail", agent_id="agent-001")
        assert err.details["agent_id"] == "agent-001"

    def test_without_agent_id(self):
        err = AgentError("generic agent error")
        assert "agent_id" not in err.details

    def test_http_status_code(self):
        assert AgentError.http_status_code == 502

    def test_default_code(self):
        err = AgentError("fail")
        assert err.code == ErrorCode.AGENT_COMMUNICATION_ERROR


class TestAgentNotFoundError:

    def test_message_includes_id(self):
        err = AgentNotFoundError("agent-123")
        assert "agent-123" in err.message

    def test_http_status_code(self):
        assert AgentNotFoundError.http_status_code == 404

    def test_default_code(self):
        err = AgentNotFoundError("x")
        assert err.code == ErrorCode.AGENT_NOT_FOUND


class TestAgentOfflineError:

    def test_message_includes_id(self):
        err = AgentOfflineError("agent-123")
        assert "agent-123" in err.message

    def test_last_seen_in_details(self):
        err = AgentOfflineError("agent-123", last_seen="2025-01-01T00:00:00Z")
        assert err.details["last_seen"] == "2025-01-01T00:00:00Z"

    def test_includes_hint(self):
        err = AgentOfflineError("agent-123")
        assert len(err.hints) > 0

    def test_http_status_code(self):
        assert AgentOfflineError.http_status_code == 503


class TestAgentConnectionError:

    def test_message_includes_agent_id(self):
        err = AgentConnectionError("agent-123")
        assert "agent-123" in err.message

    def test_reason_appended(self):
        err = AgentConnectionError("agent-123", reason="timeout")
        assert "timeout" in err.message

    def test_no_reason(self):
        err = AgentConnectionError("agent-123")
        assert ":" not in err.message.split("agent-123'")[1]


class TestConnectionTimeoutError:

    def test_message_includes_target(self):
        err = ConnectionTimeoutError("api.example.com")
        assert "api.example.com" in err.message

    def test_timeout_in_details(self):
        err = ConnectionTimeoutError("api.example.com", timeout_seconds=30.0)
        assert err.details["timeout_seconds"] == 30.0

    def test_includes_hints(self):
        err = ConnectionTimeoutError("target")
        assert len(err.hints) >= 1

    def test_http_status_code(self):
        assert ConnectionTimeoutError.http_status_code == 504


# ---------------------------------------------------------------------------
# Detection Pipeline Errors
# ---------------------------------------------------------------------------


class TestDetectionPipelineError:

    def test_with_stage(self):
        err = DetectionPipelineError("fail", stage="enrichment")
        assert err.details["pipeline_stage"] == "enrichment"

    def test_with_rule_id(self):
        err = DetectionPipelineError("fail", rule_id="RULE-001")
        assert err.details["rule_id"] == "RULE-001"

    def test_without_optional_fields(self):
        err = DetectionPipelineError("generic fail")
        assert "pipeline_stage" not in err.details
        assert "rule_id" not in err.details

    def test_http_status_code(self):
        assert DetectionPipelineError.http_status_code == 500


class TestRuleParseError:

    def test_message_includes_rule_id(self):
        err = RuleParseError("RULE-001", "syntax error at line 5")
        assert "RULE-001" in err.message

    def test_parse_error_in_details(self):
        err = RuleParseError("RULE-001", "unexpected EOF")
        assert err.details["parse_error"] == "unexpected EOF"

    def test_default_code(self):
        err = RuleParseError("x", "y")
        assert err.code == ErrorCode.DETECT_RULE_PARSE_ERROR


# ---------------------------------------------------------------------------
# Resource Errors
# ---------------------------------------------------------------------------


class TestResourceNotFoundError:

    def test_message_includes_type_and_id(self):
        err = ResourceNotFoundError("Agent", "agent-001")
        assert "Agent" in err.message
        assert "agent-001" in err.message

    def test_details_populated(self):
        err = ResourceNotFoundError("Alert", "alert-123")
        assert err.details["resource_type"] == "Alert"
        assert err.details["resource_id"] == "alert-123"

    def test_http_status_code(self):
        assert ResourceNotFoundError.http_status_code == 404


class TestResourceConflictError:

    def test_default_message(self):
        err = ResourceConflictError()
        assert err.message == "Resource conflict"

    def test_includes_hint(self):
        err = ResourceConflictError()
        assert any("refresh" in h.lower() for h in err.hints)

    def test_http_status_code(self):
        assert ResourceConflictError.http_status_code == 409


class TestRateLimitExceededError:

    def test_default_message(self):
        err = RateLimitExceededError()
        assert "rate limit" in err.message.lower()

    def test_retry_after_in_details(self):
        err = RateLimitExceededError(retry_after=60)
        assert err.details["retry_after_seconds"] == 60

    def test_retry_after_in_hint(self):
        err = RateLimitExceededError(retry_after=30)
        assert any("30" in h for h in err.hints)

    def test_no_retry_after(self):
        err = RateLimitExceededError()
        assert "retry_after_seconds" not in err.details
        assert any("wait" in h.lower() for h in err.hints)

    def test_http_status_code(self):
        assert RateLimitExceededError.http_status_code == 429


# ---------------------------------------------------------------------------
# Database Errors
# ---------------------------------------------------------------------------


class TestDatabaseError:

    def test_default_message(self):
        err = DatabaseError()
        assert "database" in err.message.lower()

    def test_http_status_code(self):
        assert DatabaseError.http_status_code == 500


class TestDatabaseConnectionError:

    def test_default_message(self):
        err = DatabaseConnectionError()
        assert "connection" in err.message.lower()

    def test_includes_hint(self):
        err = DatabaseConnectionError()
        assert len(err.hints) > 0

    def test_http_status_code(self):
        assert DatabaseConnectionError.http_status_code == 503


# ---------------------------------------------------------------------------
# Configuration Errors
# ---------------------------------------------------------------------------


class TestConfigurationError:

    def test_with_config_key(self):
        err = ConfigurationError("Invalid config", config_key="db_host")
        assert err.details["config_key"] == "db_host"

    def test_without_config_key(self):
        err = ConfigurationError("Generic config error")
        assert "config_key" not in err.details

    def test_http_status_code(self):
        assert ConfigurationError.http_status_code == 500


class TestConfigurationMissingError:

    def test_message_includes_key(self):
        err = ConfigurationMissingError("DATABASE_URL")
        assert "DATABASE_URL" in err.message

    def test_includes_hint(self):
        err = ConfigurationMissingError("API_KEY")
        assert any("API_KEY" in h for h in err.hints)

    def test_default_code(self):
        err = ConfigurationMissingError("x")
        assert err.code == ErrorCode.CFG_MISSING


# ---------------------------------------------------------------------------
# Internal Errors
# ---------------------------------------------------------------------------


class TestInternalError:

    def test_default_message(self):
        err = InternalError()
        assert "internal" in err.message.lower()

    def test_http_status_code(self):
        assert InternalError.http_status_code == 500


class TestAmoskysNotImplementedError:

    def test_message_includes_feature(self):
        err = AmoskysNotImplementedError("dark mode")
        assert "dark mode" in err.message

    def test_feature_in_details(self):
        err = AmoskysNotImplementedError("dark mode")
        assert err.details["feature"] == "dark mode"

    def test_http_status_code(self):
        assert AmoskysNotImplementedError.http_status_code == 501


class TestServiceUnavailableError:

    def test_default_message(self):
        err = ServiceUnavailableError()
        assert "unavailable" in err.message.lower()

    def test_retry_after_in_details(self):
        err = ServiceUnavailableError(retry_after=120)
        assert err.details["retry_after_seconds"] == 120

    def test_no_retry_after(self):
        err = ServiceUnavailableError()
        assert "retry_after_seconds" not in err.details

    def test_http_status_code(self):
        assert ServiceUnavailableError.http_status_code == 503


# ---------------------------------------------------------------------------
# wrap_exception
# ---------------------------------------------------------------------------


class TestWrapException:

    def test_wraps_standard_exception(self):
        exc = ValueError("bad value")
        wrapped = wrap_exception(exc)
        assert isinstance(wrapped, AmoskysError)
        assert isinstance(wrapped, InternalError)
        assert "bad value" in wrapped.message
        assert wrapped.cause is exc
        assert wrapped.code == ErrorCode.UNKNOWN_ERROR

    def test_wraps_with_custom_message(self):
        exc = RuntimeError("boom")
        wrapped = wrap_exception(exc, message="Custom error message")
        assert wrapped.message == "Custom error message"

    def test_wraps_with_custom_code(self):
        exc = RuntimeError("boom")
        wrapped = wrap_exception(exc, code=ErrorCode.AGENT_OFFLINE)
        assert wrapped.code == ErrorCode.AGENT_OFFLINE

    def test_wraps_with_correlation_id(self):
        exc = RuntimeError("boom")
        wrapped = wrap_exception(exc, correlation_id="cid-999")
        assert wrapped.correlation_id == "cid-999"

    def test_passes_through_amoskys_error(self):
        original = AuthenticationError("auth fail")
        result = wrap_exception(original)
        assert result is original

    def test_passes_through_and_sets_correlation_id(self):
        original = AuthenticationError("auth fail")
        result = wrap_exception(original, correlation_id="cid-123")
        assert result is original
        assert result.correlation_id == "cid-123"

    def test_does_not_overwrite_existing_correlation_id(self):
        original = AuthenticationError("auth fail", correlation_id="existing")
        result = wrap_exception(original, correlation_id="new-cid")
        assert result.correlation_id == "existing"

    def test_empty_exception_message(self):
        exc = RuntimeError("")
        wrapped = wrap_exception(exc)
        assert wrapped.message == "An unexpected error occurred"

    def test_inheritance_chain(self):
        """All wrapped exceptions should be AmoskysError instances."""
        exc = TypeError("type error")
        wrapped = wrap_exception(exc)
        assert isinstance(wrapped, Exception)
        assert isinstance(wrapped, AmoskysError)
