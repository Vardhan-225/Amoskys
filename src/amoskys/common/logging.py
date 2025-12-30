"""
AMOSKYS Structured Logging Infrastructure

World-class logging framework providing:
- JSON-formatted logs for machine parsing
- Request correlation IDs for distributed tracing
- Automatic sensitive data filtering
- Performance timing and metrics
- Context-aware log enrichment

Design Philosophy (Akash Thanneeru + Claude Supremacy):
    Logs are the nervous system of observability. Every log entry
    carries enough context to reconstruct the request journey
    across all services, while respecting privacy constraints.
"""

import contextvars
import functools
import json
import logging
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional, Set, TypeVar, Union

# Context variable for request correlation ID
correlation_id_var: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "correlation_id", default=None
)

# Context variable for additional request context
request_context_var: contextvars.ContextVar[Dict[str, Any]] = contextvars.ContextVar(
    "request_context", default={}
)

# Sensitive field patterns to filter
SENSITIVE_PATTERNS: Set[str] = {
    "password",
    "passwd",
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
    "social_security",
    "credit_card",
    "card_number",
    "cvv",
    "pin",
    "session_id",
    "cookie",
    "jwt",
    "bearer",
}


def generate_correlation_id() -> str:
    """Generate a unique correlation ID for request tracing.

    Format: timestamp-uuid4-short
    Example: 20251230T120000Z-a1b2c3d4
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    short_uuid = uuid.uuid4().hex[:8]
    return f"{timestamp}-{short_uuid}"


def get_correlation_id() -> Optional[str]:
    """Get the current correlation ID from context."""
    return correlation_id_var.get()


def set_correlation_id(correlation_id: Optional[str] = None) -> str:
    """Set the correlation ID in context.

    Args:
        correlation_id: ID to set, or None to generate a new one

    Returns:
        The correlation ID that was set
    """
    cid = correlation_id or generate_correlation_id()
    correlation_id_var.set(cid)
    return cid


def get_request_context() -> Dict[str, Any]:
    """Get the current request context."""
    return request_context_var.get().copy()


def set_request_context(context: Dict[str, Any]) -> None:
    """Set additional request context for logging."""
    request_context_var.set(context)


def update_request_context(**kwargs) -> None:
    """Update request context with additional fields."""
    current = request_context_var.get().copy()
    current.update(kwargs)
    request_context_var.set(current)


def clear_request_context() -> None:
    """Clear request context (call at end of request)."""
    correlation_id_var.set(None)
    request_context_var.set({})


def filter_sensitive_data(
    data: Any, max_depth: int = 10, _current_depth: int = 0
) -> Any:
    """Recursively filter sensitive data from log payloads.

    Args:
        data: Data to filter (dict, list, or primitive)
        max_depth: Maximum recursion depth to prevent infinite loops
        _current_depth: Current recursion depth (internal)

    Returns:
        Filtered copy of the data with sensitive values redacted
    """
    if _current_depth >= max_depth:
        return "[MAX_DEPTH_EXCEEDED]"

    if isinstance(data, dict):
        filtered = {}
        for key, value in data.items():
            key_lower = str(key).lower()
            if any(pattern in key_lower for pattern in SENSITIVE_PATTERNS):
                filtered[key] = "[REDACTED]"
            else:
                filtered[key] = filter_sensitive_data(
                    value, max_depth, _current_depth + 1
                )
        return filtered
    elif isinstance(data, (list, tuple)):
        return [
            filter_sensitive_data(item, max_depth, _current_depth + 1) for item in data
        ]
    elif isinstance(data, str):
        # Check if the string looks like a JWT or API key
        if len(data) > 20 and (
            data.startswith("eyJ")  # JWT
            or data.startswith("sk-")  # API key pattern
            or data.startswith("pk-")
        ):
            return "[REDACTED_TOKEN]"
        return data
    else:
        return data


class JSONFormatter(logging.Formatter):
    """JSON log formatter for structured logging.

    Produces logs in JSON format suitable for log aggregation
    systems like ELK, Splunk, or CloudWatch.

    Output format:
    {
        "timestamp": "2025-12-30T12:00:00.000000+00:00",
        "level": "INFO",
        "logger": "amoskys.api.events",
        "message": "Event submitted successfully",
        "correlation_id": "20251230T120000Z-a1b2c3d4",
        "context": {...},
        "extra": {...}
    }
    """

    # Fields to exclude from extra (already handled specially)
    RESERVED_ATTRS = {
        "name",
        "msg",
        "args",
        "created",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "module",
        "msecs",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "exc_info",
        "exc_text",
        "thread",
        "threadName",
        "message",
        "asctime",
    }

    def __init__(
        self,
        include_stack_info: bool = False,
        include_process_info: bool = True,
        include_thread_info: bool = True,
        filter_sensitive: bool = True,
    ):
        """Initialize JSON formatter.

        Args:
            include_stack_info: Include stack traces in non-error logs
            include_process_info: Include process ID and name
            include_thread_info: Include thread ID and name
            filter_sensitive: Filter sensitive data from logs
        """
        super().__init__()
        self.include_stack_info = include_stack_info
        self.include_process_info = include_process_info
        self.include_thread_info = include_thread_info
        self.filter_sensitive = filter_sensitive
        self._hostname = os.uname().nodename if hasattr(os, "uname") else "unknown"

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON string."""
        # Build base log entry
        log_entry = {
            "timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Add correlation ID if available
        correlation_id = get_correlation_id()
        if correlation_id:
            log_entry["correlation_id"] = correlation_id

        # Add request context if available
        request_context = get_request_context()
        if request_context:
            log_entry["context"] = (
                filter_sensitive_data(request_context)
                if self.filter_sensitive
                else request_context
            )

        # Add source location
        log_entry["source"] = {
            "file": record.filename,
            "line": record.lineno,
            "function": record.funcName,
            "module": record.module,
        }

        # Add process/thread info
        if self.include_process_info:
            log_entry["process"] = {
                "id": record.process,
                "name": record.processName,
            }

        if self.include_thread_info:
            log_entry["thread"] = {
                "id": record.thread,
                "name": record.threadName,
            }

        # Add hostname for distributed systems
        log_entry["host"] = self._hostname

        # Add extra fields from log call
        extra = {}
        for key, value in record.__dict__.items():
            if key not in self.RESERVED_ATTRS and not key.startswith("_"):
                extra[key] = value

        if extra:
            if self.filter_sensitive:
                extra = filter_sensitive_data(extra)
            log_entry["extra"] = extra

        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = {
                "type": record.exc_info[0].__name__ if record.exc_info[0] else None,
                "message": str(record.exc_info[1]) if record.exc_info[1] else None,
                "traceback": self.formatException(record.exc_info),
            }

        # Add stack info if present and enabled
        if record.stack_info and self.include_stack_info:
            log_entry["stack_info"] = record.stack_info

        return json.dumps(log_entry, default=str)


class StructuredLogger(logging.LoggerAdapter):
    """Logger adapter that adds structured context to all log calls.

    Extends standard Logger with:
    - Automatic correlation ID injection
    - Structured extra data handling
    - Performance timing helpers
    - Error context enrichment

    Usage:
        logger = get_logger(__name__)
        logger.info("User logged in", user_id="123", ip="192.168.1.1")

        # With timing
        with logger.timed("database_query"):
            result = db.query(...)
    """

    def __init__(self, logger: logging.Logger, extra: Optional[Dict[str, Any]] = None):
        super().__init__(logger, extra or {})

    def process(self, msg: str, kwargs: Dict[str, Any]) -> tuple:
        """Process log call to add structured context."""
        # Merge adapter extra with call extra
        extra = {**self.extra, **kwargs.pop("extra", {})}

        # Add any keyword arguments as extra data
        for key in list(kwargs.keys()):
            if key not in ("exc_info", "stack_info", "stacklevel"):
                extra[key] = kwargs.pop(key)

        kwargs["extra"] = extra
        return msg, kwargs

    def timed(self, operation: str, level: int = logging.DEBUG) -> "TimingContext":
        """Context manager for timing operations.

        Usage:
            with logger.timed("database_query"):
                result = db.query(...)
            # Logs: "database_query completed in 0.123s"
        """
        return TimingContext(self, operation, level)

    def with_context(self, **kwargs) -> "StructuredLogger":
        """Create a new logger with additional context.

        Usage:
            request_logger = logger.with_context(user_id="123", request_id="abc")
            request_logger.info("Processing request")  # includes user_id and request_id
        """
        merged_extra = {**self.extra, **kwargs}
        return StructuredLogger(self.logger, merged_extra)


class TimingContext:
    """Context manager for timing and logging operations."""

    def __init__(self, logger: StructuredLogger, operation: str, level: int):
        self.logger = logger
        self.operation = operation
        self.level = level
        self.start_time: float = 0
        self.elapsed: float = 0

    def __enter__(self) -> "TimingContext":
        self.start_time = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        self.elapsed = time.perf_counter() - self.start_time

        if exc_type:
            self.logger.log(
                logging.ERROR,
                f"{self.operation} failed after {self.elapsed:.3f}s",
                duration_seconds=self.elapsed,
                operation=self.operation,
                error_type=exc_type.__name__,
                error_message=str(exc_val),
            )
        else:
            self.logger.log(
                self.level,
                f"{self.operation} completed in {self.elapsed:.3f}s",
                duration_seconds=self.elapsed,
                operation=self.operation,
            )

        return False  # Don't suppress exceptions


def get_logger(name: str, extra: Optional[Dict[str, Any]] = None) -> StructuredLogger:
    """Get a structured logger instance.

    Args:
        name: Logger name (typically __name__)
        extra: Default extra fields for all log calls

    Returns:
        StructuredLogger instance
    """
    logger = logging.getLogger(name)
    return StructuredLogger(logger, extra)


def configure_logging(
    level: Union[int, str] = logging.INFO,
    json_format: bool = True,
    stream: Optional[Any] = None,
    log_file: Optional[str] = None,
    filter_sensitive: bool = True,
    include_process_info: bool = True,
    include_thread_info: bool = True,
) -> None:
    """Configure AMOSKYS logging infrastructure.

    Call this once at application startup to set up logging.

    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        json_format: Use JSON formatter (recommended for production)
        stream: Output stream (defaults to stderr)
        log_file: Optional log file path
        filter_sensitive: Filter sensitive data from logs
        include_process_info: Include process ID in logs
        include_thread_info: Include thread ID in logs

    Example:
        # Production setup
        configure_logging(
            level=logging.INFO,
            json_format=True,
            log_file="/var/log/amoskys/app.log"
        )

        # Development setup
        configure_logging(
            level=logging.DEBUG,
            json_format=False  # Human-readable format
        )
    """
    # Convert string level to int
    if isinstance(level, str):
        level = getattr(logging, level.upper(), logging.INFO)

    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Remove existing handlers
    root_logger.handlers.clear()

    # Create formatter
    if json_format:
        formatter = JSONFormatter(
            filter_sensitive=filter_sensitive,
            include_process_info=include_process_info,
            include_thread_info=include_thread_info,
        )
    else:
        # Human-readable format for development
        formatter = logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s | "
            "%(filename)s:%(lineno)d | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

    # Add stream handler
    stream_handler = logging.StreamHandler(stream or sys.stderr)
    stream_handler.setFormatter(formatter)
    stream_handler.setLevel(level)
    root_logger.addHandler(stream_handler)

    # Add file handler if specified
    if log_file:
        # Ensure directory exists
        log_dir = os.path.dirname(log_file)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)

        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        file_handler.setLevel(level)
        root_logger.addHandler(file_handler)

    # Set levels for noisy third-party libraries
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)


# ============================================================================
# Function Decorators
# ============================================================================

F = TypeVar("F", bound=Callable[..., Any])


def log_call(
    logger: Optional[StructuredLogger] = None,
    level: int = logging.DEBUG,
    include_args: bool = True,
    include_result: bool = False,
    timed: bool = True,
) -> Callable[[F], F]:
    """Decorator to log function calls with timing.

    Args:
        logger: Logger to use (defaults to function's module logger)
        level: Log level for call logging
        include_args: Include function arguments in log
        include_result: Include function result in log
        timed: Log execution duration

    Usage:
        @log_call()
        def process_event(event_id: str, data: dict) -> bool:
            ...
    """

    def decorator(func: F) -> F:
        nonlocal logger
        if logger is None:
            logger = get_logger(func.__module__)

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            func_name = f"{func.__module__}.{func.__name__}"

            # Log call
            call_data: Dict[str, Any] = {"function": func_name}
            if include_args:
                # Filter sensitive data from arguments
                call_data["args"] = filter_sensitive_data(
                    {"positional": args[:5], "keyword": kwargs}  # Limit args
                )

            logger.log(level, f"Calling {func_name}", **call_data)

            start_time = time.perf_counter() if timed else 0

            try:
                result = func(*args, **kwargs)

                # Log success
                log_data: Dict[str, Any] = {"function": func_name}
                if timed:
                    log_data["duration_seconds"] = time.perf_counter() - start_time
                if include_result:
                    log_data["result"] = filter_sensitive_data(result)

                logger.log(level, f"Completed {func_name}", **log_data)
                return result

            except Exception as e:
                # Log failure
                log_data = {
                    "function": func_name,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                }
                if timed:
                    log_data["duration_seconds"] = time.perf_counter() - start_time

                logger.error(f"Failed {func_name}", **log_data)
                raise

        return wrapper  # type: ignore

    return decorator


def log_exceptions(
    logger: Optional[StructuredLogger] = None,
    reraise: bool = True,
    message: Optional[str] = None,
) -> Callable[[F], F]:
    """Decorator to log exceptions with full context.

    Args:
        logger: Logger to use
        reraise: Re-raise the exception after logging
        message: Custom error message prefix

    Usage:
        @log_exceptions(message="Failed to process event")
        def process_event(event_id: str) -> None:
            ...
    """

    def decorator(func: F) -> F:
        nonlocal logger
        if logger is None:
            logger = get_logger(func.__module__)

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                func_name = f"{func.__module__}.{func.__name__}"
                error_msg = message or f"Exception in {func_name}"

                logger.exception(
                    error_msg,
                    function=func_name,
                    error_type=type(e).__name__,
                    exc_info=True,
                )

                if reraise:
                    raise
                return None

        return wrapper  # type: ignore

    return decorator


# ============================================================================
# Flask Integration
# ============================================================================


def init_flask_logging(app) -> None:
    """Initialize logging for Flask application.

    Sets up request correlation IDs and context for Flask requests.

    Args:
        app: Flask application instance

    Usage:
        from amoskys.common.logging import init_flask_logging

        app = Flask(__name__)
        init_flask_logging(app)
    """
    from flask import g, request

    @app.before_request
    def before_request():
        """Set up request context before each request."""
        # Get or generate correlation ID
        correlation_id = (
            request.headers.get("X-Correlation-ID")
            or request.headers.get("X-Request-ID")
            or generate_correlation_id()
        )
        set_correlation_id(correlation_id)

        # Store in Flask's g for access in templates/responses
        g.correlation_id = correlation_id
        g.request_start_time = time.perf_counter()

        # Set request context
        set_request_context(
            {
                "method": request.method,
                "path": request.path,
                "remote_addr": request.remote_addr,
                "user_agent": request.headers.get("User-Agent", "unknown")[:100],
            }
        )

    @app.after_request
    def after_request(response):
        """Log request completion and add correlation ID header."""
        # Add correlation ID to response headers
        correlation_id = get_correlation_id()
        if correlation_id:
            response.headers["X-Correlation-ID"] = correlation_id

        # Log request completion
        duration = time.perf_counter() - getattr(g, "request_start_time", 0)
        logger = get_logger("amoskys.http")
        logger.info(
            f"{request.method} {request.path} -> {response.status_code}",
            status_code=response.status_code,
            duration_seconds=duration,
            content_length=response.content_length,
        )

        return response

    @app.teardown_request
    def teardown_request(exception=None):
        """Clean up request context."""
        if exception:
            logger = get_logger("amoskys.http")
            logger.error(
                f"Request failed: {exception}",
                error_type=type(exception).__name__,
                error_message=str(exception),
            )
        clear_request_context()
