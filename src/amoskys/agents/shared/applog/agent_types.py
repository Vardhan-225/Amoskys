"""AppLog Agent Types - Normalized representation of application log entries.

This module provides the core data structures for application log events,
normalized from various sources (nginx, apache, syslog, journald).

Design:
    - Platform-agnostic normalized format
    - All optional fields handle varying source richness
    - Supports web server access logs, syslog, and journald
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional


@dataclass
class LogEntry:
    """Normalized application log entry.

    This is the canonical format passed to micro-probes for analysis.
    Collectors parse platform-specific log files into this format.

    Attributes:
        timestamp: When the log entry was generated
        source: Log source identifier (nginx, apache, syslog, journald)
        level: Log level (ERROR, WARNING, INFO, DEBUG)
        message: Raw log message text
        file_path: Path to the log file this entry came from
        line_number: Line number in the log file (if applicable)
        process_name: Name of the process that generated the entry
        pid: Process ID
        remote_ip: Remote IP address (for web server logs)
        http_method: HTTP method (GET, POST, etc.)
        http_path: HTTP request path
        http_status: HTTP response status code
        user_agent: HTTP User-Agent header value
    """

    timestamp: datetime
    source: str  # "nginx", "apache", "syslog", "journald"
    level: str  # "ERROR", "WARNING", "INFO", "DEBUG"
    message: str
    file_path: str
    line_number: Optional[int] = None
    process_name: Optional[str] = None
    pid: Optional[int] = None
    remote_ip: Optional[str] = None
    http_method: Optional[str] = None
    http_path: Optional[str] = None
    http_status: Optional[int] = None
    user_agent: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "level": self.level,
            "message": self.message,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "process_name": self.process_name,
            "pid": self.pid,
            "remote_ip": self.remote_ip,
            "http_method": self.http_method,
            "http_path": self.http_path,
            "http_status": self.http_status,
            "user_agent": self.user_agent,
        }


# =============================================================================
# Log Source Constants
# =============================================================================

# Known web server log sources
WEB_SOURCES = frozenset({"nginx", "apache"})

# Known system log sources
SYSTEM_SOURCES = frozenset({"syslog", "journald", "auth", "kern"})

# Error levels (severity ordering)
LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")


# =============================================================================
# Exports
# =============================================================================

__all__ = [
    "LogEntry",
    "LOG_LEVELS",
    "SYSTEM_SOURCES",
    "WEB_SOURCES",
]
