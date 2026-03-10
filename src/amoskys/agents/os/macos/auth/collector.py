"""macOS Auth Collector -- Unified Logging auth event extraction.

Queries macOS Unified Logging via ``log show --predicate`` to capture
authentication events from sshd, sudo, loginwindow, and screensaverengine.

Output keys for ProbeContext.shared_data:
    auth_events: List[AuthEvent] -- parsed auth events
    event_count: int -- total events collected
    collection_time_ms: float -- wall-clock collection duration
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# AuthEvent dataclass
# ---------------------------------------------------------------------------


@dataclass
class AuthEvent:
    """Single parsed authentication event from Unified Logging."""

    timestamp: datetime
    process: str  # sshd, sudo, loginwindow, screensaverengine, security
    message: str  # Raw log message
    category: str  # ssh, sudo, login, screensaver
    source_ip: Optional[str] = None
    username: Optional[str] = None
    event_type: str = ""  # success, failure, attempt, unlock, lock


# ---------------------------------------------------------------------------
# Category mapping
# ---------------------------------------------------------------------------

_PROCESS_CATEGORY = {
    "sshd": "ssh",
    "sudo": "sudo",
    "loginwindow": "login",
    "screensaverengine": "screensaver",
    "security": "keychain",
}

# ---------------------------------------------------------------------------
# Regex patterns for field extraction
# ---------------------------------------------------------------------------

# SSH: "Failed password for <user> from <ip> port <port>"
_SSH_FAILED_RE = re.compile(
    r"(?:Failed|Invalid)\s+(?:password|publickey)\s+for\s+(?:invalid\s+user\s+)?(\S+)\s+from\s+(\S+)"
)
# SSH: "Accepted password for <user> from <ip> port <port>"
_SSH_ACCEPTED_RE = re.compile(r"Accepted\s+\S+\s+for\s+(\S+)\s+from\s+(\S+)")
# SSH: "Connection from <ip>"
_SSH_CONNECTION_RE = re.compile(r"Connection\s+from\s+(\S+)")

# sudo: "<user> : TTY=... ; PWD=... ; USER=<target_user> ; COMMAND=..."
_SUDO_USER_RE = re.compile(r"^\s*(\S+)\s*:")
# sudo failure: "authentication failure"
_SUDO_FAILURE_RE = re.compile(r"authentication\s+failure|incorrect\s+password", re.I)

# loginwindow username extraction
_LOGIN_USER_RE = re.compile(r"user\s+(\S+)", re.I)


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------


class MacOSAuthCollector:
    """Collects auth events from macOS Unified Logging.

    Uses ``log show --predicate`` with JSON output to extract events from
    sshd, sudo, loginwindow, and screensaverengine within a rolling time
    window.

    Args:
        window_seconds: How far back to look (default 30s).
        device_id: Device identifier for correlation.
    """

    # Predicates targeting auth-relevant processes
    _PREDICATES: List[str] = [
        'process == "sshd"',
        'process == "sudo"',
        'process == "loginwindow"',
        'process == "screensaverengine"',
    ]

    def __init__(self, window_seconds: int = 30, device_id: str = "") -> None:
        self.window_seconds = window_seconds
        self.device_id = device_id or _get_hostname()

    def collect(self) -> Dict[str, Any]:
        """Run log show for each predicate and parse results.

        Returns:
            Dict for ProbeContext.shared_data with keys:
                auth_events, event_count, collection_time_ms
        """
        start = time.monotonic()
        all_events: List[AuthEvent] = []

        for predicate in self._PREDICATES:
            raw_entries = self._query_log(predicate)
            for entry in raw_entries:
                parsed = self._parse_entry(entry)
                if parsed is not None:
                    all_events.append(parsed)

        # Sort by timestamp
        all_events.sort(key=lambda e: e.timestamp)

        elapsed_ms = (time.monotonic() - start) * 1000

        logger.debug(
            "MacOSAuthCollector: %d events in %.1fms (window=%ds)",
            len(all_events),
            elapsed_ms,
            self.window_seconds,
        )

        return {
            "auth_events": all_events,
            "event_count": len(all_events),
            "collection_time_ms": round(elapsed_ms, 2),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _query_log(self, predicate: str) -> List[Dict[str, Any]]:
        """Execute ``log show`` and return parsed JSON entries."""
        cmd = [
            "log",
            "show",
            "--predicate",
            predicate,
            "--last",
            f"{self.window_seconds}s",
            "--style",
            "json",
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15,
            )

            if result.returncode != 0:
                logger.debug(
                    "log show returned %d for predicate %r: %s",
                    result.returncode,
                    predicate,
                    result.stderr.strip(),
                )
                return []

            stdout = result.stdout.strip()
            if not stdout:
                return []

            entries = json.loads(stdout)
            if isinstance(entries, list):
                return entries
            return []

        except json.JSONDecodeError as exc:
            logger.warning("JSON parse error from log show: %s", exc)
            return []
        except subprocess.TimeoutExpired:
            logger.warning("log show timed out for predicate: %s", predicate)
            return []
        except FileNotFoundError:
            logger.error("'log' command not found -- not running on macOS?")
            return []
        except Exception as exc:
            logger.error("log show failed: %s", exc)
            return []

    # Internal macOS directory services noise from sudo — NOT actual auth events.
    # A single `sudo ls /` generates 30+ log entries for group/user lookups.
    _SUDO_NOISE_PATTERNS = frozenset(
        {
            "retrieve user by id",
            "retrieve user by name",
            "retrieve group by id",
            "retrieve group by name",
            "reading config",
            "using original path",
            "performance impact",
            "too many groups requested",
            "resolve user group list",
        }
    )

    def _parse_entry(self, entry: Dict[str, Any]) -> Optional[AuthEvent]:
        """Parse a single JSON log entry into an AuthEvent."""
        process_name = entry.get("processImagePath", "")
        if "/" in process_name:
            process_name = process_name.rsplit("/", 1)[-1]

        # Also accept process name from the "process" field
        if not process_name:
            process_name = entry.get("process", "")

        category = _PROCESS_CATEGORY.get(process_name.lower(), "unknown")
        if category == "unknown":
            return None

        # Parse timestamp
        ts_str = entry.get("timestamp", "")
        timestamp = _parse_timestamp(ts_str)

        message = entry.get("eventMessage", "") or ""

        # Filter out internal macOS directory services noise from sudo.
        # A single `sudo ls /` generates 30+ group/user lookup log entries
        # that are NOT actual auth events.
        if category == "sudo":
            msg_lower = message.lower()
            if any(noise in msg_lower for noise in self._SUDO_NOISE_PATTERNS):
                return None

        # Extract fields based on process
        source_ip: Optional[str] = None
        username: Optional[str] = None
        event_type = "attempt"

        if category == "ssh":
            source_ip, username, event_type = self._parse_ssh(message)
        elif category == "sudo":
            username, event_type = self._parse_sudo(message)
        elif category == "login":
            username, event_type = self._parse_login(message)
        elif category == "screensaver":
            event_type = self._parse_screensaver(message)

        return AuthEvent(
            timestamp=timestamp,
            process=process_name,
            message=message,
            category=category,
            source_ip=source_ip,
            username=username,
            event_type=event_type,
        )

    @staticmethod
    def _parse_ssh(message: str) -> tuple[Optional[str], Optional[str], str]:
        """Extract source_ip, username, event_type from SSH log message."""
        # Failed authentication
        m = _SSH_FAILED_RE.search(message)
        if m:
            return m.group(2), m.group(1), "failure"

        # Successful authentication
        m = _SSH_ACCEPTED_RE.search(message)
        if m:
            return m.group(2), m.group(1), "success"

        # Connection attempt (no auth yet)
        m = _SSH_CONNECTION_RE.search(message)
        if m:
            return m.group(1), None, "attempt"

        return None, None, "attempt"

    @staticmethod
    def _parse_sudo(message: str) -> tuple[Optional[str], str]:
        """Extract username, event_type from sudo log message."""
        username = None
        m = _SUDO_USER_RE.search(message)
        if m:
            username = m.group(1)

        if _SUDO_FAILURE_RE.search(message):
            return username, "failure"

        return username, "success"

    @staticmethod
    def _parse_login(message: str) -> tuple[Optional[str], str]:
        """Extract username, event_type from loginwindow message."""
        username = None
        m = _LOGIN_USER_RE.search(message)
        if m:
            username = m.group(1)

        msg_lower = message.lower()
        if "failed" in msg_lower or "denied" in msg_lower:
            return username, "failure"
        if "logout" in msg_lower:
            return username, "logout"
        if "login" in msg_lower or "authenticated" in msg_lower:
            return username, "success"

        return username, "attempt"

    @staticmethod
    def _parse_screensaver(message: str) -> str:
        """Determine screensaver event type."""
        msg_lower = message.lower()
        if "unlock" in msg_lower or "authenticated" in msg_lower:
            return "unlock"
        if "lock" in msg_lower or "activate" in msg_lower:
            return "lock"
        return "attempt"


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def _parse_timestamp(ts_str: str) -> datetime:
    """Parse macOS Unified Logging timestamp string."""
    if not ts_str:
        return datetime.now(timezone.utc)
    try:
        # macOS log show JSON format: "2024-01-15 10:30:45.123456-0800"
        # or ISO-like variants
        for fmt in (
            "%Y-%m-%d %H:%M:%S.%f%z",
            "%Y-%m-%d %H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S%z",
        ):
            try:
                return datetime.strptime(ts_str, fmt)
            except ValueError:
                continue
        # Fallback: strip microseconds and timezone
        return datetime.fromisoformat(ts_str.replace(" ", "T"))
    except Exception:
        return datetime.now(timezone.utc)


def _get_hostname() -> str:
    import socket

    return socket.gethostname()
