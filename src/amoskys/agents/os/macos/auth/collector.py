"""macOS Auth Collector — Unified Logging auth event extraction.

Queries macOS Unified Logging via ``log show --predicate`` to capture
authentication and authorization events from:
    1. authd          — macOS authorization daemon (right grants/denials)
    2. TCC (tccd)     — Transparency, Consent, Control permission decisions
    3. SecurityAgent  — Password dialog prompts
    4. sshd           — SSH authentication
    5. sudo           — Privilege escalation
    6. loginwindow    — Login/logout/lock/unlock events
    7. screensaverengine — Screen lock events

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
    """Single parsed authentication/authorization event from Unified Logging."""

    timestamp: datetime
    process: str  # authd, tccd, sshd, sudo, loginwindow, SecurityAgent
    message: str  # Raw log message
    category: str  # authz, tcc, ssh, sudo, login, screensaver, keychain
    event_type: str = ""  # success, failure, attempt, grant, deny, request
    source_ip: Optional[str] = None
    username: Optional[str] = None
    # Structured fields from specific sources
    right: Optional[str] = None  # authorization right (authd)
    client_exe: Optional[str] = None  # requesting process path
    client_pid: Optional[int] = None  # requesting process PID
    service: Optional[str] = None  # TCC service name (kTCCServiceCamera etc.)
    decision: Optional[str] = None  # granted, denied, preflight


# ---------------------------------------------------------------------------
# Category mapping
# ---------------------------------------------------------------------------

_PROCESS_CATEGORY = {
    "sshd": "ssh",
    "sudo": "sudo",
    "loginwindow": "login",
    "screensaverengine": "screensaver",
    "security": "keychain",
    "authd": "authz",
    "tccd": "tcc",
    "SecurityAgent": "password_prompt",
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
_SUDO_COMMAND_RE = re.compile(r"COMMAND=(.+)$")
# sudo failure: "authentication failure"
_SUDO_FAILURE_RE = re.compile(r"authentication\s+failure|incorrect\s+password", re.I)

# loginwindow username extraction
_LOGIN_USER_RE = re.compile(r"user\s+(\S+)", re.I)

# authd: "Succeeded authorizing right '<right>' by client '<exe>' [<pid>]"
_AUTHD_SUCCEED_RE = re.compile(
    r"Succeeded\s+authorizing\s+right\s+'([^']+)'\s+by\s+client\s+'([^']+)'\s+\[(\d+)\]"
)
# authd: "Failed to authorize right '<right>' by client '<exe>' [<pid>]"
_AUTHD_FAILED_RE = re.compile(
    r"Failed\s+to\s+authorize\s+right\s+'([^']+)'\s+by\s+client\s+'([^']+)'\s+\[(\d+)\]"
)

# TCC: "Granting TCCDProcess: identifier=..., pid=..., binary_path=..."
# Same fields as AUTHREQ_ATTRIBUTION — extracted via _TCC_ATTRIB_RE.
_TCC_GRANT_PREFIX_RE = re.compile(r"Granting\s+TCCDProcess:")
_TCC_GRANT_SERVICE_RE = re.compile(r"access\s+to\s+(kTCCService\w+|\S+)")

# TCC: "REQUEST: tccd_uid=..., sender_pid=..., function=..., msgID=..."
_TCC_SENDER_PID_RE = re.compile(r"sender_pid=(\d+)")
_TCC_FUNCTION_RE = re.compile(r"function=([\w]+)")

# TCC: any line containing "service=kTCCServiceXxx"
_TCC_SERVICE_RE = re.compile(r"service=(kTCCService\w+)")

# TCC: identifier + pid + binary_path tuple — appears in BOTH AUTHREQ_ATTRIBUTION
# and Granting lines. Used as the canonical client extractor.
_TCC_ATTRIB_RE = re.compile(
    r"identifier=([^,]+),\s+pid=(\d+).*?binary_path=([^\s,}]+)"
)
# Fallback: identifier + pid only (when binary_path is private/redacted)
_TCC_IDENT_PID_RE = re.compile(r"identifier=([^,]+),\s+pid=(\d+)")


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------


def _classify_tcc_decision(message: str) -> Optional[str]:
    """Classify a TCC message into a decision type.

    We only classify lines that carry structured client attribution
    (Granting, AUTHREQ_ATTRIBUTION). REQUEST/RESULT/CTX/REPLY lines are
    skipped — they're metadata for the same decision and don't include
    the client binary path or identifier we need for the dashboard.
    """
    if "Granting" in message:
        return "granted"
    if "AUTHREQ_ATTRIBUTION" in message:
        # Attribution lines accompany every decision; classify by service
        # context but treat as observed-access since we have full client info.
        return "evaluated"
    return None  # Skip REQUEST, AUTHREQ_RESULT, AUTHREQ_CTX, REPLY


class MacOSAuthCollector:
    """Collects auth/authz events from macOS Unified Logging.

    Covers 7 macOS security-relevant processes. Each predicate targets
    a distinct authentication or authorization source.

    Args:
        window_seconds: How far back to look (default 30s).
        device_id: Device identifier for correlation.
    """

    # Predicates targeting auth-relevant processes — ordered by priority
    _PREDICATES: List[tuple] = [
        # (predicate, category_hint)
        ('subsystem == "com.apple.Authorization" AND category == "authd"', "authz"),
        ('subsystem == "com.apple.TCC" AND category == "access"', "tcc"),
        ('process == "SecurityAgent"', "password_prompt"),
        ('process == "sshd"', "ssh"),
        ('process == "sudo"', "sudo"),
        ('process == "loginwindow" AND (eventMessage CONTAINS "login" OR eventMessage CONTAINS "logout" OR eventMessage CONTAINS "unlock" OR eventMessage CONTAINS "authenticated" OR eventMessage CONTAINS "denied")', "login"),
        ('process == "screensaverengine" AND (eventMessage CONTAINS "unlock" OR eventMessage CONTAINS "lock" OR eventMessage CONTAINS "authenticated")', "screensaver"),
    ]

    # Internal macOS directory services noise from sudo — NOT actual auth events.
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

    # TCC noise patterns to filter
    _TCC_NOISE_PATTERNS = frozenset(
        {
            "sandbox extension",
            "Failed to issue generic",
        }
    )

    def __init__(self, window_seconds: int = 30, device_id: str = "") -> None:
        self.window_seconds = window_seconds
        self.device_id = device_id or _get_hostname()

    def collect(self) -> Dict[str, Any]:
        """Run log show for each predicate and parse results."""
        start = time.monotonic()
        all_events: List[AuthEvent] = []

        for predicate, category_hint in self._PREDICATES:
            raw_entries = self._query_log(predicate)
            for entry in raw_entries:
                parsed = self._parse_entry(entry, category_hint)
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
            "/usr/bin/log",
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
                    "log show returned %d for predicate %r",
                    result.returncode,
                    predicate[:60],
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
            logger.warning("log show timed out for predicate: %s", predicate[:60])
            return []
        except FileNotFoundError:
            logger.error("'log' command not found -- not running on macOS?")
            return []
        except Exception as exc:
            logger.error("log show failed: %s", exc)
            return []

    def _parse_entry(
        self, entry: Dict[str, Any], category_hint: str
    ) -> Optional[AuthEvent]:
        """Parse a single JSON log entry into an AuthEvent."""
        process_name = entry.get("processImagePath", "")
        if "/" in process_name:
            process_name = process_name.rsplit("/", 1)[-1]
        if not process_name:
            process_name = entry.get("process", "")

        category = _PROCESS_CATEGORY.get(process_name, category_hint)

        # Parse timestamp
        ts_str = entry.get("timestamp", "")
        timestamp = _parse_timestamp(ts_str)

        message = entry.get("eventMessage", "") or ""
        pid = entry.get("processID")

        # ── authd: authorization right decisions ──
        if category == "authz":
            return self._parse_authd(timestamp, process_name, message, pid)

        # ── TCC: permission decisions ──
        if category == "tcc":
            return self._parse_tcc(timestamp, process_name, message, pid)

        # ── SecurityAgent: password prompts ──
        if category == "password_prompt":
            return self._parse_security_agent(timestamp, process_name, message, pid)

        # ── SSH ──
        if category == "ssh":
            source_ip, username, event_type = self._parse_ssh(message)
            return AuthEvent(
                timestamp=timestamp,
                process=process_name,
                message=message,
                category=category,
                source_ip=source_ip,
                username=username,
                event_type=event_type,
                client_pid=pid,
            )

        # ── sudo ──
        if category == "sudo":
            msg_lower = message.lower()
            if any(noise in msg_lower for noise in self._SUDO_NOISE_PATTERNS):
                return None
            username, event_type = self._parse_sudo(message)
            return AuthEvent(
                timestamp=timestamp,
                process=process_name,
                message=message,
                category=category,
                username=username,
                event_type=event_type,
                client_pid=pid,
            )

        # ── loginwindow ──
        if category == "login":
            username, event_type = self._parse_login(message)
            return AuthEvent(
                timestamp=timestamp,
                process=process_name,
                message=message,
                category=category,
                username=username,
                event_type=event_type,
                client_pid=pid,
            )

        # ── screensaver ──
        if category == "screensaver":
            event_type = self._parse_screensaver(message)
            return AuthEvent(
                timestamp=timestamp,
                process=process_name,
                message=message,
                category=category,
                event_type=event_type,
                client_pid=pid,
            )

        return None

    # ── authd parser ──

    def _parse_authd(
        self, timestamp: datetime, process: str, message: str, pid: Optional[int]
    ) -> Optional[AuthEvent]:
        """Parse authd authorization decision."""
        # Skip cert/signature verification noise
        if message.startswith("SecKey") or message.startswith("SecTrust"):
            return None
        if "activating connection" in message or "invalidated" in message:
            return None

        m = _AUTHD_SUCCEED_RE.search(message)
        if m:
            return AuthEvent(
                timestamp=timestamp,
                process=process,
                message=message,
                category="authz",
                event_type="grant",
                right=m.group(1),
                client_exe=m.group(2),
                client_pid=int(m.group(3)),
            )

        m = _AUTHD_FAILED_RE.search(message)
        if m:
            return AuthEvent(
                timestamp=timestamp,
                process=process,
                message=message,
                category="authz",
                event_type="deny",
                right=m.group(1),
                client_exe=m.group(2),
                client_pid=int(m.group(3)),
            )

        # Any other authd message with "authoriz" keyword
        if "authoriz" in message.lower():
            return AuthEvent(
                timestamp=timestamp,
                process=process,
                message=message,
                category="authz",
                event_type="attempt",
                client_pid=pid,
            )

        return None

    # ── TCC parser ──

    def _parse_tcc(
        self, timestamp: datetime, process: str, message: str, pid: Optional[int]
    ) -> Optional[AuthEvent]:
        """Parse TCC permission decision."""
        if any(noise in message for noise in self._TCC_NOISE_PATTERNS):
            return None

        fields = self._extract_tcc_fields(message)
        if not fields:
            return None

        return AuthEvent(
            timestamp=timestamp,
            process=process,
            message=message,
            category="tcc",
            event_type=fields["decision"],
            service=fields.get("service"),
            client_exe=fields.get("client_exe"),
            client_pid=fields.get("client_pid"),
            decision=fields["decision"],
        )

    @staticmethod
    def _extract_tcc_fields(message: str) -> Optional[Dict[str, Any]]:
        """Extract structured fields from a TCC log message.

        TCC emits 5 line types per request — we extract whatever each
        contains rather than bailing when one field is missing:

        - REQUEST: sender_pid, function (no service/exe yet)
        - AUTHREQ_CTX: service (no pid/exe yet)
        - AUTHREQ_ATTRIBUTION: identifier, pid, binary_path (full client info)
        - Granting: identifier, pid, binary_path + "access to <service>"
        - AUTHREQ_RESULT: authValue=N (no fields, just decision)
        """
        decision = _classify_tcc_decision(message)
        if not decision:
            return None

        # Extract service from any line type
        service = None
        sm = _TCC_SERVICE_RE.search(message)
        if sm:
            service = sm.group(1)
        else:
            gm = _TCC_GRANT_SERVICE_RE.search(message)
            if gm and decision == "granted":
                service = gm.group(1)

        # Extract client exe + pid: try full attrib, fall back to identifier-only,
        # then to sender_pid (REQUEST lines only have this).
        client_exe = None
        client_pid = None

        am = _TCC_ATTRIB_RE.search(message)
        if am:
            client_pid = int(am.group(2))
            client_exe = am.group(3)
        else:
            im = _TCC_IDENT_PID_RE.search(message)
            if im:
                client_exe = im.group(1)  # bundle identifier as fallback
                client_pid = int(im.group(2))
            else:
                pm = _TCC_SENDER_PID_RE.search(message)
                if pm:
                    client_pid = int(pm.group(1))

        return {
            "decision": decision,
            "service": service,
            "client_exe": client_exe,
            "client_pid": client_pid,
        }

    # ── SecurityAgent parser ──

    @staticmethod
    def _parse_security_agent(
        timestamp: datetime, process: str, message: str, pid: Optional[int]
    ) -> Optional[AuthEvent]:
        """Parse SecurityAgent password dialog events."""
        event_type = "attempt"
        if "succeeded" in message.lower() or "authenticated" in message.lower():
            event_type = "success"
        elif "failed" in message.lower() or "denied" in message.lower():
            event_type = "failure"
        elif "cancel" in message.lower():
            event_type = "cancelled"

        return AuthEvent(
            timestamp=timestamp,
            process=process,
            message=message,
            category="password_prompt",
            event_type=event_type,
            client_pid=pid,
        )

    # ── SSH parser ──

    @staticmethod
    def _parse_ssh(message: str) -> tuple:
        """Extract source_ip, username, event_type from SSH log message."""
        m = _SSH_FAILED_RE.search(message)
        if m:
            return m.group(2), m.group(1), "failure"

        m = _SSH_ACCEPTED_RE.search(message)
        if m:
            return m.group(2), m.group(1), "success"

        m = _SSH_CONNECTION_RE.search(message)
        if m:
            return m.group(1), None, "attempt"

        return None, None, "attempt"

    # ── sudo parser ──

    @staticmethod
    def _parse_sudo(message: str) -> tuple:
        """Extract username, event_type from sudo log message."""
        username = None
        m = _SUDO_USER_RE.search(message)
        if m:
            username = m.group(1)

        if _SUDO_FAILURE_RE.search(message):
            return username, "failure"

        return username, "success"

    # ── loginwindow parser ──

    @staticmethod
    def _parse_login(message: str) -> tuple:
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
        if "unlock" in msg_lower or "authenticated" in msg_lower:
            return username, "unlock"
        if "login" in msg_lower:
            return username, "login"

        return username, "attempt"

    # ── screensaver parser ──

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
        return datetime.fromisoformat(ts_str.replace(" ", "T"))
    except Exception:
        return datetime.now(timezone.utc)


def _get_hostname() -> str:
    import socket

    return socket.gethostname()


# ═══════════════════════════════════════════════════════════════════
# Streaming Auth Collector — push-based via `log stream`
# ═══════════════════════════════════════════════════════════════════


class StreamingAuthCollector(MacOSAuthCollector):
    """Push-based auth collector using ``log stream`` instead of ``log show``.

    Runs a persistent ``log stream`` subprocess with a combined predicate
    covering all 7 auth sources. Events arrive in real-time via stdout.
    The agent's collect() drains the buffer — zero blind window.

    Falls back to polling MacOSAuthCollector if log stream fails.

    Architecture:
        Background thread: log stream --predicate '...' --style ndjson
            → parses each JSON line → buffers in deque
        Agent cycle: collect() → drains deque → returns events
    """

    # Combined predicate (OR of all 7 sources)
    _STREAM_PREDICATE = (
        '(subsystem == "com.apple.Authorization" AND category == "authd") OR '
        '(subsystem == "com.apple.TCC" AND category == "access") OR '
        'process == "SecurityAgent" OR '
        'process == "sshd" OR '
        'process == "sudo" OR '
        '(process == "loginwindow" AND (eventMessage CONTAINS "login" OR '
        'eventMessage CONTAINS "logout" OR eventMessage CONTAINS "unlock" OR '
        'eventMessage CONTAINS "authenticated" OR eventMessage CONTAINS "denied")) OR '
        '(process == "screensaverengine" AND (eventMessage CONTAINS "unlock" OR '
        'eventMessage CONTAINS "lock" OR eventMessage CONTAINS "authenticated"))'
    )

    def __init__(self, window_seconds: int = 10, device_id: str = "") -> None:
        super().__init__(window_seconds=window_seconds, device_id=device_id)
        import collections
        import threading

        self._buffer: collections.deque = collections.deque(maxlen=10000)
        self._stream_proc: Optional[subprocess.Popen] = None
        self._reader_thread: Optional[threading.Thread] = None
        self._shutdown = threading.Event()
        self._stream_alive = False
        self._start_stream()

    def _start_stream(self) -> None:
        """Launch log stream subprocess + reader thread."""
        import threading

        try:
            self._stream_proc = subprocess.Popen(
                [
                    "/usr/bin/log",
                    "stream",
                    "--predicate",
                    self._STREAM_PREDICATE,
                    "--style",
                    "ndjson",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,  # line-buffered
            )
            self._reader_thread = threading.Thread(
                target=self._read_loop, daemon=True, name="auth-stream-reader"
            )
            self._reader_thread.start()
            self._stream_alive = True
            logger.info(
                "StreamingAuthCollector: log stream started (pid=%d)",
                self._stream_proc.pid,
            )
        except Exception as e:
            logger.warning("StreamingAuthCollector: log stream failed, using polling: %s", e)
            self._stream_alive = False

    def _read_loop(self) -> None:
        """Background thread: read lines from log stream, parse, buffer."""
        proc = self._stream_proc
        if not proc or not proc.stdout:
            return

        for line in proc.stdout:
            if self._shutdown.is_set():
                break
            line = line.strip()
            if not line or line.startswith("Filtering"):
                continue

            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Determine category from process name
            process_name = entry.get("processImagePath", "")
            if "/" in process_name:
                process_name = process_name.rsplit("/", 1)[-1]
            if not process_name:
                process_name = entry.get("process", "")

            category = _PROCESS_CATEGORY.get(process_name, "unknown")

            parsed = self._parse_entry(entry, category)
            if parsed is not None:
                self._buffer.append(parsed)

        logger.info("StreamingAuthCollector: reader thread exiting")

    def collect(self) -> Dict[str, Any]:
        """Drain the event buffer. Zero blind window."""
        # If stream died, fall back to polling
        if not self._stream_alive or (
            self._stream_proc and self._stream_proc.poll() is not None
        ):
            if self._stream_alive:
                logger.warning("StreamingAuthCollector: stream died, falling back to polling")
                self._stream_alive = False
            return super().collect()

        start = time.monotonic()

        # Drain buffer
        events: List[AuthEvent] = []
        while self._buffer:
            try:
                events.append(self._buffer.popleft())
            except IndexError:
                break

        events.sort(key=lambda e: e.timestamp)
        elapsed_ms = (time.monotonic() - start) * 1000

        logger.debug(
            "StreamingAuthCollector: drained %d events in %.1fms (buffer remaining: %d)",
            len(events),
            elapsed_ms,
            len(self._buffer),
        )

        return {
            "auth_events": events,
            "event_count": len(events),
            "collection_time_ms": round(elapsed_ms, 2),
            "streaming": True,
        }

    def shutdown(self) -> None:
        """Stop the log stream subprocess."""
        self._shutdown.set()
        if self._stream_proc:
            try:
                self._stream_proc.terminate()
                self._stream_proc.wait(timeout=5)
            except Exception:
                try:
                    self._stream_proc.kill()
                except Exception:
                    pass
            logger.info("StreamingAuthCollector: stream stopped")
