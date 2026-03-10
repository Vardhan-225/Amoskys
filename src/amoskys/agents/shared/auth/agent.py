#!/usr/bin/env python3
"""AMOSKYS AuthGuard Agent - Micro-Probe Architecture.

This is the modernized authentication monitoring agent using the "swarm of eyes"
pattern. 7 micro-probes each watch one specific auth/privilege threat vector.

Probes:
    1. SSHPasswordSprayProbe - Low-and-slow across many users
    2. SSHGeoImpossibleTravelProbe - Geographic impossibility
    3. SudoElevationProbe - Privilege escalation patterns
    4. SudoSuspiciousCommandProbe - Dangerous sudo commands
    5. OffHoursLoginProbe - Access outside business hours
    6. MFABypassOrAnomalyProbe - MFA fatigue/bypass attempts
    7. AccountLockoutStormProbe - Mass lockout attacks

Note: SSHBruteForceProbe moved to protocol_collectors (canonical location).

MITRE ATT&CK Coverage:
    - T1110: Brute Force
    - T1110.003: Password Spraying
    - T1078: Valid Accounts
    - T1548: Abuse Elevation Control Mechanism
    - T1059: Command and Scripting Interpreter
    - T1621: Multi-Factor Authentication Request Generation

Usage:
    >>> agent = AuthGuardAgent()
    >>> agent.run_forever()
"""

from __future__ import annotations

import json
import logging
import platform
import re
import socket
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import grpc

from amoskys.agents.common.base import HardenedAgentBase, ValidationResult
from amoskys.agents.common.probes import MicroProbeAgentMixin, TelemetryEvent
from amoskys.agents.common.queue_adapter import LocalQueueAdapter
from amoskys.agents.shared.auth.probes import AuthEvent, create_auth_probes
from amoskys.config import get_config
from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2
from amoskys.proto import universal_telemetry_pb2_grpc as universal_pbrpc

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("AuthGuardAgent")

config = get_config()
EVENTBUS_ADDRESS = config.agent.bus_address
CERT_DIR = config.agent.cert_dir
QUEUE_PATH = getattr(config.agent, "auth_queue_path", "data/queue/auth.db")

# Tunables
AUTH_WINDOW_SECONDS = 900  # 15 minutes


# =============================================================================
# EventBus Publisher
# =============================================================================


class EventBusPublisher:
    """Wrapper for EventBus gRPC client."""

    def __init__(self, address: str, cert_dir: str):
        self.address = address
        self.cert_dir = cert_dir
        self._channel = None
        self._stub = None

    def _ensure_channel(self):
        """Create gRPC channel if needed."""
        if self._channel is None:
            try:
                with open(f"{self.cert_dir}/ca.crt", "rb") as f:
                    ca_cert = f.read()
                with open(f"{self.cert_dir}/agent.crt", "rb") as f:
                    client_cert = f.read()
                with open(f"{self.cert_dir}/agent.key", "rb") as f:
                    client_key = f.read()

                credentials = grpc.ssl_channel_credentials(
                    root_certificates=ca_cert,
                    private_key=client_key,
                    certificate_chain=client_cert,
                )
                self._channel = grpc.secure_channel(self.address, credentials)
                self._stub = universal_pbrpc.UniversalEventBusStub(self._channel)
                logger.info("Created secure gRPC channel with mTLS")
            except FileNotFoundError as e:
                raise RuntimeError(f"Certificate not found: {e}")
            except Exception as e:
                raise RuntimeError(f"Failed to create gRPC channel: {e}")

    def publish(self, events: list) -> None:
        """Publish events to EventBus."""
        self._ensure_channel()

        for event in events:
            # Already-wrapped envelopes (e.g. from drain path) go directly
            if isinstance(event, telemetry_pb2.UniversalEnvelope):
                envelope = event
            else:
                timestamp_ns = int(time.time() * 1e9)
                idempotency_key = f"{event.device_id}_{timestamp_ns}"
                envelope = telemetry_pb2.UniversalEnvelope(
                    version="v1",
                    ts_ns=timestamp_ns,
                    idempotency_key=idempotency_key,
                    device_telemetry=event,
                    priority="NORMAL",
                    requires_acknowledgment=True,
                    schema_version=1,
                )

            ack = self._stub.PublishTelemetry(envelope, timeout=5.0)

            if ack.status != telemetry_pb2.UniversalAck.OK:
                raise Exception(f"EventBus returned status: {ack.status}")

    def close(self):
        """Close gRPC channel."""
        if self._channel:
            self._channel.close()
            self._channel = None
            self._stub = None


# =============================================================================
# Platform-Specific Auth Log Collectors
# =============================================================================


class AuthLogCollector:
    """Base class for platform-specific auth log collection."""

    def collect(self) -> List[AuthEvent]:
        """Collect auth events from system.

        Returns:
            List of AuthEvent objects
        """
        raise NotImplementedError


class LinuxAuthLogCollector(AuthLogCollector):
    """Collects authentication events on Linux from /var/log/auth.log."""

    def __init__(self):
        self.log_path = "/var/log/auth.log"
        self.last_position = 0

    def collect(self) -> List[AuthEvent]:
        """Collect auth events from Linux auth.log."""
        events = []

        try:
            if not Path(self.log_path).exists():
                logger.debug(f"Auth log not found: {self.log_path}")
                return events

            with open(self.log_path, "r") as f:
                # Seek to last position
                f.seek(self.last_position)
                new_lines = f.readlines()
                self.last_position = f.tell()

                # Parse each line
                for line in new_lines:
                    event = self._parse_log_line(line)
                    if event:
                        events.append(event)

        except Exception as e:
            logger.error(f"Failed to collect auth logs: {e}")

        return events

    def _parse_log_line(self, line: str) -> Optional[AuthEvent]:
        """Parse a single auth.log line into AuthEvent."""
        try:
            # SSH login attempts
            # Example: "Jan  5 10:15:23 hostname sshd[1234]: Failed password for user from 1.2.3.4 port 22 ssh2"
            ssh_fail = re.search(
                r"sshd\[\d+\]: Failed password for (\S+) from ([\d.]+)",
                line,
            )
            if ssh_fail:
                username = ssh_fail.group(1)
                source_ip = ssh_fail.group(2)
                return AuthEvent(
                    timestamp_ns=int(time.time() * 1e9),  # Approximate
                    event_type="SSH_LOGIN",
                    status="FAILURE",
                    username=username,
                    source_ip=source_ip,
                    reason="invalid password",
                )

            # SSH successful login
            ssh_success = re.search(
                r"sshd\[\d+\]: Accepted password for (\S+) from ([\d.]+)",
                line,
            )
            if ssh_success:
                username = ssh_success.group(1)
                source_ip = ssh_success.group(2)
                return AuthEvent(
                    timestamp_ns=int(time.time() * 1e9),
                    event_type="SSH_LOGIN",
                    status="SUCCESS",
                    username=username,
                    source_ip=source_ip,
                )

            # Sudo execution
            # Example: "Jan  5 10:15:23 hostname sudo: user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/bin/bash"
            sudo_exec = re.search(
                r"sudo:\s+(\S+)\s+:.*COMMAND=(.+)$",
                line,
            )
            if sudo_exec:
                username = sudo_exec.group(1)
                command = sudo_exec.group(2).strip()
                return AuthEvent(
                    timestamp_ns=int(time.time() * 1e9),
                    event_type="SUDO_EXEC",
                    status="SUCCESS",
                    username=username,
                    command=command,
                )

            # Account locked
            account_locked = re.search(
                r"Account (\S+) locked",
                line,
            )
            if account_locked:
                username = account_locked.group(1)
                return AuthEvent(
                    timestamp_ns=int(time.time() * 1e9),
                    event_type="ACCOUNT_LOCKED",
                    status="FAILURE",
                    username=username,
                )

        except Exception as e:
            logger.debug(f"Failed to parse auth log line: {e}")

        return None


class MacOSAuthLogCollector(AuthLogCollector):
    """Collects authentication events on macOS via unified log + ``last``.

    Data sources (broadened from V1):
        1. **Unified log** — ``log show`` with a wide predicate covering:
           - ``sudo`` — privilege escalation & denied attempts
           - ``sshd`` — remote SSH login success/failure
           - ``loginwindow`` — console login, screen-lock/unlock
           - ``coreauthd`` / ``LocalAuthentication`` — biometric / password auth
           - ``SecurityAgent`` — authorisation dialogs
           - ``authd`` — the authorisation daemon itself
           - ``screensaver`` — screen-saver lock events
        2. **``last`` command** — session login/logout history (robust fallback
           that works even when unified log is noisy or private).

    Key fixes over V1:
        * JSON key is ``processImagePath``, **not** ``process``
        * ``--info`` flag added (many auth entries are Info-level)
        * Query window widened to 2 min with timestamp-based dedup
        * Actual macOS sudo format parsed:
          ``user : <reason> ; TTY=… ; PWD=… ; USER=… ; COMMAND=…``
        * New event types: ``SUDO_DENIED``, ``LOCAL_LOGIN``, ``SCREEN_LOCK``,
          ``SCREEN_UNLOCK``
    """

    # ── Unified-log predicate (much broader than V1) ────────────────────
    _LOG_PREDICATE = (
        '(process == "sudo"'
        ' OR process == "sshd"'
        ' OR process == "loginwindow"'
        ' OR process == "SecurityAgent"'
        ' OR process == "authd"'
        ' OR process == "screensaver"'
        ' OR process == "coreauthd"'
        ' OR subsystem == "com.apple.Authorization"'
        ' OR subsystem == "com.apple.LocalAuthentication"'
        ' OR subsystem == "com.apple.loginwindow.logging"'
        ")"
    )

    # Query window (2 min) — intentionally overlaps with 30 s cycle
    _QUERY_WINDOW = "2m"

    def __init__(self):
        self.last_timestamp: Optional[datetime] = None
        # Dedup: set of (processID, machTimestamp) seen within a sliding window
        self._seen_keys: set = set()
        self._seen_keys_max = 10_000
        # Track last 'last' parse position
        self._last_boot_time: Optional[str] = None

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    # Lockout synthesis: 5 failures in 5 min → synthesize ACCOUNT_LOCKED
    _LOCKOUT_FAILURE_THRESHOLD = 5
    _LOCKOUT_WINDOW_NS = 300 * int(1e9)  # 5 minutes in nanoseconds

    def collect(self) -> List[AuthEvent]:
        """Collect auth events from all macOS sources, deduplicated.

        Post-processes events to synthesize ACCOUNT_LOCKED from rapid
        SSH failures (macOS has no native lockout log message).
        """
        events: List[AuthEvent] = []

        # Source 1: Unified log (primary)
        events.extend(self._collect_unified_log())

        # Source 2: `last` command (login sessions – robust fallback)
        events.extend(self._collect_last())

        # Source 3 (synthetic): Synthesize ACCOUNT_LOCKED from rapid failures
        events.extend(self._synthesize_lockout_events(events))

        logger.debug(
            f"MacOSAuthLogCollector collected {len(events)} auth events "
            f"(dedup pool size: {len(self._seen_keys)})"
        )
        return events

    def _synthesize_lockout_events(self, events: List[AuthEvent]) -> List[AuthEvent]:
        """Synthesize ACCOUNT_LOCKED events from rapid SSH failures.

        macOS doesn't natively emit lockout messages. This heuristic
        flags accounts that have >=5 failures within a 5-minute window
        as effectively locked out.
        """
        from collections import defaultdict

        failures_by_user: Dict[str, List[int]] = defaultdict(list)
        already_locked: set = set()
        synthetic: List[AuthEvent] = []

        for ev in events:
            if ev.event_type == "SSH_LOGIN" and ev.status == "FAILURE":
                failures_by_user[ev.username].append(ev.timestamp_ns)

        for username, timestamps in failures_by_user.items():
            if len(timestamps) < self._LOCKOUT_FAILURE_THRESHOLD:
                continue
            timestamps.sort()
            # Sliding window check
            for i in range(len(timestamps) - self._LOCKOUT_FAILURE_THRESHOLD + 1):
                window_start = timestamps[i]
                window_end = timestamps[i + self._LOCKOUT_FAILURE_THRESHOLD - 1]
                if (
                    window_end - window_start <= self._LOCKOUT_WINDOW_NS
                    and username not in already_locked
                ):
                    already_locked.add(username)
                    # Find the source_ip from the last failure
                    src_ip = ""
                    for ev in events:
                        if (
                            ev.event_type == "SSH_LOGIN"
                            and ev.status == "FAILURE"
                            and ev.username == username
                        ):
                            src_ip = ev.source_ip
                    synthetic.append(
                        AuthEvent(
                            timestamp_ns=window_end,
                            event_type="ACCOUNT_LOCKED",
                            status="FAILURE",
                            username=username,
                            source_ip=src_ip,
                            reason=f"Synthesized: {self._LOCKOUT_FAILURE_THRESHOLD}+ "
                            f"failures in {self._LOCKOUT_WINDOW_NS // int(1e9)}s window",
                        )
                    )
                    break  # One lockout per user per cycle

        return synthetic

    # ------------------------------------------------------------------ #
    #  Source 1: Unified log                                               #
    # ------------------------------------------------------------------ #

    def _collect_unified_log(self) -> List[AuthEvent]:
        """Query unified log for auth events."""
        events: List[AuthEvent] = []

        try:
            cmd = [
                "log",
                "show",
                "--predicate",
                self._LOG_PREDICATE,
                "--last",
                self._QUERY_WINDOW,
                "--style",
                "json",
                "--info",  # capture Info-level entries (many auth events)
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15,
            )

            if result.returncode != 0:
                logger.debug(f"log show returned {result.returncode}")
                return events

            if not result.stdout or result.stdout.strip() in ("", "[]"):
                return events

            try:
                log_entries = json.loads(result.stdout)
            except json.JSONDecodeError:
                logger.debug("Failed to parse log show JSON output")
                return events

            for entry in log_entries:
                # ── Dedup by (processID, machTimestamp) ──────────────
                dedup_key = (
                    entry.get("processID", 0),
                    entry.get("machTimestamp", 0),
                )
                if dedup_key in self._seen_keys:
                    continue
                self._seen_keys.add(dedup_key)

                # Evict oldest when pool grows too large
                if len(self._seen_keys) > self._seen_keys_max:
                    self._seen_keys = set(
                        list(self._seen_keys)[self._seen_keys_max // 2 :]
                    )

                event = self._parse_unified_entry(entry)
                if event:
                    events.append(event)

        except subprocess.TimeoutExpired:
            logger.warning("Auth log collection timed out (15 s)")
        except Exception as e:
            logger.error(f"Failed to collect unified log: {e}")

        return events

    def _parse_unified_entry(self, entry: Dict) -> Optional[AuthEvent]:
        """Parse a single unified-log JSON entry into an AuthEvent.

        Key difference from V1: the JSON key for the process binary is
        ``processImagePath`` (e.g. ``/usr/bin/sudo``), **not** ``process``.
        """
        try:
            message = entry.get("eventMessage", "")
            if not message:
                return None

            timestamp_str = entry.get("timestamp", "")
            process_path = entry.get("processImagePath", "")
            process_name = process_path.rsplit("/", 1)[-1] if process_path else ""
            process_id = entry.get("processID", 0)

            # ── Parse timestamp ──────────────────────────────────────
            timestamp = datetime.now(timezone.utc)
            if timestamp_str:
                try:
                    # macOS format: "2026-02-17 17:17:13.534573-0600"
                    timestamp = datetime.fromisoformat(
                        timestamp_str.replace("Z", "+00:00")
                    )
                except ValueError:
                    pass
            timestamp_ns = int(timestamp.timestamp() * 1e9)

            # ── Process-specific parsing ─────────────────────────────

            # 1. SUDO events
            if process_name == "sudo":
                return self._parse_sudo_message(message, timestamp_ns, process_id)

            # 2. SSHD events
            if process_name == "sshd":
                return self._parse_sshd_message(message, timestamp_ns)

            # 3. loginwindow events (console login, screen lock/unlock)
            if process_name == "loginwindow":
                return self._parse_loginwindow_message(message, timestamp_ns)

            # 4. SecurityAgent (authorisation dialog events)
            if process_name == "SecurityAgent":
                return self._parse_security_agent_message(message, timestamp_ns)

            # 5. screensaver events
            if process_name in ("ScreenSaverEngine", "screensaver"):
                return self._parse_screensaver_message(message, timestamp_ns)

            # 6. coreauthd / LocalAuthentication
            if process_name == "coreauthd":
                return self._parse_coreauthd_message(message, timestamp_ns)

        except Exception as e:
            logger.debug(f"Failed to parse unified log entry: {e}")

        return None

    # ── Sudo parser ──────────────────────────────────────────────────────

    def _parse_sudo_message(
        self, message: str, timestamp_ns: int, _pid: int
    ) -> Optional[AuthEvent]:
        """Parse macOS sudo unified-log message.

        Actual macOS format:
            ``username : TTY=ttys015 ; PWD=/some/dir ; USER=root ; COMMAND=/bin/ls``
            ``username : a password is required ; TTY=... ; COMMAND=...``
            ``username : command not allowed ; TTY=... ; COMMAND=...``
        """
        # Skip noisy library messages (group lookups, config reads)
        if any(
            kw in message
            for kw in [
                "Retrieve User",
                "Retrieve Group",
                "Too many groups",
                "Performance impact",
                "Reading config",
                "Using original path",
            ]
        ):
            return None

        # Pattern: "user : <optional reason> ; TTY=… ; … ; COMMAND=…"
        sudo_match = re.match(
            r"^(\S+)\s+:\s+(.+?)(?:\s+;\s+TTY=(\S+))?(?:\s+;\s+PWD=(\S+))?"
            r"(?:\s+;\s+USER=(\S+))?(?:\s+;\s+COMMAND=(.+))?$",
            message,
        )
        if sudo_match:
            username = sudo_match.group(1)
            reason_or_info = sudo_match.group(2).strip()
            tty = sudo_match.group(3) or ""
            # groups 4 (PWD) and 5 (USER) captured but not stored on AuthEvent
            command = sudo_match.group(6) or ""

            # Determine status
            if "password is required" in reason_or_info:
                status = "FAILURE"
                event_type = "SUDO_DENIED"
                reason = "password required (non-interactive)"
            elif "command not allowed" in reason_or_info:
                status = "FAILURE"
                event_type = "SUDO_DENIED"
                reason = "command not allowed"
            elif "not allowed to run" in reason_or_info:
                status = "FAILURE"
                event_type = "SUDO_DENIED"
                reason = "user not allowed"
            elif "incorrect password" in reason_or_info.lower():
                status = "FAILURE"
                event_type = "SUDO_DENIED"
                reason = "incorrect password"
            elif command:
                status = "SUCCESS"
                event_type = "SUDO_EXEC"
                reason = ""
            else:
                # Some other sudo message — skip noise
                return None

            return AuthEvent(
                timestamp_ns=timestamp_ns,
                event_type=event_type,
                status=status,
                username=username,
                command=command.strip(),
                tty=tty,
                reason=reason,
            )

        return None

    # ── SSHD parser ──────────────────────────────────────────────────────

    def _parse_sshd_message(
        self, message: str, timestamp_ns: int
    ) -> Optional[AuthEvent]:
        """Parse sshd unified-log messages."""
        # Failed password
        match = re.search(
            r"Failed password for (?:invalid user )?(\S+) from ([\d.]+)", message
        )
        if match:
            return AuthEvent(
                timestamp_ns=timestamp_ns,
                event_type="SSH_LOGIN",
                status="FAILURE",
                username=match.group(1),
                source_ip=match.group(2),
                reason="invalid password",
            )

        # Accepted password
        match = re.search(r"Accepted password for (\S+) from ([\d.]+)", message)
        if match:
            return AuthEvent(
                timestamp_ns=timestamp_ns,
                event_type="SSH_LOGIN",
                status="SUCCESS",
                username=match.group(1),
                source_ip=match.group(2),
            )

        # Accepted publickey
        match = re.search(r"Accepted publickey for (\S+) from ([\d.]+)", message)
        if match:
            return AuthEvent(
                timestamp_ns=timestamp_ns,
                event_type="SSH_LOGIN",
                status="SUCCESS",
                username=match.group(1),
                source_ip=match.group(2),
                reason="publickey",
            )

        # Connection closed / disconnected
        match = re.search(r"Connection closed by ([\d.]+)", message)
        if match:
            return AuthEvent(
                timestamp_ns=timestamp_ns,
                event_type="SSH_DISCONNECT",
                status="SUCCESS",
                username="",
                source_ip=match.group(1),
            )

        return None

    # ── loginwindow parser ───────────────────────────────────────────────

    def _parse_loginwindow_message(
        self, message: str, timestamp_ns: int
    ) -> Optional[AuthEvent]:
        """Parse loginwindow messages for console login / screen events."""
        msg_lower = message.lower()

        # Screen lock events (SAC = Screen Assessment Context)
        if "sacshieldwindowshowing" in msg_lower and "true" in msg_lower:
            return AuthEvent(
                timestamp_ns=timestamp_ns,
                event_type="SCREEN_LOCK",
                status="SUCCESS",
                username="",
            )

        # Screen unlock
        if "sacshieldwindowshowing" in msg_lower and "false" in msg_lower:
            return AuthEvent(
                timestamp_ns=timestamp_ns,
                event_type="SCREEN_UNLOCK",
                status="SUCCESS",
                username="",
            )

        # Console login (USER_PROCESS)
        if "user_process" in msg_lower or "console login" in msg_lower:
            return AuthEvent(
                timestamp_ns=timestamp_ns,
                event_type="LOCAL_LOGIN",
                status="SUCCESS",
                username="",
                reason="console",
            )

        return None

    # ── SecurityAgent parser ─────────────────────────────────────────────

    def _parse_security_agent_message(
        self, message: str, timestamp_ns: int
    ) -> Optional[AuthEvent]:
        """Parse SecurityAgent messages (authorisation prompts).

        Maps to MFA event types so MFABypassOrAnomalyProbe can fire:
            - Authorization succeeded → MFA_SUCCESS (password factor)
            - Authorization failed → MFA_CHALLENGE (attempted factor)
        """
        msg_lower = message.lower()

        if "authorization" in msg_lower and "succeeded" in msg_lower:
            return AuthEvent(
                timestamp_ns=timestamp_ns,
                event_type="MFA_SUCCESS",
                status="SUCCESS",
                username="",
                reason="SecurityAgent authorization",
            )
        if "authorization" in msg_lower and "failed" in msg_lower:
            return AuthEvent(
                timestamp_ns=timestamp_ns,
                event_type="MFA_CHALLENGE",
                status="FAILURE",
                username="",
                reason="SecurityAgent authorization failed",
            )
        return None

    # ── screensaver parser ───────────────────────────────────────────────

    def _parse_screensaver_message(
        self, message: str, timestamp_ns: int
    ) -> Optional[AuthEvent]:
        """Parse screensaver events."""
        msg_lower = message.lower()
        if "lock" in msg_lower or "activat" in msg_lower:
            return AuthEvent(
                timestamp_ns=timestamp_ns,
                event_type="SCREEN_LOCK",
                status="SUCCESS",
                username="",
                reason="screensaver",
            )
        return None

    # ── coreauthd / LocalAuthentication parser ───────────────────────────

    def _parse_coreauthd_message(
        self, message: str, timestamp_ns: int
    ) -> Optional[AuthEvent]:
        """Parse coreauthd messages — biometric / password evaluation.

        Maps to MFA event types so MFABypassOrAnomalyProbe can fire:
            - Biometric success → MFA_SUCCESS (biometric factor)
            - Biometric failure → MFA_CHALLENGE (attempted factor)
        """
        # Only capture high-signal messages, not Context create/dealloc noise
        msg_lower = message.lower()

        if "evaluate" in msg_lower and "policy" in msg_lower:
            if "success" in msg_lower:
                return AuthEvent(
                    timestamp_ns=timestamp_ns,
                    event_type="MFA_SUCCESS",
                    status="SUCCESS",
                    username="",
                    reason="LocalAuthentication biometric success",
                )
            else:
                return AuthEvent(
                    timestamp_ns=timestamp_ns,
                    event_type="MFA_CHALLENGE",
                    status="FAILURE",
                    username="",
                    reason="LocalAuthentication biometric failure",
                )
        return None

    # ------------------------------------------------------------------ #
    #  Source 2: `last` command                                            #
    # ------------------------------------------------------------------ #

    def _collect_last(self) -> List[AuthEvent]:
        """Parse ``last`` for recent login sessions.

        Only returns events from the *current boot* that haven't been
        reported yet (tracked via dedup pool).
        """
        events: List[AuthEvent] = []
        try:
            result = subprocess.run(
                ["last", "-10"],  # last 10 entries
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                return events

            for line in result.stdout.splitlines():
                event = self._parse_last_line(line)
                if event:
                    events.append(event)

        except subprocess.TimeoutExpired:
            logger.debug("last command timed out")
        except Exception as e:
            logger.debug(f"Failed to collect from last: {e}")

        return events

    def _parse_last_line(self, line: str) -> Optional[AuthEvent]:
        """Parse a single ``last`` output line into an AuthEvent (or None)."""
        line = line.strip()
        if not line or line.startswith("wtmp"):
            return None

        parts = line.split()
        if len(parts) < 5:
            return None

        username = parts[0]
        tty = parts[1]

        # Skip reboot/shutdown meta-lines
        if username in ("reboot", "shutdown"):
            return None

        # Extract login start time string for dedup
        time_key = " ".join(parts[2:6]) if len(parts) >= 6 else line

        dedup_key = ("last", username, tty, time_key)
        if dedup_key in self._seen_keys:
            return None
        self._seen_keys.add(dedup_key)

        # Determine event type
        if tty == "console":
            event_type = "LOCAL_LOGIN"
        elif tty.startswith("ttys"):
            event_type = "TERMINAL_SESSION"
        else:
            event_type = "LOCAL_LOGIN"

        still_logged_in = "still logged in" in line

        return AuthEvent(
            timestamp_ns=int(time.time() * 1e9),
            event_type=event_type,
            status="SUCCESS",
            username=username,
            tty=tty,
            reason="still logged in" if still_logged_in else "completed",
        )


def get_auth_collector() -> AuthLogCollector:
    """Get platform-appropriate auth log collector."""
    system = platform.system()
    if system == "Linux":
        return LinuxAuthLogCollector()
    elif system == "Darwin":
        return MacOSAuthLogCollector()
    else:
        logger.warning(f"Unsupported platform: {system}")
        return LinuxAuthLogCollector()  # Default


# =============================================================================
# AuthGuard Agent
# =============================================================================


class AuthGuardAgent(MicroProbeAgentMixin, HardenedAgentBase):
    """Authentication security agent with micro-probe architecture.

    This agent hosts 8 micro-probes that each monitor a specific auth/privilege
    threat vector. The agent handles:
        - Auth log collection (platform-specific)
        - Probe lifecycle management
        - Event aggregation and publishing
        - Circuit breaker and retry logic
        - Offline queue management

    Probes are responsible only for detection - no networking or state
    management.
    """

    def __init__(
        self,
        collection_interval: float = 30.0,
        queue_path_override: Optional[str] = None,
        device_id_override: Optional[str] = None,
    ):
        """Initialize AuthGuard Agent.

        Args:
            collection_interval: Seconds between collection cycles
            queue_path_override: Optional override for local queue DB path
            device_id_override: Optional override for device ID
        """
        device_id = device_id_override or socket.gethostname()
        queue_path = queue_path_override or QUEUE_PATH

        # Create EventBus publisher
        publisher = EventBusPublisher(EVENTBUS_ADDRESS, CERT_DIR)

        # Create local queue
        Path(queue_path).parent.mkdir(parents=True, exist_ok=True)
        queue_adapter = LocalQueueAdapter(
            queue_path=queue_path,
            agent_name="auth",
            device_id=device_id,
            max_bytes=50 * 1024 * 1024,
            max_retries=10,
            signing_key_path=f"{CERT_DIR}/agent.ed25519",
        )

        # Initialize base classes
        super().__init__(
            agent_name="auth",
            device_id=device_id,
            collection_interval=collection_interval,
            eventbus_publisher=publisher,
            local_queue=queue_adapter,
        )

        # Platform-specific auth log collector
        self.auth_collector = get_auth_collector()

        # Lifetime counter for heartbeat COUNTER metric
        self._total_auth_events: int = 0

        # Register all auth probes
        self.register_probes(create_auth_probes())

        logger.info(f"AuthGuardAgent initialized with {len(self._probes)} probes")

    def setup(self) -> bool:
        """Initialize agent resources.

        Verifies:
            - Certificates exist
            - Auth log collector works
            - Probes initialize successfully

        Returns:
            True if setup succeeded
        """
        try:
            import os

            # Verify certificates (warn but don't fail — dev mode may lack certs)
            required_certs = ["ca.crt", "agent.crt", "agent.key"]
            for cert in required_certs:
                cert_path = f"{CERT_DIR}/{cert}"
                if not os.path.exists(cert_path):
                    logger.warning(
                        f"Certificate not found: {cert_path} (EventBus publishing will fail)"
                    )

            # Test auth log collector (reset dedup pool after test so first
            # real cycle still sees events)
            try:
                test_events = self.auth_collector.collect()
                logger.info(f"Auth collector test: {len(test_events)} events")
                pool = getattr(self.auth_collector, "_seen_keys", None)
                if pool is not None:
                    pool.clear()
            except Exception as e:
                logger.warning(f"Auth collector test failed: {e}")
                # Continue anyway - collector may work later

            # Setup probes
            if not self.setup_probes(collector_shared_data_keys=["auth_events"]):
                logger.error("No probes initialized successfully")
                return False

            logger.info("AuthGuardAgent setup complete")
            return True

        except Exception as e:
            logger.error(f"Setup failed: {e}")
            return False

    def collect_data(self) -> Sequence[Any]:
        """Collect auth events and run all probes.

        Returns:
            List of DeviceTelemetry protobuf messages
        """
        timestamp_ns = int(time.time() * 1e9)

        # Collect auth events
        auth_events = self.auth_collector.collect()
        self._total_auth_events += len(auth_events)
        logger.info(
            f"Collected {len(auth_events)} auth events (total: {self._total_auth_events})"
        )

        # Run probes against collected auth events
        probe_events = self._run_auth_probes(auth_events)
        logger.info(
            f"Probes generated {len(probe_events)} events from {len(auth_events)} auth events"
        )

        # Build proto events
        proto_events = self._build_heartbeat_metrics(
            timestamp_ns,
            len(auth_events),
            len(probe_events),
        )
        proto_events.extend(
            self._build_probe_security_events(timestamp_ns, probe_events)
        )

        # Create DeviceTelemetry
        telemetry = telemetry_pb2.DeviceTelemetry(
            device_id=self.device_id,
            device_type="HOST",
            protocol="AUTH",
            events=proto_events,
            timestamp_ns=timestamp_ns,
            collection_agent="auth",
            agent_version="2.1.0",
        )

        return [telemetry]

    # ── collect_data helpers ─────────────────────────────────────────────

    def _run_auth_probes(
        self,
        auth_events: List[AuthEvent],
    ) -> List[TelemetryEvent]:
        """Feed auth events to all probes and collect results."""
        context = self._create_probe_context()
        context.shared_data["auth_events"] = auth_events

        events: List[TelemetryEvent] = []
        for probe in self._probes:
            if not probe.enabled:
                continue
            try:
                probe_events = probe.scan(context)
                events.extend(probe_events)
                probe.last_scan = datetime.now(timezone.utc)
                probe.scan_count += 1
            except Exception as e:
                probe.error_count += 1
                probe.last_error = str(e)
                logger.error(f"Probe {probe.name} failed: {e}")
        return events

    def _build_heartbeat_metrics(
        self,
        timestamp_ns: int,
        auth_count: int,
        probe_event_count: int,
    ) -> List[telemetry_pb2.TelemetryEvent]:
        """Build heartbeat METRIC TelemetryEvents (always emitted)."""
        metrics: List[telemetry_pb2.TelemetryEvent] = []

        # GAUGE: auth events in this cycle
        metrics.append(
            telemetry_pb2.TelemetryEvent(
                event_id=f"auth_collection_summary_{timestamp_ns}",
                event_type="METRIC",
                severity="INFO",
                event_timestamp_ns=timestamp_ns,
                source_component="auth_collector",
                tags=["auth", "metric"],
                metric_data=telemetry_pb2.MetricData(
                    metric_name="auth_events_collected",
                    metric_type="GAUGE",
                    numeric_value=float(auth_count),
                    unit="events",
                ),
            )
        )

        # COUNTER: lifetime total
        metrics.append(
            telemetry_pb2.TelemetryEvent(
                event_id=f"auth_events_total_{timestamp_ns}",
                event_type="METRIC",
                severity="INFO",
                event_timestamp_ns=timestamp_ns,
                source_component="auth_collector",
                tags=["auth", "metric"],
                metric_data=telemetry_pb2.MetricData(
                    metric_name="auth_events_collected_total",
                    metric_type="COUNTER",
                    numeric_value=float(self._total_auth_events),
                    unit="events",
                ),
            )
        )

        # Probe events (only when > 0)
        if probe_event_count:
            metrics.append(
                telemetry_pb2.TelemetryEvent(
                    event_id=f"auth_probe_events_{timestamp_ns}",
                    event_type="METRIC",
                    severity="INFO",
                    event_timestamp_ns=timestamp_ns,
                    source_component="auth_guard_agent",
                    tags=["auth", "metric"],
                    metric_data=telemetry_pb2.MetricData(
                        metric_name="auth_probe_events",
                        metric_type="GAUGE",
                        numeric_value=float(probe_event_count),
                        unit="events",
                    ),
                )
            )

        return metrics

    _SEVERITY_MAP = {
        "DEBUG": "DEBUG",
        "INFO": "INFO",
        "LOW": "LOW",
        "MEDIUM": "MEDIUM",
        "HIGH": "HIGH",
        "CRITICAL": "CRITICAL",
    }

    def _build_probe_security_events(
        self,
        timestamp_ns: int,
        events: List[TelemetryEvent],
    ) -> List[telemetry_pb2.TelemetryEvent]:
        """Convert probe TelemetryEvents to SecurityEvent-based protos."""
        results: List[telemetry_pb2.TelemetryEvent] = []

        for event in events:
            security_event = telemetry_pb2.SecurityEvent(
                event_category=event.event_type,
                risk_score=0.8 if event.severity.value in ("HIGH", "CRITICAL") else 0.5,
                analyst_notes=(
                    f"Probe: {event.probe_name}, Severity: {event.severity.value}"
                ),
            )
            security_event.mitre_techniques.extend(event.mitre_techniques)

            tel_event = telemetry_pb2.TelemetryEvent(
                event_id=f"{event.event_type}_{timestamp_ns}",
                event_type="SECURITY",
                severity=self._SEVERITY_MAP.get(event.severity.value, "INFO"),
                event_timestamp_ns=timestamp_ns,
                source_component=event.probe_name or "auth_guard_agent",
                tags=["auth", "threat"],
                security_event=security_event,
                confidence_score=0.7,
            )

            if event.data:
                for key, value in event.data.items():
                    if value is not None:
                        tel_event.attributes[key] = str(value)

            results.append(tel_event)

        return results

    def validate_event(self, event: Any) -> ValidationResult:
        """Validate telemetry before publishing.

        Args:
            event: DeviceTelemetry protobuf message

        Returns:
            ValidationResult
        """
        errors = []

        if not event.device_id:
            errors.append("device_id required")
        if event.timestamp_ns <= 0:
            errors.append("timestamp_ns must be positive")
        if not event.events:
            errors.append("events list is empty")

        return ValidationResult(is_valid=len(errors) == 0, errors=errors)

    def shutdown(self) -> None:
        """Graceful shutdown."""
        logger.info("AuthGuardAgent shutting down...")

        # Close EventBus connection
        if self.eventbus_publisher:
            self.eventbus_publisher.close()

        logger.info("AuthGuardAgent shutdown complete")

    def get_health(self) -> Dict[str, Any]:
        """Get agent health status.

        Returns:
            Dict with health metrics
        """
        return {
            "agent_name": self.agent_name,
            "device_id": self.device_id,
            "is_running": self.is_running,
            "collection_count": self.collection_count,
            "error_count": self.error_count,
            "last_error": self.last_error,
            "probes": self.get_probe_health(),
            "circuit_breaker_state": self.circuit_breaker.state,
        }


# =============================================================================
# CLI Entry Point
# =============================================================================


def main():
    """Run AuthGuard Agent."""
    import argparse

    parser = argparse.ArgumentParser(description="AMOSKYS AuthGuard Agent")
    parser.add_argument(
        "--interval",
        type=float,
        default=30.0,
        help="Collection interval in seconds",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default=None,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level (overrides --debug)",
    )
    parser.add_argument(
        "--queue-path",
        type=str,
        default=None,
        help="Override local queue DB path",
    )
    parser.add_argument(
        "--device-id",
        type=str,
        default=None,
        help="Override device ID (default: hostname)",
    )

    args = parser.parse_args()

    if args.log_level:
        logging.getLogger().setLevel(getattr(logging, args.log_level))
    elif args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    logger.info("=" * 70)
    logger.info("AMOSKYS AuthGuard Agent (Micro-Probe Architecture)")
    logger.info("=" * 70)

    agent = AuthGuardAgent(
        collection_interval=args.interval,
        queue_path_override=args.queue_path,
        device_id_override=args.device_id,
    )

    try:
        agent.run_forever()
    except KeyboardInterrupt:
        logger.info("Received interrupt, shutting down...")
        agent.shutdown()


if __name__ == "__main__":
    main()
