"""macOS Auth Probes -- 6 detection probes for Darwin authentication events.

Each probe consumes AuthEvent data from MacOSAuthCollector via
shared_data["auth_events"]. Every probe is macOS-only (platforms=["darwin"]).

Probes:
    1. SSHBruteForceProbe     -- multiple failed SSH attempts        T1110
    2. SudoEscalationProbe    -- sudo usage detection                T1548.003
    3. OffHoursLoginProbe     -- login outside business hours        T1078
    4. ImpossibleTravelProbe  -- SSH from different IPs rapidly      T1078
    5. AccountLockoutProbe    -- repeated auth failures              T1110
    6. CredentialAccessProbe  -- security CLI (Keychain) usage       T1555.001
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from amoskys.agents.common.probes import (
    MicroProbe,
    ProbeContext,
    Severity,
    TelemetryEvent,
)

logger = logging.getLogger(__name__)


# =============================================================================
# 1. SSHBruteForceProbe
# =============================================================================


class SSHBruteForceProbe(MicroProbe):
    """Detects SSH brute-force attempts via repeated failed authentications.

    Counts failed SSH events grouped by source IP within the collection
    window. Fires when the failure count for a single IP exceeds the
    threshold (default: 5).

    MITRE: T1110 (Brute Force)
    """

    name = "macos_ssh_brute_force"
    description = "Detects SSH brute-force attempts on macOS"
    platforms = ["darwin"]
    mitre_techniques = ["T1110"]
    mitre_tactics = ["credential_access"]
    scan_interval = 30.0
    requires_fields = ["auth_events"]

    FAILURE_THRESHOLD = 5

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        auth_events = context.shared_data.get("auth_events", [])

        # Count SSH failures per source IP
        failures_by_ip: Dict[str, List[Any]] = defaultdict(list)

        for ev in auth_events:
            if ev.category != "ssh" or ev.event_type != "failure":
                continue
            ip = ev.source_ip or "unknown"
            failures_by_ip[ip].append(ev)

        for ip, failed_events in failures_by_ip.items():
            if len(failed_events) < self.FAILURE_THRESHOLD:
                continue

            # Collect targeted usernames
            usernames = {e.username for e in failed_events if e.username}

            events.append(
                self._create_event(
                    event_type="ssh_brute_force",
                    severity=Severity.HIGH,
                    data={
                        "source_ip": ip,
                        "failure_count": len(failed_events),
                        "threshold": self.FAILURE_THRESHOLD,
                        "targeted_usernames": sorted(usernames),
                        "first_attempt": failed_events[0].timestamp.isoformat(),
                        "last_attempt": failed_events[-1].timestamp.isoformat(),
                        "category": "SSH_BRUTE_FORCE",
                    },
                    confidence=min(0.5 + len(failed_events) * 0.05, 0.95),
                    tags=["brute_force", "ssh"],
                )
            )

        return events


# =============================================================================
# 2. SudoEscalationProbe
# =============================================================================


class SudoEscalationProbe(MicroProbe):
    """Detects sudo privilege escalation usage.

    Monitors sudo events for both successful and failed escalation attempts.
    Failed sudo is elevated to HIGH severity as it may indicate credential
    guessing or unauthorized escalation attempts.

    MITRE: T1548.003 (Abuse Elevation Control Mechanism: Sudo and Sudo Caching)
    """

    name = "macos_sudo_escalation"
    description = "Detects sudo privilege escalation on macOS"
    platforms = ["darwin"]
    mitre_techniques = ["T1548.003"]
    mitre_tactics = ["privilege_escalation", "defense_evasion"]
    scan_interval = 30.0
    requires_fields = ["auth_events"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        auth_events = context.shared_data.get("auth_events", [])

        for ev in auth_events:
            if ev.category != "sudo":
                continue

            if ev.event_type == "failure":
                events.append(
                    self._create_event(
                        event_type="sudo_escalation_failure",
                        severity=Severity.HIGH,
                        data={
                            "username": ev.username or "unknown",
                            "message": ev.message[:500],
                            "timestamp": ev.timestamp.isoformat(),
                            "category": "SUDO_FAILURE",
                        },
                        confidence=0.85,
                        tags=["sudo", "escalation_failure"],
                    )
                )
            elif ev.event_type == "success":
                events.append(
                    self._create_event(
                        event_type="sudo_escalation",
                        severity=Severity.MEDIUM,
                        data={
                            "username": ev.username or "unknown",
                            "message": ev.message[:500],
                            "timestamp": ev.timestamp.isoformat(),
                            "category": "SUDO_SUCCESS",
                        },
                        confidence=0.7,
                        tags=["sudo", "escalation"],
                    )
                )

        return events


# =============================================================================
# 3. OffHoursLoginProbe
# =============================================================================


class OffHoursLoginProbe(MicroProbe):
    """Detects login events outside business hours.

    Business hours default: 08:00-18:00 local time, Monday-Friday.

    Configurable via context.config:
        business_hours_start: int  — hour (0-23), default 8
        business_hours_end:   int  — hour (0-23), default 18
        check_weekends:       bool — flag weekends as off-hours, default True

    Covers SSH logins, sudo escalation, loginwindow events, and
    screensaver unlocks (event_type in success/unlock).

    MITRE: T1078 (Valid Accounts)
    """

    name = "macos_off_hours_login"
    description = "Detects login events outside business hours on macOS"
    platforms = ["darwin"]
    mitre_techniques = ["T1078"]
    mitre_tactics = ["initial_access", "persistence"]
    scan_interval = 30.0
    requires_fields = ["auth_events"]

    DEFAULT_START_HOUR = 8  # 08:00
    DEFAULT_END_HOUR = 18  # 18:00

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        auth_events = context.shared_data.get("auth_events", [])

        start_hour = context.config.get("business_hours_start", self.DEFAULT_START_HOUR)
        end_hour = context.config.get("business_hours_end", self.DEFAULT_END_HOUR)
        check_weekends = context.config.get("check_weekends", True)

        for ev in auth_events:
            # Only care about successful logins and unlocks
            if ev.event_type not in ("success", "unlock"):
                continue

            # Check if event timestamp falls outside business hours
            local_hour = ev.timestamp.hour
            weekday = ev.timestamp.weekday()  # 0=Monday, 6=Sunday

            is_off_hours = local_hour < start_hour or local_hour >= end_hour
            if check_weekends and weekday >= 5:
                is_off_hours = True

            if not is_off_hours:
                continue

            events.append(
                self._create_event(
                    event_type="off_hours_login",
                    severity=Severity.MEDIUM,
                    data={
                        "username": ev.username or "unknown",
                        "category": ev.category,
                        "process": ev.process,
                        "source_ip": ev.source_ip,
                        "timestamp": ev.timestamp.isoformat(),
                        "hour": local_hour,
                        "weekday": weekday,
                        "business_hours": f"{start_hour:02d}:00-{end_hour:02d}:00",
                    },
                    confidence=0.6,
                    tags=["off_hours", ev.category],
                )
            )

        return events


# =============================================================================
# 4. ImpossibleTravelProbe
# =============================================================================


class ImpossibleTravelProbe(MicroProbe):
    """Detects SSH connections from different IPs in a short time window.

    If the same username authenticates via SSH from two different source IPs
    within a configurable time window (default: 300 seconds / 5 minutes),
    this indicates either credential sharing or compromised credentials.

    MITRE: T1078 (Valid Accounts)
    """

    name = "macos_impossible_travel"
    description = "Detects SSH from different IPs in short time on macOS"
    platforms = ["darwin"]
    mitre_techniques = ["T1078"]
    mitre_tactics = ["initial_access"]
    scan_interval = 30.0
    requires_fields = ["auth_events"]

    # Seconds within which multi-IP login is suspicious
    TIME_WINDOW_SECONDS = 300

    def __init__(self) -> None:
        super().__init__()
        # Track last known IP per username across scan cycles
        self._last_login: Dict[str, Tuple[str, datetime]] = {}

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        auth_events = context.shared_data.get("auth_events", [])

        # Build per-user SSH success events with IPs
        user_logins: Dict[str, List[Tuple[str, datetime]]] = defaultdict(list)

        for ev in auth_events:
            if ev.category != "ssh":
                continue
            if ev.event_type not in ("success", "attempt"):
                continue
            if not ev.source_ip or not ev.username:
                continue

            user_logins[ev.username].append((ev.source_ip, ev.timestamp))

        for username, logins in user_logins.items():
            # Include the last known login from previous cycle
            if username in self._last_login:
                prev_ip, prev_ts = self._last_login[username]
                logins.insert(0, (prev_ip, prev_ts))

            # Sort by time
            logins.sort(key=lambda x: x[1])

            # Compare consecutive logins for IP changes within window
            for i in range(1, len(logins)):
                prev_ip, prev_ts = logins[i - 1]
                curr_ip, curr_ts = logins[i]

                if prev_ip == curr_ip:
                    continue

                delta_seconds = abs((curr_ts - prev_ts).total_seconds())
                if delta_seconds > self.TIME_WINDOW_SECONDS:
                    continue

                events.append(
                    self._create_event(
                        event_type="impossible_travel",
                        severity=Severity.HIGH,
                        data={
                            "username": username,
                            "ip_1": prev_ip,
                            "ip_2": curr_ip,
                            "time_1": prev_ts.isoformat(),
                            "time_2": curr_ts.isoformat(),
                            "delta_seconds": round(delta_seconds, 1),
                            "window_seconds": self.TIME_WINDOW_SECONDS,
                            "category": "IMPOSSIBLE_TRAVEL",
                        },
                        confidence=0.85,
                        tags=["impossible_travel", "ssh"],
                    )
                )

            # Remember the latest login for next cycle
            if logins:
                last_ip, last_ts = logins[-1]
                self._last_login[username] = (last_ip, last_ts)

        return events


# =============================================================================
# 5. AccountLockoutProbe
# =============================================================================


class AccountLockoutProbe(MicroProbe):
    """Detects repeated authentication failures indicating account lockout.

    Counts auth failures per username across all categories (SSH, sudo,
    loginwindow). Fires when a single account exceeds the threshold
    (default: 10 failures in the collection window).

    MITRE: T1110 (Brute Force)
    """

    name = "macos_account_lockout"
    description = "Detects repeated auth failures indicating lockout on macOS"
    platforms = ["darwin"]
    mitre_techniques = ["T1110"]
    mitre_tactics = ["credential_access"]
    scan_interval = 30.0
    requires_fields = ["auth_events"]

    FAILURE_THRESHOLD = 10

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        auth_events = context.shared_data.get("auth_events", [])

        # Count failures per username (all categories)
        failures_by_user: Dict[str, List[Any]] = defaultdict(list)

        for ev in auth_events:
            if ev.event_type != "failure":
                continue
            username = ev.username or "unknown"
            failures_by_user[username].append(ev)

        for username, failed_events in failures_by_user.items():
            if len(failed_events) < self.FAILURE_THRESHOLD:
                continue

            # Gather categories and source IPs
            categories = {e.category for e in failed_events}
            source_ips = {e.source_ip for e in failed_events if e.source_ip}

            events.append(
                self._create_event(
                    event_type="account_lockout",
                    severity=Severity.HIGH,
                    data={
                        "username": username,
                        "failure_count": len(failed_events),
                        "threshold": self.FAILURE_THRESHOLD,
                        "categories": sorted(categories),
                        "source_ips": sorted(source_ips),
                        "first_failure": failed_events[0].timestamp.isoformat(),
                        "last_failure": failed_events[-1].timestamp.isoformat(),
                        "category": "ACCOUNT_LOCKOUT",
                    },
                    confidence=min(0.5 + len(failed_events) * 0.03, 0.95),
                    tags=["account_lockout", "brute_force"],
                )
            )

        return events


# =============================================================================
# 6. CredentialAccessProbe
# =============================================================================

# Suspicious security CLI subcommands targeting Keychain
_KEYCHAIN_SUBCOMMANDS = frozenset(
    {
        "find-generic-password",
        "find-internet-password",
        "dump-keychain",
        "export",
        "find-certificate",
        "find-identity",
        "delete-keychain",
        "unlock-keychain",
    }
)


class CredentialAccessProbe(MicroProbe):
    """Detects macOS ``security`` CLI usage targeting the Keychain.

    The ``security`` command-line tool provides direct access to Keychain
    Services. Subcommands like ``find-generic-password``, ``dump-keychain``,
    and ``find-internet-password`` can extract stored credentials.

    This probe inspects auth_events for messages referencing the security
    binary and Keychain operations.

    MITRE: T1555.001 (Credentials from Password Stores: Keychain)
    """

    name = "macos_credential_access"
    description = "Detects Keychain credential access via security CLI on macOS"
    platforms = ["darwin"]
    mitre_techniques = ["T1555.001"]
    mitre_tactics = ["credential_access"]
    scan_interval = 30.0
    requires_fields = ["auth_events"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        auth_events = context.shared_data.get("auth_events", [])

        for ev in auth_events:
            # Check if the message references `security` CLI or Keychain operations
            if ev.category == "keychain":
                # Direct security process event
                severity = Severity.HIGH
                subcommand = self._extract_subcommand(ev.message)

                if subcommand in (
                    "dump-keychain",
                    "find-generic-password",
                    "find-internet-password",
                ):
                    severity = Severity.CRITICAL

                events.append(
                    self._create_event(
                        event_type="credential_access",
                        severity=severity,
                        data={
                            "process": ev.process,
                            "subcommand": subcommand,
                            "username": ev.username or "unknown",
                            "message": ev.message[:500],
                            "timestamp": ev.timestamp.isoformat(),
                            "category": "KEYCHAIN_ACCESS",
                        },
                        confidence=0.8 if subcommand else 0.6,
                        tags=["credential_access", "keychain"],
                    )
                )
                continue

            # Also check non-keychain events that mention security/Keychain
            msg_lower = ev.message.lower()
            if "security" in msg_lower and "keychain" in msg_lower:
                events.append(
                    self._create_event(
                        event_type="credential_access_indirect",
                        severity=Severity.MEDIUM,
                        data={
                            "process": ev.process,
                            "category": ev.category,
                            "username": ev.username or "unknown",
                            "message": ev.message[:500],
                            "timestamp": ev.timestamp.isoformat(),
                        },
                        confidence=0.5,
                        tags=["credential_access", "keychain", "indirect"],
                    )
                )

        return events

    @staticmethod
    def _extract_subcommand(message: str) -> str:
        """Extract the security subcommand from a log message."""
        msg_lower = message.lower()
        for subcmd in _KEYCHAIN_SUBCOMMANDS:
            if subcmd in msg_lower:
                return subcmd
        return ""


# =============================================================================
# Factory
# =============================================================================


def create_auth_probes() -> List[MicroProbe]:
    """Create all macOS auth probes."""
    return [
        SSHBruteForceProbe(),
        SudoEscalationProbe(),
        OffHoursLoginProbe(),
        ImpossibleTravelProbe(),
        AccountLockoutProbe(),
        CredentialAccessProbe(),
    ]
