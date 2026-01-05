#!/usr/bin/env python3
"""AuthGuard Micro-Probes - 8 Eyes on Authentication & Privilege.

Each probe watches ONE specific authentication/privilege threat vector:

1. SSHBruteForceProbe - Multiple login failures from single IP/user
2. SSHPasswordSprayProbe - Low-and-slow across many users
3. SSHGeoImpossibleTravelProbe - Geographic impossibility
4. SudoElevationProbe - Privilege escalation patterns
5. SudoSuspiciousCommandProbe - Dangerous sudo commands
6. OffHoursLoginProbe - Access outside business hours
7. MFABypassOrAnomalyProbe - MFA fatigue/bypass attempts
8. AccountLockoutStormProbe - Mass lockout attacks

MITRE Coverage:
    - T1110: Brute Force
    - T1110.003: Password Spraying
    - T1078: Valid Accounts
    - T1548: Abuse Elevation Control Mechanism
    - T1059: Command and Scripting Interpreter
    - T1621: Multi-Factor Authentication Request Generation
"""

from __future__ import annotations

import collections
import datetime
import math
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from amoskys.agents.common.probes import (
    MicroProbe,
    ProbeContext,
    Severity,
    TelemetryEvent,
)


# =============================================================================
# Auth Event Model
# =============================================================================


@dataclass
class AuthEvent:
    """Normalized authentication event from system logs."""

    timestamp_ns: int
    event_type: str  # SSH_LOGIN, SSH_FAILURE, SUDO_EXEC, SCREEN_LOCK, etc.
    status: str  # SUCCESS, FAILURE
    username: str
    source_ip: str = ""
    command: str = ""
    session_id: str = ""
    reason: str = ""  # "invalid password", "account locked", etc.
    tty: str = ""

    # Enriched fields (added by agent)
    src_country: Optional[str] = None
    src_city: Optional[str] = None
    src_latitude: Optional[float] = None
    src_longitude: Optional[float] = None


# =============================================================================
# Configuration
# =============================================================================


# SSH Brute Force
BRUTE_FORCE_THRESHOLD = 5  # failures per IP/user
BRUTE_FORCE_WINDOW_SECONDS = 300  # 5 minutes

# Password Spray
PASSWORD_SPRAY_USER_THRESHOLD = 10  # distinct users per IP
PASSWORD_SPRAY_WINDOW_SECONDS = 300

# Geo Impossible Travel
GEO_MIN_DISTANCE_KM = 1000  # Flag if >1000km
GEO_MIN_TIME_SECONDS = 3600  # within 1 hour
GEO_MAX_SPEED_KMH = 1000  # Max plausible speed (jet speed)

# Sudo Elevation
SUDO_SPIKE_MULTIPLIER = 3.0  # 3x normal rate
SUDO_BASELINE_WINDOW_SECONDS = 3600  # 1 hour baseline

# Off Hours
OFF_HOURS_START = 20  # 8pm
OFF_HOURS_END = 6  # 6am

# Account Lockout Storm
LOCKOUT_STORM_THRESHOLD = 5  # accounts locked
LOCKOUT_STORM_WINDOW_SECONDS = 300


# =============================================================================
# Probe 1: SSH Brute Force Detection
# =============================================================================


class SSHBruteForceProbe(MicroProbe):
    """Detects SSH brute force attacks (multiple failures from single source).

    Watches for:
        - 5+ SSH login failures from same IP to same user in 5 minutes
        - Classic credential guessing pattern

    MITRE: T1110 (Brute Force), T1078 (Valid Accounts)
    """

    name = "ssh_bruteforce"
    description = "SSH brute force detection"
    mitre_techniques = ["T1110", "T1078"]
    mitre_tactics = ["Credential Access", "Initial Access"]
    default_enabled = True
    scan_interval = 10.0

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect SSH brute force attempts."""
        events: List[TelemetryEvent] = []
        auth_events: List[AuthEvent] = context.shared_data.get("auth_events", [])

        # Count failures per (source_ip, username)
        failures: Dict[Tuple[str, str], List[AuthEvent]] = collections.defaultdict(list)

        for ev in auth_events:
            if ev.event_type == "SSH_LOGIN" and ev.status == "FAILURE":
                key = (ev.source_ip, ev.username)
                failures[key].append(ev)

        # Flag if threshold exceeded
        for (src_ip, user), fail_events in failures.items():
            if len(fail_events) >= BRUTE_FORCE_THRESHOLD:
                # Calculate time span
                timestamps = [e.timestamp_ns for e in fail_events]
                span_seconds = (max(timestamps) - min(timestamps)) / 1e9

                if span_seconds <= BRUTE_FORCE_WINDOW_SECONDS:
                    events.append(
                        TelemetryEvent(
                            event_type="ssh_bruteforce_detected",
                            severity=Severity.HIGH,
                            probe_name=self.name,
                            data={
                                "source_ip": src_ip,
                                "username": user,
                                "failure_count": len(fail_events),
                                "window_seconds": span_seconds,
                                "first_attempt_ns": min(timestamps),
                                "last_attempt_ns": max(timestamps),
                            },
                            mitre_techniques=["T1110", "T1078"],
                        )
                    )

        return events


# =============================================================================
# Probe 2: SSH Password Spray Detection
# =============================================================================


class SSHPasswordSprayProbe(MicroProbe):
    """Detects password spraying (one IP, many users, low failures per user).

    Watches for:
        - Single IP attempting 10+ distinct usernames
        - Low-and-slow to avoid account lockouts

    MITRE: T1110.003 (Password Spraying)
    """

    name = "ssh_password_spray"
    description = "SSH password spraying detection"
    mitre_techniques = ["T1110.003"]
    mitre_tactics = ["Credential Access"]
    default_enabled = True
    scan_interval = 10.0

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect password spray attacks."""
        events: List[TelemetryEvent] = []
        auth_events: List[AuthEvent] = context.shared_data.get("auth_events", [])

        # Count distinct users per source IP
        users_per_ip: Dict[str, Set[str]] = collections.defaultdict(set)

        for ev in auth_events:
            if ev.event_type == "SSH_LOGIN" and ev.status == "FAILURE":
                users_per_ip[ev.source_ip].add(ev.username)

        # Flag if threshold exceeded
        for src_ip, users in users_per_ip.items():
            if len(users) >= PASSWORD_SPRAY_USER_THRESHOLD:
                events.append(
                    TelemetryEvent(
                        event_type="ssh_password_spray_detected",
                        severity=Severity.HIGH,
                        probe_name=self.name,
                        data={
                            "source_ip": src_ip,
                            "user_count": len(users),
                            "usernames": sorted(list(users))[:20],  # First 20
                        },
                        mitre_techniques=["T1110.003"],
                    )
                )

        return events


# =============================================================================
# Probe 3: Geographic Impossible Travel
# =============================================================================


class SSHGeoImpossibleTravelProbe(MicroProbe):
    """Detects impossible geographic travel (same user, distant locations).

    Watches for:
        - Same user logging in from two locations >1000km apart within 1 hour
        - Requires GeoIP enrichment

    MITRE: T1078 (Valid Accounts - Credential Theft)
    """

    name = "ssh_geo_impossible_travel"
    description = "Geographic impossible travel detection"
    mitre_techniques = ["T1078"]
    mitre_tactics = ["Initial Access", "Persistence"]
    default_enabled = True
    scan_interval = 10.0

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect impossible travel."""
        events: List[TelemetryEvent] = []
        auth_events: List[AuthEvent] = context.shared_data.get("auth_events", [])

        # Group successful logins by user
        logins_by_user: Dict[str, List[AuthEvent]] = collections.defaultdict(list)

        for ev in auth_events:
            if ev.event_type == "SSH_LOGIN" and ev.status == "SUCCESS":
                # Only consider events with geo data
                if ev.src_latitude is not None and ev.src_longitude is not None:
                    logins_by_user[ev.username].append(ev)

        # Check each user's login sequence
        for username, logins in logins_by_user.items():
            if len(logins) < 2:
                continue

            # Sort by timestamp
            logins.sort(key=lambda e: e.timestamp_ns)

            # Check consecutive pairs
            for i in range(len(logins) - 1):
                ev1, ev2 = logins[i], logins[i + 1]

                # Calculate distance
                distance_km = self._haversine_distance(
                    ev1.src_latitude,
                    ev1.src_longitude,
                    ev2.src_latitude,
                    ev2.src_longitude,
                )

                # Calculate time difference
                time_diff_seconds = (ev2.timestamp_ns - ev1.timestamp_ns) / 1e9

                # Calculate required speed
                if time_diff_seconds > 0:
                    speed_kmh = (distance_km / time_diff_seconds) * 3600
                else:
                    speed_kmh = float("inf")

                # Flag if impossible
                if (
                    distance_km >= GEO_MIN_DISTANCE_KM
                    and time_diff_seconds <= GEO_MIN_TIME_SECONDS
                    and speed_kmh > GEO_MAX_SPEED_KMH
                ):
                    events.append(
                        TelemetryEvent(
                            event_type="impossible_travel_detected",
                            severity=Severity.CRITICAL,
                            probe_name=self.name,
                            data={
                                "username": username,
                                "location1": f"{ev1.src_city}, {ev1.src_country}",
                                "location2": f"{ev2.src_city}, {ev2.src_country}",
                                "distance_km": round(distance_km, 2),
                                "time_diff_seconds": round(time_diff_seconds, 2),
                                "required_speed_kmh": round(speed_kmh, 2),
                                "ip1": ev1.source_ip,
                                "ip2": ev2.source_ip,
                            },
                            mitre_techniques=["T1078"],
                        )
                    )

        return events

    @staticmethod
    def _haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Calculate great-circle distance between two points (km)."""
        R = 6371  # Earth radius in km

        lat1_rad = math.radians(lat1)
        lat2_rad = math.radians(lat2)
        dlat = math.radians(lat2 - lat1)
        dlon = math.radians(lon2 - lon1)

        a = (
            math.sin(dlat / 2) ** 2
            + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlon / 2) ** 2
        )
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

        return R * c


# =============================================================================
# Probe 4: Sudo Elevation Monitoring
# =============================================================================


class SudoElevationProbe(MicroProbe):
    """Detects privilege escalation via sudo.

    Watches for:
        - First-time sudo usage by a user
        - Sudden spike in sudo usage (3x baseline)

    MITRE: T1548.003 (Sudo and Sudo Caching)
    """

    name = "sudo_elevation"
    description = "Sudo privilege escalation monitoring"
    mitre_techniques = ["T1548.003"]
    mitre_tactics = ["Privilege Escalation"]
    default_enabled = True
    scan_interval = 10.0

    def __init__(self):
        super().__init__()
        # Track baseline sudo usage per user
        self.baseline_sudo_counts: Dict[str, int] = {}

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect sudo elevation anomalies."""
        events: List[TelemetryEvent] = []
        auth_events: List[AuthEvent] = context.shared_data.get("auth_events", [])

        # Count sudo executions per user
        sudo_counts: Dict[str, int] = collections.Counter()
        first_time_users: Set[str] = set()

        for ev in auth_events:
            if ev.event_type == "SUDO_EXEC" and ev.status == "SUCCESS":
                sudo_counts[ev.username] += 1

                # Check if first-time
                if ev.username not in self.baseline_sudo_counts:
                    first_time_users.add(ev.username)

        # Flag first-time sudo users
        for user in first_time_users:
            events.append(
                TelemetryEvent(
                    event_type="first_time_sudo_user",
                    severity=Severity.MEDIUM,
                    probe_name=self.name,
                    data={
                        "username": user,
                        "sudo_count": sudo_counts[user],
                    },
                    mitre_techniques=["T1548.003"],
                )
            )

        # Flag sudden spikes
        for user, current_count in sudo_counts.items():
            baseline = self.baseline_sudo_counts.get(user, 0)
            if baseline > 0 and current_count >= baseline * SUDO_SPIKE_MULTIPLIER:
                events.append(
                    TelemetryEvent(
                        event_type="sudo_usage_spike",
                        severity=Severity.HIGH,
                        probe_name=self.name,
                        data={
                            "username": user,
                            "current_count": current_count,
                            "baseline_count": baseline,
                            "multiplier": round(current_count / baseline, 2),
                        },
                        mitre_techniques=["T1548.003"],
                    )
                )

        # Update baseline
        for user, count in sudo_counts.items():
            self.baseline_sudo_counts[user] = count

        return events


# =============================================================================
# Probe 5: Suspicious Sudo Commands
# =============================================================================


class SudoSuspiciousCommandProbe(MicroProbe):
    """Detects dangerous commands executed with sudo.

    Watches for:
        - Shell spawning: sudo bash, sudo sh, sudo python -c
        - Privilege abuse: sudo chmod 4777, sudo chown root
        - Pipe execution: curl | sudo sh, wget | sudo bash
        - Sudoers modification: sudo echo >> /etc/sudoers

    MITRE: T1548, T1059, T1547
    """

    name = "sudo_suspicious_command"
    description = "Dangerous sudo command detection"
    mitre_techniques = ["T1548", "T1059", "T1547"]
    mitre_tactics = ["Privilege Escalation", "Execution", "Persistence"]
    default_enabled = True
    scan_interval = 10.0

    # Suspicious patterns (ordered from most specific to least specific)
    DANGEROUS_PATTERNS = [
        # Pipe execution (must come before shell_spawn)
        (r"(curl|wget).*\|\s*sudo\s+(bash|sh)", "pipe_to_shell", Severity.CRITICAL),
        # Sudoers modification
        (r"sudo\s+echo.*>>\s*/etc/sudoers", "sudoers_modification", Severity.CRITICAL),
        (r"sudo\s+tee.*sudoers", "sudoers_tee", Severity.CRITICAL),
        # Destructive commands
        (r"sudo\s+rm\s+-rf\s+/", "recursive_delete_root", Severity.CRITICAL),
        (r"sudo\s+dd\s+if=/dev/zero", "disk_wipe", Severity.CRITICAL),
        # SUID/privilege changes
        (r"sudo\s+chmod\s+[0-7]*[4-7][0-7][0-7]", "setuid_chmod", Severity.CRITICAL),
        (r"sudo\s+chown\s+root", "chown_root", Severity.HIGH),
        # Code execution
        (r"sudo\s+python\s+-c", "python_code_exec", Severity.HIGH),
        (r"sudo\s+perl\s+-e", "perl_code_exec", Severity.HIGH),
        # Shell spawning (must come after pipe patterns)
        (r"sudo\s+(bash|sh|zsh|fish)\b", "shell_spawn", Severity.HIGH),
    ]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect suspicious sudo commands."""
        events: List[TelemetryEvent] = []
        auth_events: List[AuthEvent] = context.shared_data.get("auth_events", [])

        for ev in auth_events:
            if ev.event_type == "SUDO_EXEC" and ev.status == "SUCCESS":
                command = ev.command

                # Check each pattern
                for pattern, threat_type, severity in self.DANGEROUS_PATTERNS:
                    if re.search(pattern, command, re.IGNORECASE):
                        events.append(
                            TelemetryEvent(
                                event_type=f"sudo_suspicious_{threat_type}",
                                severity=severity,
                                probe_name=self.name,
                                data={
                                    "username": ev.username,
                                    "command": command,
                                    "threat_type": threat_type,
                                    "source_ip": ev.source_ip,
                                },
                                mitre_techniques=["T1548", "T1059"],
                            )
                        )
                        break  # Only flag once per command

        return events


# =============================================================================
# Probe 6: Off-Hours Login Detection
# =============================================================================


class OffHoursLoginProbe(MicroProbe):
    """Detects logins outside normal business hours.

    Watches for:
        - Successful logins between 8pm-6am local time
        - Weekend logins (optional)

    MITRE: T1078 (Valid Accounts - suspicious timing)
    """

    name = "off_hours_login"
    description = "Off-hours access detection"
    mitre_techniques = ["T1078"]
    mitre_tactics = ["Initial Access", "Persistence"]
    default_enabled = True
    scan_interval = 10.0

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect off-hours logins."""
        events: List[TelemetryEvent] = []
        auth_events: List[AuthEvent] = context.shared_data.get("auth_events", [])

        for ev in auth_events:
            if ev.event_type in ("SSH_LOGIN", "LOCAL_LOGIN") and ev.status == "SUCCESS":
                # Convert to local time
                dt = datetime.datetime.fromtimestamp(ev.timestamp_ns / 1e9)
                hour = dt.hour
                weekday = dt.weekday()  # 0=Monday, 6=Sunday

                # Check if off-hours
                is_off_hours = hour >= OFF_HOURS_START or hour < OFF_HOURS_END
                is_weekend = weekday >= 5  # Saturday or Sunday

                if is_off_hours or is_weekend:
                    events.append(
                        TelemetryEvent(
                            event_type="off_hours_login",
                            severity=Severity.MEDIUM,
                            probe_name=self.name,
                            data={
                                "username": ev.username,
                                "source_ip": ev.source_ip,
                                "hour": hour,
                                "day_of_week": weekday,
                                "is_weekend": is_weekend,
                                "timestamp": dt.isoformat(),
                            },
                            mitre_techniques=["T1078"],
                        )
                    )

        return events


# =============================================================================
# Probe 7: MFA Bypass/Anomaly Detection
# =============================================================================


class MFABypassOrAnomalyProbe(MicroProbe):
    """Detects MFA bypass attempts or fatigue attacks.

    Watches for:
        - Login success without corresponding MFA success
        - Excessive MFA challenges (push bombing)
        - MFA success after many failures (fatigue attack)

    MITRE: T1621 (Multi-Factor Authentication Request Generation)
    """

    name = "mfa_bypass_anomaly"
    description = "MFA bypass and fatigue attack detection"
    mitre_techniques = ["T1621"]
    mitre_tactics = ["Credential Access"]
    default_enabled = True
    scan_interval = 10.0

    MFA_FATIGUE_THRESHOLD = 10  # MFA challenges before success

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect MFA anomalies."""
        events: List[TelemetryEvent] = []
        auth_events: List[AuthEvent] = context.shared_data.get("auth_events", [])

        # Track MFA events per user
        mfa_challenges: Dict[str, int] = collections.Counter()
        mfa_successes: Set[str] = set()
        login_successes: Set[str] = set()

        for ev in auth_events:
            if ev.event_type == "MFA_CHALLENGE":
                mfa_challenges[ev.username] += 1
            elif ev.event_type == "MFA_SUCCESS":
                mfa_successes.add(ev.username)
            elif ev.event_type in ("SSH_LOGIN", "VPN_LOGIN") and ev.status == "SUCCESS":
                login_successes.add(ev.username)

        # Check for login without MFA
        for user in login_successes:
            if user not in mfa_successes:
                events.append(
                    TelemetryEvent(
                        event_type="mfa_bypass_suspected",
                        severity=Severity.CRITICAL,
                        probe_name=self.name,
                        data={
                            "username": user,
                            "reason": "Login success without MFA success",
                        },
                        mitre_techniques=["T1621"],
                    )
                )

        # Check for MFA fatigue (many challenges before success)
        for user, challenge_count in mfa_challenges.items():
            if (
                user in mfa_successes
                and challenge_count >= self.MFA_FATIGUE_THRESHOLD
            ):
                events.append(
                    TelemetryEvent(
                        event_type="mfa_fatigue_attack",
                        severity=Severity.HIGH,
                        probe_name=self.name,
                        data={
                            "username": user,
                            "challenge_count": challenge_count,
                            "reason": "Excessive MFA challenges before success (push bombing)",
                        },
                        mitre_techniques=["T1621"],
                    )
                )

        return events


# =============================================================================
# Probe 8: Account Lockout Storm Detection
# =============================================================================


class AccountLockoutStormProbe(MicroProbe):
    """Detects mass account lockout attacks.

    Watches for:
        - Multiple distinct accounts locked in short window
        - Same source IP causing multiple lockouts
        - Potential DoS or distraction tactic

    MITRE: T1110 (Brute Force - causing lockouts), T1499 (Endpoint DoS)
    """

    name = "account_lockout_storm"
    description = "Mass account lockout detection"
    mitre_techniques = ["T1110", "T1499"]
    mitre_tactics = ["Credential Access", "Impact"]
    default_enabled = True
    scan_interval = 10.0

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect account lockout storms."""
        events: List[TelemetryEvent] = []
        auth_events: List[AuthEvent] = context.shared_data.get("auth_events", [])

        # Track lockouts
        locked_accounts: Set[str] = set()
        lockouts_by_ip: Dict[str, Set[str]] = collections.defaultdict(set)

        for ev in auth_events:
            if ev.event_type == "ACCOUNT_LOCKED":
                locked_accounts.add(ev.username)
                if ev.source_ip:
                    lockouts_by_ip[ev.source_ip].add(ev.username)

        # Flag if many accounts locked
        if len(locked_accounts) >= LOCKOUT_STORM_THRESHOLD:
            events.append(
                TelemetryEvent(
                    event_type="account_lockout_storm",
                    severity=Severity.HIGH,
                    probe_name=self.name,
                    data={
                        "locked_account_count": len(locked_accounts),
                        "locked_accounts": sorted(list(locked_accounts))[:20],
                        "reason": "Mass account lockout detected",
                    },
                    mitre_techniques=["T1110", "T1499"],
                )
            )

        # Flag if single IP causing multiple lockouts
        for src_ip, accounts in lockouts_by_ip.items():
            if len(accounts) >= 3:
                events.append(
                    TelemetryEvent(
                        event_type="lockout_storm_source",
                        severity=Severity.HIGH,
                        probe_name=self.name,
                        data={
                            "source_ip": src_ip,
                            "lockout_count": len(accounts),
                            "accounts": sorted(list(accounts)),
                        },
                        mitre_techniques=["T1110"],
                    )
                )

        return events


# =============================================================================
# Probe Factory
# =============================================================================


def create_auth_probes() -> List[MicroProbe]:
    """Create all AuthGuard micro-probes.

    Returns:
        List of 8 auth monitoring probes
    """
    return [
        SSHBruteForceProbe(),
        SSHPasswordSprayProbe(),
        SSHGeoImpossibleTravelProbe(),
        SudoElevationProbe(),
        SudoSuspiciousCommandProbe(),
        OffHoursLoginProbe(),
        MFABypassOrAnomalyProbe(),
        AccountLockoutStormProbe(),
    ]
