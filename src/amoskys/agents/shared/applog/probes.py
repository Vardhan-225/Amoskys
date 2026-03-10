"""AppLog Agent Micro-Probes - 8 Eyes Watching Every Log Entry.

Each probe monitors ONE specific application log threat vector:

    1. LogTamperingProbe - Detects log file tampering (truncation, gaps)
    2. CredentialHarvestProbe - Finds leaked credentials in log messages
    3. ErrorSpikeAnomalyProbe - Detects anomalous ERROR rate spikes
    4. WebShellAccessProbe - Identifies web shell access patterns
    5. Suspicious4xx5xxProbe - Detects scanning/abuse via HTTP status codes
    6. LogInjectionProbe - Detects CRLF injection and log poisoning
    7. PrivilegeEscalationLogProbe - Identifies sudo/su privilege changes
    8. ContainerBreakoutLogProbe - Detects container escape indicators

MITRE ATT&CK Coverage:
    - T1070.002: Indicator Removal: Clear Linux or Mac System Logs
    - T1552.001: Unsecured Credentials: Credentials In Files
    - T1499: Endpoint Denial of Service
    - T1505.003: Server Software Component: Web Shell
    - T1595: Active Scanning
    - T1562.006: Impair Defenses: Indicator Blocking
    - T1548.003: Abuse Elevation Control Mechanism: Sudo and Sudo Caching
    - T1611: Escape to Host
"""

from __future__ import annotations

import logging
import os
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from amoskys.agents.common.probes import (
    MicroProbe,
    ProbeContext,
    Severity,
    TelemetryEvent,
)

from .agent_types import LogEntry

logger = logging.getLogger(__name__)


# =============================================================================
# Shared Data Structures
# =============================================================================


@dataclass
class LogFileState:
    """Tracks state of a monitored log file for tampering detection."""

    file_path: str
    last_size: int = 0
    last_mtime: float = 0.0
    last_permissions: int = 0
    last_entry_timestamp: Optional[datetime] = None
    entry_count: int = 0


# =============================================================================
# 1. LogTamperingProbe
# =============================================================================


class LogTamperingProbe(MicroProbe):
    """Detects log file tampering indicators.

    Monitors log files for signs of anti-forensic activity:
        - Size decrease (truncation)
        - Permission changes
        - Large timestamp gaps (>5 min without entries)

    MITRE: T1070.002 (Clear Linux or Mac System Logs)
    """

    name = "log_tampering"
    description = "Detects log file tampering (truncation, permission changes, gaps)"
    mitre_techniques = ["T1070.002"]
    mitre_tactics = ["defense_evasion"]
    default_enabled = True
    scan_interval = 10.0
    requires_root = False
    platforms = ["linux", "darwin"]
    requires_fields = ["log_entries"]

    # Timestamp gap threshold in seconds
    GAP_THRESHOLD_SECONDS = 300  # 5 minutes

    def __init__(self) -> None:
        super().__init__()
        self.file_states: Dict[str, LogFileState] = {}

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Check log files for tampering indicators."""
        events = []

        entries: List[LogEntry] = context.shared_data.get("log_entries", [])

        # Group entries by file path
        entries_by_file: Dict[str, List[LogEntry]] = defaultdict(list)
        for entry in entries:
            entries_by_file[entry.file_path].append(entry)

        for file_path, file_entries in entries_by_file.items():
            # Initialize or get file state
            if file_path not in self.file_states:
                self.file_states[file_path] = LogFileState(file_path=file_path)

            state = self.file_states[file_path]

            # Check file size for truncation
            try:
                stat = os.stat(file_path)
                current_size = stat.st_size
                current_mtime = stat.st_mtime
                current_perms = stat.st_mode & 0o777

                # Truncation detection: file got smaller
                if state.last_size > 0 and current_size < state.last_size:
                    size_diff = state.last_size - current_size
                    events.append(
                        self._create_event(
                            event_type="log_truncation_detected",
                            severity=Severity.CRITICAL,
                            data={
                                "file_path": file_path,
                                "previous_size": state.last_size,
                                "current_size": current_size,
                                "bytes_removed": size_diff,
                            },
                            confidence=0.95,
                        )
                    )

                # Permission change detection
                if (
                    state.last_permissions > 0
                    and current_perms != state.last_permissions
                ):
                    events.append(
                        self._create_event(
                            event_type="log_permission_changed",
                            severity=Severity.CRITICAL,
                            data={
                                "file_path": file_path,
                                "old_permissions": oct(state.last_permissions),
                                "new_permissions": oct(current_perms),
                            },
                            confidence=0.90,
                        )
                    )

                # Update state
                state.last_size = current_size
                state.last_mtime = current_mtime
                state.last_permissions = current_perms

            except (OSError, FileNotFoundError):
                # File disappeared - potential tampering
                if state.last_size > 0:
                    events.append(
                        self._create_event(
                            event_type="log_file_deleted",
                            severity=Severity.CRITICAL,
                            data={
                                "file_path": file_path,
                                "last_known_size": state.last_size,
                            },
                            confidence=0.90,
                        )
                    )

            # Timestamp gap detection
            sorted_entries = sorted(file_entries, key=lambda e: e.timestamp)
            if state.last_entry_timestamp and sorted_entries:
                gap = (
                    sorted_entries[0].timestamp - state.last_entry_timestamp
                ).total_seconds()
                if gap > self.GAP_THRESHOLD_SECONDS:
                    events.append(
                        self._create_event(
                            event_type="log_timestamp_gap",
                            severity=Severity.CRITICAL,
                            data={
                                "file_path": file_path,
                                "gap_seconds": round(gap, 1),
                                "last_timestamp": state.last_entry_timestamp.isoformat(),
                                "next_timestamp": sorted_entries[
                                    0
                                ].timestamp.isoformat(),
                            },
                            confidence=0.80,
                        )
                    )

            # Update last entry timestamp
            if sorted_entries:
                state.last_entry_timestamp = sorted_entries[-1].timestamp
            state.entry_count += len(file_entries)

        return events


# =============================================================================
# 2. CredentialHarvestProbe
# =============================================================================


class CredentialHarvestProbe(MicroProbe):
    """Detects leaked credentials in log messages.

    Scans log messages for patterns matching:
        - AWS access keys (AKIA...)
        - Passwords in URLs (?password=, &pwd=)
        - JWTs (eyJ...)
        - API tokens and bearer tokens
        - Private keys (BEGIN RSA/EC PRIVATE KEY)

    MITRE: T1552.001 (Credentials In Files)
    """

    name = "credential_harvest"
    description = "Detects leaked credentials (AWS keys, passwords, JWTs) in logs"
    mitre_techniques = ["T1552.001"]
    mitre_tactics = ["credential_access"]
    default_enabled = True
    scan_interval = 10.0
    requires_root = False
    platforms = ["linux", "darwin"]
    requires_fields = ["log_entries"]

    # Credential patterns with names for reporting
    CREDENTIAL_PATTERNS = [
        ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
        (
            "aws_secret_key",
            re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"),
        ),
        (
            "password_in_url",
            re.compile(r"[?&](password|passwd|pwd|pass)=[^&\s]{1,100}", re.IGNORECASE),
        ),
        (
            "jwt_token",
            re.compile(
                r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
            ),
        ),
        ("bearer_token", re.compile(r"[Bb]earer\s+[A-Za-z0-9_\-\.]{20,}")),
        (
            "api_key_param",
            re.compile(
                r"[?&](api[_-]?key|apikey|token|auth[_-]?token)=[^&\s]{8,}",
                re.IGNORECASE,
            ),
        ),
        (
            "private_key",
            re.compile(r"-----BEGIN\s+(RSA|EC|DSA|OPENSSH)\s+PRIVATE\s+KEY-----"),
        ),
        ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}")),
        (
            "generic_secret",
            re.compile(
                r"(?i)(secret|token|key|password)\s*[=:]\s*['\"][A-Za-z0-9/+]{16,}['\"]"
            ),
        ),
    ]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Scan log messages for credential patterns."""
        events = []

        entries: List[LogEntry] = context.shared_data.get("log_entries", [])

        for entry in entries:
            message = entry.message
            if not message:
                continue

            for pattern_name, pattern in self.CREDENTIAL_PATTERNS:
                match = pattern.search(message)
                if match:
                    # Redact the matched value for safe logging
                    matched_text = match.group()
                    redacted = (
                        matched_text[:8] + "..." + matched_text[-4:]
                        if len(matched_text) > 16
                        else "***REDACTED***"
                    )

                    events.append(
                        self._create_event(
                            event_type="credential_in_log",
                            severity=Severity.HIGH,
                            data={
                                "credential_type": pattern_name,
                                "source": entry.source,
                                "file_path": entry.file_path,
                                "line_number": entry.line_number,
                                "redacted_match": redacted,
                                "process": entry.process_name,
                            },
                            confidence=0.85,
                        )
                    )
                    break  # One alert per log entry

        return events


# =============================================================================
# 3. ErrorSpikeAnomalyProbe
# =============================================================================


class ErrorSpikeAnomalyProbe(MicroProbe):
    """Detects anomalous spikes in ERROR-level log entries.

    Counts ERROR-level entries per source and alerts if the count exceeds
    3 standard deviations above the rolling mean (last 10 cycles).

    This can indicate:
        - Application under attack (injection, brute force)
        - Service degradation from DDoS
        - Backend compromise causing cascading errors

    MITRE: T1499 (Endpoint Denial of Service)
    """

    name = "error_spike_anomaly"
    description = "Detects ERROR rate spikes (>3 stddev above rolling mean)"
    mitre_techniques = ["T1499"]
    mitre_tactics = ["impact"]
    default_enabled = True
    scan_interval = 15.0
    requires_root = False
    platforms = ["linux", "darwin"]
    requires_fields = ["log_entries"]

    # Rolling window size for baseline
    WINDOW_SIZE = 10
    # Standard deviation multiplier for anomaly detection
    STDDEV_MULTIPLIER = 3.0

    def __init__(self) -> None:
        super().__init__()
        # History of error counts per source: source -> [count1, count2, ...]
        self.error_history: Dict[str, List[int]] = defaultdict(list)

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect ERROR rate anomalies per source."""
        events = []

        entries: List[LogEntry] = context.shared_data.get("log_entries", [])

        # Count errors per source this cycle
        error_counts: Dict[str, int] = defaultdict(int)
        for entry in entries:
            if entry.level == "ERROR":
                error_counts[entry.source] += 1

        # Analyze each source
        for source, current_count in error_counts.items():
            history = self.error_history[source]

            if len(history) >= 2:
                # Calculate rolling mean and stddev
                mean = sum(history) / len(history)
                variance = sum((x - mean) ** 2 for x in history) / len(history)
                stddev = variance**0.5

                threshold = mean + (self.STDDEV_MULTIPLIER * max(stddev, 1.0))

                if current_count > threshold and current_count > 5:
                    events.append(
                        self._create_event(
                            event_type="error_spike_detected",
                            severity=Severity.MEDIUM,
                            data={
                                "source": source,
                                "current_errors": current_count,
                                "rolling_mean": round(mean, 2),
                                "rolling_stddev": round(stddev, 2),
                                "threshold": round(threshold, 2),
                                "deviation_factor": round(
                                    (current_count - mean) / max(stddev, 1.0), 2
                                ),
                            },
                            confidence=0.75,
                        )
                    )

            # Update history (keep last WINDOW_SIZE entries)
            history.append(current_count)
            if len(history) > self.WINDOW_SIZE:
                self.error_history[source] = history[-self.WINDOW_SIZE :]

        return events


# =============================================================================
# 4. WebShellAccessProbe
# =============================================================================


class WebShellAccessProbe(MicroProbe):
    """Detects web shell access patterns in HTTP logs.

    Matches HTTP paths against known web shell filenames and patterns:
        - Known shells: cmd.php, c99.php, r57.php, b374k.php
        - Eval/exec endpoints: /eval, /shell, /cmd
        - Upload endpoints receiving POST requests to script paths
        - Suspicious JSP/ASP/PHP paths with command parameters

    MITRE: T1505.003 (Server Software Component: Web Shell)
    """

    name = "webshell_access"
    description = "Detects web shell access patterns in HTTP logs"
    mitre_techniques = ["T1505.003"]
    mitre_tactics = ["persistence"]
    default_enabled = True
    scan_interval = 10.0
    requires_root = False
    platforms = ["linux", "darwin"]
    requires_fields = ["log_entries"]

    # Known web shell filenames and paths
    WEBSHELL_PATHS = re.compile(
        r"(?i)/(cmd|c99|r57|b374k|wso|alfa|mini|p0wny|webadmin|adminer|"
        r"phpspy|shell|eval|backdoor|upload|filemanager|FilesMan|"
        r"safe0ver|IndoXploit|wsoshell|leafmailer|weevely|antsword)\."
        r"(php|jsp|asp|aspx|cgi|pl)",
    )

    # Suspicious query parameters indicating command execution
    COMMAND_PARAMS = re.compile(
        r"[?&](cmd|exec|command|run|execute|e|c|shell|eval|code)=",
        re.IGNORECASE,
    )

    # POST to script file extensions (upload/execution)
    SCRIPT_EXTENSIONS = re.compile(
        r"\.(php|jsp|asp|aspx|cgi|pl|py|sh|rb)(\?|$)",
        re.IGNORECASE,
    )

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect web shell access patterns."""
        events = []

        entries: List[LogEntry] = context.shared_data.get("log_entries", [])

        for entry in entries:
            if not entry.http_path:
                continue

            http_path = entry.http_path

            # Check for known web shell paths
            if self.WEBSHELL_PATHS.search(http_path):
                events.append(
                    self._create_event(
                        event_type="webshell_access_detected",
                        severity=Severity.CRITICAL,
                        data={
                            "http_path": http_path,
                            "http_method": entry.http_method,
                            "http_status": entry.http_status,
                            "remote_ip": entry.remote_ip,
                            "user_agent": entry.user_agent,
                            "source": entry.source,
                            "file_path": entry.file_path,
                        },
                        confidence=0.90,
                    )
                )
                continue

            # Check for command parameters
            if self.COMMAND_PARAMS.search(http_path):
                events.append(
                    self._create_event(
                        event_type="webshell_command_parameter",
                        severity=Severity.CRITICAL,
                        data={
                            "http_path": http_path,
                            "http_method": entry.http_method,
                            "http_status": entry.http_status,
                            "remote_ip": entry.remote_ip,
                            "user_agent": entry.user_agent,
                        },
                        confidence=0.85,
                    )
                )
                continue

            # POST to script files (potential upload/execution)
            if entry.http_method == "POST" and self.SCRIPT_EXTENSIONS.search(http_path):
                events.append(
                    self._create_event(
                        event_type="suspicious_script_post",
                        severity=Severity.CRITICAL,
                        data={
                            "http_path": http_path,
                            "http_method": "POST",
                            "http_status": entry.http_status,
                            "remote_ip": entry.remote_ip,
                            "user_agent": entry.user_agent,
                        },
                        confidence=0.80,
                    )
                )

        return events


# =============================================================================
# 5. Suspicious4xx5xxProbe
# =============================================================================


class Suspicious4xx5xxProbe(MicroProbe):
    """Detects scanning and abuse via HTTP 4xx/5xx status code clusters.

    Groups log entries by remote_ip and alerts when a single IP generates:
        - More than 20 4xx responses (scanning, brute force)
        - More than 10 5xx responses (exploitation attempts)

    MITRE: T1595 (Active Scanning)
    """

    name = "suspicious_4xx_5xx"
    description = "Detects HTTP 4xx/5xx clusters from single IPs (scanning)"
    mitre_techniques = ["T1595"]
    mitre_tactics = ["reconnaissance"]
    default_enabled = True
    scan_interval = 15.0
    requires_root = False
    platforms = ["linux", "darwin"]
    requires_fields = ["log_entries"]

    # Thresholds per IP per scan window
    THRESHOLD_4XX = 20
    THRESHOLD_5XX = 10

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect 4xx/5xx abuse patterns by IP."""
        events = []

        entries: List[LogEntry] = context.shared_data.get("log_entries", [])

        # Count 4xx and 5xx per remote IP
        ip_4xx: Dict[str, int] = defaultdict(int)
        ip_5xx: Dict[str, int] = defaultdict(int)
        ip_paths_4xx: Dict[str, List[str]] = defaultdict(list)
        ip_paths_5xx: Dict[str, List[str]] = defaultdict(list)

        for entry in entries:
            if not entry.remote_ip or not entry.http_status:
                continue

            ip = entry.remote_ip

            if 400 <= entry.http_status < 500:
                ip_4xx[ip] += 1
                if len(ip_paths_4xx[ip]) < 10:
                    ip_paths_4xx[ip].append(entry.http_path or "unknown")

            elif 500 <= entry.http_status < 600:
                ip_5xx[ip] += 1
                if len(ip_paths_5xx[ip]) < 10:
                    ip_paths_5xx[ip].append(entry.http_path or "unknown")

        # Alert on 4xx threshold
        for ip, count in ip_4xx.items():
            if count >= self.THRESHOLD_4XX:
                events.append(
                    self._create_event(
                        event_type="http_4xx_cluster",
                        severity=Severity.HIGH,
                        data={
                            "remote_ip": ip,
                            "count_4xx": count,
                            "sample_paths": ip_paths_4xx[ip][:10],
                            "threshold": self.THRESHOLD_4XX,
                        },
                        confidence=0.80,
                    )
                )

        # Alert on 5xx threshold
        for ip, count in ip_5xx.items():
            if count >= self.THRESHOLD_5XX:
                events.append(
                    self._create_event(
                        event_type="http_5xx_cluster",
                        severity=Severity.HIGH,
                        data={
                            "remote_ip": ip,
                            "count_5xx": count,
                            "sample_paths": ip_paths_5xx[ip][:10],
                            "threshold": self.THRESHOLD_5XX,
                        },
                        confidence=0.80,
                    )
                )

        return events


# =============================================================================
# 6. LogInjectionProbe
# =============================================================================


class LogInjectionProbe(MicroProbe):
    """Detects log injection and log poisoning attempts.

    Identifies malicious content injected into log entries:
        - CRLF injection (\\r\\n) for log forging
        - Null bytes (%00) for log truncation
        - Excessively long lines (>10KB) for buffer overflow
        - Encoded payloads (base64, URL-encoded shell commands)
        - ANSI escape sequences for terminal injection

    MITRE: T1562.006 (Impair Defenses: Indicator Blocking)
    """

    name = "log_injection"
    description = "Detects CRLF injection, null bytes, and encoded payloads in logs"
    mitre_techniques = ["T1562.006"]
    mitre_tactics = ["defense_evasion"]
    default_enabled = True
    scan_interval = 10.0
    requires_root = False
    platforms = ["linux", "darwin"]
    requires_fields = ["log_entries"]

    # Maximum safe line length in bytes
    MAX_LINE_LENGTH = 10240  # 10KB

    # CRLF injection patterns
    CRLF_PATTERN = re.compile(r"(\r\n|\r|\n|%0[dD]%0[aA]|%0[aA]|%0[dD])")

    # Null byte patterns
    NULL_PATTERN = re.compile(r"(%00|\x00)")

    # Encoded payload patterns (common shell/command injection via logs)
    ENCODED_PAYLOAD_PATTERNS = [
        (
            "base64_encoded_cmd",
            re.compile(r"(?:base64\s+-d|echo\s+[A-Za-z0-9+/=]{20,}\s*\|\s*base64)"),
        ),
        (
            "url_encoded_cmd",
            re.compile(r"(%2[fF]bin%2[fF]|%2[fF]etc%2[fF]|%2[fF]usr%2[fF])"),
        ),
        ("ansi_escape", re.compile(r"\x1b\[[\d;]*[a-zA-Z]")),
        ("shell_injection", re.compile(r"(\$\{[^}]*\}|`[^`]+`|\$\([^)]+\))")),
    ]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect log injection attempts."""
        events = []

        entries: List[LogEntry] = context.shared_data.get("log_entries", [])

        for entry in entries:
            message = entry.message
            if not message:
                continue

            # Check line length
            if len(message.encode("utf-8", errors="replace")) > self.MAX_LINE_LENGTH:
                events.append(
                    self._create_event(
                        event_type="log_oversized_entry",
                        severity=Severity.HIGH,
                        data={
                            "source": entry.source,
                            "file_path": entry.file_path,
                            "line_length": len(message),
                            "max_allowed": self.MAX_LINE_LENGTH,
                            "truncated_content": message[:200],
                        },
                        confidence=0.80,
                    )
                )

            # Check for CRLF injection
            if self.CRLF_PATTERN.search(message):
                events.append(
                    self._create_event(
                        event_type="log_crlf_injection",
                        severity=Severity.HIGH,
                        data={
                            "source": entry.source,
                            "file_path": entry.file_path,
                            "remote_ip": entry.remote_ip,
                            "truncated_content": message[:200],
                        },
                        confidence=0.85,
                    )
                )
                continue  # One alert per entry

            # Check for null bytes
            if self.NULL_PATTERN.search(message):
                events.append(
                    self._create_event(
                        event_type="log_null_byte_injection",
                        severity=Severity.HIGH,
                        data={
                            "source": entry.source,
                            "file_path": entry.file_path,
                            "remote_ip": entry.remote_ip,
                        },
                        confidence=0.85,
                    )
                )
                continue

            # Check for encoded payloads
            for pattern_name, pattern in self.ENCODED_PAYLOAD_PATTERNS:
                if pattern.search(message):
                    events.append(
                        self._create_event(
                            event_type="log_encoded_payload",
                            severity=Severity.HIGH,
                            data={
                                "pattern_type": pattern_name,
                                "source": entry.source,
                                "file_path": entry.file_path,
                                "remote_ip": entry.remote_ip,
                                "truncated_content": message[:200],
                            },
                            confidence=0.80,
                        )
                    )
                    break  # One alert per entry

        return events


# =============================================================================
# 7. PrivilegeEscalationLogProbe
# =============================================================================


class PrivilegeEscalationLogProbe(MicroProbe):
    """Detects privilege escalation attempts in system logs.

    Matches sudo/su/pkexec/doas patterns in syslog and auth.log:
        - Unusual user-to-root transitions
        - Failed sudo attempts (wrong password)
        - sudo with suspicious commands
        - pkexec and doas invocations
        - Repeated failed su attempts

    MITRE: T1548.003 (Abuse Elevation Control Mechanism: Sudo)
    """

    name = "privilege_escalation_log"
    description = "Detects sudo/su/pkexec/doas privilege escalation patterns"
    mitre_techniques = ["T1548.003"]
    mitre_tactics = ["privilege_escalation"]
    default_enabled = True
    scan_interval = 10.0
    requires_root = False
    platforms = ["linux", "darwin"]
    requires_fields = ["log_entries"]

    # Suspicious commands run via sudo
    SUSPICIOUS_SUDO_CMDS = re.compile(
        r"(?:COMMAND|command)=(?:/usr)?/s?bin/(?:bash|sh|zsh|dash|csh|"
        r"nc|ncat|netcat|wget|curl|python|perl|ruby|php|"
        r"chmod\s+[0-7]*[sS]|chown\s+root|"
        r"dd\s+if=|mount\s+-o\s+bind|nsenter|"
        r"visudo|passwd|useradd|adduser|usermod)",
        re.IGNORECASE,
    )

    # Sudo/su/pkexec/doas patterns
    PRIV_PATTERNS = [
        (
            "sudo_success",
            re.compile(
                r"sudo.*:\s+(\S+)\s+:\s+.*;\s+PWD=.*;\s+USER=root\s*;\s+COMMAND=",
            ),
        ),
        (
            "sudo_failure",
            re.compile(
                r"sudo.*:\s+(\S+)\s+:\s+\d+\s+incorrect\s+password\s+attempt",
                re.IGNORECASE,
            ),
        ),
        (
            "sudo_auth_failure",
            re.compile(
                r"sudo.*pam_unix.*authentication\s+failure.*user=(\S+)",
                re.IGNORECASE,
            ),
        ),
        (
            "su_session",
            re.compile(
                r"su\[\d+\]:\s+(?:Successful\s+su|pam_unix.*session\s+opened)\s+for\s+user\s+(\S+)\s+by\s+(\S+)",
                re.IGNORECASE,
            ),
        ),
        (
            "su_failure",
            re.compile(
                r"su\[\d+\]:\s+(?:FAILED\s+SU|pam_unix.*authentication\s+failure)",
                re.IGNORECASE,
            ),
        ),
        (
            "pkexec",
            re.compile(
                r"pkexec\[\d+\]:\s+(\S+):\s+Executing",
                re.IGNORECASE,
            ),
        ),
        (
            "doas",
            re.compile(
                r"doas\[\d+\]:\s+(\S+)\s+ran\s+command",
                re.IGNORECASE,
            ),
        ),
    ]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect privilege escalation patterns."""
        events = []

        entries: List[LogEntry] = context.shared_data.get("log_entries", [])

        for entry in entries:
            message = entry.message
            if not message:
                continue

            # Only check syslog/auth/journald sources
            if entry.source not in ("syslog", "auth", "journald", "unified_log"):
                continue

            for pattern_name, pattern in self.PRIV_PATTERNS:
                match = pattern.search(message)
                if match:
                    # Determine severity based on pattern type
                    if "failure" in pattern_name:
                        severity = Severity.HIGH
                        confidence = 0.85
                    elif pattern_name in ("pkexec", "doas"):
                        severity = Severity.HIGH
                        confidence = 0.80
                    else:
                        severity = Severity.HIGH
                        confidence = 0.75

                    event_data: Dict[str, Any] = {
                        "pattern_type": pattern_name,
                        "source": entry.source,
                        "file_path": entry.file_path,
                        "process": entry.process_name,
                        "pid": entry.pid,
                        "truncated_message": message[:300],
                    }

                    # Extract user from match groups
                    groups = match.groups()
                    if groups:
                        event_data["user"] = groups[0]
                    if len(groups) > 1:
                        event_data["target_user"] = groups[1]

                    # Check for suspicious commands in sudo
                    if pattern_name == "sudo_success":
                        if self.SUSPICIOUS_SUDO_CMDS.search(message):
                            severity = Severity.HIGH
                            confidence = 0.90
                            event_data["suspicious_command"] = True

                    events.append(
                        self._create_event(
                            event_type="privilege_escalation_detected",
                            severity=severity,
                            data=event_data,
                            confidence=confidence,
                            tags=["correlation_group:privilege_escalation"],
                        )
                    )
                    break  # One detection per entry

        return events


# =============================================================================
# 8. ContainerBreakoutLogProbe
# =============================================================================


class ContainerBreakoutLogProbe(MicroProbe):
    """Detects container escape indicators in system logs.

    Matches log patterns indicating container breakout attempts:
        - nsenter usage (namespace entry)
        - Mounting /proc from within container
        - CAP_SYS_ADMIN capability usage
        - /proc/1/root access (host PID namespace escape)
        - Docker socket access from within container
        - cgroup escape patterns
        - Kernel exploit indicators from container context

    MITRE: T1611 (Escape to Host)
    """

    name = "container_breakout_log"
    description = (
        "Detects container escape indicators (nsenter, proc mount, cap_sys_admin)"
    )
    mitre_techniques = ["T1611"]
    mitre_tactics = ["privilege_escalation"]
    default_enabled = True
    scan_interval = 10.0
    requires_root = False
    platforms = ["linux", "darwin"]
    requires_fields = ["log_entries"]

    # Container breakout patterns
    BREAKOUT_PATTERNS = [
        (
            "nsenter",
            re.compile(
                r"\bnsenter\b.*(?:--target|--mount|--pid|--net|-t\s+\d+)",
                re.IGNORECASE,
            ),
        ),
        (
            "proc_mount",
            re.compile(
                r"\bmount\b.*\bproc\b.*(?:/proc|procfs)",
                re.IGNORECASE,
            ),
        ),
        (
            "cap_sys_admin",
            re.compile(
                r"\b(?:cap_sys_admin|CAP_SYS_ADMIN|capsh|setcap|getcap)\b",
            ),
        ),
        (
            "proc_1_root",
            re.compile(
                r"/proc/1/(?:root|ns/|cgroup|exe|fd)",
            ),
        ),
        (
            "docker_socket",
            re.compile(
                r"(?:/var/run/docker\.sock|/run/docker\.sock|docker\.sock)",
            ),
        ),
        (
            "cgroup_escape",
            re.compile(
                r"(?:release_agent|notify_on_release|cgroup\.event_control)",
            ),
        ),
        (
            "runc_escape",
            re.compile(
                r"(?:runc|crun|youki).*(?:exec|--no-pivot|--rootless)",
                re.IGNORECASE,
            ),
        ),
        (
            "chroot_escape",
            re.compile(
                r"(?:chroot\s+/|pivot_root|unshare\s+-[a-z]*m)",
                re.IGNORECASE,
            ),
        ),
    ]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect container breakout indicators."""
        events = []

        entries: List[LogEntry] = context.shared_data.get("log_entries", [])

        for entry in entries:
            message = entry.message
            if not message:
                continue

            for pattern_name, pattern in self.BREAKOUT_PATTERNS:
                if pattern.search(message):
                    events.append(
                        self._create_event(
                            event_type="container_breakout_indicator",
                            severity=Severity.CRITICAL,
                            data={
                                "indicator_type": pattern_name,
                                "source": entry.source,
                                "file_path": entry.file_path,
                                "process": entry.process_name,
                                "pid": entry.pid,
                                "truncated_message": message[:300],
                            },
                            confidence=0.85,
                        )
                    )
                    break  # One detection per entry

        return events


# =============================================================================
# Probe Registry
# =============================================================================

APPLOG_PROBES = [
    LogTamperingProbe,
    CredentialHarvestProbe,
    ErrorSpikeAnomalyProbe,
    WebShellAccessProbe,
    Suspicious4xx5xxProbe,
    LogInjectionProbe,
    PrivilegeEscalationLogProbe,
    ContainerBreakoutLogProbe,
]


def create_applog_probes() -> List[MicroProbe]:
    """Create instances of all AppLog probes.

    Returns:
        List of initialized AppLog probe instances
    """
    return [probe_class() for probe_class in APPLOG_PROBES]


__all__ = [
    "APPLOG_PROBES",
    "ContainerBreakoutLogProbe",
    "create_applog_probes",
    "CredentialHarvestProbe",
    "ErrorSpikeAnomalyProbe",
    "LogEntry",
    "LogFileState",
    "LogInjectionProbe",
    "LogTamperingProbe",
    "PrivilegeEscalationLogProbe",
    "Suspicious4xx5xxProbe",
    "WebShellAccessProbe",
]
