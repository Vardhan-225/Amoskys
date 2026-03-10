"""macOS Application Log Observatory probes — threat detection via app log analysis.

7 probes covering defense evasion, credential access, impact, initial access, and
privilege escalation tactics:
    1. WebShellAccessProbe    — T1505.003 Web shell request patterns
    2. LogTamperingProbe      — T1070.002 Log gap and deletion detection
    3. ErrorSpikeProbe        — T1499    Application error rate anomalies
    4. CredentialHarvestProbe  — T1552.001 Credential patterns in logs
    5. PrivEscLogProbe        — T1548    Privilege escalation patterns
    6. SQLInjectionProbe      — T1190    SQL injection pattern detection
    7. AuthBypassProbe        — T1556    Authentication bypass patterns
"""

from __future__ import annotations

import collections
import logging
import re
import time
from typing import Any, Dict, List, Optional, Set

from amoskys.agents.common.probes import (
    MicroProbe,
    ProbeContext,
    Severity,
    TelemetryEvent,
)

logger = logging.getLogger(__name__)


# ── Probe 1: Web Shell Access Detection ──────────────────────────────────────


class WebShellAccessProbe(MicroProbe):
    """Detect web shell request patterns in application logs.

    MITRE: T1505.003 — Server Software Component: Web Shell

    Web shells are server-side scripts that provide remote command execution.
    Common indicators include URL parameters like cmd=, eval(), system(), exec(),
    and passthru() appearing in web server log messages.
    """

    name = "macos_applog_webshell"
    description = "Detects web shell access patterns in web server logs"
    platforms = ["darwin"]
    mitre_techniques = ["T1505.003"]
    mitre_tactics = ["defense_evasion"]
    scan_interval = 10.0
    requires_fields = ["app_logs"]
    maturity = "stable"
    false_positive_notes = [
        "Legitimate PHP debugging tools may reference eval() or exec()",
        "Application frameworks with 'system' in URL routes can trigger false matches",
    ]
    evasion_notes = [
        "URL-encoded or double-encoded payloads evade simple string matching",
        "Web shells using custom parameter names instead of cmd/eval avoid detection",
    ]

    # Patterns indicative of web shell activity
    _WEBSHELL_PATTERNS = re.compile(
        r"(?:cmd\s*=|eval\s*\(|system\s*\(|exec\s*\(|passthru\s*\(|"
        r"shell_exec\s*\(|popen\s*\(|proc_open\s*\(|"
        r"base64_decode\s*\(|phpinfo\s*\(|"
        r"\bwget\s+http|curl\s+-[oO]|/bin/(?:ba)?sh\b|"
        r"\.php\?(?:\w+=.*&)*(?:cmd|command|exec|run|action)\s*=)",
        re.IGNORECASE,
    )

    _WEB_PROCESSES = frozenset({"httpd", "nginx", "node", "ruby", "python", "java"})

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        app_logs = context.shared_data.get("app_logs", [])

        for entry in app_logs:
            if entry.process not in self._WEB_PROCESSES:
                continue

            match = self._WEBSHELL_PATTERNS.search(entry.message)
            if match:
                events.append(
                    self._create_event(
                        event_type="webshell_access_detected",
                        severity=Severity.CRITICAL,
                        data={
                            "process": entry.process,
                            "pid": entry.pid,
                            "matched_pattern": match.group(0)[:100],
                            "message_excerpt": entry.message[:300],
                            "log_level": entry.log_level,
                            "subsystem": entry.subsystem,
                            "timestamp": entry.timestamp,
                        },
                        confidence=0.85,
                    )
                )

        return events


# ── Probe 2: Log Tampering Detection ─────────────────────────────────────────


class LogTamperingProbe(MicroProbe):
    """Detect log tampering via timestamp gaps and deletion patterns.

    MITRE: T1070.002 — Indicator Removal: Clear Linux or Mac System Logs

    Attackers tamper with logs to cover their tracks. Indicators include sudden
    timestamp jumps (gaps where logs were deleted), references to log file
    deletion or truncation, and evidence of log rotation manipulation.
    """

    name = "macos_applog_log_tampering"
    description = "Detects log gaps and deletion patterns indicating tampering"
    platforms = ["darwin"]
    mitre_techniques = ["T1070.002"]
    mitre_tactics = ["defense_evasion"]
    scan_interval = 15.0
    requires_fields = ["app_logs"]
    maturity = "stable"
    false_positive_notes = [
        "Legitimate log rotation creates expected timestamp gaps",
        "Service restarts produce natural gaps in logging",
    ]
    evasion_notes = [
        "Gradual log deletion over time avoids sudden gap detection",
        "Replacing logs with fabricated entries preserves timestamp continuity",
    ]

    # Minimum gap (seconds) between consecutive logs to flag as suspicious
    GAP_THRESHOLD_S = 300.0  # 5-minute gap in a 30s window is suspicious

    # Patterns indicating log manipulation
    _TAMPERING_PATTERNS = re.compile(
        r"(?:log\s+(?:file\s+)?(?:deleted|removed|truncated|cleared|purged)|"
        r"rm\s+-[rf]*\s+.*\.log|"
        r"truncate\s+-s\s*0|"
        r"> /var/log/|"
        r"shred\s+.*\.log|"
        r"history\s+-c|"
        r"unset\s+HISTFILE)",
        re.IGNORECASE,
    )

    def __init__(self) -> None:
        super().__init__()
        self._last_timestamps: Dict[str, float] = {}

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        app_logs = context.shared_data.get("app_logs", [])

        # Group logs by process for gap analysis
        by_process: Dict[str, list] = collections.defaultdict(list)
        for entry in app_logs:
            by_process[entry.process].append(entry)

        # Check 1: Timestamp gap detection per process
        for process, entries in by_process.items():
            sorted_entries = sorted(entries, key=lambda e: e.timestamp)

            for i in range(1, len(sorted_entries)):
                gap = sorted_entries[i].timestamp - sorted_entries[i - 1].timestamp
                if gap >= self.GAP_THRESHOLD_S:
                    events.append(
                        self._create_event(
                            event_type="log_timestamp_gap",
                            severity=Severity.HIGH,
                            data={
                                "process": process,
                                "gap_seconds": round(gap, 2),
                                "before_timestamp": sorted_entries[i - 1].timestamp,
                                "after_timestamp": sorted_entries[i].timestamp,
                                "threshold_seconds": self.GAP_THRESHOLD_S,
                            },
                            confidence=0.70,
                        )
                    )

            # Track last timestamp for cross-cycle gap detection
            if sorted_entries:
                last_ts = self._last_timestamps.get(process)
                current_first = sorted_entries[0].timestamp
                if last_ts and (current_first - last_ts) >= self.GAP_THRESHOLD_S:
                    events.append(
                        self._create_event(
                            event_type="log_cross_cycle_gap",
                            severity=Severity.MEDIUM,
                            data={
                                "process": process,
                                "gap_seconds": round(current_first - last_ts, 2),
                                "last_seen": last_ts,
                                "current_first": current_first,
                            },
                            confidence=0.60,
                        )
                    )
                self._last_timestamps[process] = sorted_entries[-1].timestamp

        # Check 2: Log tampering patterns in messages
        for entry in app_logs:
            match = self._TAMPERING_PATTERNS.search(entry.message)
            if match:
                events.append(
                    self._create_event(
                        event_type="log_tampering_pattern",
                        severity=Severity.CRITICAL,
                        data={
                            "process": entry.process,
                            "pid": entry.pid,
                            "matched_pattern": match.group(0)[:100],
                            "message_excerpt": entry.message[:300],
                            "timestamp": entry.timestamp,
                        },
                        confidence=0.85,
                    )
                )

        return events


# ── Probe 3: Application Error Spike ─────────────────────────────────────────


class ErrorSpikeProbe(MicroProbe):
    """Detect application error rate anomalies indicative of attack impact.

    MITRE: T1499 — Endpoint Denial of Service

    A sudden spike in application errors can indicate denial-of-service attacks,
    exploitation attempts, or system compromise. We track error counts per process
    across cycles and alert when error rates spike beyond baseline.
    """

    name = "macos_applog_error_spike"
    description = (
        "Detects application error rate anomalies (DoS/exploitation indicator)"
    )
    platforms = ["darwin"]
    mitre_techniques = ["T1499"]
    mitre_tactics = ["impact"]
    scan_interval = 15.0
    requires_fields = ["app_logs"]
    maturity = "stable"
    false_positive_notes = [
        "Application deployments or restarts can cause temporary error spikes",
        "Configuration changes may trigger transient error bursts",
    ]
    evasion_notes = [
        "Low-and-slow attacks that stay below error thresholds evade detection",
        "Attacks that suppress error logging avoid triggering this probe",
    ]

    _ERROR_LEVELS = frozenset({"Error", "Fault", "error", "fault", "ERROR", "FAULT"})
    SPIKE_MULTIPLIER = 3.0  # Current errors must exceed baseline * this
    MIN_ERRORS_TO_ALERT = 10  # Minimum errors in a cycle to trigger
    BASELINE_CYCLES = 5  # Cycles to build initial baseline

    def __init__(self) -> None:
        super().__init__()
        # process → list of error counts per cycle (rolling window)
        self._error_history: Dict[str, List[int]] = collections.defaultdict(list)
        self._cycle_count = 0

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        app_logs = context.shared_data.get("app_logs", [])
        self._cycle_count += 1

        # Count errors per process
        error_counts: Dict[str, int] = collections.defaultdict(int)
        for entry in app_logs:
            if entry.log_level in self._ERROR_LEVELS:
                error_counts[entry.process] += 1

        # Update history and check for spikes
        for process, count in error_counts.items():
            history = self._error_history[process]
            history.append(count)

            # Keep rolling window of 20 cycles
            if len(history) > 20:
                history.pop(0)

            # Need baseline before alerting
            if self._cycle_count <= self.BASELINE_CYCLES:
                continue

            if count < self.MIN_ERRORS_TO_ALERT:
                continue

            # Calculate baseline from previous cycles (excluding current)
            baseline_counts = history[:-1] if len(history) > 1 else [0]
            baseline_avg = (
                sum(baseline_counts) / len(baseline_counts) if baseline_counts else 0
            )

            if baseline_avg == 0:
                # No previous errors — any significant count is anomalous
                if count >= self.MIN_ERRORS_TO_ALERT:
                    events.append(
                        self._create_event(
                            event_type="error_spike_new_process",
                            severity=Severity.HIGH,
                            data={
                                "process": process,
                                "error_count": count,
                                "baseline_avg": 0,
                                "cycle": self._cycle_count,
                            },
                            confidence=0.70,
                        )
                    )
            elif count >= baseline_avg * self.SPIKE_MULTIPLIER:
                events.append(
                    self._create_event(
                        event_type="error_spike_detected",
                        severity=Severity.HIGH,
                        data={
                            "process": process,
                            "error_count": count,
                            "baseline_avg": round(baseline_avg, 2),
                            "spike_ratio": round(count / baseline_avg, 2),
                            "threshold_multiplier": self.SPIKE_MULTIPLIER,
                            "cycle": self._cycle_count,
                        },
                        confidence=min(
                            0.95,
                            0.6 + (count / baseline_avg - self.SPIKE_MULTIPLIER) * 0.05,
                        ),
                    )
                )

        return events


# ── Probe 4: Credential Harvest Detection ────────────────────────────────────


class CredentialHarvestProbe(MicroProbe):
    """Detect credential patterns leaked or harvested in application logs.

    MITRE: T1552.001 — Unsecured Credentials: Credentials in Files

    Applications may inadvertently log sensitive credentials such as passwords,
    API keys, tokens, and secrets. Attackers also inject credential-harvesting
    payloads that surface secrets in error messages.
    """

    name = "macos_applog_credential_harvest"
    description = "Detects credential patterns in application logs (password, api_key, token, secret)"
    platforms = ["darwin"]
    mitre_techniques = ["T1552.001"]
    mitre_tactics = ["credential_access"]
    scan_interval = 10.0
    requires_fields = ["app_logs"]
    maturity = "stable"
    false_positive_notes = [
        "Debug-level logs may contain sanitized credential placeholders",
        "Password reset workflows may log 'password' keyword without actual values",
    ]
    evasion_notes = [
        "Encoded or encrypted credentials evade plaintext pattern matching",
        "Custom parameter names for secrets bypass known keyword detection",
    ]

    _CREDENTIAL_PATTERNS = re.compile(
        r"(?:password\s*[=:]\s*\S+|"
        r"api_key\s*[=:]\s*\S+|"
        r"api[-_]?secret\s*[=:]\s*\S+|"
        r"token\s*[=:]\s*[A-Za-z0-9._\-]{16,}|"
        r"secret\s*[=:]\s*\S+|"
        r"(?:aws_)?access_key(?:_id)?\s*[=:]\s*\S+|"
        r"private_key\s*[=:]\s*\S+|"
        r"bearer\s+[A-Za-z0-9._\-]{16,}|"
        r"authorization\s*:\s*(?:basic|bearer)\s+\S+)",
        re.IGNORECASE,
    )

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        app_logs = context.shared_data.get("app_logs", [])

        for entry in app_logs:
            match = self._CREDENTIAL_PATTERNS.search(entry.message)
            if match:
                # Redact the actual credential value for safety
                matched = match.group(0)
                redacted = self._redact_value(matched)

                events.append(
                    self._create_event(
                        event_type="credential_in_logs",
                        severity=Severity.HIGH,
                        data={
                            "process": entry.process,
                            "pid": entry.pid,
                            "credential_type": self._classify_credential(matched),
                            "pattern_matched": redacted,
                            "log_level": entry.log_level,
                            "subsystem": entry.subsystem,
                            "timestamp": entry.timestamp,
                        },
                        confidence=0.80,
                    )
                )

        return events

    @staticmethod
    def _redact_value(matched: str) -> str:
        """Redact the credential value, keeping only the key name."""
        for sep in ("=", ":"):
            if sep in matched:
                key, _, value = matched.partition(sep)
                visible = value.strip()[:4] if len(value.strip()) > 4 else "***"
                return f"{key}{sep}{visible}..."
        return matched[:20] + "..."

    @staticmethod
    def _classify_credential(matched: str) -> str:
        """Classify the type of credential found."""
        lower = matched.lower()
        if "password" in lower:
            return "password"
        if "api_key" in lower or "api-key" in lower:
            return "api_key"
        if "token" in lower or "bearer" in lower:
            return "token"
        if "secret" in lower:
            return "secret"
        if "access_key" in lower:
            return "access_key"
        if "private_key" in lower:
            return "private_key"
        if "authorization" in lower:
            return "authorization_header"
        return "unknown"


# ── Probe 5: Privilege Escalation via App Logs ───────────────────────────────


class PrivEscLogProbe(MicroProbe):
    """Detect privilege escalation patterns in application logs.

    MITRE: T1548 — Abuse Elevation Control Mechanism

    Detects evidence of privilege escalation attempts in application logs,
    including sudo invocations, su commands, and macOS AuthorizationRef
    usage from application processes that typically should not elevate.
    """

    name = "macos_applog_privesc"
    description = (
        "Detects privilege escalation patterns (sudo, su, AuthorizationRef) in app logs"
    )
    platforms = ["darwin"]
    mitre_techniques = ["T1548"]
    mitre_tactics = ["privilege_escalation"]
    scan_interval = 10.0
    requires_fields = ["app_logs"]
    maturity = "stable"
    false_positive_notes = [
        "Package managers (pip, npm) may invoke sudo for global installs",
        "Database maintenance scripts may use su to switch to service accounts",
    ]
    evasion_notes = [
        "Using dscl or security commands instead of sudo/su for elevation",
        "Exploiting SUID binaries does not generate sudo/su log entries",
    ]

    _PRIVESC_PATTERNS = re.compile(
        r"(?:\bsudo\s+|"
        r"\bsu\s+-\s+|"
        r"\bsu\s+\w+|"
        r"AuthorizationRef|"
        r"Security\.framework.*authorize|"
        r"setuid\s*\(|"
        r"seteuid\s*\(|"
        r"setgid\s*\(|"
        r"privilege.*escalat|"
        r"running\s+as\s+root|"
        r"gained\s+root\b|"
        r"elevation\s+request)",
        re.IGNORECASE,
    )

    # Processes that should not typically escalate privileges
    _SUSPICIOUS_ESCALATORS = frozenset(
        {
            "httpd",
            "nginx",
            "node",
            "python",
            "ruby",
            "java",
        }
    )

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        app_logs = context.shared_data.get("app_logs", [])

        for entry in app_logs:
            match = self._PRIVESC_PATTERNS.search(entry.message)
            if match:
                # Higher severity if escalation comes from a web-facing process
                severity = (
                    Severity.CRITICAL
                    if entry.process in self._SUSPICIOUS_ESCALATORS
                    else Severity.HIGH
                )
                confidence = (
                    0.85 if entry.process in self._SUSPICIOUS_ESCALATORS else 0.70
                )

                events.append(
                    self._create_event(
                        event_type="privilege_escalation_detected",
                        severity=severity,
                        data={
                            "process": entry.process,
                            "pid": entry.pid,
                            "matched_pattern": match.group(0)[:100],
                            "message_excerpt": entry.message[:300],
                            "log_level": entry.log_level,
                            "is_web_process": entry.process
                            in self._SUSPICIOUS_ESCALATORS,
                            "timestamp": entry.timestamp,
                        },
                        confidence=confidence,
                    )
                )

        return events


# ── Probe 6: SQL Injection Detection ─────────────────────────────────────────


class SQLInjectionProbe(MicroProbe):
    """Detect SQL injection patterns in application logs.

    MITRE: T1190 — Exploit Public-Facing Application

    SQL injection attacks appear in application error logs when malformed queries
    cause database errors. Common patterns include UNION SELECT, OR 1=1,
    single-quote syntax errors, and comment-based injection (--).
    """

    name = "macos_applog_sqli"
    description = "Detects SQL injection patterns in application error logs"
    platforms = ["darwin"]
    mitre_techniques = ["T1190"]
    mitre_tactics = ["initial_access"]
    scan_interval = 10.0
    requires_fields = ["app_logs"]
    maturity = "stable"
    false_positive_notes = [
        "Legitimate SQL queries containing UNION or OR clauses in error logs",
        "ORM-generated queries with complex WHERE clauses may resemble injection",
    ]
    evasion_notes = [
        "Time-based blind SQLi does not generate visible error patterns",
        "WAF bypass techniques using encoding or case variation avoid signatures",
    ]

    _SQLI_PATTERNS = re.compile(
        r"(?:UNION\s+(?:ALL\s+)?SELECT|"
        r"OR\s+1\s*=\s*1|"
        r"OR\s+['\"]1['\"]=['\"]1|"
        r"AND\s+1\s*=\s*1|"
        r"'\s*OR\s+'|"
        r";\s*DROP\s+TABLE|"
        r";\s*DELETE\s+FROM|"
        r";\s*INSERT\s+INTO|"
        r";\s*UPDATE\s+\w+\s+SET|"
        r"CONCAT\s*\(.*SELECT|"
        r"GROUP_CONCAT\s*\(|"
        r"INFORMATION_SCHEMA|"
        r"LOAD_FILE\s*\(|"
        r"INTO\s+(?:OUT|DUMP)FILE|"
        r"xp_cmdshell|"
        r"WAITFOR\s+DELAY|"
        r"BENCHMARK\s*\(|"
        r"(?:syntax\s+error|unterminated\s+quoted\s+string).*(?:near|at)\s+['\"])",
        re.IGNORECASE,
    )

    _DB_PROCESSES = frozenset(
        {"postgres", "mysqld", "httpd", "nginx", "node", "python", "ruby", "java"}
    )

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        app_logs = context.shared_data.get("app_logs", [])

        for entry in app_logs:
            if entry.process not in self._DB_PROCESSES:
                continue

            match = self._SQLI_PATTERNS.search(entry.message)
            if match:
                # Higher severity for database processes directly
                severity = (
                    Severity.CRITICAL
                    if entry.process in ("postgres", "mysqld")
                    else Severity.HIGH
                )

                events.append(
                    self._create_event(
                        event_type="sql_injection_detected",
                        severity=severity,
                        data={
                            "process": entry.process,
                            "pid": entry.pid,
                            "matched_pattern": match.group(0)[:100],
                            "message_excerpt": entry.message[:300],
                            "log_level": entry.log_level,
                            "is_db_process": entry.process in ("postgres", "mysqld"),
                            "timestamp": entry.timestamp,
                        },
                        confidence=0.80,
                    )
                )

        return events


# ── Probe 7: Authentication Bypass Detection ─────────────────────────────────


class AuthBypassProbe(MicroProbe):
    """Detect authentication bypass patterns in application logs.

    MITRE: T1556 — Modify Authentication Process

    Attackers bypass authentication by manipulating tokens, exploiting null
    checks, or using override mechanisms. Log patterns include null auth tokens,
    bypass keywords, and authentication override references.
    """

    name = "macos_applog_auth_bypass"
    description = "Detects authentication bypass patterns (null tokens, overrides)"
    platforms = ["darwin"]
    mitre_techniques = ["T1556"]
    mitre_tactics = ["credential_access"]
    scan_interval = 10.0
    requires_fields = ["app_logs"]
    maturity = "experimental"
    false_positive_notes = [
        "Development/staging environments may have auth bypass enabled intentionally",
        "Health check endpoints may log with null authentication",
    ]
    evasion_notes = [
        "Custom authentication frameworks may not log bypass attempts",
        "Successful bypasses that skip logging entirely leave no trace",
    ]

    _AUTH_BYPASS_PATTERNS = re.compile(
        r"(?:auth_token\s*=\s*(?:null|none|nil|undefined|empty|\"\")|"
        r"authentication\s+bypass|"
        r"auth\s+bypass|"
        r"bypass\s+auth(?:entication)?|"
        r"override\s+auth(?:entication)?|"
        r"auth(?:entication)?\s+override|"
        r"skip(?:ping)?\s+auth(?:entication)?|"
        r"auth(?:entication)?\s+disabled|"
        r"invalid\s+(?:jwt|token|session)\s+accepted|"
        r"forged?\s+(?:token|session|cookie)|"
        r"(?:jwt|token)\s+(?:verification|validation)\s+(?:skipped|bypassed|failed)|"
        r"unauthorized\s+access\s+(?:granted|allowed))",
        re.IGNORECASE,
    )

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        app_logs = context.shared_data.get("app_logs", [])

        for entry in app_logs:
            match = self._AUTH_BYPASS_PATTERNS.search(entry.message)
            if match:
                events.append(
                    self._create_event(
                        event_type="auth_bypass_detected",
                        severity=Severity.CRITICAL,
                        data={
                            "process": entry.process,
                            "pid": entry.pid,
                            "matched_pattern": match.group(0)[:100],
                            "message_excerpt": entry.message[:300],
                            "log_level": entry.log_level,
                            "subsystem": entry.subsystem,
                            "timestamp": entry.timestamp,
                        },
                        confidence=0.75,
                    )
                )

        return events


# ── Factory ──────────────────────────────────────────────────────────────────


def create_applog_probes() -> List[MicroProbe]:
    """Create all macOS Application Log Observatory probes."""
    return [
        WebShellAccessProbe(),
        LogTamperingProbe(),
        ErrorSpikeProbe(),
        CredentialHarvestProbe(),
        PrivEscLogProbe(),
        SQLInjectionProbe(),
        AuthBypassProbe(),
    ]
