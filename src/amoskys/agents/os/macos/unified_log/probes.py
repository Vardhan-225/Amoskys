"""macOS Unified Log Probes — 6 detection probes for Unified Logging events.

Each probe consumes LogEntry data from MacOSUnifiedLogCollector via
shared_data["log_entries"]. Every probe is macOS-only (platforms=["darwin"]).

Probes:
    1. SecurityFrameworkProbe — PKI/certificate/trust events (T1553)
    2. GatekeeperProbe — Gatekeeper bypass/anomaly detection (T1553.001)
    3. InstallerActivityProbe — installer package activity (T1204.002)
    4. XPCAnomalyProbe — suspicious XPC activity (T1559)
    5. TCCEventProbe — TCC permission changes, degraded without FDA (T1548)
    6. SharingServiceProbe — AirDrop/sharing activity (T1105)

Design notes:
    - Probes filter log_entries by event_type matching their predicate group
    - Pattern matching on eventMessage for security-relevant keywords
    - GatekeeperProbe checks for assessment failures and quarantine bypasses
    - TCCEventProbe is explicitly DEGRADED without FDA (only current-session
      TCC events are visible to non-root without Full Disk Access)
    - XPCAnomalyProbe watches for connection rejection, coding errors, and
      crash patterns that indicate exploitation attempts
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional

from amoskys.agents.common.probes import (
    MicroProbe,
    ProbeContext,
    Severity,
    TelemetryEvent,
)

logger = logging.getLogger(__name__)


# Self-exclusion: filter out AMOSKYS own log entries
_AMOSKYS_LOG_PROCESSES = frozenset(
    {
        "amoskys",
        "amoskys-agent",
        "amoskys-collector",
    }
)


def _is_amoskys_log_entry(entry) -> bool:
    """Return True if this log entry was produced by AMOSKYS itself."""
    proc_lower = (entry.process or "").lower()
    return proc_lower in _AMOSKYS_LOG_PROCESSES or "amoskys" in proc_lower


# =============================================================================
# 1. SecurityFrameworkProbe
# =============================================================================


# Keywords in securityd messages that indicate security-relevant events.
# Must be specific enough to avoid matching routine DB operations
# ("replaced <private> in SecDbConnection"), OCSP noise, and anchor records.
_SECURITY_KEYWORDS = {
    # Certificate / PKI events — specific phrases, not bare words
    "certificate.*(?:invalid|revoked|expired|untrusted)": (
        "cert_invalid",
        Severity.HIGH,
    ),
    "trust evaluation.*fail": ("trust_evaluation_fail", Severity.HIGH),
    "cert.*revoked": ("cert_revoked", Severity.HIGH),
    "cert.*expired": ("cert_expired", Severity.MEDIUM),
    "self-signed": ("cert_self_signed", Severity.MEDIUM),
    "untrusted root": ("cert_untrusted_root", Severity.HIGH),
    # Keychain events — only interesting ones
    "keychain.*unlock": ("keychain_unlock", Severity.LOW),
    "keychain.*(?:dump|export|copy all)": ("keychain_export", Severity.CRITICAL),
    # Code signing
    "code signing.*(?:fail|invalid|reject)": ("code_signing_failure", Severity.HIGH),
    "signature.*invalid": ("signature_invalid", Severity.HIGH),
    # Policy failures
    "policy.*(?:deny|block|reject|fail)": ("policy_denied", Severity.HIGH),
    "access.*denied": ("access_denied", Severity.HIGH),
    "access.*blocked": ("access_blocked", Severity.HIGH),
}

# Benign securityd messages to skip (normal DB ops, OCSP, anchor records)
_SECURITY_BENIGN_PATTERNS = [
    r"replaced.*secdbconnection",
    r"secdbconnection.*open",
    r"ocsp responder.*did not include",
    r"malformed anchor records",
    r"new thread",
    r"enabling system keychain",
    r"no pending evals",
    r"completed async eval",
]


class SecurityFrameworkProbe(MicroProbe):
    """Detects PKI, certificate, and trust events from securityd.

    Monitors the com.apple.securityd subsystem for certificate validation
    failures, revocations, trust evaluation anomalies, keychain access,
    and code signing events.

    MITRE: T1553 (Subvert Trust Controls)
    """

    name = "macos_security_framework"
    description = "Detects PKI/certificate/trust events from securityd"
    platforms = ["darwin"]
    mitre_techniques = ["T1553"]
    mitre_tactics = ["defense_evasion"]
    scan_interval = 15.0
    requires_fields = ["log_entries"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        log_entries = context.shared_data.get("log_entries", [])

        for entry in log_entries:
            if entry.event_type != "security":
                continue

            # Self-exclusion: skip AMOSKYS own log entries
            if _is_amoskys_log_entry(entry):
                continue

            message_lower = entry.message.lower()

            # Skip known-benign securityd noise (DB ops, OCSP, anchor records)
            if any(re.search(bp, message_lower) for bp in _SECURITY_BENIGN_PATTERNS):
                continue

            for pattern, (event_subtype, severity) in _SECURITY_KEYWORDS.items():
                if re.search(pattern, message_lower):
                    events.append(
                        self._create_event(
                            event_type=f"security_framework_{event_subtype}",
                            severity=severity,
                            data={
                                "probe_name": self.name,
                                "detection_source": "log_show",
                                "subsystem": entry.subsystem,
                                "process": entry.process,
                                "category": entry.category,
                                "message": entry.message[:500],
                                "event_subtype": event_subtype,
                                "log_timestamp": entry.timestamp,
                                "process_id": entry.process_id,
                            },
                            confidence=0.7,
                        )
                    )
                    break  # One match per log entry

        return events


# =============================================================================
# 2. GatekeeperProbe
# =============================================================================


# Gatekeeper message patterns indicating bypass or anomaly
_GATEKEEPER_PATTERNS = [
    # Assessment failures
    (r"assessment.*(?:reject|deny|fail|block)", "assessment_failure", Severity.HIGH),
    # Quarantine bypass
    (
        r"quarantine.*(?:bypass|remove|strip|clear)",
        "quarantine_bypass",
        Severity.CRITICAL,
    ),
    (
        r"xattr.*com\.apple\.quarantine.*(?:remov|strip|clear)",
        "quarantine_xattr_removed",
        Severity.CRITICAL,
    ),
    # Notarization failures
    (r"notariz.*(?:fail|reject|invalid|error)", "notarization_failure", Severity.HIGH),
    # First launch of unidentified app
    (r"(?:unidentified|unknown).*developer", "unidentified_developer", Severity.MEDIUM),
    # Policy override
    (
        r"(?:allow|override|bypass).*(?:policy|gatekeeper)",
        "policy_override",
        Severity.HIGH,
    ),
    # Successful assessment (informational)
    (r"assessment.*(?:allow|pass|accept|approve)", "assessment_pass", Severity.INFO),
    # Translocation events
    (r"transloc", "app_translocation", Severity.LOW),
]


class GatekeeperProbe(MicroProbe):
    """Detects Gatekeeper bypass attempts and anomalies.

    Monitors syspolicyd and GatekeeperXPC log entries for assessment
    failures, quarantine attribute removal, notarization failures,
    and policy overrides.

    Quarantine bypass (xattr -d com.apple.quarantine) is a common
    attacker technique to circumvent Gatekeeper on downloaded binaries.

    MITRE: T1553.001 (Subvert Trust Controls: Gatekeeper Bypass)
    """

    name = "macos_gatekeeper"
    description = "Detects Gatekeeper bypass and anomaly events"
    platforms = ["darwin"]
    mitre_techniques = ["T1553.001"]
    mitre_tactics = ["defense_evasion"]
    scan_interval = 10.0
    requires_fields = ["log_entries"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        log_entries = context.shared_data.get("log_entries", [])

        for entry in log_entries:
            if entry.event_type != "gatekeeper":
                continue

            # Self-exclusion: skip AMOSKYS own log entries
            if _is_amoskys_log_entry(entry):
                continue

            message_lower = entry.message.lower()
            for pattern, event_subtype, severity in _GATEKEEPER_PATTERNS:
                if re.search(pattern, message_lower):
                    events.append(
                        self._create_event(
                            event_type=f"gatekeeper_{event_subtype}",
                            severity=severity,
                            data={
                                "probe_name": self.name,
                                "detection_source": "log_show",
                                "process": entry.process,
                                "category": entry.category,
                                "message": entry.message[:500],
                                "event_subtype": event_subtype,
                                "log_timestamp": entry.timestamp,
                                "process_id": entry.process_id,
                                "sender": entry.sender,
                            },
                            confidence=0.85,
                        )
                    )
                    break  # One match per log entry

        return events


# =============================================================================
# 3. InstallerActivityProbe
# =============================================================================


# Installer message patterns
_INSTALLER_PATTERNS = [
    # Package installation
    (r"install.*(?:start|begin|initiat)", "install_started", Severity.INFO),
    (r"install.*(?:complet|finish|success)", "install_completed", Severity.INFO),
    (r"install.*(?:fail|error|abort)", "install_failed", Severity.MEDIUM),
    # Script execution within installer
    (r"(?:pre|post)(?:install|flight).*script", "installer_script", Severity.HIGH),
    (r"running.*script", "installer_script_running", Severity.HIGH),
    # Package info
    (r"package.*identifier.*:", "package_identifier", Severity.INFO),
    (r"\.pkg", "pkg_reference", Severity.INFO),
    # Privilege escalation via installer
    (r"(?:authori|authenticat|elevat|root|sudo)", "installer_privilege", Severity.HIGH),
    # Distribution script
    (r"distribution.*script", "distribution_script", Severity.MEDIUM),
]


class InstallerActivityProbe(MicroProbe):
    """Detects macOS installer package activity.

    Monitors the installer process for package installation events,
    pre/post-install script execution, and privilege escalation.
    Installer packages (.pkg) can execute arbitrary scripts with root
    privileges, making them a common persistence and execution vector.

    MITRE: T1204.002 (User Execution: Malicious File)
    """

    name = "macos_installer_activity"
    description = "Detects installer package activity on macOS"
    platforms = ["darwin"]
    mitre_techniques = ["T1204.002"]
    mitre_tactics = ["execution"]
    scan_interval = 10.0
    requires_fields = ["log_entries"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        log_entries = context.shared_data.get("log_entries", [])

        for entry in log_entries:
            if entry.event_type != "installer":
                continue

            # Self-exclusion: skip AMOSKYS own log entries
            if _is_amoskys_log_entry(entry):
                continue

            message_lower = entry.message.lower()
            for pattern, event_subtype, severity in _INSTALLER_PATTERNS:
                if re.search(pattern, message_lower):
                    # Elevate severity for script execution — primary attack surface
                    if "script" in event_subtype:
                        severity = max(
                            severity,
                            Severity.HIGH,
                            key=lambda s: list(Severity).index(s),
                        )

                    events.append(
                        self._create_event(
                            event_type=f"installer_{event_subtype}",
                            severity=severity,
                            data={
                                "probe_name": self.name,
                                "detection_source": "log_show",
                                "process": entry.process,
                                "category": entry.category,
                                "message": entry.message[:500],
                                "event_subtype": event_subtype,
                                "log_timestamp": entry.timestamp,
                                "process_id": entry.process_id,
                            },
                            confidence=0.75,
                        )
                    )
                    break  # One match per log entry

        return events


# =============================================================================
# 4. XPCAnomalyProbe
# =============================================================================


# XPC anomaly patterns — specific enough to avoid normal macOS IPC noise.
# Normal XPC messages include "invalidated because client cancelled" and
# "activating connection" which must NOT trigger alerts.
_XPC_PATTERNS = [
    # Connection rejection — specific verbs, NOT "invalidated" (normal cleanup)
    (
        r"connection.*(?:rejected|refused|denied)",
        "xpc_connection_rejected",
        Severity.HIGH,
    ),
    # Coding errors (potential exploitation)
    (r"coding.*error", "xpc_coding_error", Severity.MEDIUM),
    (r"malformed.*(?:message|payload|request)", "xpc_invalid_message", Severity.HIGH),
    # Service crash / disruption
    (r"(?:crash|abort|terminate|kill).*service", "xpc_service_crash", Severity.HIGH),
    (
        r"service.*(?:crash|abort|terminated unexpect)",
        "xpc_service_crash",
        Severity.HIGH,
    ),
    # Privilege escalation via XPC
    (
        r"(?:privilege|escalat|entitlement).*(?:fail|denied|error)",
        "xpc_privilege_failure",
        Severity.HIGH,
    ),
    # Unexpected client — NOT "invalidated because client process cancelled"
    (
        r"(?:unexpected|unknown|unauthorized)\s+(?:client|connection|pid)",
        "xpc_unexpected_client",
        Severity.HIGH,
    ),
    # Message size anomaly
    (
        r"(?:oversiz|too.*large|exceed).*(?:message|payload|limit)",
        "xpc_oversize_message",
        Severity.MEDIUM,
    ),
]

# Patterns that are NORMAL macOS XPC operations — skip these entirely
_XPC_BENIGN_PATTERNS = [
    r"activating connection",
    r"invalidated because.*client process",
    r"invalidated after the last release",
    r"connection returned listener port",
    r"connection event",
    r"sending message",
]


class XPCAnomalyProbe(MicroProbe):
    """Detects suspicious XPC (inter-process communication) activity.

    Monitors the com.apple.xpc subsystem for connection rejections,
    coding errors, service crashes, privilege escalation failures,
    and unexpected client connections. XPC is macOS's primary IPC
    mechanism; anomalies here may indicate exploitation attempts
    targeting XPC services for privilege escalation.

    MITRE: T1559 (Inter-Process Communication)
    """

    name = "macos_xpc_anomaly"
    description = "Detects suspicious XPC activity on macOS"
    platforms = ["darwin"]
    mitre_techniques = ["T1559"]
    mitre_tactics = ["execution"]
    scan_interval = 10.0
    requires_fields = ["log_entries"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        log_entries = context.shared_data.get("log_entries", [])

        for entry in log_entries:
            if entry.event_type != "xpc":
                continue

            message_lower = entry.message.lower()

            # Skip known-benign macOS XPC operations
            if any(re.search(bp, message_lower) for bp in _XPC_BENIGN_PATTERNS):
                continue

            for pattern, event_subtype, severity in _XPC_PATTERNS:
                if re.search(pattern, message_lower):
                    events.append(
                        self._create_event(
                            event_type=f"xpc_{event_subtype}",
                            severity=severity,
                            data={
                                "subsystem": entry.subsystem,
                                "process": entry.process,
                                "category": entry.category,
                                "message": entry.message[:500],
                                "event_subtype": event_subtype,
                                "log_timestamp": entry.timestamp,
                                "process_id": entry.process_id,
                                "sender": entry.sender,
                                "activity_id": entry.activity_id,
                            },
                            confidence=0.7,
                        )
                    )
                    break  # One match per log entry

        return events


# =============================================================================
# 5. TCCEventProbe
# =============================================================================


# TCC event patterns
_TCC_PATTERNS = [
    # Permission granted
    (
        r"(?:grant|allow|approv).*(?:access|permission|request)",
        "tcc_permission_granted",
        Severity.INFO,
    ),
    # Permission denied
    (
        r"(?:deny|reject|block|refus).*(?:access|permission|request)",
        "tcc_permission_denied",
        Severity.MEDIUM,
    ),
    # Permission request (user prompt)
    (
        r"(?:request|prompt|ask).*(?:access|permission)",
        "tcc_permission_request",
        Severity.INFO,
    ),
    # Permission reset / revoke
    (
        r"(?:reset|revoke|remov|withdraw).*(?:access|permission)",
        "tcc_permission_revoked",
        Severity.MEDIUM,
    ),
    # Full Disk Access
    (r"(?:full.*disk|SystemPolicyAllFiles)", "tcc_full_disk_access", Severity.HIGH),
    # Screen recording
    (r"(?:screen.*record|ScreenCapture)", "tcc_screen_recording", Severity.MEDIUM),
    # Accessibility
    (r"(?:accessibility|AXIsProcessTrusted)", "tcc_accessibility", Severity.MEDIUM),
    # Camera / Microphone
    (
        r"(?:camera|microphone|kTCCServiceCamera|kTCCServiceMicrophone)",
        "tcc_camera_microphone",
        Severity.MEDIUM,
    ),
    # Automation / AppleEvents
    (
        r"(?:automation|apple.*event|kTCCServiceAppleEvents)",
        "tcc_automation",
        Severity.MEDIUM,
    ),
    # Developer tool
    (
        r"(?:developer.*tool|kTCCServiceDeveloperTool)",
        "tcc_developer_tool",
        Severity.LOW,
    ),
]


class TCCEventProbe(MicroProbe):
    """Detects TCC (Transparency, Consent, and Control) permission changes.

    Monitors the com.apple.TCC subsystem for permission grants, denials,
    resets, and requests. TCC controls access to sensitive resources like
    Full Disk Access, screen recording, camera, microphone, and accessibility.

    DEGRADED without Full Disk Access: only current-session TCC events are
    visible to non-root processes without FDA. Historical TCC database
    queries require elevated access.

    MITRE: T1548 (Abuse Elevation Control Mechanism)
    """

    name = "macos_tcc_event"
    description = "Detects TCC permission changes on macOS (degraded without FDA)"
    platforms = ["darwin"]
    mitre_techniques = ["T1548"]
    mitre_tactics = ["privilege_escalation", "defense_evasion"]
    scan_interval = 10.0
    requires_fields = ["log_entries"]
    degraded_without = ["tcc_full_history"]  # Explicit: FDA needed for full coverage

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        from amoskys.agents.common.apple_allowlist import is_expected_tcc_action

        events: List[TelemetryEvent] = []
        log_entries = context.shared_data.get("log_entries", [])

        for entry in log_entries:
            if entry.event_type != "tcc":
                continue

            message_lower = entry.message.lower()
            for pattern, event_subtype, severity in _TCC_PATTERNS:
                if re.search(pattern, message_lower):
                    # Full Disk Access events are always HIGH
                    if "full_disk" in event_subtype:
                        severity = Severity.HIGH

                    # Check Apple allowlist: tccd/sandboxd managing permissions is expected
                    allowlist_result = is_expected_tcc_action(
                        entry.process, event_subtype
                    )
                    if allowlist_result.is_expected:
                        # Downgrade to INFO with low confidence — still log, don't alert
                        severity = Severity.INFO
                        trust_disposition = "apple_system"
                        confidence = 0.1
                    else:
                        trust_disposition = "unknown"
                        confidence = 0.65

                    events.append(
                        self._create_event(
                            event_type=f"tcc_{event_subtype}",
                            severity=severity,
                            data={
                                "subsystem": entry.subsystem,
                                "process": entry.process,
                                "category": entry.category,
                                "message": entry.message[:500],
                                "event_subtype": event_subtype,
                                "log_timestamp": entry.timestamp,
                                "process_id": entry.process_id,
                                "degraded": True,
                                "trust_disposition": trust_disposition,
                            },
                            confidence=confidence,
                        )
                    )
                    break  # One match per log entry

        return events


# =============================================================================
# 6. SharingServiceProbe
# =============================================================================


# Sharing / AirDrop patterns
_SHARING_PATTERNS = [
    # AirDrop file transfer
    (r"airdrop.*(?:receiv|accept|incoming)", "airdrop_incoming", Severity.MEDIUM),
    (r"airdrop.*(?:send|outgoing|transfer)", "airdrop_outgoing", Severity.MEDIUM),
    (r"airdrop.*(?:reject|deny|decline)", "airdrop_rejected", Severity.INFO),
    # AirDrop discovery
    (r"airdrop.*(?:discover|browse|visible)", "airdrop_discovery", Severity.LOW),
    # Sharing activation
    (
        r"(?:sharing|sharingd).*(?:start|activat|enabl)",
        "sharing_activated",
        Severity.INFO,
    ),
    (
        r"(?:sharing|sharingd).*(?:stop|deactivat|disabl)",
        "sharing_deactivated",
        Severity.INFO,
    ),
    # File transfer via sharing
    (
        r"(?:file|document).*(?:transfer|shar|send|receiv)",
        "file_shared",
        Severity.MEDIUM,
    ),
    # Nearby interaction (normal macOS behavior, INFO-level)
    (
        r"(?:nearby|proximit|peer).*(?:found|discover|connect)",
        "nearby_peer",
        Severity.INFO,
    ),
    # Handoff (normal macOS behavior, INFO-level)
    (
        r"(?:handoff|continuity).*(?:start|initiat|activat)",
        "handoff_activity",
        Severity.INFO,
    ),
    # Error / failure in sharing
    (r"(?:sharing|airdrop).*(?:fail|error|timeout)", "sharing_error", Severity.MEDIUM),
]


class SharingServiceProbe(MicroProbe):
    """Detects AirDrop and sharing service activity.

    Monitors sharingd and AirDrop process log entries for file transfers,
    discovery events, and sharing activation. AirDrop can be used for
    lateral file transfer and data exfiltration in proximity-based attacks.

    MITRE: T1105 (Ingress Tool Transfer)
    """

    name = "macos_sharing_service"
    description = "Detects AirDrop/sharing activity on macOS"
    platforms = ["darwin"]
    mitre_techniques = ["T1105"]
    mitre_tactics = ["command_and_control"]
    scan_interval = 10.0
    requires_fields = ["log_entries"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        log_entries = context.shared_data.get("log_entries", [])

        for entry in log_entries:
            if entry.event_type != "sharing":
                continue

            message_lower = entry.message.lower()
            for pattern, event_subtype, severity in _SHARING_PATTERNS:
                if re.search(pattern, message_lower):
                    events.append(
                        self._create_event(
                            event_type=f"sharing_{event_subtype}",
                            severity=severity,
                            data={
                                "process": entry.process,
                                "category": entry.category,
                                "message": entry.message[:500],
                                "event_subtype": event_subtype,
                                "log_timestamp": entry.timestamp,
                                "process_id": entry.process_id,
                            },
                            confidence=0.7,
                        )
                    )
                    break  # One match per log entry

        return events


# =============================================================================
# Factory
# =============================================================================


def create_unified_log_probes() -> List[MicroProbe]:
    """Create all macOS Unified Log probes."""
    return [
        SecurityFrameworkProbe(),
        GatekeeperProbe(),
        InstallerActivityProbe(),
        XPCAnomalyProbe(),
        TCCEventProbe(),
        SharingServiceProbe(),
    ]
