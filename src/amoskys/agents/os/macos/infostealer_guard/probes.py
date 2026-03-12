"""macOS InfostealerGuard Probes — 10 detection probes for AMOS/Poseidon/Banshee kill chain.

Each probe consumes collector data from MacOSInfostealerGuardCollector via
shared_data keys. Every probe is macOS-only (platforms=["darwin"]).

Probes:
    1.  KeychainAccessProbe         — non-expected keychain file access (T1555.001)
    2.  BrowserCredentialTheftProbe — browser credential store access  (T1555.003)
    3.  CryptoWalletTheftProbe     — crypto wallet file access         (T1005)
    4.  FakePasswordDialogProbe    — osascript password phishing       (T1056.002)
    5.  StealerSequenceProbe       — multi-category access by same PID (T1005)
    6.  CredentialArchiveProbe     — zip/tar/ditto of credential dirs  (T1560.001)
    7.  SessionCookieTheftProbe    — Chrome cookie theft               (T1539)
    8.  ClipboardHarvestProbe      — pbcopy/pbpaste from script parent (T1115)
    9.  ScreenCaptureAbuseProbe    — screencapture from non-standard   (T1113)
    10. SensitiveFileExfilProbe    — credential PID with outbound conn (T1041)

Kill chain mapping (AMOS stealer):
    Delivery → Fake dialog (T1056.002)
    Collection → Keychain + Browser + Wallet + Cookies (T1555, T1005, T1539)
    Staging → Archive credentials (T1560.001)
    Exfil → Network connection from credential-accessing PID (T1041)
"""

from __future__ import annotations

import ipaddress
import logging
from collections import defaultdict
from typing import Any, Dict, List, Set

from amoskys.agents.common.probes import (
    MicroProbe,
    ProbeContext,
    Severity,
    TelemetryEvent,
)

logger = logging.getLogger(__name__)


# =============================================================================
# 1. KeychainAccessProbe
# =============================================================================


class KeychainAccessProbe(MicroProbe):
    """Detects non-expected processes accessing macOS Keychain files.

    The Keychain is the primary credential store on macOS. AMOS stealer
    specifically targets login.keychain-db. Only a small set of system
    processes (loginwindow, securityd, secd, SecurityAgent) should read it.

    MITRE: T1555.001 (Credentials from Password Stores: Keychain)
    """

    name = "macos_infostealer_keychain_access"
    description = "Detects non-expected processes accessing macOS Keychain files"
    platforms = ["darwin"]
    mitre_techniques = ["T1555.001"]
    mitre_tactics = ["credential_access"]
    scan_interval = 15.0
    requires_fields = ["sensitive_accesses"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        accesses = context.shared_data.get("sensitive_accesses", [])

        for access in accesses:
            if access.access_category != "keychain":
                continue

            events.append(
                self._create_event(
                    event_type="keychain_access",
                    severity=Severity.HIGH,
                    data={
                        "pid": access.pid,
                        "process_name": access.process_name,
                        "file_path": access.file_path,
                        "access_category": access.access_category,
                        "process_guid": access.process_guid,
                    },
                    confidence=0.85,
                    correlation_id=access.process_guid,
                )
            )

        return events


# =============================================================================
# 2. BrowserCredentialTheftProbe
# =============================================================================

_BROWSER_CATEGORIES: Set[str] = {
    "chrome_creds",
    "firefox_creds",
    "brave_creds",
    "edge_creds",
    "safari",
}


class BrowserCredentialTheftProbe(MicroProbe):
    """Detects non-browser processes reading browser credential stores.

    AMOS/Poseidon steal Login Data (Chrome/Brave/Edge SQLite), logins.json
    (Firefox), History.db (Safari). A non-browser process reading these
    files is almost certainly credential theft.

    MITRE: T1555.003 (Credentials from Password Stores: Credentials from Web Browsers)
    """

    name = "macos_infostealer_browser_cred_theft"
    description = "Detects non-browser processes reading browser credential stores"
    platforms = ["darwin"]
    mitre_techniques = ["T1555.003"]
    mitre_tactics = ["credential_access"]
    scan_interval = 15.0
    requires_fields = ["sensitive_accesses"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        accesses = context.shared_data.get("sensitive_accesses", [])

        for access in accesses:
            if access.access_category not in _BROWSER_CATEGORIES:
                continue

            events.append(
                self._create_event(
                    event_type="browser_credential_theft",
                    severity=Severity.CRITICAL,
                    data={
                        "pid": access.pid,
                        "process_name": access.process_name,
                        "file_path": access.file_path,
                        "browser": access.access_category,
                        "access_category": access.access_category,
                        "process_guid": access.process_guid,
                    },
                    confidence=0.9,
                    correlation_id=access.process_guid,
                )
            )

        return events


# =============================================================================
# 3. CryptoWalletTheftProbe
# =============================================================================

_CRYPTO_CATEGORIES: Set[str] = {
    "crypto_exodus",
    "crypto_electrum",
    "crypto_atomic",
}


class CryptoWalletTheftProbe(MicroProbe):
    """Detects non-wallet processes reading cryptocurrency wallet data.

    AMOS stealer targets Exodus, Electrum, and Atomic wallet directories
    to extract private keys and seed phrases. Non-wallet processes reading
    these paths indicates active theft.

    MITRE: T1005 (Data from Local System)
    """

    name = "macos_infostealer_crypto_wallet_theft"
    description = "Detects non-wallet processes reading cryptocurrency wallet data"
    platforms = ["darwin"]
    mitre_techniques = ["T1005"]
    mitre_tactics = ["collection"]
    scan_interval = 15.0
    requires_fields = ["sensitive_accesses"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        accesses = context.shared_data.get("sensitive_accesses", [])

        for access in accesses:
            if access.access_category not in _CRYPTO_CATEGORIES:
                continue

            wallet_name = access.access_category.replace("crypto_", "")

            events.append(
                self._create_event(
                    event_type="crypto_wallet_theft",
                    severity=Severity.HIGH,
                    data={
                        "pid": access.pid,
                        "process_name": access.process_name,
                        "file_path": access.file_path,
                        "wallet": wallet_name,
                        "access_category": access.access_category,
                        "process_guid": access.process_guid,
                    },
                    confidence=0.85,
                    correlation_id=access.process_guid,
                )
            )

        return events


# =============================================================================
# 4. FakePasswordDialogProbe (MOST IMPORTANT)
# =============================================================================


class FakePasswordDialogProbe(MicroProbe):
    """Detects osascript fake password dialog phishing.

    THIS IS THE MOST IMPORTANT PROBE. The AMOS/Poseidon/Banshee infostealer
    family uses osascript to display a fake system password prompt via
    'display dialog'. The dialog asks for the user's password with keywords
    like "password", "credential", "authenticate", etc.

    This is the initial access / credential harvesting phase of the kill chain.
    A match here at confidence=0.95 is an almost-certain active attack.

    Rich data includes full cmdline, parent process, and PID for incident
    response correlation.

    MITRE: T1056.002 (Input Capture: GUI Input Capture)
    """

    name = "macos_infostealer_fake_dialog"
    description = "Detects osascript fake password dialog phishing"
    platforms = ["darwin"]
    mitre_techniques = ["T1056.002"]
    mitre_tactics = ["credential_access", "collection"]
    scan_interval = 15.0
    requires_fields = ["suspicious_processes"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        suspicious = context.shared_data.get("suspicious_processes", [])

        for proc in suspicious:
            if proc.category != "fake_dialog":
                continue

            events.append(
                self._create_event(
                    event_type="fake_password_dialog",
                    severity=Severity.CRITICAL,
                    data={
                        "pid": proc.pid,
                        "name": proc.name,
                        "exe": proc.exe,
                        "cmdline": proc.cmdline,
                        "cmdline_str": " ".join(proc.cmdline) if proc.cmdline else "",
                        "ppid": proc.ppid,
                        "parent_name": proc.parent_name,
                        "category": proc.category,
                        "process_guid": proc.process_guid,
                        "kill_chain_phase": "initial_access",
                        "stealer_family": "AMOS/Poseidon/Banshee",
                    },
                    confidence=0.95,
                    correlation_id=proc.process_guid,
                )
            )

        return events


# =============================================================================
# 5. StealerSequenceProbe
# =============================================================================


class StealerSequenceProbe(MicroProbe):
    """Detects multi-category credential access by a single process.

    The hallmark of an infostealer is systematic access to MULTIPLE credential
    stores. If the same PID accesses keychain + browser + wallet, it is almost
    certainly an active stealer. This behavioral pattern is the strongest signal.

    Scoring:
        2 categories  -> HIGH,     confidence=0.8
        3+ categories -> CRITICAL, confidence=0.95

    MITRE: T1005 (Data from Local System)
    """

    name = "macos_infostealer_stealer_sequence"
    description = "Detects multi-category credential access by a single process"
    platforms = ["darwin"]
    mitre_techniques = ["T1005"]
    mitre_tactics = ["collection"]
    scan_interval = 15.0
    requires_fields = ["sensitive_accesses"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        accesses = context.shared_data.get("sensitive_accesses", [])

        # Group accesses by PID
        pid_categories: Dict[int, Dict[str, Any]] = defaultdict(
            lambda: {"categories": set(), "files": [], "process_name": "", "process_guid": ""}
        )

        for access in accesses:
            entry = pid_categories[access.pid]
            entry["categories"].add(access.access_category)
            entry["files"].append(access.file_path)
            entry["process_name"] = access.process_name
            entry["process_guid"] = access.process_guid

        for pid, info in pid_categories.items():
            cat_count = len(info["categories"])
            if cat_count < 2:
                continue

            if cat_count >= 3:
                severity = Severity.CRITICAL
                confidence = 0.95
            else:
                severity = Severity.HIGH
                confidence = 0.8

            events.append(
                self._create_event(
                    event_type="stealer_sequence",
                    severity=severity,
                    data={
                        "pid": pid,
                        "process_name": info["process_name"],
                        "category_count": cat_count,
                        "categories": sorted(info["categories"]),
                        "files_accessed": info["files"][:20],  # cap for size
                        "process_guid": info["process_guid"],
                        "behavioral_pattern": "multi_category_credential_sweep",
                    },
                    confidence=confidence,
                    correlation_id=info["process_guid"],
                )
            )

        return events


# =============================================================================
# 6. CredentialArchiveProbe
# =============================================================================


class CredentialArchiveProbe(MicroProbe):
    """Detects credential staging via zip/tar/ditto archiving.

    AMOS stealer archives stolen credentials before exfiltration. Detects
    zip, tar, or ditto processes with command lines referencing sensitive
    credential directories.

    MITRE: T1560.001 (Archive Collected Data: Archive via Utility)
    """

    name = "macos_infostealer_credential_archive"
    description = "Detects credential staging via zip/tar/ditto archiving"
    platforms = ["darwin"]
    mitre_techniques = ["T1560.001"]
    mitre_tactics = ["collection"]
    scan_interval = 15.0
    requires_fields = ["suspicious_processes", "staging_archives"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        suspicious = context.shared_data.get("suspicious_processes", [])
        staging_archives = context.shared_data.get("staging_archives", [])

        # Strategy 1: Catch running archiver process (rare — zip exits in <1s)
        for proc in suspicious:
            if proc.category != "credential_archive":
                continue

            events.append(
                self._create_event(
                    event_type="credential_archive",
                    severity=Severity.HIGH,
                    data={
                        "pid": proc.pid,
                        "name": proc.name,
                        "exe": proc.exe,
                        "cmdline": proc.cmdline,
                        "ppid": proc.ppid,
                        "parent_name": proc.parent_name,
                        "process_guid": proc.process_guid,
                        "kill_chain_phase": "staging",
                        "detection_method": "process_capture",
                    },
                    confidence=0.9,
                    correlation_id=proc.process_guid,
                )
            )

        # Strategy 2: Find archive files in staging dirs containing cred data
        for archive in staging_archives:
            events.append(
                self._create_event(
                    event_type="credential_archive",
                    severity=Severity.HIGH,
                    data={
                        "archive_path": archive["path"],
                        "filename": archive["filename"],
                        "size": archive["size"],
                        "staging_dir": archive["staging_dir"],
                        "archive_contents_sample": archive.get(
                            "archive_contents_sample", []
                        ),
                        "kill_chain_phase": "staging",
                        "detection_method": "staging_file_scan",
                        "description": (
                            f"Credential archive in staging location: "
                            f"{archive['filename']}"
                        ),
                    },
                    confidence=0.8,
                )
            )

        return events


# =============================================================================
# 7. SessionCookieTheftProbe
# =============================================================================


class SessionCookieTheftProbe(MicroProbe):
    """Detects non-browser processes reading Chrome session cookies.

    Session cookies allow session hijacking without the password. AMOS stealer
    specifically targets the Chrome Cookies SQLite database. A non-Chrome
    process reading this file is stealing active sessions.

    MITRE: T1539 (Steal Web Session Cookie)
    """

    name = "macos_infostealer_session_cookie_theft"
    description = "Detects non-browser processes reading Chrome session cookies"
    platforms = ["darwin"]
    mitre_techniques = ["T1539"]
    mitre_tactics = ["credential_access"]
    scan_interval = 15.0
    requires_fields = ["sensitive_accesses"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        accesses = context.shared_data.get("sensitive_accesses", [])

        for access in accesses:
            if access.access_category != "chrome_cookies":
                continue

            events.append(
                self._create_event(
                    event_type="session_cookie_theft",
                    severity=Severity.HIGH,
                    data={
                        "pid": access.pid,
                        "process_name": access.process_name,
                        "file_path": access.file_path,
                        "access_category": access.access_category,
                        "process_guid": access.process_guid,
                        "impact": "session_hijacking",
                    },
                    confidence=0.85,
                    correlation_id=access.process_guid,
                )
            )

        return events


# =============================================================================
# 8. ClipboardHarvestProbe
# =============================================================================

_BENIGN_CLIPBOARD_PARENTS: Set[str] = {
    "zsh",
    "bash",
    "sh",
    "fish",
    "Terminal",
    "iTerm2",
    "sshd",
}


class ClipboardHarvestProbe(MicroProbe):
    """Detects clipboard harvesting by non-shell parent processes.

    pbcopy/pbpaste launched from a shell/terminal is normal user behavior.
    pbcopy/pbpaste launched from a script or unknown parent is suspicious —
    infostealers use clipboard access to capture passwords and crypto addresses.

    MITRE: T1115 (Clipboard Data)
    """

    name = "macos_infostealer_clipboard_harvest"
    description = "Detects clipboard harvesting by non-shell parent processes"
    platforms = ["darwin"]
    mitre_techniques = ["T1115"]
    mitre_tactics = ["collection"]
    scan_interval = 15.0
    requires_fields = ["process_snapshot"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        snapshot = context.shared_data.get("process_snapshot", [])

        for proc in snapshot:
            name = proc.get("name", "")
            if name.lower() not in ("pbcopy", "pbpaste"):
                continue

            parent_name = proc.get("parent_name", "")
            if parent_name in _BENIGN_CLIPBOARD_PARENTS:
                continue

            events.append(
                self._create_event(
                    event_type="clipboard_harvest",
                    severity=Severity.MEDIUM,
                    data={
                        "pid": proc.get("pid"),
                        "name": name,
                        "exe": proc.get("exe", ""),
                        "cmdline": proc.get("cmdline", []),
                        "ppid": proc.get("ppid"),
                        "parent_name": parent_name,
                        "process_guid": proc.get("process_guid", ""),
                    },
                    confidence=0.6,
                    correlation_id=proc.get("process_guid", ""),
                )
            )

        return events


# =============================================================================
# 9. ScreenCaptureAbuseProbe
# =============================================================================

_STANDARD_SCREENCAPTURE_PARENTS: Set[str] = {
    "Terminal",
    "iTerm2",
    "sshd",
    "loginwindow",
    "WindowServer",
}


class ScreenCaptureAbuseProbe(MicroProbe):
    """Detects screencapture invoked from non-standard parent processes.

    macOS screencapture is a legitimate system utility when launched from
    Terminal or by the user. When launched from an unknown parent (script,
    malware dropper), it indicates screen data collection for exfiltration.

    MITRE: T1113 (Screen Capture)
    """

    name = "macos_infostealer_screen_capture_abuse"
    description = "Detects screencapture invoked from non-standard parent processes"
    platforms = ["darwin"]
    mitre_techniques = ["T1113"]
    mitre_tactics = ["collection"]
    scan_interval = 15.0
    requires_fields = ["process_snapshot"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        snapshot = context.shared_data.get("process_snapshot", [])

        for proc in snapshot:
            name = proc.get("name", "")
            if name.lower() != "screencapture":
                continue

            parent_name = proc.get("parent_name", "")
            if parent_name in _STANDARD_SCREENCAPTURE_PARENTS:
                continue

            events.append(
                self._create_event(
                    event_type="screen_capture_abuse",
                    severity=Severity.MEDIUM,
                    data={
                        "pid": proc.get("pid"),
                        "name": name,
                        "exe": proc.get("exe", ""),
                        "cmdline": proc.get("cmdline", []),
                        "ppid": proc.get("ppid"),
                        "parent_name": parent_name,
                        "process_guid": proc.get("process_guid", ""),
                    },
                    confidence=0.6,
                    correlation_id=proc.get("process_guid", ""),
                )
            )

        return events


# =============================================================================
# 10. SensitiveFileExfilProbe
# =============================================================================


class SensitiveFileExfilProbe(MicroProbe):
    """Detects credential-accessing PIDs with outbound network connections.

    Cross-references two data sources:
        1. PIDs in sensitive_accesses (reading credential files)
        2. PIDs in pid_connections with non-private remote IPs

    If a PID reads credential files AND has outbound connections to public
    IPs, it is almost certainly exfiltrating stolen data.

    MITRE: T1041 (Exfiltration Over C2 Channel)
    """

    name = "macos_infostealer_sensitive_file_exfil"
    description = "Detects credential-accessing PIDs with outbound network connections"
    platforms = ["darwin"]
    mitre_techniques = ["T1041"]
    mitre_tactics = ["exfiltration"]
    scan_interval = 15.0
    requires_fields = ["sensitive_accesses", "pid_connections"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        accesses = context.shared_data.get("sensitive_accesses", [])
        pid_conns = context.shared_data.get("pid_connections", {})

        # Build set of PIDs accessing sensitive files
        credential_pids: Dict[int, Dict[str, Any]] = {}
        for access in accesses:
            if access.pid not in credential_pids:
                credential_pids[access.pid] = {
                    "process_name": access.process_name,
                    "categories": set(),
                    "files": [],
                    "process_guid": access.process_guid,
                }
            credential_pids[access.pid]["categories"].add(access.access_category)
            credential_pids[access.pid]["files"].append(access.file_path)

        # Cross-reference with network connections
        for pid, info in credential_pids.items():
            connections = pid_conns.get(pid, [])
            if not connections:
                continue

            # Filter for non-private (public) remote IPs
            public_connections = []
            for conn in connections:
                try:
                    ip = ipaddress.ip_address(conn.remote_ip)
                    if not ip.is_private and not ip.is_loopback and not ip.is_link_local:
                        public_connections.append(
                            {
                                "remote_ip": conn.remote_ip,
                                "remote_port": conn.remote_port,
                                "protocol": conn.protocol,
                                "state": conn.state,
                            }
                        )
                except ValueError:
                    # Invalid IP string — skip
                    continue

            if not public_connections:
                continue

            events.append(
                self._create_event(
                    event_type="sensitive_file_exfil",
                    severity=Severity.CRITICAL,
                    data={
                        "pid": pid,
                        "process_name": info["process_name"],
                        "categories_accessed": sorted(info["categories"]),
                        "files_accessed": info["files"][:10],
                        "public_connections": public_connections[:10],
                        "connection_count": len(public_connections),
                        "process_guid": info["process_guid"],
                        "kill_chain_phase": "exfiltration",
                    },
                    confidence=0.9,
                    correlation_id=info["process_guid"],
                )
            )

        return events


# =============================================================================
# Factory
# =============================================================================


def create_infostealer_guard_probes() -> List[MicroProbe]:
    """Create all macOS InfostealerGuard probes."""
    return [
        KeychainAccessProbe(),
        BrowserCredentialTheftProbe(),
        CryptoWalletTheftProbe(),
        FakePasswordDialogProbe(),
        StealerSequenceProbe(),
        CredentialArchiveProbe(),
        SessionCookieTheftProbe(),
        ClipboardHarvestProbe(),
        ScreenCaptureAbuseProbe(),
        SensitiveFileExfilProbe(),
    ]
