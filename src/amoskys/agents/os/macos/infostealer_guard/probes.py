"""macOS InfostealerGuard Probes — 14 detection probes for AMOS/Poseidon/Banshee kill chain.

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
    11. KeychainCLIAbuseProbe      — security CLI keychain extraction  (T1555.001)
    12. BrowserCacheLocalStorageProbe — browser cache/storage theft    (T1185, T1176)
    13. SSHKeyTheftProbe           — SSH private key file theft        (T1552.004)
    14. CredentialTheftProbe       — active cmdline + Safari cookie sweep (T1555.001, T1539, T1552.004)

Kill chain mapping (AMOS stealer):
    Delivery → Fake dialog (T1056.002)
    Collection → Keychain + Browser + Wallet + Cookies + SSH keys (T1555, T1005, T1539, T1552.004)
    Staging → Archive credentials (T1560.001)
    Exfil → Network connection from credential-accessing PID (T1041)
"""

from __future__ import annotations

import glob
import ipaddress
import logging
import os
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Set

from amoskys.agents.common.probes import (
    MicroProbe,
    ProbeContext,
    Severity,
    TelemetryEvent,
)

logger = logging.getLogger(__name__)


# Self-exclusion: AMOSKYS own processes accessing Ed25519 keys are expected
_AMOSKYS_PROCESS_NAMES = frozenset(
    {
        "amoskys",
        "amoskys-agent",
        "amoskys-collector",
        "python",  # when running via python -m amoskys
    }
)

_AMOSKYS_KEY_PATTERNS = (
    "amoskys",
    "id_ed25519_amoskys",
)


def _is_amoskys_self_access(process_name: str, file_path: str) -> bool:
    """Return True if this is an AMOSKYS process accessing its own Ed25519 keys."""
    if process_name.lower() not in _AMOSKYS_PROCESS_NAMES:
        return False
    file_lower = file_path.lower()
    return any(pat in file_lower for pat in _AMOSKYS_KEY_PATTERNS)


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

            # Self-exclusion: skip AMOSKYS accessing its own keys
            if _is_amoskys_self_access(access.process_name, access.file_path):
                continue

            events.append(
                self._create_event(
                    event_type="keychain_access",
                    severity=Severity.HIGH,
                    data={
                        "probe_name": self.name,
                        "detection_source": "lsof",
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

            # Self-exclusion: skip AMOSKYS accessing its own keys
            if _is_amoskys_self_access(access.process_name, access.file_path):
                continue

            events.append(
                self._create_event(
                    event_type="browser_credential_theft",
                    severity=Severity.CRITICAL,
                    data={
                        "probe_name": self.name,
                        "detection_source": "lsof",
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

            # Self-exclusion: skip AMOSKYS accessing its own keys
            if _is_amoskys_self_access(access.process_name, access.file_path):
                continue

            wallet_name = access.access_category.replace("crypto_", "")

            events.append(
                self._create_event(
                    event_type="crypto_wallet_theft",
                    severity=Severity.HIGH,
                    data={
                        "probe_name": self.name,
                        "detection_source": "lsof",
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
                        "probe_name": self.name,
                        "detection_source": "lsof",
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
            lambda: {
                "categories": set(),
                "files": [],
                "process_name": "",
                "process_guid": "",
            }
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
                        "probe_name": self.name,
                        "detection_source": "lsof",
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
                        "probe_name": self.name,
                        "detection_source": "lsof",
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
                        "probe_name": self.name,
                        "detection_source": "lsof",
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

            # Self-exclusion: skip AMOSKYS accessing its own keys
            if _is_amoskys_self_access(access.process_name, access.file_path):
                continue

            events.append(
                self._create_event(
                    event_type="session_cookie_theft",
                    severity=Severity.HIGH,
                    data={
                        "probe_name": self.name,
                        "detection_source": "lsof",
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
                        "probe_name": self.name,
                        "detection_source": "lsof",
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
                        "probe_name": self.name,
                        "detection_source": "lsof",
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
                    if (
                        not ip.is_private
                        and not ip.is_loopback
                        and not ip.is_link_local
                    ):
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
                        "probe_name": self.name,
                        "detection_source": "lsof",
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


# =============================================================================
# 11. KeychainCLIAbuseProbe
# =============================================================================


class KeychainCLIAbuseProbe(MicroProbe):
    """Detects macOS `security` CLI abuse for keychain credential theft.

    The collector already flags keychain_cli processes as SuspiciousProcess.
    This probe fires a proper MITRE-tagged event for T1555.001 when it sees
    `security dump-keychain`, `find-generic-password`, etc.

    MITRE: T1555.001 (Credentials from Password Stores: Keychain)
    """

    name = "keychain_cli_abuse"
    description = (
        "Detects security CLI commands that dump or query keychain credentials"
    )
    platforms = ["darwin"]
    mitre_techniques = ["T1555.001"]
    mitre_tactics = ["credential_access"]
    scan_interval = 10.0
    requires_fields = ["suspicious_processes"]

    _ABUSE_PATTERNS = [
        "dump-keychain",
        "find-generic-password",
        "find-internet-password",
        "find-certificate",
        "export-keychain",
        "delete-keychain",
        "find-key",
    ]

    _ALLOWLIST = {
        "Keychain Access",
        "SecurityAgent",
        "securityd",
        "trustd",
        "codesign",
        "xcodebuild",
        "Xcode",
    }

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        suspicious = context.shared_data.get("suspicious_processes", [])

        for proc in suspicious:
            if proc.category != "keychain_cli":
                continue
            if proc.name in self._ALLOWLIST:
                continue

            cmdline_str = (
                " ".join(proc.cmdline)
                if isinstance(proc.cmdline, list)
                else str(proc.cmdline)
            )
            matched_pattern = "keychain_cli"
            for pattern in self._ABUSE_PATTERNS:
                if pattern in cmdline_str.lower():
                    matched_pattern = pattern
                    break

            events.append(
                self._create_event(
                    event_type="keychain_cli_abuse",
                    severity=Severity.HIGH,
                    data={
                        "probe_name": self.name,
                        "detection_source": "lsof",
                        "pid": proc.pid,
                        "process_name": proc.name,
                        "exe": proc.exe,
                        "cmdline": cmdline_str[:500],
                        "abuse_pattern": matched_pattern,
                        "process_guid": proc.process_guid,
                    },
                    confidence=0.92,
                    correlation_id=proc.process_guid,
                )
            )

        # Also check process_snapshot (dicts) for security CLI invocations
        # that the collector might not have flagged
        snapshots = context.shared_data.get("process_snapshot", [])
        flagged_pids = {
            proc.pid for proc in suspicious if proc.category == "keychain_cli"
        }

        for snap in snapshots:
            pid = snap.get("pid", 0)
            if pid in flagged_pids:
                continue
            name = snap.get("name", "")
            if name in self._ALLOWLIST:
                continue
            cmdline = snap.get("cmdline", [])
            cmdline_str = (
                " ".join(cmdline) if isinstance(cmdline, list) else str(cmdline)
            )
            cmd_lower = cmdline_str.lower()

            if "security " not in cmd_lower and "/security " not in cmd_lower:
                continue

            for pattern in self._ABUSE_PATTERNS:
                if pattern in cmd_lower:
                    events.append(
                        self._create_event(
                            event_type="keychain_cli_abuse",
                            severity=Severity.HIGH,
                            data={
                                "probe_name": self.name,
                                "detection_source": "lsof",
                                "pid": pid,
                                "process_name": name,
                                "exe": snap.get("exe", ""),
                                "cmdline": cmdline_str[:500],
                                "abuse_pattern": pattern,
                            },
                            confidence=0.88,
                        )
                    )
                    break

        return events


# =============================================================================
# 12. BrowserCacheLocalStorageProbe
# =============================================================================

# Browser processes that legitimately access their own cache/storage
_BROWSER_PROCESS_ALLOWLIST: Set[str] = {
    "Google Chrome",
    "Google Chrome Helper",
    "Google Chrome Helper (Renderer)",
    "Google Chrome Helper (GPU)",
    "Google Chrome Helper (Plugin)",
    "com.google.Chrome",
    "Safari",
    "com.apple.Safari",
    "com.apple.WebKit",
    "WebContent",
    "firefox",
    "firefox-bin",
    "plugin-container",
}

# Directories containing browser cache and local storage
_BROWSER_CACHE_DIRS = [
    "Library/Caches/Google/Chrome/Default/Cache/",
    "Library/Application Support/Google/Chrome/Default/Local Storage/",
    "Library/Safari/LocalStorage/",
]

# Firefox profiles use a wildcard
_FIREFOX_STORAGE_GLOB = "Library/Application Support/Firefox/Profiles/*/storage/"

# Browser extension directories
_BROWSER_EXTENSION_DIRS = [
    "Library/Application Support/Google/Chrome/Default/Extensions/",
    "Library/Safari/Extensions/",
]


def _parse_lsof_for_paths(
    target_dirs: List[str],
) -> List[Dict[str, Any]]:
    """Run lsof and find non-browser processes accessing target directories.

    Returns a list of dicts with pid, process_name, and file_path for each
    suspicious access found.
    """
    results: List[Dict[str, Any]] = []
    try:
        proc = subprocess.run(
            ["lsof", "-F", "pcn", "+D", *target_dirs],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if proc.returncode != 0:
            return results

        current_pid = 0
        current_name = ""
        for line in proc.stdout.splitlines():
            if line.startswith("p"):
                try:
                    current_pid = int(line[1:])
                except ValueError:
                    current_pid = 0
            elif line.startswith("c"):
                current_name = line[1:]
            elif line.startswith("n") and current_pid > 0:
                file_path = line[1:]
                if current_name not in _BROWSER_PROCESS_ALLOWLIST:
                    results.append(
                        {
                            "pid": current_pid,
                            "process_name": current_name,
                            "file_path": file_path,
                        }
                    )
    except (subprocess.TimeoutExpired, OSError) as e:
        logger.debug("lsof browser cache scan failed: %s", e)

    return results


class BrowserCacheLocalStorageProbe(MicroProbe):
    """Detects non-browser processes accessing browser cache and local storage.

    Monitors browser cache, local storage, and extension directories for
    access by non-browser processes. Non-browser processes reading these
    files indicates credential/session theft or malicious extension
    installation.

    Also monitors browser extension directories for new extensions added
    outside of normal browser workflows.

    MITRE: T1185 (Browser Session Hijacking), T1176 (Browser Extensions)
    """

    name = "macos_infostealer_browser_cache_localstorage"
    description = (
        "Detects non-browser processes accessing browser cache and local storage"
    )
    platforms = ["darwin"]
    mitre_techniques = ["T1185", "T1176"]
    mitre_tactics = ["collection", "persistence"]
    scan_interval = 20.0
    requires_fields = ["sensitive_accesses"]

    def __init__(self) -> None:
        super().__init__()
        self._home = str(Path.home())
        self._known_extensions: Set[str] = set()
        self._first_run = True

    def _resolve_target_dirs(self) -> List[str]:
        """Build absolute paths for browser cache/storage directories."""
        dirs: List[str] = []
        for rel in _BROWSER_CACHE_DIRS:
            full = os.path.join(self._home, rel)
            if os.path.isdir(full):
                dirs.append(full)
        # Firefox profile wildcard
        ff_glob = os.path.join(self._home, _FIREFOX_STORAGE_GLOB)
        dirs.extend(d for d in glob.glob(ff_glob) if os.path.isdir(d))
        return dirs

    def _resolve_extension_dirs(self) -> List[str]:
        """Build absolute paths for browser extension directories."""
        dirs: List[str] = []
        for rel in _BROWSER_EXTENSION_DIRS:
            full = os.path.join(self._home, rel)
            if os.path.isdir(full):
                dirs.append(full)
        return dirs

    def _scan_cache_access(self) -> List[TelemetryEvent]:
        """Check for non-browser processes reading cache/storage files."""
        events: List[TelemetryEvent] = []
        target_dirs = self._resolve_target_dirs()
        if not target_dirs:
            return events

        suspicious = _parse_lsof_for_paths(target_dirs)
        for access in suspicious:
            events.append(
                self._create_event(
                    event_type="browser_cache_theft",
                    severity=Severity.HIGH,
                    data={
                        "probe_name": self.name,
                        "detection_source": "lsof",
                        "pid": access["pid"],
                        "process_name": access["process_name"],
                        "file_path": access["file_path"],
                        "threat": "non_browser_cache_access",
                    },
                    confidence=0.85,
                )
            )
        return events

    def _scan_extensions(self) -> List[TelemetryEvent]:
        """Check for new browser extensions added since last scan."""
        events: List[TelemetryEvent] = []
        ext_dirs = self._resolve_extension_dirs()

        current_extensions: Set[str] = set()
        for ext_dir in ext_dirs:
            try:
                for entry in os.scandir(ext_dir):
                    if entry.is_dir():
                        current_extensions.add(entry.path)
            except OSError:
                continue

        if self._first_run:
            self._known_extensions = current_extensions
            return events

        new_extensions = current_extensions - self._known_extensions
        for ext_path in new_extensions:
            ext_name = os.path.basename(ext_path)
            parent_dir = os.path.basename(os.path.dirname(ext_path))
            events.append(
                self._create_event(
                    event_type="browser_extension_added",
                    severity=Severity.MEDIUM,
                    data={
                        "probe_name": self.name,
                        "detection_source": "filesystem_monitor",
                        "extension_path": ext_path,
                        "extension_id": ext_name,
                        "browser": parent_dir,
                        "threat": "new_browser_extension",
                    },
                    confidence=0.7,
                )
            )

        self._known_extensions = current_extensions
        return events

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        events.extend(self._scan_cache_access())
        events.extend(self._scan_extensions())
        self._first_run = False
        return events


# =============================================================================
# 13. SSHKeyTheftProbe
# =============================================================================

# Processes that legitimately read SSH private keys
_SSH_KEY_ALLOWLIST: Set[str] = {
    "ssh",
    "ssh-agent",
    "ssh-keygen",
    "ssh-add",
    "sshd",
    "git",
    "Git",
    "GitHub Desktop",
    "com.apple.Terminal",
    "iTerm2",
    "gpg-agent",
    "rsync",
    "scp",
    "sftp",
}

# Private key file basenames — public keys (.pub) are not sensitive
_SSH_PRIVATE_KEY_NAMES: Set[str] = {
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
    "id_xmss",
}


class SSHKeyTheftProbe(MicroProbe):
    """Detects non-SSH processes reading SSH private key files.

    SSH private keys grant passwordless access to remote systems. An
    infostealer or post-exploitation tool reading ~/.ssh/id_rsa or
    ~/.ssh/id_ed25519 is almost certainly stealing lateral-movement
    credentials. Only ssh, ssh-agent, git, and a small allowlist of
    processes should ever read these files.

    Detection strategy:
        1. Passive: Check collector's sensitive_accesses for ssh_keys category
        2. Active: Scan process_snapshot for processes with open handles to
           ~/.ssh/ private key paths (catches processes the collector may miss)

    MITRE: T1552.004 (Unsecured Credentials: Private Keys)
    """

    name = "macos_infostealer_ssh_key_theft"
    description = "Detects non-SSH processes reading SSH private key files"
    platforms = ["darwin"]
    mitre_techniques = ["T1552.004"]
    mitre_tactics = ["credential_access"]
    scan_interval = 15.0
    requires_fields = ["sensitive_accesses"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        accesses = context.shared_data.get("sensitive_accesses", [])

        for access in accesses:
            if access.access_category != "ssh_keys":
                continue

            # Self-exclusion: skip AMOSKYS accessing its own Ed25519 keys
            if _is_amoskys_self_access(access.process_name, access.file_path):
                continue

            # Skip allowlisted SSH-related processes
            if access.process_name in _SSH_KEY_ALLOWLIST:
                continue

            # Only alert on private key files, not known_hosts or config
            basename = os.path.basename(access.file_path)
            if basename not in _SSH_PRIVATE_KEY_NAMES and not basename.startswith(
                "id_"
            ):
                continue

            # Public keys (.pub) are not sensitive
            if access.file_path.endswith(".pub"):
                continue

            events.append(
                self._create_event(
                    event_type="ssh_key_theft",
                    severity=Severity.CRITICAL,
                    data={
                        "probe_name": self.name,
                        "detection_source": "lsof",
                        "pid": access.pid,
                        "process_name": access.process_name,
                        "file_path": access.file_path,
                        "key_type": basename,
                        "access_category": access.access_category,
                        "process_guid": access.process_guid,
                        "impact": "lateral_movement_credential_theft",
                    },
                    confidence=0.92,
                    correlation_id=access.process_guid,
                )
            )

        return events


# =============================================================================
# 14. CredentialTheftProbe (Active Process Scanning)
# =============================================================================

# Commands that directly extract credentials — running these is high-signal
_CREDENTIAL_THEFT_COMMANDS = {
    "dump-keychain": {
        "mitre": "T1555.001",
        "severity": Severity.HIGH,
        "description": "Keychain credential dump",
    },
    "find-generic-password": {
        "mitre": "T1555.001",
        "severity": Severity.HIGH,
        "description": "Keychain generic password extraction",
    },
    "find-internet-password": {
        "mitre": "T1555.001",
        "severity": Severity.HIGH,
        "description": "Keychain internet password extraction",
    },
    "export": {
        "mitre": "T1555.001",
        "severity": Severity.HIGH,
        "description": "Keychain certificate/key export",
    },
}

# Sensitive file paths that indicate credential theft when accessed by
# non-standard processes. Maps path fragment -> (mitre, severity, label).
_SENSITIVE_PATH_INDICATORS = {
    "Library/Keychains/": ("T1555.001", Severity.HIGH, "keychain_file_access"),
    "Application Support/Google/Chrome/Default/Login Data": (
        "T1555.003",
        Severity.HIGH,
        "chrome_login_data",
    ),
    "Application Support/Google/Chrome/Default/Cookies": (
        "T1539",
        Severity.HIGH,
        "chrome_cookies",
    ),
    "Application Support/Firefox/Profiles/": (
        "T1555.003",
        Severity.HIGH,
        "firefox_credential_store",
    ),
    "Library/Cookies/Cookies.binarycookies": (
        "T1539",
        Severity.HIGH,
        "safari_cookies",
    ),
    ".ssh/id_rsa": ("T1552.004", Severity.CRITICAL, "ssh_rsa_private_key"),
    ".ssh/id_ed25519": ("T1552.004", Severity.CRITICAL, "ssh_ed25519_private_key"),
    ".ssh/id_ecdsa": ("T1552.004", Severity.CRITICAL, "ssh_ecdsa_private_key"),
    ".ssh/id_dsa": ("T1552.004", Severity.CRITICAL, "ssh_dsa_private_key"),
}

# Processes that legitimately run `security` commands
_SECURITY_CLI_ALLOWLIST: Set[str] = {
    "Keychain Access",
    "SecurityAgent",
    "securityd",
    "trustd",
    "codesign",
    "xcodebuild",
    "Xcode",
    "productbuild",
    "pkgbuild",
}


class CredentialTheftProbe(MicroProbe):
    """Active credential theft detection via process-list scanning.

    Complements the passive lsof-based probes by actively scanning the
    live process list for:

    1. **Keychain CLI abuse** — Processes running `security dump-keychain`,
       `security find-generic-password`, `security find-internet-password`,
       or direct keychain file access by non-Apple processes.
       MITRE: T1555.001 — Severity: HIGH

    2. **Browser credential/cookie theft** — Processes with open file handles
       to Chrome Login Data, Chrome Cookies, Firefox credentials, or Safari
       Cookies.binarycookies.
       MITRE: T1539 / T1555.003 — Severity: HIGH

    3. **SSH private key theft** — Processes reading ~/.ssh/id_rsa,
       ~/.ssh/id_ed25519, or other private key files.
       MITRE: T1552.004 — Severity: CRITICAL

    Detection method:
        - Scan process_snapshot cmdlines for credential theft commands
        - Cross-reference lsof-derived sensitive_accesses for path-based theft
        - Deduplicate against KeychainCLIAbuseProbe / SSHKeyTheftProbe
          by using a distinct event_type

    This probe runs as a sweep detector: it scans all running processes
    in a single pass rather than waiting for collector-flagged events.
    """

    name = "macos_credential_theft_sweep"
    description = (
        "Active credential theft detection via process-list and file-handle scanning"
    )
    platforms = ["darwin"]
    mitre_techniques = ["T1555.001", "T1539", "T1552.004"]
    mitre_tactics = ["credential_access"]
    scan_interval = 10.0
    requires_fields = ["process_snapshot"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        snapshot = context.shared_data.get("process_snapshot", [])

        # --- Strategy 1: Scan process cmdlines for credential theft commands ---
        events.extend(self._scan_cmdlines(snapshot))

        # --- Strategy 2: Check lsof-derived sensitive accesses for SSH/cookie paths ---
        accesses = context.shared_data.get("sensitive_accesses", [])
        events.extend(self._scan_sensitive_paths(accesses))

        return events

    def _scan_cmdlines(self, snapshot: List[Dict[str, Any]]) -> List[TelemetryEvent]:
        """Scan process cmdlines for credential theft commands."""
        events: List[TelemetryEvent] = []

        for proc in snapshot:
            name = proc.get("name", "")
            cmdline = proc.get("cmdline", [])
            if not cmdline:
                continue

            cmdline_str = (
                " ".join(cmdline) if isinstance(cmdline, list) else str(cmdline)
            )
            cmd_lower = cmdline_str.lower()

            # Skip allowlisted processes
            if name in _SECURITY_CLI_ALLOWLIST:
                continue

            # Check for `security` CLI credential extraction commands
            if "security " not in cmd_lower and "/security " not in cmd_lower:
                continue

            for pattern, info in _CREDENTIAL_THEFT_COMMANDS.items():
                if pattern in cmd_lower:
                    events.append(
                        self._create_event(
                            event_type="credential_theft_command",
                            severity=info["severity"],
                            data={
                                "probe_name": self.name,
                                "detection_source": "process_cmdline_scan",
                                "pid": proc.get("pid"),
                                "process_name": name,
                                "exe": proc.get("exe", ""),
                                "cmdline": cmdline_str[:500],
                                "ppid": proc.get("ppid"),
                                "parent_name": proc.get("parent_name", ""),
                                "matched_pattern": pattern,
                                "mitre_technique": info["mitre"],
                                "description": info["description"],
                                "process_guid": proc.get("process_guid", ""),
                            },
                            confidence=0.90,
                            correlation_id=proc.get("process_guid", ""),
                        )
                    )
                    break  # one event per process

        return events

    def _scan_sensitive_paths(
        self, accesses: list,
    ) -> List[TelemetryEvent]:
        """Check sensitive_accesses for high-value credential file theft.

        Emits events for Safari cookies and SSH keys that the more specific
        probes may not cover (e.g. non-standard key filenames, Safari cookies).
        Deduplicates by only firing for safari_cookies access_category here
        (SSH keys are handled by SSHKeyTheftProbe, browser creds by
        BrowserCredentialTheftProbe).
        """
        events: List[TelemetryEvent] = []

        for access in accesses:
            if access.access_category != "safari_cookies":
                continue

            # Self-exclusion
            if _is_amoskys_self_access(access.process_name, access.file_path):
                continue

            events.append(
                self._create_event(
                    event_type="credential_theft_file_access",
                    severity=Severity.HIGH,
                    data={
                        "probe_name": self.name,
                        "detection_source": "lsof",
                        "pid": access.pid,
                        "process_name": access.process_name,
                        "file_path": access.file_path,
                        "access_category": access.access_category,
                        "process_guid": access.process_guid,
                        "mitre_technique": "T1539",
                        "theft_target": "safari_cookies",
                        "impact": "session_hijacking",
                    },
                    confidence=0.85,
                    correlation_id=access.process_guid,
                )
            )

        return events


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
        KeychainCLIAbuseProbe(),
        BrowserCacheLocalStorageProbe(),
        SSHKeyTheftProbe(),
        CredentialTheftProbe(),
    ]
