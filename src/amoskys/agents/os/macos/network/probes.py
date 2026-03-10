"""macOS Network Probes — 8 detection probes for network activity.

Each probe consumes Connection data from MacOSNetworkCollector via
shared_data["connections"]. All probes are macOS-only.

Probes:
    1. C2BeaconProbe — periodic connection patterns (beaconing)
    2. ExfilSpikeProbe — unusual outbound data volume
    3. LateralSSHProbe — outbound SSH to internal hosts
    4. CleartextProbe — cleartext protocols on sensitive ports
    5. TunnelDetectProbe — TOR, VPN, proxy tunnel detection
    6. NonStandardPortProbe — known services on wrong ports
    7. CloudExfilProbe — cloud storage service connections
    8. NewConnectionProbe — baseline-diff for new external connections

MITRE: T1071, T1573, T1572, T1571, T1048, T1570, T1021
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional, Set

from amoskys.agents.common.probes import (
    MicroProbe,
    ProbeContext,
    Severity,
    TelemetryEvent,
)

logger = logging.getLogger(__name__)

from amoskys.agents.common.ip_utils import is_private_ip as _is_private

# =============================================================================
# 1. C2BeaconProbe
# =============================================================================


# Known-good processes that maintain persistent external connections.
# These are NOT C2 beacons — they are legitimate applications.
_BEACON_WHITELIST = frozenset(
    {
        # Browsers
        "safari",
        "google",
        "google chrome",
        "google chrome helper",
        "firefox",
        "microsoft edge",
        "arc",
        "brave browser",
        "opera",
        # Communication
        "slack",
        "slack\x20helper",
        "slack helper",
        "slack\x20",
        "discord",
        "zoom.us",
        "microsoft teams",
        "telegram",
        "whatsapp",
        "messages",
        "facetime",
        "skype",
        # Dev tools
        "claude",
        "cursor",
        "code",
        "code helper",
        "code h",
        "copilot",
        "github desktop",
        "gitkraken",
        # Apple services
        "appstoreagent",
        "nsurlsessiond",
        "cloudd",
        "imtransferagent",
        "rapportd",
        "sharingd",
        "identityservicesd",
        "apsd",
        "bird",
        "accountsd",
        "callservicesd",
        "parsecd",
        "siriknowledged",
        "suggestd",
        "spotlightnethelper",
        "corespotlightd",
        # Cloud sync
        "dropbox",
        "google drive",
        "icloud",
        "onedrive",
        # System
        "softwareupdated",
        "trustd",
        "syspolicyd",
        "mdnsresponder",
        "networkserviceproxy",
        "symptomsd",
        "mdsync",
        "replayd",
    }
)


class C2BeaconProbe(MicroProbe):
    """Detects C2 beaconing patterns — periodic connections to same host.

    Tracks connection history per remote IP. When a process connects to
    the same external IP repeatedly at regular intervals, flags as potential
    C2 beaconing. Known-good applications (browsers, Slack, Claude, etc.)
    are whitelisted to avoid false positives.

    MITRE: T1071 (Application Layer Protocol)
    """

    name = "macos_c2_beacon"
    description = "Detects C2 beaconing patterns on macOS"
    platforms = ["darwin"]
    mitre_techniques = ["T1071", "T1071.001"]
    mitre_tactics = ["command_and_control"]
    scan_interval = 30.0
    requires_fields = ["connections"]

    HISTORY_SIZE = 10
    MIN_HITS = 3  # Minimum times seen to flag

    def __init__(self) -> None:
        super().__init__()
        # remote_ip -> list of (timestamp, pid, process)
        self._history: Dict[str, List[tuple]] = {}

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        connections = context.shared_data.get("connections", [])
        now = time.time()

        for conn in connections:
            if conn.state != "ESTABLISHED":
                continue
            if not conn.remote_ip or _is_private(conn.remote_ip):
                continue

            # Skip known-good applications.
            # macOS process names can have trailing spaces, null bytes, and
            # truncation (e.g. "Slack\x20", "Code\x20H", "Google Chrome H").
            # Use prefix matching to handle these variations.
            proc_lower = (conn.process_name or "").lower().strip().strip("\x00")
            if any(proc_lower.startswith(w) for w in _BEACON_WHITELIST):
                continue

            key = conn.remote_ip
            if key not in self._history:
                self._history[key] = []

            self._history[key].append((now, conn.pid, conn.process_name))

            # Keep only recent entries
            self._history[key] = self._history[key][-self.HISTORY_SIZE :]

            if len(self._history[key]) >= self.MIN_HITS:
                events.append(
                    self._create_event(
                        event_type="c2_beacon_suspect",
                        severity=Severity.HIGH,
                        data={
                            "remote_ip": conn.remote_ip,
                            "remote_port": conn.remote_port,
                            "process_name": conn.process_name,
                            "pid": conn.pid,
                            "hit_count": len(self._history[key]),
                            "first_seen": self._history[key][0][0],
                        },
                        confidence=0.6,
                    )
                )

        return events


# =============================================================================
# 2. ExfilSpikeProbe
# =============================================================================


class ExfilSpikeProbe(MicroProbe):
    """Detects unusual outbound data volume (potential exfiltration).

    Uses nettop bandwidth data to flag processes sending large amounts
    of data to external hosts.

    MITRE: T1048 (Exfiltration Over Alternative Protocol)
    """

    name = "macos_exfil_spike"
    description = "Detects unusual outbound data volume on macOS"
    platforms = ["darwin"]
    mitre_techniques = ["T1048", "T1048.002"]
    mitre_tactics = ["exfiltration"]
    scan_interval = 30.0
    requires_fields = ["connections"]
    degraded_without = ["bandwidth"]

    BYTES_OUT_THRESHOLD = 10 * 1024 * 1024  # 10MB

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        bandwidth = context.shared_data.get("bandwidth", [])

        for bw in bandwidth:
            if bw.bytes_out > self.BYTES_OUT_THRESHOLD:
                events.append(
                    self._create_event(
                        event_type="exfil_spike",
                        severity=Severity.HIGH,
                        data={
                            "process_name": bw.process_name,
                            "pid": bw.pid,
                            "bytes_out": bw.bytes_out,
                            "bytes_in": bw.bytes_in,
                            "threshold": self.BYTES_OUT_THRESHOLD,
                        },
                        confidence=0.7,
                    )
                )

        return events


# =============================================================================
# 3. LateralSSHProbe
# =============================================================================


class LateralSSHProbe(MicroProbe):
    """Detects outbound SSH connections to internal hosts (lateral movement).

    SSH to internal network hosts from this device may indicate lateral
    movement. Tracks ssh process connections to private IPs.

    MITRE: T1021.004 (Remote Services: SSH)
    """

    name = "macos_lateral_ssh"
    description = "Detects outbound SSH to internal hosts on macOS"
    platforms = ["darwin"]
    mitre_techniques = ["T1021.004", "T1570"]
    mitre_tactics = ["lateral_movement"]
    scan_interval = 10.0
    requires_fields = ["connections"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        connections = context.shared_data.get("connections", [])

        for conn in connections:
            if conn.state != "ESTABLISHED":
                continue
            if conn.remote_port != 22:
                continue
            if not conn.remote_ip or not _is_private(conn.remote_ip):
                continue

            events.append(
                self._create_event(
                    event_type="lateral_ssh",
                    severity=Severity.MEDIUM,
                    data={
                        "process_name": conn.process_name,
                        "pid": conn.pid,
                        "remote_ip": conn.remote_ip,
                        "remote_port": conn.remote_port,
                        "local_port": conn.local_port,
                        "user": conn.user,
                    },
                    confidence=0.7,
                )
            )

        return events


# =============================================================================
# 4. CleartextProbe
# =============================================================================

_CLEARTEXT_PORTS = {
    21: "FTP",
    23: "Telnet",
    25: "SMTP",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    389: "LDAP",
    513: "rlogin",
    514: "rsh",
}


class CleartextProbe(MicroProbe):
    """Detects cleartext protocol usage.

    Flags connections on known cleartext ports (FTP, Telnet, HTTP, etc.)
    to external hosts — potential credential leak.

    MITRE: T1048 (Exfiltration), T1071 (Application Layer Protocol)
    """

    name = "macos_cleartext"
    description = "Detects cleartext protocol usage on macOS"
    platforms = ["darwin"]
    mitre_techniques = ["T1071", "T1040"]
    mitre_tactics = ["command_and_control", "credential_access"]
    scan_interval = 10.0
    requires_fields = ["connections"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        connections = context.shared_data.get("connections", [])

        for conn in connections:
            if conn.state != "ESTABLISHED":
                continue
            if _is_private(conn.remote_ip or "127.0.0.1"):
                continue

            port = conn.remote_port
            if port in _CLEARTEXT_PORTS:
                events.append(
                    self._create_event(
                        event_type="cleartext_protocol",
                        severity=Severity.MEDIUM,
                        data={
                            "process_name": conn.process_name,
                            "pid": conn.pid,
                            "remote_ip": conn.remote_ip,
                            "remote_port": port,
                            "protocol_name": _CLEARTEXT_PORTS[port],
                        },
                        confidence=0.8,
                    )
                )

        return events


# =============================================================================
# 5. TunnelDetectProbe
# =============================================================================

_TUNNEL_PROCESSES = frozenset(
    {
        "tor",
        "openvpn",
        "wireguard-go",
        "wg-quick",
        "stunnel",
        "socat",
        "chisel",
        "ngrok",
        "cloudflared",
        "bore",
    }
)

_TUNNEL_PORTS = {
    9050: "TOR_SOCKS",
    9051: "TOR_CONTROL",
    1194: "OpenVPN",
    51820: "WireGuard",
}


class TunnelDetectProbe(MicroProbe):
    """Detects tunnel/proxy connections (TOR, VPN, ngrok, etc.).

    MITRE: T1572 (Protocol Tunneling)
    """

    name = "macos_tunnel_detect"
    description = "Detects tunnel/proxy connections on macOS"
    platforms = ["darwin"]
    mitre_techniques = ["T1572", "T1090"]
    mitre_tactics = ["command_and_control"]
    scan_interval = 10.0
    requires_fields = ["connections"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        connections = context.shared_data.get("connections", [])

        for conn in connections:
            reason = None

            # Check process name
            if conn.process_name.lower() in _TUNNEL_PROCESSES:
                reason = f"tunnel_process:{conn.process_name}"

            # Check port
            elif conn.local_port in _TUNNEL_PORTS:
                reason = f"tunnel_port:{_TUNNEL_PORTS[conn.local_port]}"
            elif conn.remote_port in _TUNNEL_PORTS:
                reason = f"tunnel_port:{_TUNNEL_PORTS[conn.remote_port]}"

            if reason:
                events.append(
                    self._create_event(
                        event_type="tunnel_detected",
                        severity=Severity.HIGH,
                        data={
                            "process_name": conn.process_name,
                            "pid": conn.pid,
                            "reason": reason,
                            "remote_ip": conn.remote_ip,
                            "remote_port": conn.remote_port,
                            "local_port": conn.local_port,
                        },
                        confidence=0.8,
                    )
                )

        return events


# =============================================================================
# 6. NonStandardPortProbe
# =============================================================================

_STANDARD_SERVICE_PORTS = {
    "sshd": {22},
    "httpd": {80, 443, 8080, 8443},
    "nginx": {80, 443, 8080, 8443},
    "mysqld": {3306, 33060},
    "mongod": {27017},
    "postgres": {5432},
    "redis-server": {6379},
}


class NonStandardPortProbe(MicroProbe):
    """Detects known services running on non-standard ports.

    MITRE: T1571 (Non-Standard Port)
    """

    name = "macos_non_standard_port"
    description = "Detects services on non-standard ports on macOS"
    platforms = ["darwin"]
    mitre_techniques = ["T1571"]
    mitre_tactics = ["command_and_control"]
    scan_interval = 30.0
    requires_fields = ["connections"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        connections = context.shared_data.get("connections", [])

        for conn in connections:
            if conn.state != "LISTEN":
                continue

            name_lower = conn.process_name.lower()
            if name_lower in _STANDARD_SERVICE_PORTS:
                expected = _STANDARD_SERVICE_PORTS[name_lower]
                if conn.local_port not in expected:
                    events.append(
                        self._create_event(
                            event_type="non_standard_port",
                            severity=Severity.MEDIUM,
                            data={
                                "process_name": conn.process_name,
                                "pid": conn.pid,
                                "actual_port": conn.local_port,
                                "expected_ports": list(expected),
                            },
                            confidence=0.7,
                        )
                    )

        return events


# =============================================================================
# 7. CloudExfilProbe
# =============================================================================

_CLOUD_DOMAINS = {
    "dropbox": "Dropbox",
    "icloud": "iCloud",
    "gdrive": "Google Drive",
    "onedrive": "OneDrive",
    "mega": "MEGA",
    "box": "Box",
    "wetransfer": "WeTransfer",
}

_CLOUD_PROCESSES = frozenset(
    {
        "Dropbox",
        "Dropbox Web Helper",
        "bird",
        "cloudd",  # iCloud daemons
        "Google Drive",
        "Google Drive Helper",
        "OneDrive",
        "OneDriveStandaloneUpdater",
    }
)


class CloudExfilProbe(MicroProbe):
    """Detects cloud storage sync activity (potential exfiltration vector).

    MITRE: T1567.002 (Exfiltration Over Web Service: Exfiltration to Cloud Storage)
    """

    name = "macos_cloud_exfil"
    description = "Detects cloud storage activity on macOS"
    platforms = ["darwin"]
    mitre_techniques = ["T1567.002"]
    mitre_tactics = ["exfiltration"]
    scan_interval = 30.0
    requires_fields = ["connections"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        connections = context.shared_data.get("connections", [])

        for conn in connections:
            if conn.state != "ESTABLISHED":
                continue
            if conn.process_name in _CLOUD_PROCESSES:
                events.append(
                    self._create_event(
                        event_type="cloud_sync_active",
                        severity=Severity.INFO,
                        data={
                            "process_name": conn.process_name,
                            "pid": conn.pid,
                            "remote_ip": conn.remote_ip,
                            "remote_port": conn.remote_port,
                        },
                        confidence=0.5,
                    )
                )

        return events


# =============================================================================
# 8. NewConnectionProbe
# =============================================================================


class NewConnectionProbe(MicroProbe):
    """Detects new external connections via baseline-diff.

    Tracks remote_ip:remote_port pairs per process. Alerts on new
    connections to previously unseen external hosts.

    MITRE: T1071 (Application Layer Protocol)
    """

    name = "macos_new_connection"
    description = "Detects new external connections on macOS"
    platforms = ["darwin"]
    mitre_techniques = ["T1071"]
    mitre_tactics = ["command_and_control"]
    scan_interval = 10.0
    requires_fields = ["connections"]

    def __init__(self) -> None:
        super().__init__()
        self._known: Set[str] = set()  # "process:remote_ip:remote_port"
        self._first_run = True

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        connections = context.shared_data.get("connections", [])

        current: Set[str] = set()
        for conn in connections:
            if conn.state != "ESTABLISHED":
                continue
            if not conn.remote_ip or _is_private(conn.remote_ip):
                continue

            key = f"{conn.process_name}:{conn.remote_ip}:{conn.remote_port}"
            current.add(key)

            if not self._first_run and key not in self._known:
                events.append(
                    self._create_event(
                        event_type="new_external_connection",
                        severity=Severity.LOW,
                        data={
                            "process_name": conn.process_name,
                            "pid": conn.pid,
                            "remote_ip": conn.remote_ip,
                            "remote_port": conn.remote_port,
                            "user": conn.user,
                        },
                        confidence=0.5,
                    )
                )

        self._known = current
        self._first_run = False
        return events


# =============================================================================
# Factory
# =============================================================================


def create_network_probes() -> List[MicroProbe]:
    """Create all macOS network probes."""
    return [
        C2BeaconProbe(),
        ExfilSpikeProbe(),
        LateralSSHProbe(),
        CleartextProbe(),
        TunnelDetectProbe(),
        NonStandardPortProbe(),
        CloudExfilProbe(),
        NewConnectionProbe(),
    ]
