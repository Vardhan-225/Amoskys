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

Agent Observability Mandate v1.0 — every event populates mandatory fields
via _mandate_network_context().  Self-exclusion via self_identity.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional, Set

from amoskys.agents.common.ip_utils import is_private_ip as _is_private
from amoskys.agents.common.probes import (
    MicroProbe,
    ProbeContext,
    Severity,
    TelemetryEvent,
)
from amoskys.agents.common.self_identity import self_identity

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Non-routable IP filter (mandate: NEVER link-local, loopback, APIPA)
# ---------------------------------------------------------------------------

_NON_ROUTABLE_PREFIXES = ("fe80:", "127.", "::1", "169.254.", "0.0.0.0", "::")


def _is_non_routable(ip: str) -> bool:
    """Return True if IP is link-local, loopback, APIPA, or empty."""
    if not ip:
        return True
    ip_clean = ip.strip("[]")
    if ip_clean in ("0.0.0.0", "::", "::1", "127.0.0.1"):
        return True
    return any(ip_clean.startswith(p) for p in _NON_ROUTABLE_PREFIXES)


# ---------------------------------------------------------------------------
# Process resolution helper — resolve exe from PID via psutil
# ---------------------------------------------------------------------------


def _resolve_process(pid: int, fallback_name: str = "UNKNOWN") -> Dict[str, Any]:
    """Best-effort exe resolution from PID using psutil."""
    try:
        import psutil

        proc = psutil.Process(pid)
        return {
            "pid": pid,
            "process_name": proc.name() or fallback_name,
            "exe": proc.exe() or "ACCESS_DENIED",
        }
    except Exception:
        return {
            "pid": pid,
            "process_name": fallback_name,
            "exe": "UNRESOLVED",
        }


# ---------------------------------------------------------------------------
# Mandate helper — builds full network context dict
# ---------------------------------------------------------------------------


def _mandate_network_context(
    conn: Any,
    probe_name: str,
    *,
    extras: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build full network context per Agent Observability Mandate v1.0.

    MANDATORY fields (never NULL):
        pid, process_name, exe, remote_ip, remote_port, local_port,
        protocol, connection_state, bytes_in, bytes_out,
        connection_count, connection_duration_s, probe_name, detection_source.

    ``conn`` is a collector.Connection dataclass.
    ``extras`` are probe-specific conditional fields merged on top.
    """
    resolved = _resolve_process(conn.pid, fallback_name=conn.process_name or "UNKNOWN")

    ctx: Dict[str, Any] = {
        # Identity (MANDATORY)
        "pid": resolved["pid"],
        "process_name": resolved["process_name"],
        "exe": resolved["exe"],
        # Network addressing (MANDATORY)
        "remote_ip": conn.remote_ip or "",
        "remote_port": conn.remote_port or 0,
        "local_port": conn.local_port or 0,
        "protocol": getattr(conn, "protocol", "TCP"),
        "connection_state": conn.state or "UNKNOWN",
        # Volume (MANDATORY — probes that have bandwidth override later)
        "bytes_in": 0,
        "bytes_out": 0,
        # Aggregates (MANDATORY — probes set meaningful values)
        "connection_count": 1,
        "connection_duration_s": 0.0,
        # Attribution (MANDATORY universal)
        "probe_name": probe_name,
        "detection_source": "lsof",
    }
    if extras:
        ctx.update(extras)
    return ctx


def _mandate_bandwidth_context(
    bw: Any,
    probe_name: str,
    *,
    extras: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build mandate context for bandwidth (nettop) events.

    ProcessBandwidth has pid, process_name, bytes_in, bytes_out but no
    connection-level fields. We fill what we can and mark the rest.
    """
    resolved = _resolve_process(bw.pid, fallback_name=bw.process_name or "UNKNOWN")

    ctx: Dict[str, Any] = {
        "pid": resolved["pid"],
        "process_name": resolved["process_name"],
        "exe": resolved["exe"],
        "remote_ip": "",
        "remote_port": 0,
        "local_port": 0,
        "protocol": "TCP",
        "connection_state": "AGGREGATE",
        "bytes_in": bw.bytes_in,
        "bytes_out": bw.bytes_out,
        "connection_count": 1,
        "connection_duration_s": 0.0,
        "probe_name": probe_name,
        "detection_source": "nettop",
    }
    if extras:
        ctx.update(extras)
    return ctx


# ---------------------------------------------------------------------------
# Self-exclusion check
# ---------------------------------------------------------------------------


def _is_self(conn: Any) -> bool:
    """Return True if the connection belongs to AMOSKYS itself."""
    return self_identity.is_self_process(
        pid=conn.pid,
        name=conn.process_name,
    )


def _is_self_bw(bw: Any) -> bool:
    """Return True if the bandwidth entry belongs to AMOSKYS itself."""
    return self_identity.is_self_process(
        pid=bw.pid,
        name=bw.process_name,
    )


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

    @staticmethod
    def _beacon_stats(timestamps: List[float]) -> Dict[str, Any]:
        """Compute beacon interval and jitter from a timestamp series."""
        intervals = [
            timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)
        ]
        mean_interval = sum(intervals) / len(intervals) if intervals else 0.0
        jitter_cv = 0.0
        if mean_interval > 0 and len(intervals) > 1:
            import statistics

            jitter_cv = statistics.stdev(intervals) / mean_interval
        return {
            "beacon_interval_s": round(mean_interval, 2),
            "beacon_jitter_cv": round(jitter_cv, 4),
            "sample_count": len(timestamps),
        }

    def _should_skip(self, conn: Any) -> bool:
        """Return True if connection should be excluded from beacon analysis."""
        if _is_self(conn):
            return True
        if _is_non_routable(conn.remote_ip):
            return True
        if not conn.remote_ip or _is_private(conn.remote_ip):
            return True
        if conn.state != "ESTABLISHED":
            return True
        proc_lower = (conn.process_name or "").lower().strip().strip("\x00")
        return any(proc_lower.startswith(w) for w in _BEACON_WHITELIST)

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        connections = context.shared_data.get("connections", [])
        now = time.time()

        for conn in connections:
            if self._should_skip(conn):
                continue

            key = conn.remote_ip
            if key not in self._history:
                self._history[key] = []

            self._history[key].append((now, conn.pid, conn.process_name))
            self._history[key] = self._history[key][-self.HISTORY_SIZE :]

            if len(self._history[key]) >= self.MIN_HITS:
                entry = self._history[key]
                timestamps = [t for t, _, _ in entry]
                stats = self._beacon_stats(timestamps)

                events.append(
                    self._create_event(
                        event_type="c2_beacon_suspect",
                        severity=Severity.HIGH,
                        data=_mandate_network_context(
                            conn,
                            self.name,
                            extras={
                                "hit_count": len(entry),
                                "first_seen": entry[0][0],
                                "connection_count": len(entry),
                                **stats,
                            },
                        ),
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
            # Self-exclusion (mandate)
            if _is_self_bw(bw):
                continue

            if bw.bytes_out > self.BYTES_OUT_THRESHOLD:
                events.append(
                    self._create_event(
                        event_type="exfil_spike",
                        severity=Severity.HIGH,
                        data=_mandate_bandwidth_context(
                            bw,
                            self.name,
                            extras={
                                "threshold": self.BYTES_OUT_THRESHOLD,
                            },
                        ),
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
            # Self-exclusion (mandate)
            if _is_self(conn):
                continue
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
                    data=_mandate_network_context(
                        conn,
                        self.name,
                        extras={
                            "user": conn.user,
                        },
                    ),
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
            # Self-exclusion (mandate)
            if _is_self(conn):
                continue
            # IP filtering BEFORE probe evaluation (mandate)
            if _is_non_routable(conn.remote_ip):
                continue
            if _is_private(conn.remote_ip or "127.0.0.1"):
                continue
            if conn.state != "ESTABLISHED":
                continue

            port = conn.remote_port
            if port in _CLEARTEXT_PORTS:
                events.append(
                    self._create_event(
                        event_type="cleartext_protocol",
                        severity=Severity.MEDIUM,
                        data=_mandate_network_context(
                            conn,
                            self.name,
                            extras={
                                "protocol_name": _CLEARTEXT_PORTS[port],
                            },
                        ),
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
            # Self-exclusion (mandate)
            if _is_self(conn):
                continue

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
                        data=_mandate_network_context(
                            conn,
                            self.name,
                            extras={
                                "reason": reason,
                            },
                        ),
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
            # Self-exclusion (mandate)
            if _is_self(conn):
                continue
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
                            data=_mandate_network_context(
                                conn,
                                self.name,
                                extras={
                                    "actual_port": conn.local_port,
                                    "expected_ports": list(expected),
                                },
                            ),
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
            # Self-exclusion (mandate)
            if _is_self(conn):
                continue
            if conn.state != "ESTABLISHED":
                continue
            if conn.process_name in _CLOUD_PROCESSES:
                events.append(
                    self._create_event(
                        event_type="cloud_sync_active",
                        severity=Severity.INFO,
                        data=_mandate_network_context(
                            conn,
                            self.name,
                        ),
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
            # Self-exclusion (mandate)
            if _is_self(conn):
                continue
            # IP filtering BEFORE probe evaluation (mandate)
            if _is_non_routable(conn.remote_ip):
                continue
            if not conn.remote_ip or _is_private(conn.remote_ip):
                continue
            if conn.state != "ESTABLISHED":
                continue

            key = f"{conn.process_name}:{conn.remote_ip}:{conn.remote_port}"
            current.add(key)

            if not self._first_run and key not in self._known:
                events.append(
                    self._create_event(
                        event_type="new_external_connection",
                        severity=Severity.LOW,
                        data=_mandate_network_context(
                            conn,
                            self.name,
                            extras={
                                "user": conn.user,
                            },
                        ),
                        confidence=0.5,
                    )
                )

        self._known = current
        self._first_run = False
        return events


# =============================================================================
# 9. PortScanDetectionProbe
# =============================================================================


class PortScanDetectionProbe(MicroProbe):
    """Detects inbound port scanning from a single source IP.

    Fires when a single remote IP connects to 8+ unique local ports,
    indicating nmap or similar reconnaissance.

    MITRE: T1046 (Network Service Discovery)
    """

    name = "macos_port_scan_detection"
    description = "Detects port scanning from single source IP hitting multiple ports"
    platforms = ["darwin"]
    mitre_techniques = ["T1046"]
    mitre_tactics = ["discovery"]
    scan_interval = 15.0
    requires_fields = ["connections"]

    _MIN_PORTS = 8
    _ALLOWLIST_IPS = {"127.0.0.1", "::1", "0.0.0.0", ""}

    def __init__(self) -> None:
        super().__init__()
        self._alerted: Set[str] = set()

    @staticmethod
    def _classify_scan(ports: Set[int]) -> tuple:
        """Return (scan_type, severity) for a set of hit ports."""
        if len(ports) > 100:
            return "full_port_scan", Severity.HIGH
        if sum(1 for p in ports if p < 1024) > 10:
            return "service_scan", Severity.HIGH
        return "targeted_scan", Severity.MEDIUM

    def _aggregate_sources(self, connections: List[Any]) -> tuple:
        """Aggregate connections by source IP, filtering per mandate."""
        src_ports: Dict[str, Set[int]] = {}
        src_repr: Dict[str, Any] = {}
        for conn in connections:
            if _is_self(conn):
                continue
            src_ip = conn.remote_ip
            if not src_ip or src_ip in self._ALLOWLIST_IPS:
                continue
            if _is_non_routable(src_ip):
                continue
            if src_ip not in src_ports:
                src_ports[src_ip] = set()
                src_repr[src_ip] = conn
            if conn.local_port:
                src_ports[src_ip].add(conn.local_port)
        return src_ports, src_repr

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        connections = context.shared_data.get("connections", [])

        src_ports, src_repr = self._aggregate_sources(connections)

        for src_ip, ports in src_ports.items():
            if len(ports) < self._MIN_PORTS:
                continue
            key = f"{src_ip}:{len(ports)}"
            if key in self._alerted:
                continue
            self._alerted.add(key)

            scan_type, severity = self._classify_scan(ports)
            events.append(
                self._create_event(
                    event_type="port_scan_detected",
                    severity=severity,
                    data=_mandate_network_context(
                        src_repr[src_ip],
                        self.name,
                        extras={
                            "source_ip": src_ip,
                            "unique_ports_hit": len(ports),
                            "scan_type": scan_type,
                            "sample_ports": sorted(ports)[:20],
                            "connection_count": len(ports),
                        },
                    ),
                    confidence=min(0.95, 0.50 + len(ports) / 100),
                    tags=["reconnaissance", "port-scan"],
                )
            )

        # Prune dedup cache
        if len(self._alerted) > 1000:
            self._alerted = set(list(self._alerted)[-500:])

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
        PortScanDetectionProbe(),
    ]
