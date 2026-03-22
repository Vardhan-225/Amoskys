"""macOS Internet Activity Observatory probes — threat detection via network connection analysis.

8 probes covering exfiltration, command & control, and impact tactics:
    1. CloudExfilProbe        — T1567   Exfiltration to cloud storage endpoints
    2. TORVPNUsageProbe       — T1090.003 TOR exit node / VPN port detection
    3. CryptoMiningProbe      — T1496   Mining pool port pattern detection
    4. GeoAnomalyProbe        — T1071   Connections to unusual IP ranges
    5. LongLivedConnProbe     — T1571   Persistent connections to non-CDN IPs
    6. DataExfilTimingProbe   — T1048   Late-night / burst data transfer patterns
    7. ShadowITProbe          — T1567.002 Unauthorized cloud service usage
    8. CDNMasqueradeProbe     — T1090.002 C2 traffic hiding behind CDN infra
"""

from __future__ import annotations

import collections
import logging
import time
from typing import Any, Dict, List, Optional, Set

from amoskys.agents.common.probes import (
    MicroProbe,
    ProbeContext,
    Severity,
    TelemetryEvent,
)
from amoskys.agents.os.macos.internet_activity.collector import (
    InternetConnection,
    _is_cdn,
    _is_cloud_provider,
    _is_private_ip,
    _is_tor_exit_node,
)

logger = logging.getLogger(__name__)


# ── Shared utilities ─────────────────────────────────────────────────────────


# VPN-related ports
_VPN_PORTS = frozenset(
    {
        1194,  # OpenVPN
        1723,  # PPTP
        4500,  # IPSec NAT-T
        500,  # IKE (IPSec)
        1701,  # L2TP
        51820,  # WireGuard
    }
)

# Crypto mining stratum ports
_MINING_PORTS = frozenset(
    {
        3333,  # Stratum (common)
        4444,  # Stratum (alt)
        5555,  # Stratum (alt)
        7777,  # Stratum (alt)
        8333,  # Bitcoin P2P
        8332,  # Bitcoin RPC
        9333,  # Litecoin P2P
        14444,  # Monero stratum
        45700,  # Monero alt
    }
)

# Shadow IT cloud service ports and IP indicators
_SHADOW_IT_PORTS = frozenset(
    {
        17500,  # Dropbox LAN sync
        19302,  # Google STUN (used by Drive)
        443,  # HTTPS (combined with IP classification)
    }
)

# Dropbox IP prefixes (representative)
_DROPBOX_PREFIXES = (
    "162.125.",
    "108.160.160.",
    "108.160.161.",
    "108.160.162.",
    "108.160.163.",
    "108.160.164.",
    "108.160.165.",
    "108.160.166.",
    "108.160.167.",
    "108.160.168.",
    "108.160.169.",
    "108.160.170.",
    "45.58.64.",
    "45.58.65.",
    "45.58.66.",
    "45.58.67.",
)

# Mega.nz IP prefixes (representative)
_MEGA_PREFIXES = (
    "31.216.144.",
    "31.216.145.",
    "31.216.146.",
    "31.216.147.",
    "31.216.148.",
    "89.44.169.",
    "66.203.125.",
)

# S3/GCS/Azure Blob storage ports — primarily 443, but also 80 and custom
_CLOUD_STORAGE_PORTS = frozenset({80, 443, 8443, 9000})

# Cloud provider S3-specific prefixes (Amazon S3 IP ranges)
_S3_PREFIXES = (
    "52.216.",
    "52.217.",
    "52.218.",
    "52.219.",
    "52.92.",
    "54.231.",
    "3.5.",
)

# GCS-specific prefixes
_GCS_PREFIXES = (
    "142.250.",
    "172.217.",
    "216.58.",
    "74.125.",
    "173.194.",
    "108.177.",
)

# Azure Blob-specific prefixes
_AZURE_BLOB_PREFIXES = (
    "52.239.",
    "20.150.",
    "20.60.",
    "13.66.",
    "13.68.",
    "13.70.",
    "13.71.",
    "13.72.",
    "13.73.",
)


def _is_s3_endpoint(ip: str, port: int) -> bool:
    """Check if connection targets AWS S3 endpoint."""
    return port in _CLOUD_STORAGE_PORTS and any(ip.startswith(p) for p in _S3_PREFIXES)


def _is_gcs_endpoint(ip: str, port: int) -> bool:
    """Check if connection targets Google Cloud Storage endpoint."""
    return port in _CLOUD_STORAGE_PORTS and any(ip.startswith(p) for p in _GCS_PREFIXES)


def _is_azure_blob_endpoint(ip: str, port: int) -> bool:
    """Check if connection targets Azure Blob Storage endpoint."""
    return port in _CLOUD_STORAGE_PORTS and any(
        ip.startswith(p) for p in _AZURE_BLOB_PREFIXES
    )


def _is_dropbox_ip(ip: str) -> bool:
    """Check if IP belongs to Dropbox."""
    return any(ip.startswith(p) for p in _DROPBOX_PREFIXES)


def _is_mega_ip(ip: str) -> bool:
    """Check if IP belongs to Mega.nz."""
    return any(ip.startswith(p) for p in _MEGA_PREFIXES)


def _get_hour() -> int:
    """Get current hour (0-23) for timing analysis."""
    return time.localtime().tm_hour


# ── Probe 1: Cloud Exfiltration ──────────────────────────────────────────────


class CloudExfilProbe(MicroProbe):
    """Detect exfiltration to cloud storage endpoints (S3, GCS, Azure Blob).

    MITRE: T1567 — Exfiltration Over Web Service

    Adversaries exfiltrate data to cloud storage services to blend with normal
    traffic. We detect connections to known S3, GCS, and Azure Blob IP ranges
    combined with storage-typical port patterns.
    """

    name = "macos_internet_cloud_exfil"
    description = (
        "Detects connections to AWS S3/GCS/Azure Blob endpoints by IP range and port"
    )
    platforms = ["darwin"]
    mitre_techniques = ["T1567"]
    mitre_tactics = ["exfiltration"]
    scan_interval = 10.0
    requires_fields = ["connections"]
    maturity = "stable"
    false_positive_notes = [
        "Legitimate cloud backup tools (Time Machine to S3, rclone) produce similar patterns",
        "Developer tools (aws-cli, gsutil, azcopy) make expected S3/GCS/Azure connections",
    ]
    evasion_notes = [
        "Using non-standard ports or tunneling through HTTPS proxies",
        "Exfiltrating via lesser-known cloud providers not in detection ranges",
    ]

    # Thresholds
    MIN_CONNECTIONS_TO_SAME_CLOUD = (
        3  # Multiple connections to same cloud → more suspicious
    )

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        connections = context.shared_data.get("connections", [])

        cloud_hits: Dict[str, List[InternetConnection]] = collections.defaultdict(list)

        for conn in connections:
            if conn.remote_addr == "*" or _is_private_ip(conn.remote_addr):
                continue

            cloud_type = None
            if _is_s3_endpoint(conn.remote_addr, conn.remote_port):
                cloud_type = "aws_s3"
            elif _is_gcs_endpoint(conn.remote_addr, conn.remote_port):
                cloud_type = "gcs"
            elif _is_azure_blob_endpoint(conn.remote_addr, conn.remote_port):
                cloud_type = "azure_blob"

            if cloud_type:
                cloud_hits[cloud_type].append(conn)

        for cloud_type, conns in cloud_hits.items():
            severity = (
                Severity.HIGH
                if len(conns) >= self.MIN_CONNECTIONS_TO_SAME_CLOUD
                else Severity.MEDIUM
            )
            confidence = min(0.90, 0.5 + len(conns) * 0.1)

            unique_pids = {c.pid for c in conns}
            processes = {c.process_name for c in conns}
            remote_ips = {c.remote_addr for c in conns}

            events.append(
                self._create_event(
                    event_type="cloud_exfil_detected",
                    severity=severity,
                    data={
                        "probe_name": self.name,
                        "detection_source": "lsof",
                        "cloud_type": cloud_type,
                        "connection_count": len(conns),
                        "unique_pids": sorted(unique_pids),
                        "processes": sorted(processes),
                        "remote_ips": sorted(remote_ips),
                        "remote_ports": sorted({c.remote_port for c in conns}),
                        "users": sorted({c.user for c in conns}),
                    },
                    confidence=confidence,
                )
            )

        return events


# ── Probe 2: TOR / VPN Usage ────────────────────────────────────────────────


class TORVPNUsageProbe(MicroProbe):
    """Detect TOR exit node connections and common VPN port usage.

    MITRE: T1090.003 — Proxy: Multi-hop Proxy

    Adversaries use TOR or VPN tunnels to anonymize C2 traffic and exfiltration.
    We detect connections to known TOR exit nodes and common VPN protocol ports
    (OpenVPN 1194, PPTP 1723, IPSec NAT-T 4500).
    """

    name = "macos_internet_tor_vpn"
    description = "Detects TOR exit node connections and common VPN port usage"
    platforms = ["darwin"]
    mitre_techniques = ["T1090.003"]
    mitre_tactics = ["command_and_control"]
    scan_interval = 10.0
    requires_fields = ["connections"]
    maturity = "stable"
    false_positive_notes = [
        "Privacy-conscious users running TOR Browser or legitimate VPN clients",
        "Corporate VPN connections (Cisco AnyConnect, GlobalProtect) use IPSec ports",
    ]
    evasion_notes = [
        "Using TOR bridges (obfs4) on non-standard ports",
        "VPN over HTTPS (port 443) blends with normal web traffic",
    ]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        connections = context.shared_data.get("connections", [])

        tor_connections: List[InternetConnection] = []
        vpn_connections: List[InternetConnection] = []

        for conn in connections:
            if conn.remote_addr == "*" or _is_private_ip(conn.remote_addr):
                continue

            # Check TOR exit nodes
            if _is_tor_exit_node(conn.remote_addr):
                tor_connections.append(conn)

            # Check VPN ports
            if conn.remote_port in _VPN_PORTS or conn.local_port in _VPN_PORTS:
                vpn_connections.append(conn)

        if tor_connections:
            events.append(
                self._create_event(
                    event_type="tor_connection_detected",
                    severity=Severity.HIGH,
                    data={
                        "probe_name": self.name,
                        "detection_source": "lsof",
                        "connection_count": len(tor_connections),
                        "tor_ips": sorted({c.remote_addr for c in tor_connections}),
                        "processes": sorted({c.process_name for c in tor_connections}),
                        "pids": sorted({c.pid for c in tor_connections}),
                        "users": sorted({c.user for c in tor_connections}),
                    },
                    confidence=0.85,
                )
            )

        if vpn_connections:
            # Group by VPN port
            port_groups: Dict[int, List[InternetConnection]] = collections.defaultdict(
                list
            )
            for conn in vpn_connections:
                port = (
                    conn.remote_port
                    if conn.remote_port in _VPN_PORTS
                    else conn.local_port
                )
                port_groups[port].append(conn)

            for port, conns in port_groups.items():
                events.append(
                    self._create_event(
                        event_type="vpn_port_usage_detected",
                        severity=Severity.MEDIUM,
                        data={
                            "probe_name": self.name,
                            "detection_source": "lsof",
                            "vpn_port": port,
                            "connection_count": len(conns),
                            "remote_ips": sorted({c.remote_addr for c in conns}),
                            "processes": sorted({c.process_name for c in conns}),
                            "pids": sorted({c.pid for c in conns}),
                        },
                        confidence=0.70,
                    )
                )

        return events


# ── Probe 3: Crypto Mining ───────────────────────────────────────────────────


class CryptoMiningProbe(MicroProbe):
    """Detect crypto mining pool connections via known stratum port patterns.

    MITRE: T1496 — Resource Hijacking

    Cryptojacking malware connects to mining pools using well-known stratum
    protocol ports (3333, 4444, 8333). We detect connections to these ports
    from non-browser processes.
    """

    name = "macos_internet_crypto_mining"
    description = (
        "Detects mining pool connections via stratum port patterns (3333, 4444, 8333)"
    )
    platforms = ["darwin"]
    mitre_techniques = ["T1496"]
    mitre_tactics = ["impact"]
    scan_interval = 10.0
    requires_fields = ["connections"]
    maturity = "stable"
    false_positive_notes = [
        "Legitimate Bitcoin/cryptocurrency wallet software uses port 8333",
        "Blockchain development tools may connect to test mining pools",
    ]
    evasion_notes = [
        "Mining over HTTPS (port 443) using stratum-over-TLS",
        "Using proxy/SOCKS to tunnel mining traffic through standard ports",
    ]

    # Processes that legitimately use mining ports
    _BENIGN_MINING_PROCESSES = frozenset(
        {
            "Bitcoin-Qt",
            "bitcoin-qt",
            "bitcoind",
            "Electrum",
            "electrum",
        }
    )

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        connections = context.shared_data.get("connections", [])

        mining_connections: List[InternetConnection] = []

        for conn in connections:
            if conn.remote_addr == "*" or _is_private_ip(conn.remote_addr):
                continue

            if conn.remote_port in _MINING_PORTS:
                if conn.process_name not in self._BENIGN_MINING_PROCESSES:
                    mining_connections.append(conn)

        if mining_connections:
            # Group by process
            by_process: Dict[str, List[InternetConnection]] = collections.defaultdict(
                list
            )
            for conn in mining_connections:
                by_process[conn.process_name].append(conn)

            for process, conns in by_process.items():
                ports_hit = {c.remote_port for c in conns}
                severity = Severity.CRITICAL if len(ports_hit) >= 2 else Severity.HIGH

                events.append(
                    self._create_event(
                        event_type="crypto_mining_detected",
                        severity=severity,
                        data={
                            "probe_name": self.name,
                            "detection_source": "lsof",
                            "process_name": process,
                            "pids": sorted({c.pid for c in conns}),
                            "mining_ports": sorted(ports_hit),
                            "remote_ips": sorted({c.remote_addr for c in conns}),
                            "connection_count": len(conns),
                            "user": conns[0].user,
                        },
                        confidence=min(0.95, 0.7 + len(ports_hit) * 0.1),
                    )
                )

        return events


# ── Probe 4: Geo-Anomaly ────────────────────────────────────────────────────


class GeoAnomalyProbe(MicroProbe):
    """Detect connections to unusual IP ranges using simple heuristics.

    MITRE: T1071 — Application Layer Protocol

    Connections to IP ranges outside typical US/EU allocations may indicate
    C2 infrastructure in unusual geographies. We use IANA regional allocation
    heuristics for first-octet classification.
    """

    name = "macos_internet_geo_anomaly"
    description = "Detects connections to unusual IP ranges (non-US/EU heuristics)"
    platforms = ["darwin"]
    mitre_techniques = ["T1071"]
    mitre_tactics = ["command_and_control"]
    scan_interval = 30.0
    requires_fields = ["connections"]
    maturity = "experimental"
    false_positive_notes = [
        "Global CDNs serve content from worldwide PoPs with diverse IP ranges",
        "International services (gaming, messaging) use APAC/LATAM IP allocations",
    ]
    evasion_notes = [
        "Using cloud VPS in US/EU regions for C2 infrastructure",
        "Routing C2 through CDN-fronted domains (domain fronting)",
    ]

    # IP ranges commonly associated with unusual/suspicious geographies
    # These are IANA-allocated prefixes for regions less commonly seen in
    # typical US/EU enterprise traffic
    _UNUSUAL_FIRST_OCTETS = frozenset(
        {
            # Ranges often allocated to regions with higher C2 infrastructure prevalence
            14,
            27,
            36,
            37,
            39,
            41,
            42,
            43,
            45,
            46,
            47,
            49,
            58,
            59,
            60,
            61,
            77,
            78,
            79,
            80,
            81,
            82,
            83,
            84,
            85,
            86,
            87,
            88,
            89,
            91,
            92,
            93,
            94,
            95,
            101,
            103,
            105,
            106,
            109,
            110,
            111,
            112,
            113,
            114,
            115,
            116,
            117,
            118,
            119,
            120,
            121,
            122,
            123,
            124,
            125,
            126,
            133,
            150,
            153,
            154,
            155,
            156,
            157,
            158,
            159,
            160,
            161,
            163,
            164,
            175,
            176,
            177,
            178,
            179,
            180,
            181,
            182,
            183,
            185,
            186,
            187,
            188,
            189,
            190,
            191,
            193,
            194,
            195,
            196,
            197,
            200,
            201,
            202,
            203,
            210,
            211,
            212,
            213,
            217,
            218,
            219,
            220,
            221,
            222,
            223,
        }
    )

    # Minimum unique unusual IPs to trigger
    MIN_UNUSUAL_IPS = 3

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        connections = context.shared_data.get("connections", [])

        unusual_connections: List[InternetConnection] = []

        for conn in connections:
            if conn.remote_addr == "*" or _is_private_ip(conn.remote_addr):
                continue

            # Skip known CDN/cloud — they're globally distributed
            if _is_cdn(conn.remote_addr) or _is_cloud_provider(conn.remote_addr):
                continue

            try:
                first_octet = int(conn.remote_addr.split(".")[0])
            except (ValueError, IndexError):
                continue

            if first_octet in self._UNUSUAL_FIRST_OCTETS:
                unusual_connections.append(conn)

        unusual_ips = {c.remote_addr for c in unusual_connections}

        if len(unusual_ips) >= self.MIN_UNUSUAL_IPS:
            events.append(
                self._create_event(
                    event_type="geo_anomaly_detected",
                    severity=Severity.MEDIUM,
                    data={
                        "probe_name": self.name,
                        "detection_source": "lsof",
                        "unusual_ip_count": len(unusual_ips),
                        "unusual_ips": sorted(unusual_ips)[:20],
                        "connection_count": len(unusual_connections),
                        "processes": sorted(
                            {c.process_name for c in unusual_connections}
                        ),
                        "remote_ports": sorted(
                            {c.remote_port for c in unusual_connections}
                        ),
                        "threshold": self.MIN_UNUSUAL_IPS,
                    },
                    confidence=min(0.80, 0.4 + len(unusual_ips) * 0.05),
                )
            )

        return events


# ── Probe 5: Long-Lived Connections ─────────────────────────────────────────


class LongLivedConnProbe(MicroProbe):
    """Detect persistent connections tracked over multiple collection cycles.

    MITRE: T1571 — Non-Standard Port

    C2 implants often maintain long-lived connections to command servers.
    We track connections across cycles and alert when a connection to a
    non-CDN IP persists beyond 1 hour.
    """

    name = "macos_internet_long_lived"
    description = "Detects persistent connections (>1hr) to non-CDN IPs across cycles"
    platforms = ["darwin"]
    mitre_techniques = ["T1571"]
    mitre_tactics = ["command_and_control"]
    scan_interval = 30.0
    requires_fields = ["connections"]
    maturity = "stable"
    false_positive_notes = [
        "SSH sessions and remote desktop connections are naturally long-lived",
        "Streaming services (Spotify, Netflix) maintain persistent connections",
    ]
    evasion_notes = [
        "Periodic connection tear-down and re-establishment to reset duration",
        "Using CDN-fronted C2 (connections appear as CDN traffic)",
    ]

    DURATION_THRESHOLD_S = 3600.0  # 1 hour

    # Processes with legitimately long connections
    _BENIGN_LONG_PROCESSES = frozenset(
        {
            "ssh",
            "mosh-client",
            "mosh-server",
            "Spotify",
            "spotify",
            "Slack",
            "slack",
            "Teams",
            "teams",
            "zoom.us",
            "Discord",
            "discord",
            "Dropbox",
            "OneDrive",
            "GoogleDrive",
        }
    )

    def __init__(self) -> None:
        super().__init__()
        # conn_key → first_seen_timestamp
        self._tracked_connections: Dict[str, float] = {}
        self._alerted: Set[str] = set()

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        connections = context.shared_data.get("connections", [])
        now = time.time()

        current_keys: Set[str] = set()

        for conn in connections:
            if conn.remote_addr == "*" or _is_private_ip(conn.remote_addr):
                continue
            if conn.state not in ("ESTABLISHED", "UNKNOWN"):
                continue
            if _is_cdn(conn.remote_addr):
                continue
            if conn.process_name in self._BENIGN_LONG_PROCESSES:
                continue

            conn_key = f"{conn.pid}:{conn.remote_addr}:{conn.remote_port}"
            current_keys.add(conn_key)

            if conn_key not in self._tracked_connections:
                self._tracked_connections[conn_key] = now
                continue

            duration = now - self._tracked_connections[conn_key]

            # Also use collector's duration estimate if available
            effective_duration = max(duration, conn.duration_estimate_s)

            if (
                effective_duration >= self.DURATION_THRESHOLD_S
                and conn_key not in self._alerted
            ):
                events.append(
                    self._create_event(
                        event_type="long_lived_connection",
                        severity=Severity.HIGH,
                        data={
                            "probe_name": self.name,
                            "detection_source": "lsof",
                            "process_name": conn.process_name,
                            "pid": conn.pid,
                            "remote_addr": conn.remote_addr,
                            "remote_port": conn.remote_port,
                            "duration_s": round(effective_duration, 1),
                            "duration_hours": round(effective_duration / 3600, 2),
                            "user": conn.user,
                            "protocol": conn.protocol,
                            "threshold_s": self.DURATION_THRESHOLD_S,
                        },
                        confidence=min(
                            0.90,
                            0.6
                            + (effective_duration / self.DURATION_THRESHOLD_S) * 0.1,
                        ),
                    )
                )
                self._alerted.add(conn_key)

        # Prune connections that are no longer active
        stale_keys = [k for k in self._tracked_connections if k not in current_keys]
        for k in stale_keys:
            del self._tracked_connections[k]
            self._alerted.discard(k)

        return events


# ── Probe 6: Data Exfil Timing ──────────────────────────────────────────────


class DataExfilTimingProbe(MicroProbe):
    """Detect unusual data transfer timing patterns (late-night, burst).

    MITRE: T1048 — Exfiltration Over Alternative Protocol

    Adversaries often schedule exfiltration during off-hours to avoid detection.
    We detect connections occurring during unusual hours (00:00-05:00) and
    burst patterns (many new connections in a short window).
    """

    name = "macos_internet_exfil_timing"
    description = (
        "Detects unusual data transfer timing (late-night connections, burst patterns)"
    )
    platforms = ["darwin"]
    mitre_techniques = ["T1048"]
    mitre_tactics = ["exfiltration"]
    scan_interval = 30.0
    requires_fields = ["connections"]
    maturity = "experimental"
    false_positive_notes = [
        "Scheduled backups and cron jobs legitimately run during off-hours",
        "Software update services (softwareupdated) download during night hours",
    ]
    evasion_notes = [
        "Exfiltrating during business hours to blend with normal traffic",
        "Throttling data transfer to avoid burst pattern detection",
    ]

    # Late-night window (00:00 - 05:00)
    LATE_NIGHT_START = 0
    LATE_NIGHT_END = 5

    # Burst detection
    BURST_THRESHOLD = 15  # New outbound connections in single cycle

    # Processes expected to run at night
    _NIGHT_BENIGN = frozenset(
        {
            "softwareupdated",
            "SoftwareUpdateD",
            "com.apple.MobileSoftwareUpdate",
            "TimeMachine",
            "backupd",
            "backupd-helper",
            "CrashReporterSupportHelper",
            "trustd",
            "timed",
            "nsurlsessiond",
            "apsd",
        }
    )

    def __init__(self) -> None:
        super().__init__()
        self._cycle_count = 0

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        connections = context.shared_data.get("connections", [])
        self._cycle_count += 1

        hour = _get_hour()
        is_late_night = self.LATE_NIGHT_START <= hour < self.LATE_NIGHT_END

        outbound_connections = [
            c
            for c in connections
            if c.direction == "outbound"
            and c.remote_addr != "*"
            and not _is_private_ip(c.remote_addr)
        ]

        # Check 1: Late-night connections
        if is_late_night:
            suspicious_night = [
                c
                for c in outbound_connections
                if c.process_name not in self._NIGHT_BENIGN
            ]

            if suspicious_night:
                events.append(
                    self._create_event(
                        event_type="late_night_connections",
                        severity=Severity.MEDIUM,
                        data={
                            "probe_name": self.name,
                            "detection_source": "lsof",
                            "hour": hour,
                            "connection_count": len(suspicious_night),
                            "processes": sorted(
                                {c.process_name for c in suspicious_night}
                            ),
                            "remote_ips": sorted(
                                {c.remote_addr for c in suspicious_night}
                            )[:10],
                            "pids": sorted({c.pid for c in suspicious_night}),
                        },
                        confidence=0.60,
                    )
                )

        # Check 2: Connection burst pattern
        if len(outbound_connections) >= self.BURST_THRESHOLD:
            # Group by process to find bursting process
            by_process: Dict[str, List[InternetConnection]] = collections.defaultdict(
                list
            )
            for conn in outbound_connections:
                by_process[conn.process_name].append(conn)

            for process, conns in by_process.items():
                if len(conns) >= self.BURST_THRESHOLD:
                    events.append(
                        self._create_event(
                            event_type="connection_burst_detected",
                            severity=Severity.HIGH,
                            data={
                                "probe_name": self.name,
                                "detection_source": "lsof",
                                "process_name": process,
                                "connection_count": len(conns),
                                "unique_remote_ips": len(
                                    {c.remote_addr for c in conns}
                                ),
                                "remote_ports": sorted({c.remote_port for c in conns}),
                                "pids": sorted({c.pid for c in conns}),
                                "threshold": self.BURST_THRESHOLD,
                            },
                            confidence=min(0.85, 0.5 + len(conns) * 0.02),
                        )
                    )

        return events


# ── Probe 7: Shadow IT ──────────────────────────────────────────────────────


class ShadowITProbe(MicroProbe):
    """Detect unauthorized cloud service usage (Dropbox, Google Drive, Mega.nz).

    MITRE: T1567.002 — Exfiltration Over Web Service: Exfiltration to Cloud Storage

    Employees may use personal cloud storage to exfiltrate data. We detect
    connections to known Dropbox, personal Google Drive, and Mega.nz IP ranges
    and service-specific ports.
    """

    name = "macos_internet_shadow_it"
    description = (
        "Detects unauthorized cloud service usage (Dropbox, Google Drive, Mega.nz)"
    )
    platforms = ["darwin"]
    mitre_techniques = ["T1567.002"]
    mitre_tactics = ["exfiltration"]
    scan_interval = 15.0
    requires_fields = ["connections"]
    maturity = "stable"
    false_positive_notes = [
        "IT-approved Dropbox/Google Drive installations are legitimate",
        "Browser-based access to cloud storage may match on IP ranges",
    ]
    evasion_notes = [
        "Using browser-based upload to avoid process-level detection",
        "Using lesser-known cloud storage (pCloud, Tresorit) not in detection list",
    ]

    # Dropbox-specific process names
    _DROPBOX_PROCESSES = frozenset(
        {
            "Dropbox",
            "dropbox",
            "DropboxMacUpdate",
            "dbfseventsd",
        }
    )

    # Google Drive process names (personal vs enterprise)
    _GDRIVE_PROCESSES = frozenset(
        {
            "Google Drive",
            "GoogleDriveFS",
            "Backup and Sync",
        }
    )

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        connections = context.shared_data.get("connections", [])

        dropbox_hits: List[InternetConnection] = []
        mega_hits: List[InternetConnection] = []
        gdrive_hits: List[InternetConnection] = []

        for conn in connections:
            if conn.remote_addr == "*" or _is_private_ip(conn.remote_addr):
                continue

            # Dropbox detection: process name OR IP + LAN sync port
            if (
                conn.process_name in self._DROPBOX_PROCESSES
                or _is_dropbox_ip(conn.remote_addr)
                or conn.remote_port == 17500
                or conn.local_port == 17500
            ):
                dropbox_hits.append(conn)

            # Mega.nz detection: IP range
            elif _is_mega_ip(conn.remote_addr):
                mega_hits.append(conn)

            # Google Drive detection: process name
            elif conn.process_name in self._GDRIVE_PROCESSES:
                gdrive_hits.append(conn)

        if dropbox_hits:
            events.append(
                self._create_event(
                    event_type="shadow_it_dropbox",
                    severity=Severity.MEDIUM,
                    data={
                        "probe_name": self.name,
                        "detection_source": "lsof",
                        "service": "dropbox",
                        "connection_count": len(dropbox_hits),
                        "processes": sorted({c.process_name for c in dropbox_hits}),
                        "remote_ips": sorted({c.remote_addr for c in dropbox_hits})[
                            :10
                        ],
                        "pids": sorted({c.pid for c in dropbox_hits}),
                        "users": sorted({c.user for c in dropbox_hits}),
                    },
                    confidence=0.75,
                )
            )

        if mega_hits:
            events.append(
                self._create_event(
                    event_type="shadow_it_mega",
                    severity=Severity.HIGH,
                    data={
                        "probe_name": self.name,
                        "detection_source": "lsof",
                        "service": "mega.nz",
                        "connection_count": len(mega_hits),
                        "processes": sorted({c.process_name for c in mega_hits}),
                        "remote_ips": sorted({c.remote_addr for c in mega_hits})[:10],
                        "pids": sorted({c.pid for c in mega_hits}),
                        "users": sorted({c.user for c in mega_hits}),
                    },
                    confidence=0.80,
                )
            )

        if gdrive_hits:
            events.append(
                self._create_event(
                    event_type="shadow_it_gdrive",
                    severity=Severity.MEDIUM,
                    data={
                        "probe_name": self.name,
                        "detection_source": "lsof",
                        "service": "google_drive_personal",
                        "connection_count": len(gdrive_hits),
                        "processes": sorted({c.process_name for c in gdrive_hits}),
                        "remote_ips": sorted({c.remote_addr for c in gdrive_hits})[:10],
                        "pids": sorted({c.pid for c in gdrive_hits}),
                        "users": sorted({c.user for c in gdrive_hits}),
                    },
                    confidence=0.70,
                )
            )

        return events


# ── Probe 8: CDN Masquerade ─────────────────────────────────────────────────


class CDNMasqueradeProbe(MicroProbe):
    """Detect C2 traffic hiding behind CDN infrastructure.

    MITRE: T1090.002 — Proxy: External Proxy

    Adversaries use CDN-fronted domains to hide C2 servers behind legitimate
    CDN infrastructure (Cloudflare, Akamai, Fastly). Indicators: unusual
    traffic patterns to CDN IPs — non-browser processes, non-standard ports,
    persistent connections, or high connection counts.
    """

    name = "macos_internet_cdn_masquerade"
    description = "Detects C2 hiding behind CDN via unusual traffic patterns to CDN IPs"
    platforms = ["darwin"]
    mitre_techniques = ["T1090.002"]
    mitre_tactics = ["command_and_control"]
    scan_interval = 30.0
    requires_fields = ["connections"]
    maturity = "experimental"
    false_positive_notes = [
        "CLI tools (curl, wget, httpie) making legitimate CDN requests",
        "Development tools and package managers use CDN-hosted endpoints",
    ]
    evasion_notes = [
        "Using browser process for C2 to blend with normal web traffic",
        "Low-frequency beaconing to CDN-fronted domains",
    ]

    # Browser processes (legitimate CDN users)
    _BROWSER_PROCESSES = frozenset(
        {
            "Safari",
            "com.apple.WebKit.Networking",
            "com.apple.Safari",
            "Google Chrome",
            "Google Chrome Helper",
            "Chrome",
            "firefox",
            "Firefox",
            "firefox-bin",
            "Microsoft Edge",
            "msedge",
            "Arc",
            "Brave Browser",
            "Opera",
        }
    )

    # Standard web ports
    _WEB_PORTS = frozenset({80, 443, 8080, 8443})

    # Threshold for suspicious CDN connections from single non-browser process
    SUSPICIOUS_CDN_CONN_THRESHOLD = 5

    def __init__(self) -> None:
        super().__init__()
        # Track CDN connections per process across cycles
        self._cdn_process_history: Dict[str, int] = collections.defaultdict(int)

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        connections = context.shared_data.get("connections", [])

        # Group CDN connections by process
        cdn_by_process: Dict[str, List[InternetConnection]] = collections.defaultdict(
            list
        )

        for conn in connections:
            if conn.remote_addr == "*" or _is_private_ip(conn.remote_addr):
                continue

            if not _is_cdn(conn.remote_addr):
                continue

            cdn_by_process[conn.process_name].append(conn)

        for process, conns in cdn_by_process.items():
            # Skip browsers — they legitimately use CDNs
            if process in self._BROWSER_PROCESSES:
                continue

            self._cdn_process_history[process] = self._cdn_process_history.get(
                process, 0
            ) + len(conns)

            # Check 1: Non-standard ports to CDN
            non_web_port_conns = [
                c for c in conns if c.remote_port not in self._WEB_PORTS
            ]
            if non_web_port_conns:
                events.append(
                    self._create_event(
                        event_type="cdn_masquerade_non_standard_port",
                        severity=Severity.HIGH,
                        data={
                            "probe_name": self.name,
                            "detection_source": "lsof",
                            "process_name": process,
                            "non_standard_ports": sorted(
                                {c.remote_port for c in non_web_port_conns}
                            ),
                            "cdn_ips": sorted(
                                {c.remote_addr for c in non_web_port_conns}
                            )[:10],
                            "connection_count": len(non_web_port_conns),
                            "pids": sorted({c.pid for c in non_web_port_conns}),
                        },
                        confidence=0.80,
                    )
                )

            # Check 2: High connection count from non-browser to CDN
            if len(conns) >= self.SUSPICIOUS_CDN_CONN_THRESHOLD:
                events.append(
                    self._create_event(
                        event_type="cdn_masquerade_high_volume",
                        severity=Severity.MEDIUM,
                        data={
                            "probe_name": self.name,
                            "detection_source": "lsof",
                            "process_name": process,
                            "connection_count": len(conns),
                            "cumulative_count": self._cdn_process_history[process],
                            "cdn_ips": sorted({c.remote_addr for c in conns})[:10],
                            "remote_ports": sorted({c.remote_port for c in conns}),
                            "pids": sorted({c.pid for c in conns}),
                            "threshold": self.SUSPICIOUS_CDN_CONN_THRESHOLD,
                        },
                        confidence=min(0.75, 0.4 + len(conns) * 0.05),
                    )
                )

        return events


# ── Factory ──────────────────────────────────────────────────────────────────


def create_internet_activity_probes() -> List[MicroProbe]:
    """Create all macOS Internet Activity Observatory probes."""
    return [
        CloudExfilProbe(),
        TORVPNUsageProbe(),
        CryptoMiningProbe(),
        GeoAnomalyProbe(),
        LongLivedConnProbe(),
        DataExfilTimingProbe(),
        ShadowITProbe(),
        CDNMasqueradeProbe(),
    ]
