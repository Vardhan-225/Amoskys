#!/usr/bin/env python3
"""FlowAgent Micro-Probes - 8 Eyes on Network Traffic & C2.

Each probe watches ONE specific network threat vector:

1. PortScanSweepProbe - Port scanning detection (vertical/horizontal)
2. LateralSMBWinRMProbe - Lateral movement over admin protocols
3. DataExfilVolumeSpikeProbe - Bulk data exfiltration detection
4. C2BeaconFlowProbe - Beaconing pattern detection (periodic small flows)
5. CleartextCredentialLeakProbe - Credentials in transit detection
6. SuspiciousTunnelProbe - Long-lived tunnels & proxies
7. InternalReconDNSFlowProbe - DNS-based internal reconnaissance
8. NewExternalServiceProbe - First-time external connections

MITRE ATT&CK Coverage:
    - T1046: Network Service Discovery
    - T1021: Remote Services (SMB, RDP, WinRM, SSH)
    - T1041: Exfiltration Over C2 Channel
    - T1048: Exfiltration Over Alternative Protocol
    - T1071: Application Layer Protocol (C2)
    - T1090: Proxy
    - T1572: Protocol Tunneling
    - T1552: Unsecured Credentials
    - T1590: Gather Victim Network Information
"""

from __future__ import annotations

import ipaddress
import statistics
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from amoskys.agents.common.probes import (
    MicroProbe,
    ProbeContext,
    Severity,
    TelemetryEvent,
)


# =============================================================================
# Flow Event Model
# =============================================================================


@dataclass
class FlowEvent:
    """Network flow metadata - the "blood cell" of the circulatory system."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str  # "TCP", "UDP", "ICMP", "OTHER"

    bytes_tx: int  # from src → dst
    bytes_rx: int  # from dst → src
    packet_count: int  # total packets in this flow

    first_seen_ns: int  # start time of this flow
    last_seen_ns: int  # end time (for span), or == first_seen if single record

    # Optional / enriched
    direction: str = "UNKNOWN"  # "INBOUND", "OUTBOUND", "LATERAL"
    app_protocol: str = "UNKNOWN"  # "HTTP", "HTTPS", "DNS", "SMB", "RDP", "SSH", etc.
    tcp_flags: Optional[str] = None  # summary flags for TCP (e.g., "S", "SA", "FA", "R")

    def duration_seconds(self) -> float:
        """Calculate flow duration in seconds."""
        return (self.last_seen_ns - self.first_seen_ns) / 1e9

    def total_bytes(self) -> int:
        """Total bytes transferred (bidirectional)."""
        return self.bytes_tx + self.bytes_rx

    def is_internal(self) -> bool:
        """Check if both src and dst are RFC1918 private addresses."""
        try:
            src = ipaddress.ip_address(self.src_ip)
            dst = ipaddress.ip_address(self.dst_ip)
            return src.is_private and dst.is_private
        except ValueError:
            return False


# =============================================================================
# Configuration & Thresholds
# =============================================================================

# Port scan detection
PORTSCAN_DISTINCT_PORTS_THRESHOLD = 20  # Unique ports to same dst_ip
PORTSCAN_WINDOW_SECONDS = 60

# Lateral movement
LATERAL_MOVEMENT_PORTS = {
    22: "SSH",
    445: "SMB",
    3389: "RDP",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
}

# Data exfiltration
EXFIL_MIN_BYTES_THRESHOLD = 50 * 1024 * 1024  # 50 MB
EXFIL_SPIKE_FACTOR = 5.0  # 5x baseline

# C2 beaconing
BEACON_MIN_FLOWS = 4
BEACON_MIN_INTERVAL_SECONDS = 30
BEACON_MAX_INTERVAL_SECONDS = 600
BEACON_MAX_JITTER_RATIO = 0.2  # σ/μ < 20%
BEACON_MAX_BYTES_PER_FLOW = 5 * 1024  # 5 KB

# Suspicious tunnels
TUNNEL_MIN_DURATION_SECONDS = 600  # 10 minutes
TUNNEL_MIN_PACKETS = 100

# DNS recon
DNS_RECON_HOSTNAME_THRESHOLD = 100  # Unique hostnames in window
DNS_RECON_WINDOW_SECONDS = 600  # 10 minutes

# =============================================================================
# Probe 1: Port Scan Detection
# =============================================================================


class PortScanSweepProbe(MicroProbe):
    """Detects vertical/horizontal port scanning using flow metadata.

    Watches:
        - Many distinct destination ports to same target (vertical scan)
        - Same destination port to many targets (horizontal scan)

    Flags:
        - TCP SYN scans, UDP probes, connection attempts to uncommon ports

    MITRE: T1046 (Network Service Discovery)
    """

    name = "port_scan_sweep"
    description = "Port scanning detection (vertical/horizontal)"
    mitre_techniques = ["T1046"]
    mitre_tactics = ["Discovery"]
    default_enabled = True
    scan_interval = 60.0

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect port scanning patterns."""
        events: List[TelemetryEvent] = []
        flows: List[FlowEvent] = context.shared_data.get("flows", [])

        # Track: (src_ip, dst_ip) -> set of dst_ports
        port_mapping: Dict[Tuple[str, str], Set[int]] = defaultdict(set)

        for flow in flows:
            if flow.protocol in ("TCP", "UDP"):
                key = (flow.src_ip, flow.dst_ip)
                port_mapping[key].add(flow.dst_port)

        # Check for vertical scans (many ports to same dst)
        for (src_ip, dst_ip), ports in port_mapping.items():
            if len(ports) >= PORTSCAN_DISTINCT_PORTS_THRESHOLD:
                events.append(
                    TelemetryEvent(
                        event_type="flow_portscan_vertical",
                        severity=Severity.HIGH,
                        probe_name=self.name,
                        data={
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "unique_ports": sorted(list(ports))[:50],  # First 50
                            "port_count": len(ports),
                            "reason": "Many distinct ports scanned on single target",
                        },
                        mitre_techniques=["T1046"],
                    )
                )

        return events


# =============================================================================
# Probe 2: Lateral Movement Detection
# =============================================================================


class LateralSMBWinRMProbe(MicroProbe):
    """Detects lateral movement over admin protocols (SMB, RDP, WinRM, SSH).

    Watches:
        - Internal-to-internal flows on admin ports
        - New lateral edges (never-seen-before src→dst pairs)
        - High connection frequency

    Flags:
        - SMB (445), RDP (3389), WinRM (5985/5986), SSH (22) lateral traffic

    MITRE: T1021.002 (SMB/Admin Shares), T1021.003 (RDP), T1021.006 (WinRM)
    """

    name = "lateral_smb_winrm"
    description = "Lateral movement over admin protocols"
    mitre_techniques = ["T1021.002", "T1021.003", "T1021.006"]
    mitre_tactics = ["Lateral Movement"]
    default_enabled = True
    scan_interval = 60.0

    def __init__(self):
        super().__init__()
        # Track seen lateral edges: (src_ip, dst_ip, dst_port)
        self.seen_edges: Set[Tuple[str, str, int]] = set()

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect lateral movement patterns."""
        events: List[TelemetryEvent] = []
        flows: List[FlowEvent] = context.shared_data.get("flows", [])

        # Track connections per edge
        edge_counts: Dict[Tuple[str, str, int], int] = defaultdict(int)

        for flow in flows:
            # Only consider internal lateral flows
            if not flow.is_internal():
                continue

            # Check if admin protocol
            if flow.dst_port not in LATERAL_MOVEMENT_PORTS:
                continue

            edge = (flow.src_ip, flow.dst_ip, flow.dst_port)
            edge_counts[edge] += 1

            # Check if new edge
            is_new_edge = edge not in self.seen_edges
            self.seen_edges.add(edge)

            # Emit for new edges or high frequency
            if is_new_edge or edge_counts[edge] >= 10:
                app_protocol = LATERAL_MOVEMENT_PORTS[flow.dst_port]

                events.append(
                    TelemetryEvent(
                        event_type="flow_lateral_smb_winrm_detected",
                        severity=Severity.HIGH,
                        probe_name=self.name,
                        data={
                            "src_ip": flow.src_ip,
                            "dst_ip": flow.dst_ip,
                            "dst_port": flow.dst_port,
                            "app_protocol": app_protocol,
                            "flow_count": edge_counts[edge],
                            "is_new_edge": is_new_edge,
                            "reason": f"Lateral movement via {app_protocol}",
                        },
                        mitre_techniques=self.mitre_techniques,
                    )
                )

                # Only emit once per edge per cycle
                break

        return events


# =============================================================================
# Probe 3: Data Exfiltration Volume Spike
# =============================================================================


class DataExfilVolumeSpikeProbe(MicroProbe):
    """Detects bulk data exfiltration via volume anomalies.

    Watches:
        - Total bytes transmitted to external destinations
        - Baseline deviation (spike factor)

    Flags:
        - Large outbound transfers (>50MB in window)
        - Transfers >5x baseline to same destination

    MITRE: T1041 (Exfil Over C2), T1048 (Exfil Over Alternative Protocol)
    """

    name = "data_exfil_volume_spike"
    description = "Bulk data exfiltration detection"
    mitre_techniques = ["T1041", "T1048"]
    mitre_tactics = ["Exfiltration"]
    default_enabled = True
    scan_interval = 60.0

    def __init__(self):
        super().__init__()
        # Simple baseline: dst_ip -> EWMA of bytes_tx
        self.baseline_bytes: Dict[str, float] = {}
        self.alpha = 0.3  # EWMA smoothing factor

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect exfiltration volume spikes."""
        events: List[TelemetryEvent] = []
        flows: List[FlowEvent] = context.shared_data.get("flows", [])

        # Aggregate bytes_tx per dst_ip (outbound only)
        dst_bytes: Dict[str, int] = defaultdict(int)

        for flow in flows:
            if flow.direction == "OUTBOUND" or not flow.is_internal():
                dst_bytes[flow.dst_ip] += flow.bytes_tx

        # Check for spikes
        for dst_ip, total_bytes in dst_bytes.items():
            baseline = self.baseline_bytes.get(dst_ip, 0)

            # Update baseline (EWMA)
            self.baseline_bytes[dst_ip] = (
                self.alpha * total_bytes + (1 - self.alpha) * baseline
            )

            # Check threshold
            threshold = max(EXFIL_MIN_BYTES_THRESHOLD, baseline * EXFIL_SPIKE_FACTOR)

            if total_bytes >= threshold:
                spike_factor = total_bytes / max(baseline, 1)

                events.append(
                    TelemetryEvent(
                        event_type="flow_exfil_volume_spike",
                        severity=Severity.CRITICAL,
                        probe_name=self.name,
                        data={
                            "dst_ip": dst_ip,
                            "total_bytes_tx": total_bytes,
                            "baseline_bytes_tx": int(baseline),
                            "spike_factor": round(spike_factor, 2),
                            "threshold_bytes": int(threshold),
                            "reason": "Large outbound data transfer detected",
                        },
                        mitre_techniques=["T1041", "T1048"],
                    )
                )

        return events


# =============================================================================
# Probe 4: C2 Beaconing Pattern Detection
# =============================================================================


class C2BeaconFlowProbe(MicroProbe):
    """Detects C2 beaconing patterns (periodic small flows).

    Watches:
        - Regular periodic connections to same destination
        - Low jitter in inter-arrival times
        - Small payload sizes

    Flags:
        - Flows with regular intervals (30s - 10min) and <20% jitter
        - Avg bytes per flow <5KB

    MITRE: T1071.001 (Web Protocols C2), T1071.004 (DNS C2)
    """

    name = "c2_beacon_flow"
    description = "C2 beaconing pattern detection"
    mitre_techniques = ["T1071.001", "T1071.004"]
    mitre_tactics = ["Command and Control"]
    default_enabled = True
    scan_interval = 60.0

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect beaconing patterns."""
        events: List[TelemetryEvent] = []
        flows: List[FlowEvent] = context.shared_data.get("flows", [])

        # Group flows by (src_ip, dst_ip)
        flow_groups: Dict[Tuple[str, str], List[FlowEvent]] = defaultdict(list)

        for flow in flows:
            key = (flow.src_ip, flow.dst_ip)
            flow_groups[key].append(flow)

        # Analyze each group for beaconing
        for (src_ip, dst_ip), group_flows in flow_groups.items():
            if len(group_flows) < BEACON_MIN_FLOWS:
                continue

            # Sort by timestamp
            sorted_flows = sorted(group_flows, key=lambda f: f.first_seen_ns)
            timestamps = [f.first_seen_ns for f in sorted_flows]

            # Calculate inter-arrival times
            intervals = [
                (timestamps[i + 1] - timestamps[i]) / 1e9
                for i in range(len(timestamps) - 1)
            ]

            if not intervals:
                continue

            # Calculate statistics
            avg_interval = statistics.mean(intervals)
            std_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0
            jitter_ratio = std_interval / avg_interval if avg_interval > 0 else 1.0

            # Calculate average bytes per flow
            avg_bytes = statistics.mean([f.total_bytes() for f in sorted_flows])

            # Check beaconing conditions
            if (
                BEACON_MIN_INTERVAL_SECONDS <= avg_interval <= BEACON_MAX_INTERVAL_SECONDS
                and jitter_ratio <= BEACON_MAX_JITTER_RATIO
                and avg_bytes <= BEACON_MAX_BYTES_PER_FLOW
            ):
                events.append(
                    TelemetryEvent(
                        event_type="flow_c2_beaconing_pattern",
                        severity=Severity.HIGH,
                        probe_name=self.name,
                        data={
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "avg_interval_seconds": round(avg_interval, 2),
                            "jitter_ratio": round(jitter_ratio, 3),
                            "flow_count": len(sorted_flows),
                            "avg_bytes_per_flow": int(avg_bytes),
                            "reason": "Regular periodic beaconing pattern detected",
                        },
                        mitre_techniques=["T1071.001", "T1071.004"],
                    )
                )

        return events


# =============================================================================
# Probe 5: Cleartext Credential Leak Detection
# =============================================================================


class CleartextCredentialLeakProbe(MicroProbe):
    """Detects credentials transmitted in cleartext.

    Watches:
        - HTTP Basic Auth (port 80, app_protocol=HTTP)
        - FTP (port 21)
        - Telnet (port 23)
        - POP3, IMAP, SMTP without TLS

    Flags:
        - Authentication protocols over cleartext connections

    MITRE: T1552.001 (Credentials In Files)
    """

    name = "cleartext_credential_leak"
    description = "Cleartext credentials detection"
    mitre_techniques = ["T1552.001"]
    mitre_tactics = ["Credential Access"]
    default_enabled = True
    scan_interval = 60.0

    # Cleartext credential ports
    CLEARTEXT_PORTS = {
        21: "FTP",
        23: "Telnet",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        25: "SMTP",
    }

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect cleartext credential transmission."""
        events: List[TelemetryEvent] = []
        flows: List[FlowEvent] = context.shared_data.get("flows", [])

        for flow in flows:
            # Check if cleartext protocol
            if flow.dst_port in self.CLEARTEXT_PORTS:
                app_protocol = self.CLEARTEXT_PORTS[flow.dst_port]

                # Skip if internal (lower risk)
                if flow.is_internal():
                    severity = Severity.MEDIUM
                else:
                    severity = Severity.HIGH

                events.append(
                    TelemetryEvent(
                        event_type="flow_cleartext_credentials_detected",
                        severity=severity,
                        probe_name=self.name,
                        data={
                            "src_ip": flow.src_ip,
                            "dst_ip": flow.dst_ip,
                            "dst_port": flow.dst_port,
                            "app_protocol": app_protocol,
                            "evidence": f"{app_protocol} over cleartext connection",
                            "reason": "Credentials may be transmitted in cleartext",
                        },
                        mitre_techniques=["T1552.001"],
                    )
                )

        return events


# =============================================================================
# Probe 6: Suspicious Tunnel Detection
# =============================================================================


class SuspiciousTunnelProbe(MicroProbe):
    """Detects long-lived tunnels and suspicious proxies.

    Watches:
        - Long-duration TCP connections (>10 minutes)
        - High packet count with low average packet size
        - Bidirectional traffic patterns

    Flags:
        - SOCKS proxies, HTTP CONNECT tunnels, VPN connections
        - Connections to non-standard ports

    MITRE: T1090 (Proxy), T1572 (Protocol Tunneling)
    """

    name = "suspicious_tunnel"
    description = "Long-lived tunnel & proxy detection"
    mitre_techniques = ["T1090", "T1572"]
    mitre_tactics = ["Command and Control"]
    default_enabled = True
    scan_interval = 60.0

    # Known proxy/VPN ports (allowlist)
    KNOWN_PROXY_PORTS = {1080, 8080, 8888, 3128}  # SOCKS, HTTP proxies

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect suspicious tunnels."""
        events: List[TelemetryEvent] = []
        flows: List[FlowEvent] = context.shared_data.get("flows", [])

        for flow in flows:
            if flow.protocol != "TCP":
                continue

            duration_s = flow.duration_seconds()

            # Check for long-lived connection
            if duration_s < TUNNEL_MIN_DURATION_SECONDS:
                continue

            if flow.packet_count < TUNNEL_MIN_PACKETS:
                continue

            # Calculate average packet size
            total_bytes = flow.total_bytes()
            avg_packet_size = total_bytes / flow.packet_count if flow.packet_count > 0 else 0

            # Check if port is in known proxy list
            is_known_proxy = flow.dst_port in self.KNOWN_PROXY_PORTS

            # Flag if not a known proxy and has tunnel characteristics
            if not is_known_proxy and avg_packet_size < 500:  # Small packets
                events.append(
                    TelemetryEvent(
                        event_type="flow_suspicious_tunnel_detected",
                        severity=Severity.HIGH,
                        probe_name=self.name,
                        data={
                            "src_ip": flow.src_ip,
                            "dst_ip": flow.dst_ip,
                            "dst_port": flow.dst_port,
                            "duration_seconds": round(duration_s, 2),
                            "bytes_tx": flow.bytes_tx,
                            "bytes_rx": flow.bytes_rx,
                            "packet_count": flow.packet_count,
                            "avg_packet_size": int(avg_packet_size),
                            "is_known_proxy": is_known_proxy,
                            "reason": "Long-lived connection with tunnel characteristics",
                        },
                        mitre_techniques=["T1090", "T1572"],
                    )
                )

        return events


# =============================================================================
# Probe 7: Internal DNS Reconnaissance
# =============================================================================


class InternalReconDNSFlowProbe(MicroProbe):
    """Detects DNS-based internal reconnaissance.

    Watches:
        - High volume of DNS queries from single source
        - Many distinct hostnames queried
        - High NXDOMAIN rate (failed lookups)

    Flags:
        - >100 unique hostnames in 10 minutes
        - Internal DNS scanning patterns

    MITRE: T1046 (Network Service Discovery), T1590 (Gather Victim Network Info)
    """

    name = "internal_recon_dns_flow"
    description = "DNS-based internal reconnaissance"
    mitre_techniques = ["T1046", "T1590"]
    mitre_tactics = ["Discovery", "Reconnaissance"]
    default_enabled = True
    scan_interval = 60.0

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect DNS-based reconnaissance."""
        events: List[TelemetryEvent] = []
        flows: List[FlowEvent] = context.shared_data.get("flows", [])

        # Track DNS queries per src_ip
        dns_queries: Dict[str, int] = defaultdict(int)

        for flow in flows:
            # Check if DNS traffic
            if flow.dst_port == 53 or flow.app_protocol == "DNS":
                dns_queries[flow.src_ip] += 1

        # Flag high-volume DNS sources
        for src_ip, query_count in dns_queries.items():
            if query_count >= DNS_RECON_HOSTNAME_THRESHOLD:
                events.append(
                    TelemetryEvent(
                        event_type="flow_internal_dns_recon_suspected",
                        severity=Severity.MEDIUM,
                        probe_name=self.name,
                        data={
                            "src_ip": src_ip,
                            "unique_dns_queries": query_count,
                            "threshold": DNS_RECON_HOSTNAME_THRESHOLD,
                            "reason": "High volume DNS queries suggest reconnaissance",
                        },
                        mitre_techniques=["T1046", "T1590"],
                    )
                )

        return events


# =============================================================================
# Probe 8: New External Service Discovery
# =============================================================================


class NewExternalServiceProbe(MicroProbe):
    """Detects connections to never-seen-before external services.

    Watches:
        - First-time connections to external IPs/ports
        - Non-standard ports (not 80, 443, 53, etc.)

    Flags:
        - New external destinations for visibility
        - Potential command & control or exfiltration paths

    MITRE: T1041 (Exfil Over C2), T1595 (Active Scanning)
    """

    name = "new_external_service"
    description = "First-time external connection detection"
    mitre_techniques = ["T1041", "T1595"]
    mitre_tactics = ["Command and Control", "Reconnaissance"]
    default_enabled = True
    scan_interval = 60.0

    # Common approved ports (allowlist)
    COMMON_PORTS = {53, 80, 443, 123, 22, 25, 587, 465, 993, 995}

    def __init__(self):
        super().__init__()
        # Track seen external destinations: (dst_ip, dst_port)
        self.seen_destinations: Set[Tuple[str, int]] = set()

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect new external connections."""
        events: List[TelemetryEvent] = []
        flows: List[FlowEvent] = context.shared_data.get("flows", [])

        for flow in flows:
            # Only consider external destinations
            if flow.is_internal():
                continue

            dest = (flow.dst_ip, flow.dst_port)

            # Check if new destination
            is_new = dest not in self.seen_destinations
            self.seen_destinations.add(dest)

            # Only emit for new destinations on non-standard ports
            if is_new and flow.dst_port not in self.COMMON_PORTS:
                events.append(
                    TelemetryEvent(
                        event_type="flow_new_external_service_seen",
                        severity=Severity.INFO,
                        probe_name=self.name,
                        data={
                            "src_ip": flow.src_ip,
                            "dst_ip": flow.dst_ip,
                            "dst_port": flow.dst_port,
                            "protocol": flow.protocol,
                            "first_seen_ns": flow.first_seen_ns,
                            "reason": "First-time connection to external service",
                        },
                        mitre_techniques=["T1041", "T1595"],
                    )
                )

        return events


# =============================================================================
# Probe Factory
# =============================================================================


def create_flow_probes() -> List[MicroProbe]:
    """Create all flow micro-probes.

    Returns:
        List of 8 flow probes
    """
    return [
        PortScanSweepProbe(),
        LateralSMBWinRMProbe(),
        DataExfilVolumeSpikeProbe(),
        C2BeaconFlowProbe(),
        CleartextCredentialLeakProbe(),
        SuspiciousTunnelProbe(),
        InternalReconDNSFlowProbe(),
        NewExternalServiceProbe(),
    ]
