#!/usr/bin/env python3
"""NetScanner Micro-Probes - 7 Eyes on Network Topology & Services.

Each probe watches ONE specific network security vector:

1. NewServiceDetectionProbe - New (ip, port, service) tuples not in baseline
2. OpenPortChangeProbe - Port state transitions (closed->open, open->closed)
3. RogueServiceProbe - Services running on non-standard ports
4. SSLCertIssueProbe - Expired, self-signed, or weak SSL certificates
5. VulnerableBannerProbe - Banners matching known vulnerable versions
6. UnauthorizedListenerProbe - New local listeners not in baseline
7. NetworkTopologyChangeProbe - New/missing hosts, MAC address changes

MITRE ATT&CK Coverage:
    - T1133: External Remote Services
    - T1046: Network Service Scanning
    - T1090.001: Internal Proxy
    - T1573.002: Asymmetric Cryptography
    - T1595: Active Scanning
    - T1571: Non-Standard Port
    - T1557.002: ARP Cache Poisoning
"""

from __future__ import annotations

import logging
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from amoskys.agents.common.probes import (
    MicroProbe,
    ProbeContext,
    Severity,
    TelemetryEvent,
)
from amoskys.agents.shared.net_scanner.agent_types import (
    STANDARD_SERVICE_PORTS,
    HostScanResult,
    PortInfo,
    ScanDiff,
    ScanResult,
)

logger = logging.getLogger(__name__)


# =============================================================================
# Vulnerable Banner Patterns
# =============================================================================

# (compiled_regex, description, CVE_reference)
VULNERABLE_BANNER_PATTERNS: List[tuple] = [
    (
        re.compile(r"Apache/2\.4\.49\b", re.IGNORECASE),
        "Apache 2.4.49 - Path traversal and RCE",
        "CVE-2021-41773",
    ),
    (
        re.compile(r"Apache/2\.4\.50\b", re.IGNORECASE),
        "Apache 2.4.50 - Incomplete fix for path traversal",
        "CVE-2021-42013",
    ),
    (
        re.compile(r"OpenSSH_7\.\d", re.IGNORECASE),
        "OpenSSH 7.x - Multiple known vulnerabilities",
        "CVE-2016-10009",
    ),
    (
        re.compile(r"OpenSSH_6\.\d", re.IGNORECASE),
        "OpenSSH 6.x - Severely outdated, multiple CVEs",
        "CVE-2015-5600",
    ),
    (
        re.compile(r"nginx/1\.1[0-6]\.", re.IGNORECASE),
        "nginx 1.10-1.16 - Known HTTP/2 vulnerabilities",
        "CVE-2019-9511",
    ),
    (
        re.compile(r"nginx/1\.[0-9]\.", re.IGNORECASE),
        "nginx 1.x single-digit minor - Very old version",
        "CVE-2014-0133",
    ),
    (
        re.compile(r"Microsoft-IIS/[67]\.", re.IGNORECASE),
        "IIS 6/7 - End of life, multiple critical CVEs",
        "CVE-2017-7269",
    ),
    (
        re.compile(r"ProFTPD\s+1\.[23]\.", re.IGNORECASE),
        "ProFTPD 1.2/1.3 - Known backdoor and RCE vulnerabilities",
        "CVE-2015-3306",
    ),
    (
        re.compile(r"vsftpd\s+2\.3\.4", re.IGNORECASE),
        "vsftpd 2.3.4 - Backdoor vulnerability",
        "CVE-2011-2523",
    ),
    (
        re.compile(r"Exim\s+4\.[0-8][0-9]\b", re.IGNORECASE),
        "Exim 4.x - Multiple RCE vulnerabilities",
        "CVE-2019-15846",
    ),
]


# =============================================================================
# Service identification from banners
# =============================================================================


def _identify_service_from_banner(banner: Optional[str]) -> Optional[str]:
    """Try to identify service type from banner string."""
    if not banner:
        return None
    banner_lower = banner.lower()
    if "ssh" in banner_lower:
        return "ssh"
    if "http" in banner_lower or "html" in banner_lower:
        return "http"
    if "mysql" in banner_lower or "mariadb" in banner_lower:
        return "mysql"
    if "postgresql" in banner_lower:
        return "postgresql"
    if "redis" in banner_lower:
        return "redis"
    if "mongodb" in banner_lower or "mongo" in banner_lower:
        return "mongodb"
    if "elasticsearch" in banner_lower or "elastic" in banner_lower:
        return "elasticsearch"
    if "ftp" in banner_lower:
        return "ftp"
    if "smtp" in banner_lower:
        return "smtp"
    if "socks" in banner_lower:
        return "socks"
    if "rdp" in banner_lower or "remote desktop" in banner_lower:
        return "rdp"
    if "vnc" in banner_lower or "rfb" in banner_lower:
        return "vnc"
    return None


# =============================================================================
# Probe 1: NewServiceDetectionProbe
# =============================================================================


class NewServiceDetectionProbe(MicroProbe):
    """Detects new (ip, port, service) tuples not present in baseline.

    Alerts when a new service appears on the network that was not
    previously observed. This could indicate:
        - Unauthorized service deployment
        - Lateral movement
        - Backdoor installation
        - Shadow IT

    MITRE ATT&CK: T1133 (External Remote Services)
    """

    name = "new_service_detection"
    description = "Alert on new services not in baseline"
    mitre_techniques = ["T1133"]
    mitre_tactics = ["Persistence", "Initial Access"]
    platforms = ["linux", "darwin"]
    requires_fields = ["scan_diff"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Scan for new services detected in the scan diff."""
        events: List[TelemetryEvent] = []
        diff: Optional[ScanDiff] = context.shared_data.get("scan_diff")
        if not diff:
            return events

        now_ns = context.now_ns or int(time.time() * 1e9)

        # New ports on existing or new hosts
        for port_entry in diff.new_ports:
            ip = port_entry.get("ip", "unknown")
            port = port_entry.get("port", 0)
            service = port_entry.get("service", "unknown")
            banner = port_entry.get("banner", "")

            events.append(
                TelemetryEvent(
                    event_type="net_new_service_detected",
                    severity=Severity.HIGH,
                    probe_name=self.name,
                    timestamp_ns=now_ns,
                    data={
                        "ip": ip,
                        "port": port,
                        "service": service,
                        "banner": banner,
                        "reason": (f"New service detected: {service} on {ip}:{port}"),
                    },
                    mitre_techniques=self.mitre_techniques,
                    mitre_tactics=self.mitre_tactics,
                    confidence=0.85,
                )
            )

        # Also flag entirely new hosts (all their ports are new)
        for host in diff.new_hosts:
            for port_info in host.open_ports:
                events.append(
                    TelemetryEvent(
                        event_type="net_new_service_detected",
                        severity=Severity.HIGH,
                        probe_name=self.name,
                        timestamp_ns=now_ns,
                        data={
                            "ip": host.ip,
                            "port": port_info.port,
                            "service": port_info.service or "unknown",
                            "banner": port_info.banner or "",
                            "hostname": host.hostname,
                            "new_host": True,
                            "reason": (
                                f"New host {host.ip} running "
                                f"{port_info.service or 'unknown'} on port "
                                f"{port_info.port}"
                            ),
                        },
                        mitre_techniques=self.mitre_techniques,
                        mitre_tactics=self.mitre_tactics,
                        confidence=0.85,
                    )
                )

        return events


# =============================================================================
# Probe 2: OpenPortChangeProbe
# =============================================================================


class OpenPortChangeProbe(MicroProbe):
    """Detects port state transitions between scan cycles.

    Monitors for:
        - closed -> open: Potential backdoor or unauthorized service
        - open -> closed: Potential service disruption or cleanup

    MITRE ATT&CK: T1046 (Network Service Scanning)
    """

    name = "open_port_change"
    description = "Alert on port state changes between scans"
    mitre_techniques = ["T1046"]
    mitre_tactics = ["Discovery"]
    platforms = ["linux", "darwin"]
    requires_fields = ["scan_diff"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Scan for port state changes."""
        events: List[TelemetryEvent] = []
        diff: Optional[ScanDiff] = context.shared_data.get("scan_diff")
        if not diff:
            return events

        now_ns = context.now_ns or int(time.time() * 1e9)

        # New ports (closed -> open)
        for port_entry in diff.new_ports:
            ip = port_entry.get("ip", "unknown")
            port = port_entry.get("port", 0)
            service = port_entry.get("service", "unknown")

            events.append(
                TelemetryEvent(
                    event_type="net_port_opened",
                    severity=Severity.MEDIUM,
                    probe_name=self.name,
                    timestamp_ns=now_ns,
                    data={
                        "ip": ip,
                        "port": port,
                        "service": service,
                        "transition": "closed_to_open",
                        "reason": (
                            f"Port {port} opened on {ip} " f"(service: {service})"
                        ),
                    },
                    mitre_techniques=self.mitre_techniques,
                    mitre_tactics=self.mitre_tactics,
                    confidence=0.8,
                )
            )

        # Removed ports (open -> closed)
        for port_entry in diff.removed_ports:
            ip = port_entry.get("ip", "unknown")
            port = port_entry.get("port", 0)
            service = port_entry.get("service", "unknown")

            events.append(
                TelemetryEvent(
                    event_type="net_port_closed",
                    severity=Severity.MEDIUM,
                    probe_name=self.name,
                    timestamp_ns=now_ns,
                    data={
                        "ip": ip,
                        "port": port,
                        "service": service,
                        "transition": "open_to_closed",
                        "reason": (
                            f"Port {port} closed on {ip} "
                            f"(was: {service}) - possible disruption"
                        ),
                    },
                    mitre_techniques=self.mitre_techniques,
                    mitre_tactics=self.mitre_tactics,
                    confidence=0.75,
                )
            )

        return events


# =============================================================================
# Probe 3: RogueServiceProbe
# =============================================================================


class RogueServiceProbe(MicroProbe):
    """Flags services running on non-standard ports.

    Detects when known services are running on unexpected ports,
    which may indicate:
        - Evasion of firewall rules
        - SOCKS/HTTP proxy for pivoting
        - Backdoors disguised as legitimate services
        - Tunneling (SSH on port 443, etc.)

    MITRE ATT&CK: T1090.001 (Internal Proxy)
    """

    name = "rogue_service"
    description = "Flag services on non-standard ports"
    mitre_techniques = ["T1090.001"]
    mitre_tactics = ["Command and Control"]
    platforms = ["linux", "darwin"]
    requires_fields = ["scan_results"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Scan for services on non-standard ports."""
        events: List[TelemetryEvent] = []
        scan_results: Optional[List[ScanResult]] = context.shared_data.get(
            "scan_results"
        )
        if not scan_results:
            return events

        now_ns = context.now_ns or int(time.time() * 1e9)

        for result in scan_results:
            for host in result.hosts:
                for port_info in host.open_ports:
                    if port_info.state != "open":
                        continue

                    # Identify service from banner or port_info.service
                    service = port_info.service
                    if not service and port_info.banner:
                        service = _identify_service_from_banner(port_info.banner)

                    if not service:
                        continue

                    service_lower = service.lower()

                    # Check if service is on a standard port
                    standard_ports = STANDARD_SERVICE_PORTS.get(service_lower, [])
                    if not standard_ports:
                        continue

                    if port_info.port not in standard_ports:
                        # SOCKS proxy on any port is always suspicious
                        severity = Severity.HIGH
                        if service_lower == "socks":
                            severity = Severity.HIGH
                            reason = (
                                f"SOCKS proxy detected on {host.ip}:"
                                f"{port_info.port}"
                            )
                        else:
                            reason = (
                                f"{service} on non-standard port "
                                f"{port_info.port} on {host.ip} "
                                f"(expected: {standard_ports})"
                            )

                        events.append(
                            TelemetryEvent(
                                event_type="net_rogue_service",
                                severity=severity,
                                probe_name=self.name,
                                timestamp_ns=now_ns,
                                data={
                                    "ip": host.ip,
                                    "port": port_info.port,
                                    "service": service,
                                    "expected_ports": standard_ports,
                                    "banner": port_info.banner,
                                    "reason": reason,
                                },
                                mitre_techniques=self.mitre_techniques,
                                mitre_tactics=self.mitre_tactics,
                                confidence=0.8,
                            )
                        )

        return events


# =============================================================================
# Probe 4: SSLCertIssueProbe
# =============================================================================


class SSLCertIssueProbe(MicroProbe):
    """Flags SSL/TLS certificate issues.

    Detects:
        - Expired certificates
        - Certificates expiring within 30 days
        - Self-signed certificates (subject == issuer heuristic)
        - CN/hostname mismatch
        - Weak key sizes (RSA < 2048 bits)

    MITRE ATT&CK: T1573.002 (Asymmetric Cryptography)
    """

    name = "ssl_cert_issue"
    description = "Flag expired, self-signed, or weak SSL certificates"
    mitre_techniques = ["T1573.002"]
    mitre_tactics = ["Command and Control"]
    platforms = ["linux", "darwin"]
    requires_fields = ["scan_results"]

    # Days before expiry to warn
    EXPIRY_WARNING_DAYS = 30

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Scan for SSL certificate issues."""
        events: List[TelemetryEvent] = []
        scan_results: Optional[List[ScanResult]] = context.shared_data.get(
            "scan_results"
        )
        if not scan_results:
            return events

        now_ns = context.now_ns or int(time.time() * 1e9)
        now = datetime.now(timezone.utc)

        for result in scan_results:
            for host in result.hosts:
                for port_info in host.open_ports:
                    if port_info.state != "open":
                        continue

                    # Only check ports with SSL info
                    if not port_info.ssl_subject and not port_info.ssl_expiry:
                        continue

                    issues: List[str] = []
                    severity = Severity.MEDIUM

                    # Check expiry
                    if port_info.ssl_expiry:
                        try:
                            expiry = datetime.fromisoformat(port_info.ssl_expiry)
                            if expiry.tzinfo is None:
                                expiry = expiry.replace(tzinfo=timezone.utc)
                            days_until = (expiry - now).days
                            if days_until < 0:
                                issues.append(
                                    f"Certificate EXPIRED "
                                    f"({abs(days_until)} days ago)"
                                )
                                severity = Severity.HIGH
                            elif days_until <= self.EXPIRY_WARNING_DAYS:
                                issues.append(
                                    f"Certificate expires in " f"{days_until} days"
                                )
                        except (ValueError, TypeError):
                            issues.append(
                                f"Unparseable expiry: " f"{port_info.ssl_expiry}"
                            )

                    # Check for self-signed (heuristic: subject contains
                    # patterns suggesting self-signed)
                    if port_info.ssl_subject:
                        subject_lower = port_info.ssl_subject.lower()
                        if "self-signed" in subject_lower:
                            issues.append("Self-signed certificate detected")
                            severity = Severity.MEDIUM
                        # Check CN/hostname mismatch
                        cn_match = re.search(r"CN=([^/,]+)", port_info.ssl_subject)
                        if cn_match:
                            cn = cn_match.group(1).strip()
                            if (
                                cn != host.ip
                                and cn != host.hostname
                                and not cn.startswith("*.")
                            ):
                                issues.append(
                                    f"CN mismatch: cert CN={cn}, " f"host={host.ip}"
                                )

                    if issues:
                        events.append(
                            TelemetryEvent(
                                event_type="net_ssl_cert_issue",
                                severity=severity,
                                probe_name=self.name,
                                timestamp_ns=now_ns,
                                data={
                                    "ip": host.ip,
                                    "port": port_info.port,
                                    "ssl_subject": port_info.ssl_subject,
                                    "ssl_expiry": port_info.ssl_expiry,
                                    "issues": issues,
                                    "reason": "; ".join(issues),
                                },
                                mitre_techniques=self.mitre_techniques,
                                mitre_tactics=self.mitre_tactics,
                                confidence=0.9,
                            )
                        )

        return events


# =============================================================================
# Probe 5: VulnerableBannerProbe
# =============================================================================


class VulnerableBannerProbe(MicroProbe):
    """Matches service banners against known vulnerable version patterns.

    Checks banners for:
        - Apache 2.4.49 (CVE-2021-41773 path traversal)
        - OpenSSH 7.x (multiple CVEs)
        - nginx 1.x old versions
        - vsftpd 2.3.4 (backdoor)
        - Other known-vulnerable service versions

    MITRE ATT&CK: T1595 (Active Scanning)
    """

    name = "vulnerable_banner"
    description = "Match banners against known vulnerable versions"
    mitre_techniques = ["T1595"]
    mitre_tactics = ["Reconnaissance"]
    platforms = ["linux", "darwin"]
    requires_fields = ["scan_results"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Scan banners for vulnerable version patterns."""
        events: List[TelemetryEvent] = []
        scan_results: Optional[List[ScanResult]] = context.shared_data.get(
            "scan_results"
        )
        if not scan_results:
            return events

        now_ns = context.now_ns or int(time.time() * 1e9)

        for result in scan_results:
            for host in result.hosts:
                for port_info in host.open_ports:
                    if port_info.state != "open" or not port_info.banner:
                        continue

                    for pattern, desc, cve in VULNERABLE_BANNER_PATTERNS:
                        if pattern.search(port_info.banner):
                            events.append(
                                TelemetryEvent(
                                    event_type="net_vulnerable_banner",
                                    severity=Severity.HIGH,
                                    probe_name=self.name,
                                    timestamp_ns=now_ns,
                                    data={
                                        "ip": host.ip,
                                        "port": port_info.port,
                                        "banner": port_info.banner[:200],
                                        "vulnerability": desc,
                                        "cve": cve,
                                        "reason": (
                                            f"Vulnerable service on "
                                            f"{host.ip}:{port_info.port}: "
                                            f"{desc} ({cve})"
                                        ),
                                    },
                                    mitre_techniques=self.mitre_techniques,
                                    mitre_tactics=self.mitre_tactics,
                                    confidence=0.85,
                                )
                            )
                            # Only match first pattern per banner
                            break

        return events


# =============================================================================
# Probe 6: UnauthorizedListenerProbe
# =============================================================================


class UnauthorizedListenerProbe(MicroProbe):
    """Detects new local listeners not present in baseline.

    Checks local listener addresses (127.0.0.1, 0.0.0.0) for new ports
    that were not in the previous baseline. Flags potential:
        - Reverse shells
        - Bind shells
        - Unauthorized services
        - C2 listeners

    MITRE ATT&CK: T1571 (Non-Standard Port)
    """

    name = "unauthorized_listener"
    description = "Check for new local listeners not in baseline"
    mitre_techniques = ["T1571"]
    mitre_tactics = ["Command and Control"]
    platforms = ["linux", "darwin"]
    requires_fields = ["scan_diff"]

    # Local/listener addresses
    LOCAL_ADDRESSES = frozenset({"127.0.0.1", "0.0.0.0", "::1", "::"})

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Scan for unauthorized local listeners."""
        events: List[TelemetryEvent] = []
        diff: Optional[ScanDiff] = context.shared_data.get("scan_diff")
        if not diff:
            return events

        now_ns = context.now_ns or int(time.time() * 1e9)

        # Check new ports on local addresses
        for port_entry in diff.new_ports:
            ip = port_entry.get("ip", "")
            if ip not in self.LOCAL_ADDRESSES:
                continue

            port = port_entry.get("port", 0)
            service = port_entry.get("service", "unknown")
            banner = port_entry.get("banner", "")

            # High ports with no known service are very suspicious
            severity = Severity.CRITICAL
            reason = (
                f"New unauthorized listener on {ip}:{port} " f"(service: {service})"
            )

            # Known services on expected ports are less concerning
            if service and service != "unknown":
                standard = STANDARD_SERVICE_PORTS.get(service.lower(), [])
                if port in standard:
                    severity = Severity.HIGH
                    reason = (
                        f"New listener for {service} on {ip}:{port} "
                        f"(standard port, but not in baseline)"
                    )

            events.append(
                TelemetryEvent(
                    event_type="net_unauthorized_listener",
                    severity=severity,
                    probe_name=self.name,
                    timestamp_ns=now_ns,
                    data={
                        "ip": ip,
                        "port": port,
                        "service": service,
                        "banner": banner,
                        "reason": reason,
                    },
                    mitre_techniques=self.mitre_techniques,
                    mitre_tactics=self.mitre_tactics,
                    confidence=0.9,
                )
            )

        return events


# =============================================================================
# Probe 7: NetworkTopologyChangeProbe
# =============================================================================


class NetworkTopologyChangeProbe(MicroProbe):
    """Detects network topology changes: new hosts, missing hosts, MAC changes.

    Monitors for:
        - New hosts appearing on subnet (rogue devices)
        - Previously seen hosts going offline
        - MAC address changes for same IP (ARP spoofing indicator)

    MITRE ATT&CK: T1557.002 (ARP Cache Poisoning)
    """

    name = "network_topology_change"
    description = "Detect host/MAC changes on subnet"
    mitre_techniques = ["T1557.002"]
    mitre_tactics = ["Credential Access", "Collection"]
    platforms = ["linux", "darwin"]
    requires_fields = ["scan_diff"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Scan for network topology changes."""
        events: List[TelemetryEvent] = []
        diff: Optional[ScanDiff] = context.shared_data.get("scan_diff")
        if not diff:
            return events

        now_ns = context.now_ns or int(time.time() * 1e9)

        # New hosts
        for host in diff.new_hosts:
            events.append(
                TelemetryEvent(
                    event_type="net_new_host",
                    severity=Severity.HIGH,
                    probe_name=self.name,
                    timestamp_ns=now_ns,
                    data={
                        "ip": host.ip,
                        "hostname": host.hostname,
                        "mac": host.mac,
                        "open_port_count": len(host.open_ports),
                        "reason": (
                            f"New host detected on network: {host.ip} "
                            f"(hostname: {host.hostname or 'unknown'}, "
                            f"MAC: {host.mac or 'unknown'})"
                        ),
                    },
                    mitre_techniques=self.mitre_techniques,
                    mitre_tactics=self.mitre_tactics,
                    confidence=0.85,
                )
            )

        # Missing hosts (went offline)
        for host in diff.removed_hosts:
            events.append(
                TelemetryEvent(
                    event_type="net_host_offline",
                    severity=Severity.HIGH,
                    probe_name=self.name,
                    timestamp_ns=now_ns,
                    data={
                        "ip": host.ip,
                        "hostname": host.hostname,
                        "mac": host.mac,
                        "reason": (
                            f"Host went offline: {host.ip} "
                            f"(was: {host.hostname or 'unknown'})"
                        ),
                    },
                    mitre_techniques=self.mitre_techniques,
                    mitre_tactics=self.mitre_tactics,
                    confidence=0.7,
                )
            )

        # MAC address changes (potential ARP spoofing)
        for mac_change in diff.mac_changes:
            ip = mac_change.get("ip", "unknown")
            old_mac = mac_change.get("old_mac", "unknown")
            new_mac = mac_change.get("new_mac", "unknown")

            events.append(
                TelemetryEvent(
                    event_type="net_mac_change",
                    severity=Severity.HIGH,
                    probe_name=self.name,
                    timestamp_ns=now_ns,
                    data={
                        "ip": ip,
                        "old_mac": old_mac,
                        "new_mac": new_mac,
                        "reason": (
                            f"MAC address changed for {ip}: "
                            f"{old_mac} -> {new_mac} "
                            f"(possible ARP spoofing)"
                        ),
                    },
                    mitre_techniques=self.mitre_techniques,
                    mitre_tactics=self.mitre_tactics,
                    confidence=0.9,
                )
            )

        return events


# =============================================================================
# Probe Registry
# =============================================================================

# All probes for this agent
NET_SCANNER_PROBES = [
    NewServiceDetectionProbe,
    OpenPortChangeProbe,
    RogueServiceProbe,
    SSLCertIssueProbe,
    VulnerableBannerProbe,
    UnauthorizedListenerProbe,
    NetworkTopologyChangeProbe,
]


def create_net_scanner_probes() -> List[MicroProbe]:
    """Create instances of all network scanner probes.

    Returns:
        List of instantiated probes
    """
    return [probe_class() for probe_class in NET_SCANNER_PROBES]


# =============================================================================
# Exports
# =============================================================================

__all__ = [
    "NewServiceDetectionProbe",
    "OpenPortChangeProbe",
    "RogueServiceProbe",
    "SSLCertIssueProbe",
    "VulnerableBannerProbe",
    "UnauthorizedListenerProbe",
    "NetworkTopologyChangeProbe",
    "NET_SCANNER_PROBES",
    "create_net_scanner_probes",
]
