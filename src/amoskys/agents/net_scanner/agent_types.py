"""Network Scanner Agent Types - Shared dataclasses for scan results.

This module provides the core data structures for network scan results,
including host discovery, port scanning, and service identification.

Design:
    - Immutable-friendly dataclasses for scan results
    - JSON-serializable for baseline persistence
    - All fields optional where appropriate to handle partial scans
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class PortInfo:
    """Information about a single port on a host.

    Attributes:
        port: TCP port number (1-65535)
        state: Port state - "open", "closed", or "filtered"
        service: Identified service name (e.g., "ssh", "http")
        banner: Raw banner string received from the service
        ssl_subject: SSL certificate subject CN (if TLS-enabled)
        ssl_expiry: SSL certificate expiry date as ISO string
    """

    port: int
    state: str  # "open", "closed", "filtered"
    service: Optional[str] = None
    banner: Optional[str] = None
    ssl_subject: Optional[str] = None
    ssl_expiry: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "port": self.port,
            "state": self.state,
            "service": self.service,
            "banner": self.banner,
            "ssl_subject": self.ssl_subject,
            "ssl_expiry": self.ssl_expiry,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PortInfo":
        """Create PortInfo from dictionary."""
        return cls(
            port=data["port"],
            state=data.get("state", "open"),
            service=data.get("service"),
            banner=data.get("banner"),
            ssl_subject=data.get("ssl_subject"),
            ssl_expiry=data.get("ssl_expiry"),
        )


@dataclass
class HostScanResult:
    """Result of scanning a single host.

    Attributes:
        ip: IP address of the host
        hostname: Resolved hostname (if available)
        mac: MAC address (if available, typically from ARP)
        is_alive: Whether the host responded to probes
        open_ports: List of PortInfo for discovered ports
        os_fingerprint: Guessed OS from TTL/banner analysis
    """

    ip: str
    hostname: Optional[str] = None
    mac: Optional[str] = None
    is_alive: bool = True
    open_ports: List[PortInfo] = field(default_factory=list)
    os_fingerprint: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "mac": self.mac,
            "is_alive": self.is_alive,
            "open_ports": [p.to_dict() for p in self.open_ports],
            "os_fingerprint": self.os_fingerprint,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "HostScanResult":
        """Create HostScanResult from dictionary."""
        return cls(
            ip=data["ip"],
            hostname=data.get("hostname"),
            mac=data.get("mac"),
            is_alive=data.get("is_alive", True),
            open_ports=[PortInfo.from_dict(p) for p in data.get("open_ports", [])],
            os_fingerprint=data.get("os_fingerprint"),
        )


@dataclass
class ScanResult:
    """Complete result of a network scan cycle.

    Attributes:
        timestamp: When the scan was performed
        target_subnet: CIDR notation of scanned subnet
        hosts: List of discovered hosts
        scan_duration_seconds: How long the scan took
        scan_type: Type of scan ("incremental", "full", "targeted")
    """

    timestamp: datetime
    target_subnet: str
    hosts: List[HostScanResult] = field(default_factory=list)
    scan_duration_seconds: float = 0.0
    scan_type: str = "incremental"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "target_subnet": self.target_subnet,
            "hosts": [h.to_dict() for h in self.hosts],
            "scan_duration_seconds": self.scan_duration_seconds,
            "scan_type": self.scan_type,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanResult":
        """Create ScanResult from dictionary."""
        ts = data.get("timestamp", "")
        if isinstance(ts, str) and ts:
            timestamp = datetime.fromisoformat(ts)
        else:
            timestamp = datetime.now(timezone.utc)
        return cls(
            timestamp=timestamp,
            target_subnet=data.get("target_subnet", ""),
            hosts=[HostScanResult.from_dict(h) for h in data.get("hosts", [])],
            scan_duration_seconds=data.get("scan_duration_seconds", 0.0),
            scan_type=data.get("scan_type", "incremental"),
        )


@dataclass
class ScanDiff:
    """Difference between current scan and baseline.

    Computed by comparing current ScanResult against the stored baseline.
    Probes operate on this diff rather than raw scan results.

    Attributes:
        new_hosts: Hosts present now but not in baseline
        removed_hosts: Hosts in baseline but not present now
        new_ports: (ip, PortInfo) tuples for newly opened ports
        removed_ports: (ip, PortInfo) tuples for ports no longer open
        changed_banners: (ip, port, old_banner, new_banner) tuples
        mac_changes: (ip, old_mac, new_mac) tuples indicating ARP spoofing
    """

    new_hosts: List[HostScanResult] = field(default_factory=list)
    removed_hosts: List[HostScanResult] = field(default_factory=list)
    new_ports: List[Dict[str, Any]] = field(default_factory=list)
    removed_ports: List[Dict[str, Any]] = field(default_factory=list)
    changed_banners: List[Dict[str, Any]] = field(default_factory=list)
    mac_changes: List[Dict[str, Any]] = field(default_factory=list)


# =============================================================================
# Common port/service mappings
# =============================================================================

# Default ports to scan - common services that are security-relevant
COMMON_SCAN_PORTS: List[int] = [
    22,  # SSH
    80,  # HTTP
    443,  # HTTPS
    3306,  # MySQL
    5432,  # PostgreSQL
    8080,  # HTTP Proxy / Alt HTTP
    8443,  # HTTPS Alt
    3389,  # RDP
    5900,  # VNC
    6379,  # Redis
    27017,  # MongoDB
    9200,  # Elasticsearch
]

# Well-known service-to-port mappings for rogue service detection
STANDARD_SERVICE_PORTS: Dict[str, List[int]] = {
    "ssh": [22],
    "http": [80, 8080, 8000, 8888],
    "https": [443, 8443],
    "mysql": [3306],
    "postgresql": [5432],
    "redis": [6379],
    "mongodb": [27017],
    "elasticsearch": [9200, 9300],
    "rdp": [3389],
    "vnc": [5900, 5901],
    "ftp": [21],
    "smtp": [25, 587],
    "dns": [53],
    "socks": [1080, 9050],
}


# =============================================================================
# Exports
# =============================================================================

__all__ = [
    "PortInfo",
    "HostScanResult",
    "ScanResult",
    "ScanDiff",
    "COMMON_SCAN_PORTS",
    "STANDARD_SERVICE_PORTS",
]
