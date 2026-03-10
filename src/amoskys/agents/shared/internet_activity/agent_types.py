"""Internet Activity Agent Types - Data structures for internet activity monitoring.

This module provides the core data structures for tracking outbound connections
and browsing activity, normalized from various system sources.

Design:
    - Platform-agnostic normalized format
    - Captures both connection-level and browser-level activity
    - Supports geo-tagging and process attribution
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class OutboundConnection:
    """Normalized outbound network connection for security analysis.

    This is the canonical format passed to micro-probes for analysis.
    Collectors parse platform-specific network tools into this format.

    Attributes:
        timestamp: When the connection was observed
        process_name: Name of the process owning the connection
        pid: Process ID
        dst_ip: Destination IP address
        dst_port: Destination port
        dst_hostname: Resolved hostname (if available)
        protocol: Transport protocol (TCP, UDP)
        bytes_sent: Total bytes sent
        bytes_received: Total bytes received
        duration_seconds: Connection duration (if tracked)
        geo_country: Country code from IP geolocation
        is_encrypted: Whether connection uses TLS/SSL
        connection_state: TCP state (ESTABLISHED, TIME_WAIT, etc.)
    """

    timestamp: datetime
    process_name: str
    pid: int
    dst_ip: str
    dst_port: int
    dst_hostname: Optional[str] = None
    protocol: str = "TCP"
    bytes_sent: int = 0
    bytes_received: int = 0
    duration_seconds: Optional[float] = None
    geo_country: Optional[str] = None
    is_encrypted: bool = False
    connection_state: str = "ESTABLISHED"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "process_name": self.process_name,
            "pid": self.pid,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "dst_hostname": self.dst_hostname,
            "protocol": self.protocol,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "duration_seconds": self.duration_seconds,
            "geo_country": self.geo_country,
            "is_encrypted": self.is_encrypted,
            "connection_state": self.connection_state,
        }


@dataclass
class BrowsingEntry:
    """Normalized browser history entry for security analysis.

    Tracks visited URLs from browser history databases for detecting
    suspicious download patterns, shadow IT usage, etc.

    Attributes:
        timestamp: When the page was visited
        url: Full URL visited
        domain: Extracted domain name
        title: Page title (if available)
        browser: Browser name (safari, chrome, firefox)
        visit_count: Number of visits to this URL
    """

    timestamp: datetime
    url: str
    domain: str
    title: Optional[str] = None
    browser: str = "unknown"
    visit_count: int = 1

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "url": self.url,
            "domain": self.domain,
            "title": self.title,
            "browser": self.browser,
            "visit_count": self.visit_count,
        }


# =============================================================================
# Exports
# =============================================================================

__all__ = [
    "OutboundConnection",
    "BrowsingEntry",
]
