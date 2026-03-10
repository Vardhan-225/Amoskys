"""HTTP Inspector Agent Types - Data structures for HTTP transaction analysis.

This module provides the core data structures for HTTP transaction monitoring,
normalized from various sources (proxy logs, nettop, unified logging, access logs).

Design:
    - Platform-agnostic normalized format
    - Captures full request/response lifecycle
    - Supports both forward and reverse proxy scenarios
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class HTTPTransaction:
    """Normalized HTTP transaction for security analysis.

    This is the canonical format passed to micro-probes for analysis.
    Collectors parse platform-specific logs and network captures into this format.

    Attributes:
        timestamp: When the transaction occurred
        method: HTTP method (GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD)
        url: Full URL including scheme, host, path, and query string
        host: Host header or destination hostname
        path: URL path component
        query_params: Parsed query string parameters
        request_headers: HTTP request headers
        request_body: Request body content (if captured)
        response_status: HTTP response status code
        content_type: Response Content-Type header
        src_ip: Source IP address
        dst_ip: Destination IP address
        bytes_sent: Bytes sent in request
        bytes_received: Bytes received in response
        process_name: Process that initiated the request (if available)
        is_tls: Whether the connection used TLS/SSL
    """

    timestamp: datetime
    method: str
    url: str
    host: str
    path: str
    query_params: Dict[str, str]
    request_headers: Dict[str, str]
    request_body: Optional[str]
    response_status: int
    content_type: str
    src_ip: str
    dst_ip: str
    bytes_sent: int
    bytes_received: int
    process_name: Optional[str] = None
    is_tls: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "method": self.method,
            "url": self.url,
            "host": self.host,
            "path": self.path,
            "query_params": self.query_params,
            "request_headers": self.request_headers,
            "request_body": self.request_body,
            "response_status": self.response_status,
            "content_type": self.content_type,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "process_name": self.process_name,
            "is_tls": self.is_tls,
        }


# =============================================================================
# Exports
# =============================================================================

__all__ = [
    "HTTPTransaction",
]
