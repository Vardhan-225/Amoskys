#!/usr/bin/env python3
"""HTTP Inspector Micro-Probes - 8 Eyes on Every HTTP Transaction.

Each probe monitors ONE specific HTTP threat vector:

    1. XSSDetectionProbe - Cross-site scripting payload detection
    2. SSRFDetectionProbe - Server-side request forgery detection
    3. PathTraversalProbe - Directory traversal attack detection
    4. APIAbuseProbe - API enumeration and abuse patterns
    5. DataExfilHTTPProbe - Data exfiltration over HTTP
    6. SuspiciousUploadProbe - Malicious file upload detection
    7. WebSocketAbuseProbe - WebSocket protocol abuse
    8. CSRFTokenMissingProbe - Missing CSRF protection detection

MITRE ATT&CK Coverage:
    - T1059.007: Command and Scripting Interpreter: JavaScript
    - T1090: Proxy
    - T1083: File and Directory Discovery
    - T1087: Account Discovery
    - T1567: Exfiltration Over Web Service
    - T1505.003: Server Software Component: Web Shell
    - T1071.001: Application Layer Protocol: Web Protocols
    - T1557: Adversary-in-the-Middle
"""

from __future__ import annotations

import base64
import ipaddress
import logging
import math
import re
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set
from urllib.parse import unquote

from amoskys.agents.common.probes import (
    MicroProbe,
    ProbeContext,
    Severity,
    TelemetryEvent,
)
from amoskys.agents.shared.http_inspector.agent_types import HTTPTransaction

logger = logging.getLogger(__name__)


# =============================================================================
# Detection Constants
# =============================================================================

# XSS patterns (URL-decoded and raw)
XSS_PATTERNS: List[re.Pattern] = [
    re.compile(r"<script", re.IGNORECASE),
    re.compile(r"onerror\s*=", re.IGNORECASE),
    re.compile(r"onload\s*=", re.IGNORECASE),
    re.compile(r"javascript:", re.IGNORECASE),
    re.compile(r"%3[Cc]script", re.IGNORECASE),
    re.compile(r"&#x3[Cc];?\s*script", re.IGNORECASE),
    re.compile(r"svg/onload", re.IGNORECASE),
    re.compile(r"<img[^>]+onerror", re.IGNORECASE),
    re.compile(r"<iframe", re.IGNORECASE),
    re.compile(r"eval\s*\(", re.IGNORECASE),
    re.compile(r"document\.cookie", re.IGNORECASE),
    re.compile(r"document\.location", re.IGNORECASE),
]

# SSRF target patterns (internal IPs, metadata endpoints, file protocol)
SSRF_INTERNAL_PATTERNS: List[re.Pattern] = [
    re.compile(r"169\.254\.169\.254"),
    re.compile(r"127\.0\.0\.1"),
    re.compile(r"localhost", re.IGNORECASE),
    re.compile(r"\[::1\]"),
    re.compile(r"0\.0\.0\.0"),
    re.compile(r"file://", re.IGNORECASE),
    re.compile(r"gopher://", re.IGNORECASE),
    re.compile(r"dict://", re.IGNORECASE),
    re.compile(r"metadata\.google\.internal"),
    re.compile(r"100\.100\.100\.200"),  # Alibaba metadata
]

# Internal IP ranges for SSRF detection
INTERNAL_IP_PREFIXES = (
    "10.",
    "192.168.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.20.",
    "172.21.",
    "172.22.",
    "172.23.",
    "172.24.",
    "172.25.",
    "172.26.",
    "172.27.",
    "172.28.",
    "172.29.",
    "172.30.",
    "172.31.",
    "fd",
    "fc",
)

# Path traversal patterns
PATH_TRAVERSAL_PATTERNS: List[re.Pattern] = [
    re.compile(r"\.\./"),
    re.compile(r"\.\.\\"),
    re.compile(r"%2[Ee]%2[Ee]", re.IGNORECASE),  # URL-encoded ../
    re.compile(r"%252[Ee]", re.IGNORECASE),  # Double URL-encoded
    re.compile(r"%00"),  # Null byte
    re.compile(r"\x00"),  # Raw null byte
    re.compile(r"\.\.%2[Ff]", re.IGNORECASE),  # ../ mixed encoding
    re.compile(r"%2[Ff]\.\.", re.IGNORECASE),  # /../ mixed encoding
    re.compile(r"/etc/passwd"),
    re.compile(r"/etc/shadow"),
    re.compile(r"/proc/self"),
    re.compile(r"C:\\Windows", re.IGNORECASE),
]

# Dangerous file extensions for upload detection
DANGEROUS_EXTENSIONS = frozenset(
    {
        ".php",
        ".php3",
        ".php4",
        ".php5",
        ".phtml",
        ".phar",
        ".jsp",
        ".jspx",
        ".jsw",
        ".jsv",
        ".asp",
        ".aspx",
        ".ashx",
        ".asmx",
        ".exe",
        ".dll",
        ".com",
        ".bat",
        ".cmd",
        ".ps1",
        ".psm1",
        ".psd1",
        ".sh",
        ".bash",
        ".zsh",
        ".py",
        ".pl",
        ".rb",
        ".cgi",
        ".war",
        ".jar",
        ".elf",
        ".svg",  # Can contain scripts
    }
)

# CDN and well-known domains (not suspicious for large uploads/downloads)
CDN_DOMAINS = frozenset(
    {
        "cdn.jsdelivr.net",
        "cdnjs.cloudflare.com",
        "unpkg.com",
        "ajax.googleapis.com",
        "fonts.googleapis.com",
        "fonts.gstatic.com",
        "s3.amazonaws.com",
        "cloudfront.net",
        "akamai.net",
        "akamaized.net",
        "fastly.net",
        "stackpath.com",
        "maxcdn.com",
        "bootstrapcdn.com",
        "github.com",
        "githubusercontent.com",
        "gitlab.com",
        "npmjs.org",
        "pypi.org",
        "rubygems.org",
        "microsoft.com",
        "apple.com",
        "google.com",
        "amazon.com",
    }
)

# GraphQL introspection indicators
GRAPHQL_INTROSPECTION_PATTERNS = [
    re.compile(r"__schema", re.IGNORECASE),
    re.compile(r"__type", re.IGNORECASE),
    re.compile(r"introspectionquery", re.IGNORECASE),
]


def _is_cdn_domain(host: str) -> bool:
    """Check if a host matches known CDN/trusted domains."""
    host_lower = host.lower()
    for cdn in CDN_DOMAINS:
        if host_lower == cdn or host_lower.endswith("." + cdn):
            return True
    return False


def _check_internal_ip(value: str) -> bool:
    """Check if a string contains references to internal IPs."""
    for pattern in SSRF_INTERNAL_PATTERNS:
        if pattern.search(value):
            return True
    # Check for raw internal IP addresses in the value
    for prefix in INTERNAL_IP_PREFIXES:
        if prefix in value:
            return True
    return False


def _calculate_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    freq: Dict[str, int] = defaultdict(int)
    for char in data:
        freq[char] += 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    # Normalize to 0-1 range (max entropy for byte data is 8)
    return entropy / 8.0


# =============================================================================
# Probe 1: XSSDetectionProbe
# =============================================================================


class XSSDetectionProbe(MicroProbe):
    """Detects cross-site scripting (XSS) payloads in HTTP transactions.

    Scans URL parameters, request bodies, and headers for common XSS patterns
    including encoded variants.

    MITRE ATT&CK: T1059.007 (Command and Scripting Interpreter: JavaScript)
    """

    name = "xss_detection"
    description = "Detects XSS payloads in HTTP requests"
    mitre_techniques = ["T1059.007"]
    mitre_tactics = ["execution"]
    default_enabled = True
    scan_interval = 10.0
    requires_root = False
    platforms = ["linux", "darwin"]
    requires_fields = ["http_transactions"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Scan HTTP transactions for XSS patterns."""
        events: List[TelemetryEvent] = []
        transactions: List[HTTPTransaction] = context.shared_data.get(
            "http_transactions", []
        )

        for txn in transactions:
            matched_patterns: List[str] = []

            # Scan URL query parameters
            for param_name, param_value in txn.query_params.items():
                decoded = unquote(param_value)
                for pattern in XSS_PATTERNS:
                    if pattern.search(param_value) or pattern.search(decoded):
                        matched_patterns.append(
                            f"query_param[{param_name}]: {pattern.pattern}"
                        )
                        break

            # Scan request body
            if txn.request_body:
                decoded_body = unquote(txn.request_body)
                for pattern in XSS_PATTERNS:
                    if pattern.search(txn.request_body) or pattern.search(decoded_body):
                        matched_patterns.append(f"body: {pattern.pattern}")
                        break

            # Scan select request headers (Referer, User-Agent)
            for header_name in ("referer", "user-agent", "x-forwarded-for"):
                header_val = txn.request_headers.get(header_name, "")
                if header_val:
                    decoded_header = unquote(header_val)
                    for pattern in XSS_PATTERNS:
                        if pattern.search(header_val) or pattern.search(decoded_header):
                            matched_patterns.append(
                                f"header[{header_name}]: {pattern.pattern}"
                            )
                            break

            if matched_patterns:
                events.append(
                    self._create_event(
                        event_type="http_xss_detected",
                        severity=Severity.HIGH,
                        data={
                            "url": txn.url,
                            "method": txn.method,
                            "host": txn.host,
                            "src_ip": txn.src_ip,
                            "dst_ip": txn.dst_ip,
                            "matched_patterns": matched_patterns,
                            "pattern_count": len(matched_patterns),
                            "process_name": txn.process_name,
                            "reason": f"XSS payload detected in {len(matched_patterns)} location(s)",
                        },
                        confidence=0.85,
                    )
                )

        return events


# =============================================================================
# Probe 2: SSRFDetectionProbe
# =============================================================================


class SSRFDetectionProbe(MicroProbe):
    """Detects server-side request forgery (SSRF) attempts.

    Checks URL parameters and request body for references to internal IPs,
    cloud metadata endpoints, and file:// protocols.

    MITRE ATT&CK: T1090 (Proxy)
    """

    name = "ssrf_detection"
    description = "Detects SSRF attempts targeting internal services"
    mitre_techniques = ["T1090"]
    mitre_tactics = ["command_and_control"]
    default_enabled = True
    scan_interval = 10.0
    requires_root = False
    platforms = ["linux", "darwin"]
    requires_fields = ["http_transactions"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Scan HTTP transactions for SSRF patterns."""
        events: List[TelemetryEvent] = []
        transactions: List[HTTPTransaction] = context.shared_data.get(
            "http_transactions", []
        )

        for txn in transactions:
            ssrf_indicators: List[str] = []

            # Scan query params for internal IP references
            for param_name, param_value in txn.query_params.items():
                decoded = unquote(param_value)
                if _check_internal_ip(decoded):
                    ssrf_indicators.append(
                        f"query_param[{param_name}] references internal resource"
                    )

            # Scan request body
            if txn.request_body:
                decoded_body = unquote(txn.request_body)
                if _check_internal_ip(decoded_body):
                    ssrf_indicators.append("request_body references internal resource")

            # Check if URL itself targets internal services
            if _check_internal_ip(txn.url):
                ssrf_indicators.append("URL targets internal resource directly")

            if ssrf_indicators:
                # Metadata endpoint access is always CRITICAL
                is_metadata = any(
                    p in txn.url or p in str(txn.query_params)
                    for p in (
                        "169.254.169.254",
                        "metadata.google.internal",
                        "100.100.100.200",
                    )
                )
                severity = Severity.CRITICAL if is_metadata else Severity.CRITICAL

                events.append(
                    self._create_event(
                        event_type="http_ssrf_detected",
                        severity=severity,
                        data={
                            "url": txn.url,
                            "method": txn.method,
                            "host": txn.host,
                            "src_ip": txn.src_ip,
                            "dst_ip": txn.dst_ip,
                            "ssrf_indicators": ssrf_indicators,
                            "is_metadata_access": is_metadata,
                            "process_name": txn.process_name,
                            "reason": f"SSRF attempt: {ssrf_indicators[0]}",
                        },
                        confidence=0.90,
                    )
                )

        return events


# =============================================================================
# Probe 3: PathTraversalProbe
# =============================================================================


class PathTraversalProbe(MicroProbe):
    """Detects directory traversal attacks in HTTP requests.

    Matches ../,  ..\\, URL-encoded variants, null bytes, and double-encoded
    traversal sequences in URL paths and query parameters.

    MITRE ATT&CK: T1083 (File and Directory Discovery)
    """

    name = "path_traversal"
    description = "Detects path traversal attempts in HTTP requests"
    mitre_techniques = ["T1083"]
    mitre_tactics = ["discovery"]
    default_enabled = True
    scan_interval = 10.0
    requires_root = False
    platforms = ["linux", "darwin"]
    requires_fields = ["http_transactions"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Scan HTTP transactions for path traversal patterns."""
        events: List[TelemetryEvent] = []
        transactions: List[HTTPTransaction] = context.shared_data.get(
            "http_transactions", []
        )

        for txn in transactions:
            traversal_matches: List[str] = []

            # Scan URL path
            decoded_path = unquote(txn.path)
            for pattern in PATH_TRAVERSAL_PATTERNS:
                if pattern.search(txn.path) or pattern.search(decoded_path):
                    traversal_matches.append(f"path: {pattern.pattern}")
                    break

            # Scan query parameters
            for param_name, param_value in txn.query_params.items():
                decoded = unquote(param_value)
                for pattern in PATH_TRAVERSAL_PATTERNS:
                    if pattern.search(param_value) or pattern.search(decoded):
                        traversal_matches.append(
                            f"query_param[{param_name}]: {pattern.pattern}"
                        )
                        break

            # Scan request body for path traversal
            if txn.request_body:
                decoded_body = unquote(txn.request_body)
                for pattern in PATH_TRAVERSAL_PATTERNS:
                    if pattern.search(txn.request_body) or pattern.search(decoded_body):
                        traversal_matches.append(f"body: {pattern.pattern}")
                        break

            if traversal_matches:
                events.append(
                    self._create_event(
                        event_type="http_path_traversal",
                        severity=Severity.HIGH,
                        data={
                            "url": txn.url,
                            "method": txn.method,
                            "host": txn.host,
                            "path": txn.path,
                            "src_ip": txn.src_ip,
                            "dst_ip": txn.dst_ip,
                            "traversal_matches": traversal_matches,
                            "process_name": txn.process_name,
                            "reason": f"Path traversal detected: {traversal_matches[0]}",
                        },
                        confidence=0.85,
                    )
                )

        return events


# =============================================================================
# Probe 4: APIAbuseProbe
# =============================================================================


class APIAbuseProbe(MicroProbe):
    """Detects API abuse patterns including enumeration and introspection.

    Monitors for:
        - Sequential ID probing (id=1,2,3...)
        - High request rates from single IPs (>100/min)
        - GraphQL introspection queries (__schema, __type)

    MITRE ATT&CK: T1087 (Account Discovery)
    """

    name = "api_abuse"
    description = "Detects API enumeration and abuse patterns"
    mitre_techniques = ["T1087"]
    mitre_tactics = ["discovery"]
    default_enabled = True
    scan_interval = 10.0
    requires_root = False
    platforms = ["linux", "darwin"]
    requires_fields = ["http_transactions"]

    # Thresholds
    REQUESTS_PER_MINUTE_THRESHOLD = 100
    SEQUENTIAL_ID_THRESHOLD = 5  # consecutive IDs before alerting

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Scan HTTP transactions for API abuse patterns."""
        events: List[TelemetryEvent] = []
        transactions: List[HTTPTransaction] = context.shared_data.get(
            "http_transactions", []
        )

        if not transactions:
            return events

        # Track request rates per source IP
        ip_request_counts: Dict[str, int] = defaultdict(int)
        # Track sequential ID probing per source IP
        ip_id_values: Dict[str, List[int]] = defaultdict(list)

        for txn in transactions:
            ip_request_counts[txn.src_ip] += 1

            # Check for sequential ID probing in query params
            for param_name, param_value in txn.query_params.items():
                if param_name.lower() in (
                    "id",
                    "user_id",
                    "userid",
                    "account",
                    "uid",
                    "pid",
                    "item_id",
                    "order_id",
                ):
                    try:
                        id_val = int(param_value)
                        ip_id_values[txn.src_ip].append(id_val)
                    except (ValueError, OverflowError):
                        pass

            # Check for GraphQL introspection
            body = txn.request_body or ""
            url_str = txn.url + str(txn.query_params)
            combined = body + url_str

            for pattern in GRAPHQL_INTROSPECTION_PATTERNS:
                if pattern.search(combined):
                    events.append(
                        self._create_event(
                            event_type="http_graphql_introspection",
                            severity=Severity.MEDIUM,
                            data={
                                "url": txn.url,
                                "method": txn.method,
                                "host": txn.host,
                                "src_ip": txn.src_ip,
                                "pattern": pattern.pattern,
                                "process_name": txn.process_name,
                                "reason": "GraphQL introspection query detected",
                            },
                            confidence=0.80,
                        )
                    )
                    break

        # Check for high request rates
        for src_ip, count in ip_request_counts.items():
            if count >= self.REQUESTS_PER_MINUTE_THRESHOLD:
                events.append(
                    self._create_event(
                        event_type="http_api_rate_abuse",
                        severity=Severity.MEDIUM,
                        data={
                            "src_ip": src_ip,
                            "request_count": count,
                            "threshold": self.REQUESTS_PER_MINUTE_THRESHOLD,
                            "reason": f"High request rate: {count} requests from {src_ip}",
                        },
                        confidence=0.75,
                    )
                )

        # Check for sequential ID probing
        for src_ip, id_values in ip_id_values.items():
            if len(id_values) >= self.SEQUENTIAL_ID_THRESHOLD:
                sorted_ids = sorted(set(id_values))
                # Check for sequential pattern
                sequential_count = 0
                for i in range(1, len(sorted_ids)):
                    if sorted_ids[i] == sorted_ids[i - 1] + 1:
                        sequential_count += 1
                    else:
                        sequential_count = 0

                    if sequential_count >= self.SEQUENTIAL_ID_THRESHOLD - 1:
                        events.append(
                            self._create_event(
                                event_type="http_api_id_enumeration",
                                severity=Severity.MEDIUM,
                                data={
                                    "src_ip": src_ip,
                                    "sequential_ids": sorted_ids[:20],
                                    "id_count": len(sorted_ids),
                                    "reason": f"Sequential ID probing from {src_ip}: "
                                    f"{sequential_count + 1} sequential IDs",
                                },
                                confidence=0.80,
                            )
                        )
                        break

        return events


# =============================================================================
# Probe 5: DataExfilHTTPProbe
# =============================================================================


class DataExfilHTTPProbe(MicroProbe):
    """Detects data exfiltration over HTTP.

    Flags:
        - Outbound POST/PUT > 1MB to non-CDN hosts
        - Base64 blobs > 10KB in request body
        - Multipart uploads to suspicious domains

    MITRE ATT&CK: T1567 (Exfiltration Over Web Service)
    """

    name = "data_exfil_http"
    description = "Detects data exfiltration via HTTP uploads"
    mitre_techniques = ["T1567"]
    mitre_tactics = ["exfiltration"]
    default_enabled = True
    scan_interval = 10.0
    requires_root = False
    platforms = ["linux", "darwin"]
    requires_fields = ["http_transactions"]

    # Thresholds
    LARGE_UPLOAD_BYTES = 1_000_000  # 1 MB
    BASE64_BLOB_THRESHOLD = 10_240  # 10 KB

    # Base64 detection pattern (at least 100 chars of base64)
    _BASE64_RE = re.compile(r"[A-Za-z0-9+/]{100,}={0,2}")

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Scan HTTP transactions for data exfiltration indicators."""
        events: List[TelemetryEvent] = []
        transactions: List[HTTPTransaction] = context.shared_data.get(
            "http_transactions", []
        )

        for txn in transactions:
            # Only check outbound data-sending methods
            if txn.method not in ("POST", "PUT", "PATCH"):
                continue

            exfil_indicators: List[str] = []

            # Check for large uploads to non-CDN hosts
            if txn.bytes_sent > self.LARGE_UPLOAD_BYTES:
                if not _is_cdn_domain(txn.host):
                    size_mb = txn.bytes_sent / (1024 * 1024)
                    exfil_indicators.append(
                        f"Large upload: {size_mb:.1f}MB to {txn.host}"
                    )

            # Check for base64 blobs in request body
            if txn.request_body:
                b64_matches = self._BASE64_RE.findall(txn.request_body)
                for match in b64_matches:
                    # Estimate decoded size (base64 is ~4/3 ratio)
                    decoded_size = len(match) * 3 // 4
                    if decoded_size > self.BASE64_BLOB_THRESHOLD:
                        exfil_indicators.append(
                            f"Base64 blob: ~{decoded_size // 1024}KB encoded data"
                        )
                        break  # One match is enough

            # Check for multipart uploads to suspicious domains
            content_type = txn.content_type.lower() if txn.content_type else ""
            if "multipart" in content_type and not _is_cdn_domain(txn.host):
                if txn.bytes_sent > self.LARGE_UPLOAD_BYTES // 2:
                    exfil_indicators.append(
                        f"Multipart upload ({txn.bytes_sent} bytes) to {txn.host}"
                    )

            if exfil_indicators:
                events.append(
                    self._create_event(
                        event_type="http_data_exfiltration",
                        severity=Severity.HIGH,
                        data={
                            "url": txn.url,
                            "method": txn.method,
                            "host": txn.host,
                            "src_ip": txn.src_ip,
                            "dst_ip": txn.dst_ip,
                            "bytes_sent": txn.bytes_sent,
                            "content_type": txn.content_type,
                            "exfil_indicators": exfil_indicators,
                            "process_name": txn.process_name,
                            "reason": f"Data exfiltration: {exfil_indicators[0]}",
                        },
                        confidence=0.80,
                        tags=["correlation_group:data_exfiltration"],
                    )
                )

        return events


# =============================================================================
# Probe 6: SuspiciousUploadProbe
# =============================================================================


class SuspiciousUploadProbe(MicroProbe):
    """Detects suspicious file uploads that may indicate web shell drops.

    Checks multipart uploads for:
        - Dangerous file extensions (.php, .jsp, .aspx, .exe, .ps1, .bat)
        - Double extensions (file.php.jpg)
        - MIME type mismatches

    MITRE ATT&CK: T1505.003 (Server Software Component: Web Shell)
    """

    name = "suspicious_upload"
    description = "Detects malicious file uploads and web shell drops"
    mitre_techniques = ["T1505.003"]
    mitre_tactics = ["persistence"]
    default_enabled = True
    scan_interval = 10.0
    requires_root = False
    platforms = ["linux", "darwin"]
    requires_fields = ["http_transactions"]

    # Regex to extract filename from Content-Disposition or multipart body
    _FILENAME_RE = re.compile(r'filename[*]?=["\']?([^"\';\r\n]+)', re.IGNORECASE)

    # MIME types that should not contain executable content
    _SAFE_MIMES = frozenset(
        {
            "image/jpeg",
            "image/png",
            "image/gif",
            "image/webp",
            "image/bmp",
            "text/plain",
            "text/csv",
            "application/pdf",
            "application/zip",
            "application/gzip",
        }
    )

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Scan HTTP transactions for suspicious file uploads."""
        events: List[TelemetryEvent] = []
        transactions: List[HTTPTransaction] = context.shared_data.get(
            "http_transactions", []
        )

        for txn in transactions:
            if txn.method not in ("POST", "PUT", "PATCH"):
                continue

            content_type = txn.content_type.lower() if txn.content_type else ""

            # Only check multipart uploads or direct file uploads
            if "multipart" not in content_type and "octet-stream" not in content_type:
                continue

            upload_concerns: List[str] = []
            filename = None

            # Extract filename from headers or body
            disp = txn.request_headers.get("content-disposition", "")
            if disp:
                match = self._FILENAME_RE.search(disp)
                if match:
                    filename = match.group(1).strip()

            # Also try to extract from body (multipart boundary parsing)
            if not filename and txn.request_body:
                match = self._FILENAME_RE.search(txn.request_body)
                if match:
                    filename = match.group(1).strip()

            if filename:
                filename_lower = filename.lower()

                # Check for dangerous extensions
                for ext in DANGEROUS_EXTENSIONS:
                    if filename_lower.endswith(ext):
                        upload_concerns.append(
                            f"Dangerous extension: {ext} (file: {filename})"
                        )
                        break

                # Check for double extensions (e.g., file.php.jpg)
                parts = filename_lower.rsplit(".", 2)
                if len(parts) >= 3:
                    inner_ext = "." + parts[-2]
                    if inner_ext in DANGEROUS_EXTENSIONS:
                        upload_concerns.append(
                            f"Double extension: {filename} (hidden: {inner_ext})"
                        )

                # Check MIME mismatch
                declared_mime = txn.request_headers.get("content-type", "").lower()
                if declared_mime in self._SAFE_MIMES:
                    for ext in DANGEROUS_EXTENSIONS:
                        if filename_lower.endswith(ext):
                            upload_concerns.append(
                                f"MIME mismatch: {declared_mime} with {ext} file"
                            )
                            break

            if upload_concerns:
                events.append(
                    self._create_event(
                        event_type="http_suspicious_upload",
                        severity=Severity.CRITICAL,
                        data={
                            "url": txn.url,
                            "method": txn.method,
                            "host": txn.host,
                            "src_ip": txn.src_ip,
                            "dst_ip": txn.dst_ip,
                            "filename": filename,
                            "content_type": txn.content_type,
                            "upload_concerns": upload_concerns,
                            "bytes_sent": txn.bytes_sent,
                            "process_name": txn.process_name,
                            "reason": f"Suspicious upload: {upload_concerns[0]}",
                        },
                        confidence=0.90,
                    )
                )

        return events


# =============================================================================
# Probe 7: WebSocketAbuseProbe
# =============================================================================


class WebSocketAbuseProbe(MicroProbe):
    """Detects WebSocket protocol abuse.

    Monitors for:
        - WebSocket upgrade requests to unusual paths
        - Binary frames with high entropy (>0.9)
        - Persistent WS connections to non-CDN hosts

    MITRE ATT&CK: T1071.001 (Application Layer Protocol: Web Protocols)
    """

    name = "websocket_abuse"
    description = "Detects WebSocket protocol abuse patterns"
    mitre_techniques = ["T1071.001"]
    mitre_tactics = ["command_and_control"]
    default_enabled = True
    scan_interval = 10.0
    requires_root = False
    platforms = ["linux", "darwin"]
    requires_fields = ["http_transactions"]

    # Normal WebSocket paths
    _NORMAL_WS_PATHS = frozenset(
        {
            "/ws",
            "/websocket",
            "/socket.io/",
            "/sockjs/",
            "/hub",
            "/signalr",
            "/cable",
            "/realtime",
            "/graphql",
            "/subscriptions",
        }
    )

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Scan HTTP transactions for WebSocket abuse."""
        events: List[TelemetryEvent] = []
        transactions: List[HTTPTransaction] = context.shared_data.get(
            "http_transactions", []
        )

        for txn in transactions:
            ws_concerns: List[str] = []

            # Detect WebSocket upgrade requests
            upgrade_header = txn.request_headers.get("upgrade", "").lower()
            connection_header = txn.request_headers.get("connection", "").lower()

            is_ws_upgrade = (
                upgrade_header == "websocket" or "upgrade" in connection_header
            )

            if is_ws_upgrade:
                # Check for unusual WebSocket paths
                path_lower = txn.path.lower().rstrip("/")
                is_normal_path = any(
                    path_lower == p.rstrip("/") or path_lower.startswith(p)
                    for p in self._NORMAL_WS_PATHS
                )
                if not is_normal_path:
                    ws_concerns.append(f"WebSocket upgrade to unusual path: {txn.path}")

                # Check if connecting to non-CDN host
                if not _is_cdn_domain(txn.host):
                    ws_concerns.append(f"WebSocket to non-CDN host: {txn.host}")

            # Check for high-entropy binary content in request body
            if txn.request_body and is_ws_upgrade:
                entropy = _calculate_entropy(txn.request_body)
                if entropy > 0.9:
                    ws_concerns.append(
                        f"High entropy content ({entropy:.2f}) in WebSocket payload"
                    )

            if ws_concerns:
                events.append(
                    self._create_event(
                        event_type="http_websocket_abuse",
                        severity=Severity.MEDIUM,
                        data={
                            "url": txn.url,
                            "method": txn.method,
                            "host": txn.host,
                            "path": txn.path,
                            "src_ip": txn.src_ip,
                            "dst_ip": txn.dst_ip,
                            "ws_concerns": ws_concerns,
                            "process_name": txn.process_name,
                            "reason": f"WebSocket abuse: {ws_concerns[0]}",
                        },
                        confidence=0.70,
                    )
                )

        return events


# =============================================================================
# Probe 8: CSRFTokenMissingProbe
# =============================================================================


class CSRFTokenMissingProbe(MicroProbe):
    """Detects POST/PUT/DELETE requests without CSRF protection.

    Flags state-changing requests that lack:
        - X-CSRF-Token header
        - X-XSRF-Token header
        - Origin/Referer header matching Host

    MITRE ATT&CK: T1557 (Adversary-in-the-Middle)
    """

    name = "csrf_token_missing"
    description = "Detects requests missing CSRF protection"
    mitre_techniques = ["T1557"]
    mitre_tactics = ["credential_access"]
    default_enabled = True
    scan_interval = 10.0
    requires_root = False
    platforms = ["linux", "darwin"]
    requires_fields = ["http_transactions"]

    # CSRF token header names to check
    _CSRF_HEADERS = frozenset(
        {
            "x-csrf-token",
            "x-xsrf-token",
            "x-csrftoken",
            "csrf-token",
            "anti-csrf-token",
        }
    )

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Scan HTTP transactions for missing CSRF protection."""
        events: List[TelemetryEvent] = []
        transactions: List[HTTPTransaction] = context.shared_data.get(
            "http_transactions", []
        )

        for txn in transactions:
            # Only check state-changing methods
            if txn.method not in ("POST", "PUT", "DELETE", "PATCH"):
                continue

            # Skip API calls that use Bearer/API key auth (typically CSRF-exempt)
            auth_header = txn.request_headers.get("authorization", "").lower()
            if auth_header.startswith("bearer ") or "api" in auth_header:
                continue

            # Skip non-HTML content types (API calls)
            content_type = txn.content_type.lower() if txn.content_type else ""
            if (
                "application/json" in content_type
                and "x-requested-with" in txn.request_headers
            ):
                continue  # AJAX with custom header provides CSRF protection

            csrf_issues: List[str] = []

            # Check for CSRF token headers
            has_csrf_token = False
            headers_lower = {k.lower(): v for k, v in txn.request_headers.items()}
            for csrf_header in self._CSRF_HEADERS:
                if csrf_header in headers_lower:
                    has_csrf_token = True
                    break

            if not has_csrf_token:
                csrf_issues.append("No CSRF token header present")

            # Check Origin/Referer vs Host
            origin = headers_lower.get("origin", "")
            referer = headers_lower.get("referer", "")
            host = txn.host.lower()

            if origin and host:
                # Extract host from origin URL
                origin_host = origin.split("//")[-1].split("/")[0].split(":")[0]
                if origin_host.lower() != host.split(":")[0]:
                    csrf_issues.append(f"Origin mismatch: {origin_host} != {host}")

            if not origin and not referer:
                csrf_issues.append("No Origin or Referer header")

            # Only alert if there are multiple CSRF concerns
            if len(csrf_issues) >= 2:
                events.append(
                    self._create_event(
                        event_type="http_csrf_missing",
                        severity=Severity.MEDIUM,
                        data={
                            "url": txn.url,
                            "method": txn.method,
                            "host": txn.host,
                            "src_ip": txn.src_ip,
                            "dst_ip": txn.dst_ip,
                            "csrf_issues": csrf_issues,
                            "origin": origin or None,
                            "referer": referer or None,
                            "process_name": txn.process_name,
                            "reason": f"Missing CSRF protection: {csrf_issues[0]}",
                        },
                        confidence=0.70,
                    )
                )

        return events


# =============================================================================
# Probe Registry
# =============================================================================

HTTP_INSPECTOR_PROBES = [
    XSSDetectionProbe,
    SSRFDetectionProbe,
    PathTraversalProbe,
    APIAbuseProbe,
    DataExfilHTTPProbe,
    SuspiciousUploadProbe,
    WebSocketAbuseProbe,
    CSRFTokenMissingProbe,
]


def create_http_inspector_probes() -> List[MicroProbe]:
    """Create instances of all HTTP inspector probes.

    Returns:
        List of instantiated probes
    """
    return [probe_class() for probe_class in HTTP_INSPECTOR_PROBES]


# =============================================================================
# Exports
# =============================================================================

__all__ = [
    "XSSDetectionProbe",
    "SSRFDetectionProbe",
    "PathTraversalProbe",
    "APIAbuseProbe",
    "DataExfilHTTPProbe",
    "SuspiciousUploadProbe",
    "WebSocketAbuseProbe",
    "CSRFTokenMissingProbe",
    "HTTP_INSPECTOR_PROBES",
    "create_http_inspector_probes",
]
