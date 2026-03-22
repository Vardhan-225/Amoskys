"""macOS HTTP Inspector Observatory probes — threat detection via HTTP traffic analysis.

8 probes covering web application attack detection and HTTP-based threats:
    1. XSSDetectionProbe       — T1059.007 Cross-site scripting in request paths
    2. SSRFDetectionProbe      — T1090     Server-side request forgery patterns
    3. PathTraversalProbe      — T1083     Directory traversal escape sequences
    4. APIAbuseProbe           — T1106     Rate limiting violations
    5. WebShellUploadProbe     — T1505.003 File upload webshell patterns
    6. C2WebChannelProbe       — T1071.001 HTTP beaconing with encoded payloads
    7. DataExfilHTTPProbe      — T1048     Large POST exfiltration
    8. CookieTheftProbe        — T1539     Session hijacking patterns
"""

from __future__ import annotations

import collections
import logging
import re
import time
from typing import Any, Dict, List, Optional, Set
from urllib.parse import unquote

from amoskys.agents.common.probes import (
    MicroProbe,
    ProbeContext,
    Severity,
    TelemetryEvent,
)

logger = logging.getLogger(__name__)


# -- Shared utilities ---------------------------------------------------------


def _url_decode(s: str) -> str:
    """Double URL-decode a string to catch evasion via encoding."""
    try:
        decoded = unquote(unquote(s))
        return decoded
    except Exception:
        return s


def _is_internal_ip(ip: str) -> bool:
    """Check if an IP address is in a private/reserved range."""
    _INTERNAL_PREFIXES = (
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
        "127.",
        "169.254.",
        "0.",
        "::1",
        "fe80:",
        "fc00:",
        "fd00:",
    )
    return any(ip.startswith(p) for p in _INTERNAL_PREFIXES)


# -- Benign path allowlists --------------------------------------------------

_BENIGN_PATHS = frozenset(
    {
        "/favicon.ico",
        "/robots.txt",
        "/sitemap.xml",
        "/apple-touch-icon.png",
        "/apple-touch-icon-precomposed.png",
        "/.well-known/",
        "/health",
        "/healthz",
        "/ready",
        "/readyz",
    }
)


def _is_benign_path(path: str) -> bool:
    """Check if the request path is a known benign endpoint."""
    return path.lower() in _BENIGN_PATHS


# -- Probe 1: XSS Detection --------------------------------------------------


class XSSDetectionProbe(MicroProbe):
    """Detect cross-site scripting patterns in HTTP request paths and parameters.

    MITRE: T1059.007 — Command and Scripting Interpreter: JavaScript

    XSS attacks inject JavaScript into web application inputs. We detect common
    XSS payloads in request paths and query parameters including <script> tags,
    javascript: URIs, and event handler attributes.
    """

    name = "macos_http_xss"
    description = "Detects XSS patterns in request paths and query parameters"
    platforms = ["darwin"]
    mitre_techniques = ["T1059.007"]
    mitre_tactics = ["execution"]
    scan_interval = 10.0
    requires_fields = ["http_requests"]
    maturity = "stable"
    false_positive_notes = [
        "Developer testing tools may send XSS payloads intentionally",
        "Security scanners (Burp, OWASP ZAP) generate XSS test requests",
    ]
    evasion_notes = [
        "Polyglot XSS using unusual encodings (UTF-7, HTML entities)",
        "DOM-based XSS that does not appear in request paths",
    ]

    _XSS_PATTERNS = [
        re.compile(r"<\s*script", re.IGNORECASE),
        re.compile(r"javascript\s*:", re.IGNORECASE),
        re.compile(r"on(error|load|click|mouseover|focus|blur)\s*=", re.IGNORECASE),
        re.compile(r"<\s*img[^>]+onerror\s*=", re.IGNORECASE),
        re.compile(r"<\s*svg[^>]+onload\s*=", re.IGNORECASE),
        re.compile(r"<\s*iframe", re.IGNORECASE),
        re.compile(r"<\s*object", re.IGNORECASE),
        re.compile(r"<\s*embed", re.IGNORECASE),
        re.compile(r"document\.(cookie|location|write)", re.IGNORECASE),
        re.compile(r"eval\s*\(", re.IGNORECASE),
        re.compile(r"alert\s*\(", re.IGNORECASE),
    ]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        requests = context.shared_data.get("http_requests", [])

        for request in requests:
            decoded_path = _url_decode(request.path)
            decoded_ua = _url_decode(request.user_agent)

            matched_patterns: List[str] = []

            for pattern in self._XSS_PATTERNS:
                if pattern.search(decoded_path):
                    matched_patterns.append(pattern.pattern)
                if pattern.search(decoded_ua):
                    matched_patterns.append(f"ua:{pattern.pattern}")

            if matched_patterns:
                events.append(
                    self._create_event(
                        event_type="xss_attempt_detected",
                        severity=Severity.HIGH,
                        data={
                            "probe_name": self.name,
                            "detection_source": "log_show",
                            "client_ip": request.client_ip,
                            "method": request.method,
                            "path": request.path[:500],
                            "decoded_path": decoded_path[:500],
                            "status_code": request.status_code,
                            "matched_patterns": matched_patterns[:5],
                            "user_agent": request.user_agent[:200],
                            "server_type": request.server_type,
                        },
                        confidence=min(0.95, 0.6 + len(matched_patterns) * 0.1),
                    )
                )

        return events


# -- Probe 2: SSRF Detection -------------------------------------------------


class SSRFDetectionProbe(MicroProbe):
    """Detect server-side request forgery patterns in HTTP requests.

    MITRE: T1090 — Proxy

    SSRF attacks trick the server into making requests to internal resources.
    We detect requests containing internal IP addresses (127.0.0.1,
    169.254.169.254, 10.*) in URL parameters, indicating attempts to reach
    internal services or cloud metadata endpoints.
    """

    name = "macos_http_ssrf"
    description = "Detects SSRF patterns via internal IPs in URL parameters"
    platforms = ["darwin"]
    mitre_techniques = ["T1090"]
    mitre_tactics = ["command_and_control"]
    scan_interval = 10.0
    requires_fields = ["http_requests"]
    maturity = "stable"
    false_positive_notes = [
        "Internal API gateways routing to localhost are legitimate",
        "Development environments may proxy to internal addresses",
    ]
    evasion_notes = [
        "DNS rebinding to resolve external domain to internal IP",
        "URL encoding or IP obfuscation (decimal, hex, octal IP formats)",
    ]

    # Internal/metadata IP patterns in URL params
    _SSRF_PATTERNS = [
        re.compile(r"127\.0\.0\.1", re.IGNORECASE),
        re.compile(r"localhost", re.IGNORECASE),
        re.compile(r"169\.254\.169\.254", re.IGNORECASE),
        re.compile(r"0\.0\.0\.0", re.IGNORECASE),
        re.compile(r"(?:^|[=&?/])10\.\d{1,3}\.\d{1,3}\.\d{1,3}", re.IGNORECASE),
        re.compile(r"(?:^|[=&?/])192\.168\.\d{1,3}\.\d{1,3}", re.IGNORECASE),
        re.compile(
            r"(?:^|[=&?/])172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}", re.IGNORECASE
        ),
        re.compile(r"metadata\.google\.internal", re.IGNORECASE),
        re.compile(r"instance-data", re.IGNORECASE),
        re.compile(r"\[::1\]", re.IGNORECASE),
    ]

    # Cloud metadata paths
    _METADATA_PATHS = [
        "/latest/meta-data/",
        "/latest/api/token",
        "/metadata/v1/",
        "/computeMetadata/v1/",
    ]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        requests = context.shared_data.get("http_requests", [])

        for request in requests:
            decoded_path = _url_decode(request.path)
            matched_indicators: List[str] = []

            # Check for internal IP patterns in path/params
            for pattern in self._SSRF_PATTERNS:
                if pattern.search(decoded_path):
                    matched_indicators.append(pattern.pattern)

            # Check for cloud metadata paths
            for meta_path in self._METADATA_PATHS:
                if meta_path in decoded_path.lower():
                    matched_indicators.append(f"metadata:{meta_path}")

            if matched_indicators:
                events.append(
                    self._create_event(
                        event_type="ssrf_attempt_detected",
                        severity=Severity.HIGH,
                        data={
                            "probe_name": self.name,
                            "detection_source": "log_show",
                            "client_ip": request.client_ip,
                            "method": request.method,
                            "path": request.path[:500],
                            "decoded_path": decoded_path[:500],
                            "status_code": request.status_code,
                            "matched_indicators": matched_indicators[:5],
                            "server_type": request.server_type,
                        },
                        confidence=min(0.95, 0.65 + len(matched_indicators) * 0.1),
                    )
                )

        return events


# -- Probe 3: Path Traversal -------------------------------------------------


class PathTraversalProbe(MicroProbe):
    """Detect path traversal attacks in HTTP request paths.

    MITRE: T1083 — File and Directory Discovery

    Path traversal attacks use sequences like ../, ....\\\\, /etc/passwd,
    /proc/self to escape the web root and access arbitrary files on the
    server filesystem.
    """

    name = "macos_http_path_traversal"
    description = "Detects path traversal via directory escape sequences"
    platforms = ["darwin"]
    mitre_techniques = ["T1083"]
    mitre_tactics = ["discovery"]
    scan_interval = 10.0
    requires_fields = ["http_requests"]
    maturity = "stable"
    false_positive_notes = [
        "Some CMS platforms use ../ in legitimate URL rewriting",
        "Build tools may reference relative paths in API calls",
    ]
    evasion_notes = [
        "Double URL encoding (%%2e%%2e%%2f) to bypass simple filters",
        "Unicode normalization (..%c0%af) on misconfigured servers",
    ]

    _TRAVERSAL_PATTERNS = [
        re.compile(r"\.\./", re.IGNORECASE),
        re.compile(r"\.\.\\", re.IGNORECASE),
        re.compile(r"\.\.\.\./", re.IGNORECASE),
        re.compile(r"\.\.;/", re.IGNORECASE),
        re.compile(r"%2e%2e[%/\\]", re.IGNORECASE),
        re.compile(r"%252e%252e", re.IGNORECASE),
        re.compile(r"\.\.%00", re.IGNORECASE),
    ]

    _SENSITIVE_FILES = [
        re.compile(r"/etc/passwd", re.IGNORECASE),
        re.compile(r"/etc/shadow", re.IGNORECASE),
        re.compile(r"/etc/hosts", re.IGNORECASE),
        re.compile(r"/proc/self", re.IGNORECASE),
        re.compile(r"/proc/version", re.IGNORECASE),
        re.compile(r"boot\.ini", re.IGNORECASE),
        re.compile(r"win\.ini", re.IGNORECASE),
        re.compile(r"web\.config", re.IGNORECASE),
        re.compile(r"\.htaccess", re.IGNORECASE),
        re.compile(r"\.env", re.IGNORECASE),
        re.compile(r"\.git/", re.IGNORECASE),
        re.compile(r"wp-config\.php", re.IGNORECASE),
    ]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        requests = context.shared_data.get("http_requests", [])

        for request in requests:
            decoded_path = _url_decode(request.path)
            matched_indicators: List[str] = []

            # Check traversal sequences
            for pattern in self._TRAVERSAL_PATTERNS:
                if pattern.search(decoded_path):
                    matched_indicators.append(f"traversal:{pattern.pattern}")

            # Check sensitive file access
            for pattern in self._SENSITIVE_FILES:
                if pattern.search(decoded_path):
                    matched_indicators.append(f"sensitive:{pattern.pattern}")

            if matched_indicators:
                # Higher severity if both traversal + sensitive file
                has_traversal = any(
                    i.startswith("traversal:") for i in matched_indicators
                )
                has_sensitive = any(
                    i.startswith("sensitive:") for i in matched_indicators
                )
                severity = (
                    Severity.CRITICAL
                    if (has_traversal and has_sensitive)
                    else Severity.HIGH
                )

                events.append(
                    self._create_event(
                        event_type="path_traversal_detected",
                        severity=severity,
                        data={
                            "probe_name": self.name,
                            "detection_source": "log_show",
                            "client_ip": request.client_ip,
                            "method": request.method,
                            "path": request.path[:500],
                            "decoded_path": decoded_path[:500],
                            "status_code": request.status_code,
                            "matched_indicators": matched_indicators[:10],
                            "has_traversal": has_traversal,
                            "has_sensitive_file": has_sensitive,
                            "server_type": request.server_type,
                        },
                        confidence=min(0.95, 0.6 + len(matched_indicators) * 0.1),
                    )
                )

        return events


# -- Probe 4: API Abuse (Rate Limiting) --------------------------------------


class APIAbuseProbe(MicroProbe):
    """Detect API abuse via rate limiting violations.

    MITRE: T1106 — Native API

    Attackers performing brute-force, credential stuffing, or enumeration
    attacks generate high request volumes from the same IP. We detect when
    a single client exceeds 100 requests within a 30-second window.
    """

    name = "macos_http_api_abuse"
    description = "Detects rate limiting violations from high-volume clients"
    platforms = ["darwin"]
    mitre_techniques = ["T1106"]
    mitre_tactics = ["execution"]
    scan_interval = 15.0
    requires_fields = ["http_requests"]
    maturity = "stable"
    false_positive_notes = [
        "Load testing tools (wrk, ab, siege) generate high request volumes",
        "Legitimate crawlers (Googlebot) may exceed rate limits",
    ]
    evasion_notes = [
        "Distributed attacks across many source IPs evade per-IP thresholds",
        "Slow-rate attacks below threshold but sustained over long periods",
    ]

    RATE_THRESHOLD = 100  # Max requests from single IP in window
    WINDOW_SECONDS = 30.0  # Observation window

    def __init__(self) -> None:
        super().__init__()
        # client_ip → list of request timestamps
        self._ip_history: Dict[str, List[float]] = collections.defaultdict(list)

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        requests = context.shared_data.get("http_requests", [])
        now = time.time()

        # Record timestamps
        for request in requests:
            self._ip_history[request.client_ip].append(request.timestamp)

        # Evaluate per-IP rates
        cutoff = now - self.WINDOW_SECONDS
        alerted_ips: Set[str] = set()

        for client_ip, timestamps in list(self._ip_history.items()):
            # Trim old entries
            timestamps = [t for t in timestamps if t > cutoff]
            self._ip_history[client_ip] = timestamps

            if not timestamps:
                del self._ip_history[client_ip]
                continue

            if len(timestamps) >= self.RATE_THRESHOLD and client_ip not in alerted_ips:
                # Gather path distribution
                ip_requests = [r for r in requests if r.client_ip == client_ip]
                paths = [r.path.split("?")[0] for r in ip_requests]
                path_counts = collections.Counter(paths)

                events.append(
                    self._create_event(
                        event_type="api_abuse_rate_violation",
                        severity=Severity.HIGH,
                        data={
                            "probe_name": self.name,
                            "detection_source": "log_show",
                            "client_ip": client_ip,
                            "request_count": len(timestamps),
                            "window_seconds": self.WINDOW_SECONDS,
                            "threshold": self.RATE_THRESHOLD,
                            "top_paths": dict(path_counts.most_common(5)),
                            "unique_paths": len(set(paths)),
                        },
                        confidence=min(
                            0.95, 0.6 + (len(timestamps) - self.RATE_THRESHOLD) * 0.002
                        ),
                    )
                )
                alerted_ips.add(client_ip)

        return events


# -- Probe 5: WebShell Upload ------------------------------------------------


class WebShellUploadProbe(MicroProbe):
    """Detect file upload followed by webshell deployment patterns.

    MITRE: T1505.003 — Server Software Component: Web Shell

    Attackers upload webshells (PHP, JSP, ASP files) through file upload
    endpoints. We detect POST requests to upload paths that include
    suspicious file extensions (.php, .jsp, .asp, .aspx, .war).
    """

    name = "macos_http_webshell_upload"
    description = "Detects file upload to webshell patterns (POST + shell extensions)"
    platforms = ["darwin"]
    mitre_techniques = ["T1505.003"]
    mitre_tactics = ["persistence"]
    scan_interval = 10.0
    requires_fields = ["http_requests"]
    maturity = "stable"
    false_positive_notes = [
        "CMS file managers (WordPress media upload) generate legitimate .php uploads",
        "CI/CD deployment systems may upload .war/.jar artifacts",
    ]
    evasion_notes = [
        "Double extensions (shell.php.jpg) bypass extension-only checks",
        "Content-Type manipulation to upload as image then rename",
    ]

    # Upload endpoint patterns
    _UPLOAD_PATTERNS = [
        re.compile(r"upload", re.IGNORECASE),
        re.compile(r"file", re.IGNORECASE),
        re.compile(r"import", re.IGNORECASE),
        re.compile(r"attach", re.IGNORECASE),
        re.compile(r"media", re.IGNORECASE),
    ]

    # Webshell extensions
    _SHELL_EXTENSIONS = re.compile(
        r"\.(php[3-8]?|jsp|jspx|asp|aspx|war|cfm|cgi|pl|py|sh|bash)\b",
        re.IGNORECASE,
    )

    # Known webshell filenames
    _KNOWN_SHELLS = re.compile(
        r"(c99|r57|b374k|wso|webshell|cmd|shell|backdoor|hack|pwn)",
        re.IGNORECASE,
    )

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        requests = context.shared_data.get("http_requests", [])

        for request in requests:
            if request.method not in ("POST", "PUT"):
                continue

            decoded_path = _url_decode(request.path)
            indicators: List[str] = []

            # Check if path looks like an upload endpoint
            is_upload = any(p.search(decoded_path) for p in self._UPLOAD_PATTERNS)

            # Check for shell extensions in path
            has_shell_ext = bool(self._SHELL_EXTENSIONS.search(decoded_path))

            # Check for known webshell names
            has_known_shell = bool(self._KNOWN_SHELLS.search(decoded_path))

            if is_upload:
                indicators.append("upload_endpoint")
            if has_shell_ext:
                indicators.append("shell_extension")
            if has_known_shell:
                indicators.append("known_shell_name")

            # Alert if upload + shell extension, or known shell name
            if (is_upload and has_shell_ext) or has_known_shell:
                severity = Severity.CRITICAL if has_known_shell else Severity.HIGH

                events.append(
                    self._create_event(
                        event_type="webshell_upload_detected",
                        severity=severity,
                        data={
                            "probe_name": self.name,
                            "detection_source": "log_show",
                            "client_ip": request.client_ip,
                            "method": request.method,
                            "path": request.path[:500],
                            "decoded_path": decoded_path[:500],
                            "status_code": request.status_code,
                            "body_size": request.body_size,
                            "indicators": indicators,
                            "server_type": request.server_type,
                        },
                        confidence=min(0.95, 0.65 + len(indicators) * 0.1),
                    )
                )

        return events


# -- Probe 6: C2 Web Channel (HTTP Beaconing) --------------------------------


class C2WebChannelProbe(MicroProbe):
    """Detect HTTP-based C2 beaconing with encoded payloads.

    MITRE: T1071.001 — Application Layer Protocol: Web Protocols

    C2 implants communicate over HTTP/HTTPS at regular intervals, often using
    encoded payloads in URL parameters or POST bodies. We detect periodic
    request patterns with high-entropy (encoded) payloads.
    """

    name = "macos_http_c2_beacon"
    description = "Detects HTTP beaconing patterns with encoded payloads"
    platforms = ["darwin"]
    mitre_techniques = ["T1071.001"]
    mitre_tactics = ["command_and_control"]
    scan_interval = 30.0
    requires_fields = ["http_requests"]
    maturity = "experimental"
    supports_baseline = True
    baseline_window_hours = 24
    false_positive_notes = [
        "Polling APIs (long-poll, heartbeat endpoints) generate periodic traffic",
        "Analytics and telemetry SDKs beacon at regular intervals",
    ]
    evasion_notes = [
        "High jitter randomization defeats periodicity detection",
        "Domain fronting hides C2 behind legitimate CDN domains",
    ]

    MIN_SAMPLES = 5  # Minimum requests to analyze periodicity
    MAX_JITTER_CV = 0.15  # Coefficient of variation threshold
    MIN_INTERVAL_S = 2.0
    MAX_INTERVAL_S = 3600.0

    # Encoded payload patterns (base64, hex)
    _ENCODED_PATTERNS = [
        re.compile(r"[A-Za-z0-9+/=]{32,}"),  # Base64-like
        re.compile(r"[0-9a-fA-F]{32,}"),  # Hex-encoded
        re.compile(r"(%[0-9a-fA-F]{2}){10,}"),  # URL-encoded sequences
    ]

    def __init__(self) -> None:
        super().__init__()
        # path → list of request timestamps
        self._path_history: Dict[str, List[float]] = collections.defaultdict(list)

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        requests = context.shared_data.get("http_requests", [])
        now = time.time()

        for request in requests:
            # Normalize path (strip query params for grouping)
            base_path = request.path.split("?")[0]
            self._path_history[base_path].append(request.timestamp)

        # Analyze periodicity per path
        for path, timestamps in list(self._path_history.items()):
            # Trim old entries (keep last hour)
            cutoff = now - 3600
            timestamps = [t for t in timestamps if t > cutoff]
            self._path_history[path] = timestamps

            if len(timestamps) < self.MIN_SAMPLES:
                continue

            timestamps.sort()
            intervals = [
                timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)
            ]

            # Filter to valid interval range
            valid_intervals = [
                iv
                for iv in intervals
                if self.MIN_INTERVAL_S <= iv <= self.MAX_INTERVAL_S
            ]

            if len(valid_intervals) < self.MIN_SAMPLES - 1:
                continue

            mean_interval = sum(valid_intervals) / len(valid_intervals)
            if mean_interval == 0:
                continue

            variance = sum((iv - mean_interval) ** 2 for iv in valid_intervals) / len(
                valid_intervals
            )
            std_dev = variance**0.5
            cv = std_dev / mean_interval

            if cv <= self.MAX_JITTER_CV:
                # Check if requests contain encoded payloads
                path_requests = [r for r in requests if r.path.split("?")[0] == path]
                has_encoded = any(
                    any(p.search(r.path) for p in self._ENCODED_PATTERNS)
                    for r in path_requests
                )

                severity = Severity.HIGH if has_encoded else Severity.MEDIUM

                events.append(
                    self._create_event(
                        event_type="http_c2_beacon_detected",
                        severity=severity,
                        data={
                            "probe_name": self.name,
                            "detection_source": "log_show",
                            "path": path[:500],
                            "mean_interval_s": round(mean_interval, 2),
                            "jitter_cv": round(cv, 4),
                            "sample_count": len(timestamps),
                            "interval_count": len(valid_intervals),
                            "has_encoded_payload": has_encoded,
                            "client_ips": list({r.client_ip for r in path_requests})[
                                :5
                            ],
                        },
                        confidence=max(0.7, 1.0 - cv * 3),
                    )
                )

        return events


# -- Probe 7: Data Exfiltration via HTTP -------------------------------------


class DataExfilHTTPProbe(MicroProbe):
    """Detect data exfiltration via large HTTP POST bodies to unusual endpoints.

    MITRE: T1048 — Exfiltration Over Alternative Protocol

    Attackers exfiltrate data by sending large POST requests to external
    endpoints. We detect POST/PUT requests with body sizes exceeding a
    threshold to non-standard endpoints.
    """

    name = "macos_http_data_exfil"
    description = "Detects large POST bodies to unusual endpoints (data exfiltration)"
    platforms = ["darwin"]
    mitre_techniques = ["T1048"]
    mitre_tactics = ["exfiltration"]
    scan_interval = 10.0
    requires_fields = ["http_requests"]
    maturity = "stable"
    false_positive_notes = [
        "File upload features legitimately send large POST bodies",
        "API endpoints accepting bulk data imports",
    ]
    evasion_notes = [
        "Chunked exfiltration in many small requests below threshold",
        "Steganography in image uploads hides data in legitimate content",
    ]

    BODY_SIZE_THRESHOLD = 1_048_576  # 1 MB
    LARGE_BODY_THRESHOLD = 10_485_760  # 10 MB (critical)

    # Known safe upload paths
    _SAFE_UPLOAD_PATHS = frozenset(
        {
            "/api/upload",
            "/api/v1/upload",
            "/api/v2/upload",
            "/upload",
            "/files",
            "/attachments",
            "/api/import",
            "/api/bulk",
        }
    )

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        requests = context.shared_data.get("http_requests", [])

        for request in requests:
            if request.method not in ("POST", "PUT", "PATCH"):
                continue

            if request.body_size < self.BODY_SIZE_THRESHOLD:
                continue

            base_path = request.path.split("?")[0].lower()

            # Skip known safe upload paths
            if base_path in self._SAFE_UPLOAD_PATHS:
                continue

            is_critical = request.body_size >= self.LARGE_BODY_THRESHOLD
            severity = Severity.CRITICAL if is_critical else Severity.HIGH

            events.append(
                self._create_event(
                    event_type="http_data_exfil_detected",
                    severity=severity,
                    data={
                        "probe_name": self.name,
                        "detection_source": "log_show",
                        "client_ip": request.client_ip,
                        "method": request.method,
                        "path": request.path[:500],
                        "status_code": request.status_code,
                        "body_size": request.body_size,
                        "body_size_mb": round(request.body_size / 1_048_576, 2),
                        "threshold_mb": round(self.BODY_SIZE_THRESHOLD / 1_048_576, 2),
                        "server_type": request.server_type,
                    },
                    confidence=min(
                        0.95,
                        0.6 + (request.body_size / self.LARGE_BODY_THRESHOLD) * 0.3,
                    ),
                )
            )

        return events


# -- Probe 8: Cookie Theft / Session Hijacking --------------------------------


class CookieTheftProbe(MicroProbe):
    """Detect session hijacking patterns via cookie manipulation in requests.

    MITRE: T1539 — Steal Web Session Cookie

    Attackers steal session cookies to hijack authenticated sessions. We detect
    patterns like cookie exfiltration in URL parameters, rapid session switching,
    and cookie injection in non-standard headers.
    """

    name = "macos_http_cookie_theft"
    description = "Detects session hijacking patterns (cookie manipulation in requests)"
    platforms = ["darwin"]
    mitre_techniques = ["T1539"]
    mitre_tactics = ["credential_access"]
    scan_interval = 10.0
    requires_fields = ["http_requests"]
    maturity = "experimental"
    false_positive_notes = [
        "SSO redirects may pass session tokens in URL parameters",
        "OAuth flows include tokens in redirect URLs temporarily",
    ]
    evasion_notes = [
        "Encrypted or encoded cookie values bypass pattern matching",
        "Using WebSocket channels to exfiltrate cookies avoids HTTP detection",
    ]

    # Cookie/session patterns in URL parameters
    _COOKIE_LEAK_PATTERNS = [
        re.compile(
            r"[?&](session_?id|sess_?id|PHPSESSID|JSESSIONID|ASP\.NET_SessionId)\s*=",
            re.IGNORECASE,
        ),
        re.compile(
            r"[?&](token|auth_?token|access_?token|jwt|bearer)\s*=", re.IGNORECASE
        ),
        re.compile(r"[?&]cookie\s*=", re.IGNORECASE),
        re.compile(r"document\.cookie", re.IGNORECASE),
    ]

    # Session fixation / injection patterns
    _SESSION_FIXATION_PATTERNS = [
        re.compile(r"Set-Cookie:", re.IGNORECASE),
        re.compile(r"Cookie:\s*.*=.*;\s*.*=", re.IGNORECASE),
    ]

    def __init__(self) -> None:
        super().__init__()
        # Track session IDs per client IP to detect session switching
        self._ip_sessions: Dict[str, Set[str]] = collections.defaultdict(set)

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        requests = context.shared_data.get("http_requests", [])

        for request in requests:
            decoded_path = _url_decode(request.path)
            matched_indicators: List[str] = []

            # Check for cookie/session leakage in URL
            for pattern in self._COOKIE_LEAK_PATTERNS:
                if pattern.search(decoded_path):
                    matched_indicators.append(f"cookie_leak:{pattern.pattern}")

            # Check user-agent for cookie exfiltration scripts
            if "document.cookie" in _url_decode(request.user_agent).lower():
                matched_indicators.append("cookie_in_ua")

            # Extract session IDs from path params for tracking
            session_match = re.search(
                r"(?:session_?id|PHPSESSID|JSESSIONID|token)=([^&]+)",
                decoded_path,
                re.IGNORECASE,
            )
            if session_match:
                session_id = session_match.group(1)
                self._ip_sessions[request.client_ip].add(session_id)

                # Multiple different sessions from same IP → session hijacking
                if len(self._ip_sessions[request.client_ip]) > 3:
                    matched_indicators.append(
                        f"multi_session:{len(self._ip_sessions[request.client_ip])}"
                    )

            if matched_indicators:
                events.append(
                    self._create_event(
                        event_type="cookie_theft_detected",
                        severity=Severity.HIGH,
                        data={
                            "probe_name": self.name,
                            "detection_source": "log_show",
                            "client_ip": request.client_ip,
                            "method": request.method,
                            "path": request.path[:500],
                            "decoded_path": decoded_path[:500],
                            "status_code": request.status_code,
                            "matched_indicators": matched_indicators[:5],
                            "user_agent": request.user_agent[:200],
                            "server_type": request.server_type,
                        },
                        confidence=min(0.90, 0.55 + len(matched_indicators) * 0.15),
                    )
                )

        return events


# -- Factory ------------------------------------------------------------------


def create_http_inspector_probes() -> List[MicroProbe]:
    """Create all macOS HTTP Inspector Observatory probes."""
    return [
        XSSDetectionProbe(),
        SSRFDetectionProbe(),
        PathTraversalProbe(),
        APIAbuseProbe(),
        WebShellUploadProbe(),
        C2WebChannelProbe(),
        DataExfilHTTPProbe(),
        CookieTheftProbe(),
    ]
