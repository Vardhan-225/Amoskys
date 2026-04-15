"""macOS HTTP Inspector Collector — gathers HTTP request logs and activity.

Data sources:
    1. Apache access log (/var/log/apache2/access_log) — if present
    2. Nginx access log (/var/log/nginx/access.log) — if present
    3. Unified Logging (URLSession/NSURLConnection) — real-time HTTP activity

Returns shared_data dict with:
    http_requests: List[HTTPRequest] — recent HTTP requests from logs
    request_count: int — total requests collected
    unique_clients: int — unique client IPs
    error_count: int — requests with 4xx/5xx status codes
    collection_time_ms: float — collection duration
"""

from __future__ import annotations

import logging
import re
import subprocess
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class HTTPRequest:
    """Single HTTP request captured from web server logs or Unified Logging."""

    timestamp: float  # Unix epoch seconds
    method: str  # GET, POST, PUT, DELETE, etc.
    path: str  # Request path including query string
    status_code: int  # HTTP status code
    client_ip: str  # Client IP address
    user_agent: str = ""  # User-Agent header value
    body_size: int = 0  # Request/response body size in bytes
    response_time_ms: float = 0.0  # Server response time in milliseconds
    protocol: str = "HTTP/1.1"  # HTTP protocol version
    server_type: str = ""  # "apache", "nginx", or "urlsession"


class MacOSHTTPInspectorCollector:
    """Collects HTTP request data from macOS web server logs and Unified Logging.

    Returns shared_data dict for ProbeContext with keys:
        http_requests: List[HTTPRequest]
        request_count: int
        unique_clients: int
        error_count: int
        collection_time_ms: float
    """

    # Log file paths
    _APACHE_LOG = "/var/log/apache2/access_log"
    _NGINX_LOG = "/var/log/nginx/access.log"

    # Unified Logging predicate for URLSession/NSURLConnection
    _LOG_PREDICATE = (
        '(process == "nsurlsessiond" OR process == "cfnetwork") AND '
        '(eventMessage CONTAINS "HTTP" OR eventMessage CONTAINS "request" '
        'OR eventMessage CONTAINS "response")'
    )
    _LOG_WINDOW_SECONDS = 30  # Look back 30s for recent activity
    _LOG_TIMEOUT = 15  # Subprocess timeout

    # Combined Log Format (Apache/Nginx):
    # 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /path HTTP/1.0" 200 2326
    _COMBINED_LOG_PATTERN = re.compile(
        r"(\S+)"  # client_ip
        r"\s+\S+\s+\S+\s+"  # ident, auth_user
        r"\[([^\]]+)\]"  # timestamp
        r'\s+"(\S+)\s+(\S+)\s*(\S*)"'  # method, path, protocol
        r"\s+(\d{3})"  # status_code
        r"\s+(\d+|-)"  # body_size
        r'(?:\s+"([^"]*)")?'  # referer (ignored)
        r'(?:\s+"([^"]*)")?'  # user_agent
    )

    # Unified Logging URL pattern
    _URL_SESSION_PATTERN = re.compile(
        r"(?:request|load)\s+(\S+)\s+"  # URL
        r"(?:HTTP\s+)?(\d{3})?"  # optional status
        r"(?:.*?(\d+)\s+bytes)?"  # optional body size
    )

    # Timestamp parsing for Combined Log Format
    _MONTH_MAP = {
        "Jan": 1,
        "Feb": 2,
        "Mar": 3,
        "Apr": 4,
        "May": 5,
        "Jun": 6,
        "Jul": 7,
        "Aug": 8,
        "Sep": 9,
        "Oct": 10,
        "Nov": 11,
        "Dec": 12,
    }

    def __init__(self, device_id: str = "", log_window: int = 30) -> None:
        self.device_id = device_id or _get_hostname()
        self._log_window = log_window
        self._last_apache_pos: int = 0
        self._last_nginx_pos: int = 0

    def collect(self) -> Dict[str, Any]:
        """Collect HTTP requests from all available sources.

        Returns dict for ProbeContext.shared_data.
        """
        start = time.monotonic()

        requests: List[HTTPRequest] = []

        # Collect from Apache access log
        apache_requests = self._collect_access_log(self._APACHE_LOG, "apache")
        requests.extend(apache_requests)

        # Collect from Nginx access log
        nginx_requests = self._collect_access_log(self._NGINX_LOG, "nginx")
        requests.extend(nginx_requests)

        # Collect from Unified Logging (URLSession/NSURLConnection)
        urlsession_requests = self._collect_urlsession_logs()
        requests.extend(urlsession_requests)

        elapsed_ms = (time.monotonic() - start) * 1000

        unique_clients = len({r.client_ip for r in requests})
        error_count = sum(1 for r in requests if r.status_code >= 400)

        return {
            "http_requests": requests,
            "request_count": len(requests),
            "unique_clients": unique_clients,
            "error_count": error_count,
            "collection_time_ms": round(elapsed_ms, 2),
        }

    def _collect_access_log(self, log_path: str, server_type: str) -> List[HTTPRequest]:
        """Parse an Apache/Nginx Combined Log Format access log.

        Reads from last known position to avoid re-processing old entries.
        """
        requests: List[HTTPRequest] = []

        try:
            with open(log_path) as f:
                # Seek to last known position
                if server_type == "apache":
                    f.seek(self._last_apache_pos)
                else:
                    f.seek(self._last_nginx_pos)

                for line in f:
                    request = self._parse_access_log_line(line, server_type)
                    if request:
                        requests.append(request)

                # Update position
                pos = f.tell()
                if server_type == "apache":
                    self._last_apache_pos = pos
                else:
                    self._last_nginx_pos = pos

        except FileNotFoundError:
            logger.debug("%s log not found at %s", server_type, log_path)
        except PermissionError:
            logger.warning(
                "Permission denied reading %s log at %s", server_type, log_path
            )
        except Exception as e:
            logger.error("%s log collection failed: %s", server_type, e)

        if requests:
            logger.debug("Collected %d requests from %s", len(requests), log_path)
        return requests

    def _parse_access_log_line(
        self, line: str, server_type: str
    ) -> Optional[HTTPRequest]:
        """Parse a Combined Log Format line into HTTPRequest."""
        if not line or line.startswith("#"):
            return None

        match = self._COMBINED_LOG_PATTERN.search(line)
        if not match:
            return None

        client_ip = match.group(1)
        timestamp_str = match.group(2)
        method = match.group(3)
        path = match.group(4)
        protocol = match.group(5) or "HTTP/1.1"
        status_code = int(match.group(6))
        body_size_str = match.group(7)
        user_agent = match.group(9) or ""

        body_size = int(body_size_str) if body_size_str != "-" else 0
        timestamp = self._parse_clf_timestamp(timestamp_str)
        if timestamp is None:
            timestamp = time.time()  # ingest time — flagged via log warning

        return HTTPRequest(
            timestamp=timestamp,
            method=method,
            path=path,
            status_code=status_code,
            client_ip=client_ip,
            user_agent=user_agent,
            body_size=body_size,
            protocol=protocol,
            server_type=server_type,
        )

    def _parse_clf_timestamp(self, ts: str) -> Optional[float]:
        """Parse Combined Log Format timestamp to Unix epoch.

        Format: 10/Oct/2000:13:55:36 -0700

        Returns ``None`` when parsing fails so callers can flag the
        event rather than silently fabricating a timestamp.
        """
        try:
            parts = ts.split(":")
            date_part = parts[0]
            day, month_str, year = date_part.split("/")
            hour, minute, second_tz = parts[1], parts[2], parts[3]
            second = second_tz.split(" ")[0]

            month = self._MONTH_MAP.get(month_str, 1)

            import datetime as _dt

            dt = _dt.datetime(
                int(year),
                month,
                int(day),
                int(hour),
                int(minute),
                int(second),
            )
            return dt.timestamp()
        except Exception:
            logger.warning("http_inspector: unparseable CLF timestamp %r", ts)
            return None

    def _collect_urlsession_logs(self) -> List[HTTPRequest]:
        """Parse Unified Logging for URLSession/NSURLConnection activity."""
        requests: List[HTTPRequest] = []

        try:
            result = subprocess.run(
                [
                    "log",
                    "show",
                    "--predicate",
                    self._LOG_PREDICATE,
                    "--last",
                    f"{self._log_window}s",
                    "--style",
                    "compact",
                    "--info",
                ],
                capture_output=True,
                text=True,
                timeout=self._LOG_TIMEOUT,
            )

            if result.returncode != 0:
                logger.warning(
                    "log show returned %d: %s",
                    result.returncode,
                    result.stderr[:200],
                )
                return requests

            for line in result.stdout.strip().split("\n"):
                request = self._parse_urlsession_line(line)
                if request:
                    requests.append(request)

        except subprocess.TimeoutExpired:
            logger.warning(
                "URLSession log query timed out after %ds",
                self._LOG_TIMEOUT,
            )
        except FileNotFoundError:
            logger.error("'log' command not found — cannot collect URL activity")
        except Exception as e:
            logger.error("URLSession log collection failed: %s", e)

        logger.debug("Collected %d URLSession requests", len(requests))
        return requests

    def _parse_urlsession_line(self, line: str) -> Optional[HTTPRequest]:
        """Parse a Unified Logging line for URLSession/NSURLConnection data."""
        if not line or line.startswith("---") or line.startswith("Filtering"):
            return None

        match = self._URL_SESSION_PATTERN.search(line)
        if match:
            url = match.group(1)
            status = int(match.group(2)) if match.group(2) else 0
            body_size = int(match.group(3)) if match.group(3) else 0

            # Extract path from URL
            path = url
            if "://" in url:
                # Strip scheme and host
                after_scheme = url.split("://", 1)[1]
                slash_idx = after_scheme.find("/")
                path = after_scheme[slash_idx:] if slash_idx >= 0 else "/"

            return HTTPRequest(
                timestamp=time.time(),
                method="GET",
                path=path,
                status_code=status,
                client_ip="127.0.0.1",
                body_size=body_size,
                server_type="urlsession",
            )

        return None

    def get_capabilities(self) -> Dict[str, str]:
        """Report collector capabilities."""
        caps = {}

        # Check Apache log
        try:
            with open(self._APACHE_LOG):
                caps["apache_log"] = "REAL"
        except FileNotFoundError:
            caps["apache_log"] = "BLIND"
        except PermissionError:
            caps["apache_log"] = "DEGRADED"

        # Check Nginx log
        try:
            with open(self._NGINX_LOG):
                caps["nginx_log"] = "REAL"
        except FileNotFoundError:
            caps["nginx_log"] = "BLIND"
        except PermissionError:
            caps["nginx_log"] = "DEGRADED"

        # Check Unified Logging
        try:
            result = subprocess.run(
                [
                    "log",
                    "show",
                    "--predicate",
                    self._LOG_PREDICATE,
                    "--last",
                    "1s",
                    "--style",
                    "compact",
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )
            caps["unified_logging"] = "REAL" if result.returncode == 0 else "DEGRADED"
        except Exception:
            caps["unified_logging"] = "BLIND"

        return caps


def _get_hostname() -> str:
    import socket

    return socket.gethostname()
