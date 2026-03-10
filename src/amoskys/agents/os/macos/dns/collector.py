"""macOS DNS Collector — gathers DNS query logs and configuration.

Data sources:
    1. Unified Logging (mDNSResponder) — real-time DNS queries
    2. scutil --dns — resolver configuration and search domains
    3. /etc/resolv.conf — system DNS servers (fallback)

Returns shared_data dict with:
    dns_queries: List[DNSQuery] — recent queries from Unified Logging
    dns_servers: List[str] — configured DNS servers
    search_domains: List[str] — configured search domains
    query_count: int — total queries collected
    collection_time_ms: float — collection duration
"""

from __future__ import annotations

import logging
import re
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class DNSQuery:
    """Single DNS query captured from mDNSResponder logs."""

    timestamp: float  # Unix epoch seconds
    domain: str  # Queried domain name
    record_type: str  # A, AAAA, CNAME, TXT, MX, PTR, etc.
    response_ips: List[str] = field(default_factory=list)  # Resolved IPs
    ttl: int = 0  # Response TTL in seconds
    response_code: str = "NOERROR"  # NOERROR, NXDOMAIN, SERVFAIL, etc.
    source_process: str = ""  # Process that made the query (if available)
    source_pid: int = 0  # PID of querying process
    response_size: int = 0  # Response payload size (bytes)
    is_reverse: bool = False  # PTR / reverse lookup


@dataclass
class DNSServerInfo:
    """DNS server configuration entry."""

    address: str  # IP address of DNS server
    port: int = 53
    interface: str = ""  # Network interface scope
    is_default: bool = False
    protocol: str = "udp"  # udp, tcp, tls, https


class MacOSDNSCollector:
    """Collects DNS query data from macOS Unified Logging and system config.

    Returns shared_data dict for ProbeContext with keys:
        dns_queries: List[DNSQuery]
        dns_servers: List[DNSServerInfo]
        search_domains: List[str]
        query_count: int
        unique_domains: int
        collection_time_ms: float
    """

    # Unified Logging predicate for mDNSResponder
    _LOG_PREDICATE = (
        'process == "mDNSResponder" AND '
        '(eventMessage CONTAINS "Query" OR eventMessage CONTAINS "response")'
    )
    _LOG_WINDOW_SECONDS = 30  # Look back 30s for recent queries
    _LOG_TIMEOUT = 15  # Subprocess timeout

    # Regex patterns for parsing mDNSResponder log lines
    _QUERY_PATTERN = re.compile(
        r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)"  # timestamp
        r".*?"
        r"(?:Query|question)\s+"
        r"(\S+)"  # domain
        r"\s+(\w+)"  # record type
        r"(?:\s+(\S+))?"  # optional response
    )
    _RESPONSE_PATTERN = re.compile(
        r"(\S+\.)\s+"  # domain
        r"(?:Addr|CNAME|Rdata)\s+"
        r"(\S+)"  # value/IP
        r"(?:\s+TTL\s+(\d+))?"  # optional TTL
    )
    _DOH_PROVIDERS = frozenset(
        {
            "1.1.1.1",
            "1.0.0.1",  # Cloudflare
            "8.8.8.8",
            "8.8.4.4",  # Google
            "9.9.9.9",
            "149.112.112.112",  # Quad9
            "208.67.222.222",
            "208.67.220.220",  # OpenDNS
            "94.140.14.14",
            "94.140.15.15",  # AdGuard
        }
    )

    def __init__(self, device_id: str = "", log_window: int = 30) -> None:
        self.device_id = device_id or _get_hostname()
        self._log_window = log_window

    def collect(self) -> Dict[str, Any]:
        """Collect DNS queries and configuration.

        Returns dict for ProbeContext.shared_data.
        """
        start = time.monotonic()

        queries = self._collect_dns_queries()
        servers, search_domains = self._collect_dns_config()

        elapsed_ms = (time.monotonic() - start) * 1000

        unique_domains = len({q.domain for q in queries})

        return {
            "dns_queries": queries,
            "dns_servers": servers,
            "search_domains": search_domains,
            "query_count": len(queries),
            "unique_domains": unique_domains,
            "doh_providers": self._DOH_PROVIDERS,
            "collection_time_ms": round(elapsed_ms, 2),
        }

    def _collect_dns_queries(self) -> List[DNSQuery]:
        """Parse mDNSResponder logs via Unified Logging."""
        queries: List[DNSQuery] = []

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
                return queries

            for line in result.stdout.strip().split("\n"):
                query = self._parse_log_line(line)
                if query:
                    queries.append(query)

        except subprocess.TimeoutExpired:
            logger.warning(
                "mDNSResponder log query timed out after %ds",
                self._LOG_TIMEOUT,
            )
        except FileNotFoundError:
            logger.error("'log' command not found — cannot collect DNS queries")
        except Exception as e:
            logger.error("DNS query collection failed: %s", e)

        logger.debug("Collected %d DNS queries", len(queries))
        return queries

    def _parse_log_line(self, line: str) -> Optional[DNSQuery]:
        """Parse a single mDNSResponder log line into DNSQuery."""
        if not line or line.startswith("---") or line.startswith("Filtering"):
            return None

        # Try query pattern
        match = self._QUERY_PATTERN.search(line)
        if match:
            domain = match.group(2).rstrip(".")
            record_type = match.group(3).upper()
            is_reverse = domain.endswith(".in-addr.arpa") or domain.endswith(
                ".ip6.arpa"
            )

            return DNSQuery(
                timestamp=time.time(),
                domain=domain,
                record_type=record_type,
                is_reverse=is_reverse,
            )

        # Try response pattern
        match = self._RESPONSE_PATTERN.search(line)
        if match:
            domain = match.group(1).rstrip(".")
            value = match.group(2)
            ttl = int(match.group(3)) if match.group(3) else 0

            response_ips = [value] if _is_ip(value) else []

            return DNSQuery(
                timestamp=time.time(),
                domain=domain,
                record_type="A" if response_ips else "CNAME",
                response_ips=response_ips,
                ttl=ttl,
            )

        return None

    def _collect_dns_config(self) -> tuple[List[DNSServerInfo], List[str]]:
        """Parse scutil --dns for DNS server config and search domains."""
        servers: List[DNSServerInfo] = []
        search_domains: List[str] = []
        seen_servers: set[str] = set()

        try:
            result = subprocess.run(
                ["scutil", "--dns"],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode != 0:
                logger.warning("scutil --dns returned %d", result.returncode)
                return servers, search_domains

            current_interface = ""
            in_default = False

            for line in result.stdout.split("\n"):
                line = line.strip()

                # Detect resolver section
                if line.startswith("resolver #"):
                    current_interface = ""
                    in_default = "Default" in line or "#1" in line

                # Parse nameserver
                if line.startswith("nameserver["):
                    addr_match = re.search(r":\s+(\S+)", line)
                    if addr_match:
                        addr = addr_match.group(1)
                        if addr not in seen_servers:
                            seen_servers.add(addr)
                            servers.append(
                                DNSServerInfo(
                                    address=addr,
                                    interface=current_interface,
                                    is_default=in_default,
                                )
                            )

                # Parse search domains
                if line.startswith("search domain["):
                    domain_match = re.search(r":\s+(\S+)", line)
                    if domain_match:
                        domain = domain_match.group(1)
                        if domain not in search_domains:
                            search_domains.append(domain)

                # Parse interface
                if line.startswith("if_index"):
                    iface_match = re.search(r"\((\w+)\)", line)
                    if iface_match:
                        current_interface = iface_match.group(1)

        except subprocess.TimeoutExpired:
            logger.warning("scutil --dns timed out")
        except FileNotFoundError:
            logger.error("scutil not found")
        except Exception as e:
            logger.error("DNS config collection failed: %s", e)

        # Fallback: /etc/resolv.conf
        if not servers:
            servers = self._parse_resolv_conf()

        return servers, search_domains

    @staticmethod
    def _parse_resolv_conf() -> List[DNSServerInfo]:
        """Parse /etc/resolv.conf as fallback."""
        servers: List[DNSServerInfo] = []
        try:
            with open("/etc/resolv.conf") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("nameserver"):
                        parts = line.split()
                        if len(parts) >= 2:
                            servers.append(
                                DNSServerInfo(
                                    address=parts[1],
                                    is_default=True,
                                )
                            )
        except FileNotFoundError:
            pass
        except Exception as e:
            logger.debug("resolv.conf parse failed: %s", e)
        return servers

    def get_capabilities(self) -> Dict[str, str]:
        """Report collector capabilities."""
        caps = {}

        # Check Unified Logging
        try:
            result = subprocess.run(
                [
                    "log",
                    "show",
                    "--predicate",
                    'process == "mDNSResponder"',
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

        # Check scutil
        try:
            result = subprocess.run(
                ["scutil", "--dns"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            caps["dns_config"] = "REAL" if result.returncode == 0 else "DEGRADED"
        except Exception:
            caps["dns_config"] = "BLIND"

        return caps


def _get_hostname() -> str:
    import socket

    return socket.gethostname()


def _is_ip(value: str) -> bool:
    """Check if string is an IP address."""
    parts = value.split(".")
    if len(parts) == 4:
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            pass
    return ":" in value  # IPv6
