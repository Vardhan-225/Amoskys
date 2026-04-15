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
from datetime import datetime, timezone
from pathlib import Path
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
    # On macOS 15+ (Sequoia), domain names are privacy-hashed in logs.
    # We extract: process name, PID, record type, query suppression status.
    # Actual domains are masked as <mask.hash: 'xxx'>.
    _LOG_PREDICATE = (
        'process == "mDNSResponder" AND '
        '(eventMessage CONTAINS "getaddrinfo start" '
        'OR eventMessage CONTAINS "Query suppressed" '
        'OR eventMessage CONTAINS "Query" OR eventMessage CONTAINS "response")'
    )
    _LOG_WINDOW_SECONDS = 30  # Look back 30s for recent queries
    _LOG_TIMEOUT = 15  # Subprocess timeout

    # macOS 15+ getaddrinfo start pattern (domains are hashed)
    _GETADDR_PATTERN = re.compile(
        r"getaddrinfo\s+start\s+--\s+"
        r".*?hostname:\s+(?:<mask\.hash:\s+'([^']+)'>|(\S+))"  # hashed or plain domain
        r".*?client\s+pid:\s+(\d+)\s+\(([^)]+)\)"  # client PID and process name
    )

    # Query suppression pattern (AAAA records unusable etc.)
    _SUPPRESSED_PATTERN = re.compile(
        r"Query\s+suppressed\s+for\s+(?:<mask\.hash:\s+'([^']+)'>|(\S+))"
        r"\s+(\w+)"  # record type
    )

    # Legacy query pattern (pre-macOS 15, domains visible)
    _QUERY_PATTERN = re.compile(
        r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)"  # timestamp
        r".*?"
        r"(?:Query|question)\s+"
        r"(\S+)"  # domain
        r"\s+(\w+)"  # record type
        r"(?:\s+(\S+))?"  # optional response
    )
    # Legacy response pattern
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

    # Path where the standalone DNS pcap daemon writes captured domains
    _PCAP_DOMAINS_PATH = Path("/var/lib/amoskys/data/dns_plaintext.log")

    def _collect_dns_queries(self) -> List[DNSQuery]:
        """Collect DNS queries from multiple sources.

        Strategy:
          1. Parse mDNSResponder Unified Logging (always — gives PID attribution)
          2. Read plaintext domains from dns_plaintext.log (written by
             standalone pcap daemon, not inline subprocess)
          3. Merge both — plaintext from pcap + PID from Unified Log
        """
        log_queries = self._collect_from_unified_log()
        pcap_queries = self._read_pcap_domains()

        if pcap_queries:
            # Attach PID/process from log queries by timestamp proximity
            log_by_ts = {}
            for lq in log_queries:
                bucket = int(lq.timestamp)
                if bucket not in log_by_ts:
                    log_by_ts[bucket] = lq
            for pq in pcap_queries:
                bucket = int(pq.timestamp)
                match = log_by_ts.get(bucket) or log_by_ts.get(bucket - 1)
                if match and not pq.source_process:
                    pq.source_process = match.source_process
                    pq.source_pid = match.source_pid

        return pcap_queries + log_queries

    def _read_pcap_domains(self) -> List[DNSQuery]:
        """Read plaintext domains from the pcap daemon's output file.

        The dns_pcap_daemon.py runs as a separate process under the watchdog,
        captures port 53 traffic via tcpdump, and appends lines like:
            1712345678.123|A|api.github.com
        to /var/lib/amoskys/data/dns_plaintext.log

        We read and consume lines newer than our last read.
        """
        queries: List[DNSQuery] = []
        try:
            if not self._PCAP_DOMAINS_PATH.exists():
                return queries
            cutoff = time.time() - self._log_window
            with open(self._PCAP_DOMAINS_PATH) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split("|", 2)
                    if len(parts) < 3:
                        continue
                    try:
                        ts = float(parts[0])
                    except ValueError:
                        continue
                    if ts < cutoff:
                        continue
                    record_type = parts[1]
                    domain = parts[2]
                    if domain and "." in domain and not domain.endswith(".local"):
                        queries.append(
                            DNSQuery(
                                timestamp=ts,
                                domain=domain,
                                record_type=record_type,
                                response_code="PCAP",
                            )
                        )
        except Exception:
            pass
        return queries

    def _collect_from_unified_log(self) -> List[DNSQuery]:
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

        logger.debug("Collected %d DNS queries from Unified Log", len(queries))
        return queries

    # Regex to extract domain from tcpdump DNS output
    # Matches lines like: "12:34:56.789 IP 192.168.1.1.52311 > 8.8.8.8.53: 12345+ A? example.com. (30)"
    _TCPDUMP_DNS_PATTERN = re.compile(
        r"(\d{2}:\d{2}:\d{2}\.\d+)\s+"  # timestamp
        r"IP[46]?\s+\S+\s+>\s+\S+:\s+"  # src > dst:
        r"\d+\+?\s+"  # query ID
        r"(A{1,4}\??|AAAA\??|PTR\??|MX\??|TXT\??|CNAME\??|SRV\??|NS\??)\s+"  # record type
        r"(\S+?)\.\s"  # domain (ends with dot + space)
    )

    def _collect_from_pcap(self) -> List[DNSQuery]:
        """Capture plaintext DNS queries via tcpdump on port 53.

        The agent runs as root, so BPF access is available. Captures
        outbound DNS queries for a short window and extracts the actual
        domain names from the wire — bypasses macOS 15+ Unified Logging
        privacy hashing entirely.

        Captures for 3 seconds max or 200 packets, whichever comes first.
        """
        queries: List[DNSQuery] = []
        output = ""
        try:
            # Use Popen so we can capture output even on timeout.
            # DNS collector runs every 10s — tcpdump must finish well within
            # that window. 3s capture + 50 packet cap keeps it fast.
            proc = subprocess.Popen(
                [
                    "tcpdump",
                    "-i", "any",
                    "-nn",           # no name resolution
                    "-l",            # line-buffered
                    "-c", "50",      # max packets (enough for one burst)
                    "udp port 53 and not src port 53",  # outbound queries only
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            try:
                output, _ = proc.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                output, _ = proc.communicate()

        except FileNotFoundError:
            logger.warning("tcpdump not found — DNS plaintext capture unavailable")
            return queries
        except Exception as e:
            logger.debug("DNS pcap capture failed: %s", e)
            return queries

        seen = set()
        for line in output.split("\n"):
            match = self._TCPDUMP_DNS_PATTERN.search(line)
            if not match:
                continue
            record_type = match.group(2).rstrip("?").upper()
            domain = match.group(3).rstrip(".")

            if not domain or domain.endswith(".local"):
                continue
            if domain in seen:
                continue
            seen.add(domain)

            queries.append(
                DNSQuery(
                    timestamp=time.time(),
                    domain=domain,
                    record_type=record_type,
                    response_code="PCAP",
                )
            )

        logger.debug("DNS pcap: %d unique queries captured", len(queries))
        return queries

    def _parse_log_line(self, line: str) -> Optional[DNSQuery]:
        """Parse a single mDNSResponder log line into DNSQuery.

        Handles both macOS 15+ (privacy-hashed domains) and legacy formats.
        On macOS 15+, domains are <mask.hash:'xxx'> but we still get:
        - Client PID and process name (critical for attribution)
        - Record type (A, AAAA)
        - Query suppression status
        """
        if not line or line.startswith("---") or line.startswith("Filtering"):
            return None

        return (
            self._try_parse_getaddrinfo(line)
            or self._try_parse_suppressed(line)
            or self._try_parse_legacy_query(line)
            or self._try_parse_legacy_response(line)
        )

    def _try_parse_getaddrinfo(self, line: str) -> Optional[DNSQuery]:
        """Parse macOS 15+ getaddrinfo start line."""
        match = self._GETADDR_PATTERN.search(line)
        if not match:
            return None
        domain_hash = match.group(1) or ""  # privacy hash
        domain_plain = match.group(2) or ""  # plain domain (rare)
        client_pid = int(match.group(3))
        client_process = match.group(4)

        domain = domain_plain if domain_plain else f"[hash:{domain_hash[:12]}]"

        return DNSQuery(
            timestamp=time.time(),
            domain=domain,
            record_type="A",
            source_process=client_process,
            source_pid=client_pid,
            response_code="QUERY",
        )

    def _try_parse_suppressed(self, line: str) -> Optional[DNSQuery]:
        """Parse query suppression line (e.g., AAAA unusable)."""
        match = self._SUPPRESSED_PATTERN.search(line)
        if not match:
            return None
        domain_hash = match.group(1) or ""
        domain_plain = match.group(2) or ""
        record_type = match.group(3).upper()

        domain = domain_plain if domain_plain else f"[hash:{domain_hash[:12]}]"

        return DNSQuery(
            timestamp=time.time(),
            domain=domain,
            record_type=record_type,
            response_code="SUPPRESSED",
        )

    def _try_parse_legacy_query(self, line: str) -> Optional[DNSQuery]:
        """Parse legacy (pre-macOS 15) query line with visible domain."""
        match = self._QUERY_PATTERN.search(line)
        if not match:
            return None
        ts = _parse_log_timestamp(match.group(1)) or time.time()
        domain = match.group(2).rstrip(".")
        record_type = match.group(3).upper()
        is_reverse = domain.endswith(".in-addr.arpa") or domain.endswith(".ip6.arpa")

        return DNSQuery(
            timestamp=ts,
            domain=domain,
            record_type=record_type,
            is_reverse=is_reverse,
        )

    def _try_parse_legacy_response(self, line: str) -> Optional[DNSQuery]:
        """Parse legacy response line with visible domain and IP."""
        match = self._RESPONSE_PATTERN.search(line)
        if not match:
            return None
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


def _parse_log_timestamp(ts_str: str) -> Optional[float]:
    """Convert a Unified Logging timestamp string to epoch seconds.

    Expected format: '2026-03-26 14:05:32.123456'
    Returns ``None`` when parsing fails so callers can flag the
    event rather than silently fabricating a timestamp.
    """
    try:
        # Parse the timestamp assuming local time (macOS log show uses local tz)
        dt = datetime.strptime(ts_str.strip(), "%Y-%m-%d %H:%M:%S.%f")
        # Attach local timezone then convert to UTC epoch
        dt = dt.replace(tzinfo=datetime.now(timezone.utc).astimezone().tzinfo)
        return dt.timestamp()
    except (ValueError, OSError):
        logger.warning("dns: unparseable timestamp %r", ts_str)
        return None


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
