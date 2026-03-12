"""Protocol event collectors for ProtocolCollectors agent.

Provides collectors for various protocol event sources:
    - NetworkLogCollector: Parse network/protocol logs
    - StubProtocolCollector: For testing without real sources
"""

import logging
import os
import re
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, Iterator, List, Optional

# Use relative import to avoid triggering amoskys.agents.__init__
from .agent_types import ProtocolEvent, ProtocolType

logger = logging.getLogger(__name__)


class BaseProtocolCollector(ABC):
    """Abstract base class for protocol event collectors."""

    @abstractmethod
    def collect(self) -> List[ProtocolEvent]:
        """Collect and return protocol events.

        Returns:
            List of ProtocolEvent objects
        """
        pass


class NetworkLogCollector(BaseProtocolCollector):
    """Collector that parses network/protocol logs.

    Supports multiple log formats:
        - Syslog with network events
        - Connection logs
        - Firewall/IDS logs
    """

    def __init__(
        self,
        log_path: str = "/var/log/syslog",
        tail_lines: int = 1000,
    ):
        """Initialize the collector.

        Args:
            log_path: Path to log file
            tail_lines: Number of lines to read from end of file
        """
        self.log_path = log_path
        self.tail_lines = tail_lines
        self._last_position = 0
        self._last_inode = 0

    def collect(self) -> List[ProtocolEvent]:
        """Collect protocol events from log file.

        Returns:
            List of parsed ProtocolEvent objects
        """
        events = []

        if not os.path.exists(self.log_path):
            logger.warning(f"Log file not found: {self.log_path}")
            return events

        try:
            # Check for log rotation
            current_inode = os.stat(self.log_path).st_ino
            if current_inode != self._last_inode:
                self._last_position = 0
                self._last_inode = current_inode

            with open(self.log_path, "r", errors="ignore") as f:
                # Seek to last position
                f.seek(self._last_position)

                for line in f:
                    event = self._parse_log_line(line.strip())
                    if event:
                        events.append(event)

                self._last_position = f.tell()

        except PermissionError:
            logger.warning(f"Permission denied reading: {self.log_path}")
        except Exception as e:
            logger.error(f"Error reading log file: {e}")

        return events

    def _parse_log_line(self, line: str) -> Optional[ProtocolEvent]:
        """Parse a log line into a ProtocolEvent.

        Args:
            line: Raw log line

        Returns:
            ProtocolEvent if parseable, None otherwise
        """
        if not line:
            return None

        # Try to detect protocol from log content
        protocol = self._detect_protocol(line)
        if protocol == ProtocolType.UNKNOWN:
            return None

        # Extract IP addresses if present
        ip_pattern = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
        ips = re.findall(ip_pattern, line)

        src_ip = ips[0] if len(ips) > 0 else "0.0.0.0"
        dst_ip = ips[1] if len(ips) > 1 else "0.0.0.0"

        # Extract ports if present
        port_pattern = r":(\d{1,5})"
        ports = re.findall(port_pattern, line)

        src_port = int(ports[0]) if len(ports) > 0 else 0
        dst_port = int(ports[1]) if len(ports) > 1 else 0

        return ProtocolEvent(
            timestamp=datetime.now(),
            protocol=protocol,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            raw_data=line[:500],  # Truncate for storage
            metadata=self._extract_metadata(line, protocol),
        )

    def _detect_protocol(self, line: str) -> ProtocolType:
        """Detect protocol type from log line content."""
        line_lower = line.lower()

        if "sshd" in line_lower or "ssh" in line_lower:
            return ProtocolType.SSH
        elif "http" in line_lower:
            if "https" in line_lower:
                return ProtocolType.HTTPS
            return ProtocolType.HTTP
        elif "dns" in line_lower or ":53" in line:
            return ProtocolType.DNS
        elif "smtp" in line_lower or ":25" in line or ":587" in line:
            return ProtocolType.SMTP
        elif "ftp" in line_lower or ":21" in line:
            return ProtocolType.FTP
        elif "rdp" in line_lower or ":3389" in line:
            return ProtocolType.RDP
        elif (
            "mysql" in line_lower
            or "postgres" in line_lower
            or ":3306" in line
            or ":5432" in line
        ):
            return ProtocolType.SQL
        elif "irc" in line_lower or ":6667" in line:
            return ProtocolType.IRC
        elif "tls" in line_lower or "ssl" in line_lower:
            return ProtocolType.TLS

        return ProtocolType.UNKNOWN

    def _extract_metadata(self, line: str, protocol: ProtocolType) -> Dict[str, Any]:
        """Extract protocol-specific metadata from log line."""
        metadata: Dict[str, Any] = {}

        if protocol == ProtocolType.SSH:
            if "failed" in line.lower():
                metadata["auth_result"] = "failed"
            elif "accepted" in line.lower():
                metadata["auth_result"] = "accepted"
            if "invalid user" in line.lower():
                metadata["invalid_user"] = True

        elif protocol == ProtocolType.HTTP or protocol == ProtocolType.HTTPS:
            # Extract HTTP method
            for method in ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]:
                if method in line:
                    metadata["method"] = method
                    break
            # Extract status code
            status_match = re.search(r"\s(\d{3})\s", line)
            if status_match:
                metadata["status_code"] = int(status_match.group(1))

        elif protocol == ProtocolType.DNS:
            # Check for query type
            for qtype in ["A", "AAAA", "MX", "TXT", "CNAME", "NS", "PTR"]:
                if f" {qtype} " in line or f"type={qtype}" in line.lower():
                    metadata["query_type"] = qtype
                    break

        return metadata


class StubProtocolCollector(BaseProtocolCollector):
    """Stub collector for testing without real protocol sources.

    Generates simulated protocol events for development and testing.
    """

    def __init__(self, events_per_cycle: int = 5):
        """Initialize stub collector.

        Args:
            events_per_cycle: Number of events to generate per collect() call
        """
        self.events_per_cycle = events_per_cycle
        self._cycle_count = 0
        self._scenarios = [
            self._generate_ssh_event,
            self._generate_http_event,
            self._generate_dns_event,
            self._generate_smtp_event,
            self._generate_ftp_event,
        ]

    def collect(self) -> List[ProtocolEvent]:
        """Generate simulated protocol events.

        Returns:
            List of simulated ProtocolEvent objects
        """
        events = []
        self._cycle_count += 1

        for i in range(self.events_per_cycle):
            scenario = self._scenarios[i % len(self._scenarios)]
            events.append(scenario())

        return events

    def _generate_ssh_event(self) -> ProtocolEvent:
        """Generate simulated SSH event."""
        return ProtocolEvent(
            timestamp=datetime.now(),
            protocol=ProtocolType.SSH,
            src_ip=f"192.168.1.{self._cycle_count % 255}",
            dst_ip="10.0.0.1",
            src_port=50000 + self._cycle_count,
            dst_port=22,
            metadata={
                "auth_result": "failed" if self._cycle_count % 3 == 0 else "accepted",
                "username": "admin" if self._cycle_count % 2 == 0 else "root",
            },
        )

    def _generate_http_event(self) -> ProtocolEvent:
        """Generate simulated HTTP event."""
        return ProtocolEvent(
            timestamp=datetime.now(),
            protocol=ProtocolType.HTTP,
            src_ip=f"10.0.0.{self._cycle_count % 255}",
            dst_ip="192.168.1.100",
            src_port=60000 + self._cycle_count,
            dst_port=80,
            metadata={
                "method": "POST" if self._cycle_count % 2 == 0 else "GET",
                "status_code": 200,
                "user_agent": "Mozilla/5.0",
            },
        )

    def _generate_dns_event(self) -> ProtocolEvent:
        """Generate simulated DNS event."""
        return ProtocolEvent(
            timestamp=datetime.now(),
            protocol=ProtocolType.DNS,
            src_ip="192.168.1.50",
            dst_ip="8.8.8.8",
            src_port=53000 + self._cycle_count,
            dst_port=53,
            payload_size=50 + (self._cycle_count * 10) % 500,
            metadata={
                "query_type": "TXT" if self._cycle_count % 5 == 0 else "A",
                "domain": f"test{self._cycle_count}.example.com",
            },
        )

    def _generate_smtp_event(self) -> ProtocolEvent:
        """Generate simulated SMTP event."""
        return ProtocolEvent(
            timestamp=datetime.now(),
            protocol=ProtocolType.SMTP,
            src_ip=f"172.16.0.{self._cycle_count % 255}",
            dst_ip="10.0.0.25",
            src_port=40000 + self._cycle_count,
            dst_port=25,
            metadata={
                "from": "sender@example.com",
                "to": f"recipient{self._cycle_count}@company.com",
            },
        )

    def _generate_ftp_event(self) -> ProtocolEvent:
        """Generate simulated FTP event."""
        return ProtocolEvent(
            timestamp=datetime.now(),
            protocol=ProtocolType.FTP,
            src_ip=f"192.168.2.{self._cycle_count % 255}",
            dst_ip="10.0.0.21",
            src_port=55000 + self._cycle_count,
            dst_port=21,
            metadata={
                "command": "RETR" if self._cycle_count % 2 == 0 else "STOR",
                "filename": f"file{self._cycle_count}.dat",
            },
        )


def create_protocol_collector(
    use_stub: bool = False,
    log_path: str = "/var/log/syslog",
    **kwargs,
) -> BaseProtocolCollector:
    """Factory function to create appropriate protocol collector.

    Args:
        use_stub: Use stub collector for testing
        log_path: Path to network log file
        **kwargs: Additional collector-specific arguments

    Returns:
        Configured protocol collector instance
    """
    if use_stub:
        return StubProtocolCollector(**kwargs)

    return NetworkLogCollector(log_path=log_path, **kwargs)
