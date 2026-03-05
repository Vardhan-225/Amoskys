#!/usr/bin/env python3
"""AMOSKYS Internet Activity Agent - Micro-Probe Architecture.

This is the modernized Internet Activity agent using the "swarm of eyes" pattern.
8 micro-probes each watch one specific internet activity threat vector.

Probes:
    1. CloudExfilProbe - Data exfiltration to cloud storage services
    2. TORVPNUsageProbe - TOR, VPN, and anonymization tool detection
    3. CryptoMiningProbe - Cryptocurrency mining activity detection
    4. SuspiciousDownloadProbe - Dangerous file downloads from untrusted sources
    5. ShadowITSaaSProbe - Unauthorized SaaS and personal service usage
    6. UnusualGeoConnectionProbe - Connections to unusual geographic locations
    7. LongLivedConnectionProbe - Suspiciously persistent outbound connections
    8. DNSOverHTTPSProbe - DNS-over-HTTPS bypass detection

MITRE ATT&CK Coverage:
    - T1567: Exfiltration Over Web Service
    - T1090.003: Multi-hop Proxy (TOR)
    - T1496: Resource Hijacking (Mining)
    - T1105: Ingress Tool Transfer
    - T1567.002: Exfiltration to Cloud Storage
    - T1071: Application Layer Protocol
    - T1572: Protocol Tunneling
    - T1071.004: Application Layer Protocol: DNS

Usage:
    >>> agent = InternetActivityAgent()
    >>> agent.run_forever()
"""

from __future__ import annotations

import logging
import os
import platform
import re
import shutil
import socket
import sqlite3
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence
from urllib.parse import urlparse

import grpc

from amoskys.agents.common.base import HardenedAgentBase, ValidationResult
from amoskys.agents.common.probes import MicroProbeAgentMixin, TelemetryEvent
from amoskys.agents.common.queue_adapter import LocalQueueAdapter
from amoskys.agents.internet_activity.agent_types import (
    BrowsingEntry,
    OutboundConnection,
)
from amoskys.agents.internet_activity.probes import create_internet_activity_probes
from amoskys.config import get_config
from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2
from amoskys.proto import universal_telemetry_pb2_grpc as universal_pbrpc

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("InternetActivityAgent")

config = get_config()
EVENTBUS_ADDRESS = config.agent.bus_address
CERT_DIR = config.agent.cert_dir
QUEUE_PATH = getattr(
    config.agent, "internet_activity_queue_path", "data/queue/internet_activity.db"
)


# =============================================================================
# EventBus Publisher
# =============================================================================


class EventBusPublisher:
    """Wrapper for EventBus gRPC client."""

    def __init__(self, address: str, cert_dir: str):
        self.address = address
        self.cert_dir = cert_dir
        self._channel = None
        self._stub = None

    def _ensure_channel(self):
        """Create gRPC channel if needed."""
        if self._channel is None:
            try:
                with open(f"{self.cert_dir}/ca.crt", "rb") as f:
                    ca_cert = f.read()
                with open(f"{self.cert_dir}/agent.crt", "rb") as f:
                    client_cert = f.read()
                with open(f"{self.cert_dir}/agent.key", "rb") as f:
                    client_key = f.read()

                credentials = grpc.ssl_channel_credentials(
                    root_certificates=ca_cert,
                    private_key=client_key,
                    certificate_chain=client_cert,
                )
                self._channel = grpc.secure_channel(self.address, credentials)
                self._stub = universal_pbrpc.UniversalEventBusStub(self._channel)
                logger.info("Created secure gRPC channel with mTLS")
            except FileNotFoundError as e:
                raise RuntimeError(f"Certificate not found: {e}")
            except Exception as e:
                raise RuntimeError(f"Failed to create gRPC channel: {e}")

    def publish(self, events: list) -> None:
        """Publish events to EventBus."""
        self._ensure_channel()

        for event in events:
            # Already-wrapped envelopes (e.g. from drain path) go directly
            if isinstance(event, telemetry_pb2.UniversalEnvelope):
                envelope = event
            else:
                timestamp_ns = int(time.time() * 1e9)
                idempotency_key = f"{event.device_id}_{timestamp_ns}"
                envelope = telemetry_pb2.UniversalEnvelope(
                    version="v1",
                    ts_ns=timestamp_ns,
                    idempotency_key=idempotency_key,
                    device_telemetry=event,
                    priority="NORMAL",
                    requires_acknowledgment=True,
                    schema_version=1,
                )

            ack = self._stub.PublishTelemetry(envelope, timeout=5.0)

            if ack.status != telemetry_pb2.UniversalAck.OK:
                raise Exception(f"EventBus returned status: {ack.status}")

    def close(self):
        """Close gRPC channel."""
        if self._channel:
            self._channel.close()
            self._channel = None
            self._stub = None


# =============================================================================
# Platform-Specific Internet Activity Collectors
# =============================================================================


class InternetCollector:
    """Base class for platform-specific internet activity collection."""

    def collect_connections(self) -> List[OutboundConnection]:
        """Collect outbound connections from system.

        Returns:
            List of OutboundConnection objects
        """
        raise NotImplementedError

    def collect_browsing(self) -> List[BrowsingEntry]:
        """Collect browser history entries.

        Returns:
            List of BrowsingEntry objects
        """
        raise NotImplementedError


class MacOSInternetCollector(InternetCollector):
    """Collects internet activity on macOS.

    Data sources:
        - lsof -i -n -P for active connections
        - nettop -d for bandwidth data
        - Safari History.db
        - Chrome History database
    """

    def __init__(self):
        self._last_collection: Optional[datetime] = None

    def collect_connections(self) -> List[OutboundConnection]:
        """Collect outbound connections via lsof and nettop."""
        connections: List[OutboundConnection] = []

        # Source 1: lsof for active connections with process attribution
        connections.extend(self._collect_from_lsof())

        # Source 2: nettop for bandwidth data
        self._enrich_with_nettop(connections)

        self._last_collection = datetime.now(timezone.utc)
        return connections

    def _collect_from_lsof(self) -> List[OutboundConnection]:
        """Collect connections via lsof -i -n -P."""
        connections: List[OutboundConnection] = []
        try:
            cmd = ["lsof", "-i", "-n", "-P", "-F", "pcnTPt"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)

            if result.returncode == 0 and result.stdout:
                connections = self._parse_lsof_output(result.stdout)

        except subprocess.TimeoutExpired:
            logger.warning("lsof collection timed out")
        except FileNotFoundError:
            logger.debug("lsof not available")
        except Exception as e:
            logger.error("Failed to collect from lsof: %s", e)

        return connections

    def _parse_lsof_output(self, output: str) -> List[OutboundConnection]:
        """Parse lsof -F output into OutboundConnection objects."""
        connections: List[OutboundConnection] = []
        current_pid = 0
        current_process = ""
        current_type = ""

        for line in output.strip().split("\n"):
            if not line:
                continue

            field = line[0]
            value = line[1:]

            if field == "p":
                try:
                    current_pid = int(value)
                except ValueError:
                    current_pid = 0
            elif field == "c":
                current_process = value
            elif field == "P":
                current_type = value  # TCP, UDP
            elif field == "t":
                pass  # type field (IPv4, IPv6)
            elif field == "T":
                # TCP state info: ST=ESTABLISHED, etc.
                pass
            elif field == "n":
                # Network name field: src->dst
                conn = self._parse_lsof_connection(
                    value, current_process, current_pid, current_type
                )
                if conn:
                    connections.append(conn)

        return connections

    def _parse_lsof_connection(
        self, name_field: str, process: str, pid: int, proto: str
    ) -> Optional[OutboundConnection]:
        """Parse lsof network name field into OutboundConnection."""
        try:
            if "->" not in name_field:
                return None

            src, dst = name_field.split("->", 1)

            # Parse dst IP:port
            if "]:" in dst:
                # IPv6: [::1]:443
                ip_end = dst.rindex("]:")
                dst_ip = dst[1:ip_end]
                dst_port = int(dst[ip_end + 2 :])
            elif dst.count(":") == 1:
                # IPv4: 1.2.3.4:443
                parts = dst.rsplit(":", 1)
                dst_ip = parts[0]
                dst_port = int(parts[1])
            else:
                return None

            # Skip loopback connections
            if dst_ip in ("127.0.0.1", "::1", "0.0.0.0"):
                return None

            # Determine if encrypted based on port
            is_encrypted = dst_port in (443, 8443, 993, 995, 465, 587)

            return OutboundConnection(
                timestamp=datetime.now(timezone.utc),
                process_name=process,
                pid=pid,
                dst_ip=dst_ip,
                dst_port=dst_port,
                dst_hostname=self._reverse_dns(dst_ip),
                protocol=proto or "TCP",
                bytes_sent=0,
                bytes_received=0,
                is_encrypted=is_encrypted,
                connection_state="ESTABLISHED",
            )
        except (ValueError, IndexError) as e:
            logger.debug("Failed to parse lsof connection: %s", e)
            return None

    @staticmethod
    def _reverse_dns(ip: str) -> Optional[str]:
        """Attempt reverse DNS lookup for an IP."""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror, OSError):
            return None

    def _enrich_with_nettop(self, connections: List[OutboundConnection]) -> None:
        """Enrich connections with bandwidth data from nettop."""
        try:
            cmd = [
                "nettop",
                "-d",
                "-x",
                "-J",
                "bytes_in,bytes_out",
                "-L",
                "1",
                "-P",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and result.stdout:
                # Build a map of process -> bandwidth
                bandwidth_map: Dict[str, tuple] = {}
                for line in result.stdout.strip().split("\n"):
                    parts = line.strip().split(",")
                    if len(parts) >= 3:
                        proc = parts[0].strip().rsplit(".", 1)[0]
                        try:
                            bytes_in = int(parts[1])
                            bytes_out = int(parts[2])
                            bandwidth_map[proc] = (bytes_in, bytes_out)
                        except ValueError:
                            continue

                # Enrich connections
                for conn in connections:
                    bw = bandwidth_map.get(conn.process_name)
                    if bw:
                        conn.bytes_received = bw[0]
                        conn.bytes_sent = bw[1]

        except subprocess.TimeoutExpired:
            logger.debug("nettop enrichment timed out")
        except FileNotFoundError:
            logger.debug("nettop not available")
        except Exception as e:
            logger.debug("nettop enrichment failed: %s", e)

    def collect_browsing(self) -> List[BrowsingEntry]:
        """Collect browser history from Safari and Chrome."""
        entries: List[BrowsingEntry] = []

        # Safari history
        entries.extend(self._collect_safari_history())

        # Chrome history
        entries.extend(self._collect_chrome_history())

        return entries

    def _collect_safari_history(self) -> List[BrowsingEntry]:
        """Read Safari browsing history from History.db."""
        entries: List[BrowsingEntry] = []
        home = Path.home()
        history_path = home / "Library" / "Safari" / "History.db"

        if not history_path.exists():
            return entries

        try:
            # Copy to temp file (Safari locks the DB)
            tmp_path = Path("/tmp/amoskys_safari_history.db")
            shutil.copy2(history_path, tmp_path)

            conn = sqlite3.connect(f"file:{tmp_path}?mode=ro", uri=True)
            cursor = conn.cursor()

            # Query recent history (last hour)
            cursor.execute(
                """
                SELECT
                    hi.url,
                    hv.visit_time,
                    hv.title
                FROM history_items hi
                JOIN history_visits hv ON hi.id = hv.history_item
                WHERE hv.visit_time > ?
                ORDER BY hv.visit_time DESC
                LIMIT 500
            """,
                (time.time() - 978307200 - 3600,),
            )  # Safari epoch offset

            for row in cursor.fetchall():
                url = row[0]
                # Safari uses Core Data epoch (2001-01-01)
                visit_time = row[1] + 978307200
                title = row[2]

                try:
                    parsed = urlparse(url)
                    domain = parsed.hostname or ""

                    entries.append(
                        BrowsingEntry(
                            timestamp=datetime.fromtimestamp(
                                visit_time, tz=timezone.utc
                            ),
                            url=url,
                            domain=domain,
                            title=title,
                            browser="safari",
                        )
                    )
                except Exception:
                    continue

            conn.close()

            # Clean up temp file
            try:
                tmp_path.unlink()
            except OSError:
                pass

        except sqlite3.OperationalError as e:
            logger.debug("Failed to read Safari history: %s", e)
        except Exception as e:
            logger.error("Failed to collect Safari history: %s", e)

        return entries

    def _collect_chrome_history(self) -> List[BrowsingEntry]:
        """Read Chrome browsing history from History database."""
        entries: List[BrowsingEntry] = []
        home = Path.home()
        history_path = (
            home
            / "Library"
            / "Application Support"
            / "Google"
            / "Chrome"
            / "Default"
            / "History"
        )

        if not history_path.exists():
            return entries

        try:
            # Copy to temp file (Chrome locks the DB)
            tmp_path = Path("/tmp/amoskys_chrome_history.db")
            shutil.copy2(history_path, tmp_path)

            conn = sqlite3.connect(f"file:{tmp_path}?mode=ro", uri=True)
            cursor = conn.cursor()

            # Query recent history (last hour)
            # Chrome uses Windows epoch (1601-01-01) in microseconds
            chrome_epoch_offset = 11644473600
            cutoff = (time.time() + chrome_epoch_offset) * 1_000_000 - 3600 * 1_000_000

            cursor.execute(
                """
                SELECT url, title, visit_count, last_visit_time
                FROM urls
                WHERE last_visit_time > ?
                ORDER BY last_visit_time DESC
                LIMIT 500
            """,
                (int(cutoff),),
            )

            for row in cursor.fetchall():
                url = row[0]
                title = row[1]
                visit_count = row[2]
                last_visit = row[3]

                try:
                    # Convert Chrome timestamp
                    ts_seconds = (last_visit / 1_000_000) - chrome_epoch_offset
                    parsed = urlparse(url)
                    domain = parsed.hostname or ""

                    entries.append(
                        BrowsingEntry(
                            timestamp=datetime.fromtimestamp(
                                ts_seconds, tz=timezone.utc
                            ),
                            url=url,
                            domain=domain,
                            title=title,
                            browser="chrome",
                            visit_count=visit_count,
                        )
                    )
                except Exception:
                    continue

            conn.close()

            # Clean up temp file
            try:
                tmp_path.unlink()
            except OSError:
                pass

        except sqlite3.OperationalError as e:
            logger.debug("Failed to read Chrome history: %s", e)
        except Exception as e:
            logger.error("Failed to collect Chrome history: %s", e)

        return entries


class LinuxInternetCollector(InternetCollector):
    """Collects internet activity on Linux.

    Data sources:
        - ss -tunp for connections
        - Chrome history from ~/.config/google-chrome/Default/History
        - Firefox from ~/.mozilla/firefox/*/places.sqlite
    """

    def __init__(self):
        self._last_collection: Optional[datetime] = None

    def collect_connections(self) -> List[OutboundConnection]:
        """Collect outbound connections via ss."""
        connections: List[OutboundConnection] = []

        connections.extend(self._collect_from_ss())

        self._last_collection = datetime.now(timezone.utc)
        return connections

    def _collect_from_ss(self) -> List[OutboundConnection]:
        """Collect connections via ss -tunp."""
        connections: List[OutboundConnection] = []
        try:
            cmd = ["ss", "-tunp", "--no-header"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            if result.returncode == 0 and result.stdout:
                for line in result.stdout.strip().split("\n"):
                    conn = self._parse_ss_line(line)
                    if conn:
                        connections.append(conn)

        except subprocess.TimeoutExpired:
            logger.warning("ss collection timed out")
        except FileNotFoundError:
            logger.debug("ss not available")
        except Exception as e:
            logger.error("Failed to collect from ss: %s", e)

        return connections

    # Regex to extract process info from ss output
    _SS_USERS_RE = re.compile(r'users:\(\("([^"]+)",pid=(\d+)')

    def _parse_ss_line(self, line: str) -> Optional[OutboundConnection]:
        """Parse ss -tunp output line into OutboundConnection."""
        try:
            parts = line.split()
            if len(parts) < 5:
                return None

            proto = parts[0].upper()  # tcp or udp
            state = parts[1] if proto == "TCP" else "UNCONN"
            # recv_q = parts[2] if proto == "TCP" else parts[1]
            # send_q = parts[3] if proto == "TCP" else parts[2]

            if proto == "TCP":
                local_addr = parts[4]
                peer_addr = parts[5]
                process_info = " ".join(parts[6:]) if len(parts) > 6 else ""
            else:
                local_addr = parts[3]
                peer_addr = parts[4]
                process_info = " ".join(parts[5:]) if len(parts) > 5 else ""

            # Only track established connections
            if proto == "TCP" and state not in ("ESTAB", "ESTABLISHED"):
                return None

            # Parse peer address
            if "]:" in peer_addr:
                # IPv6
                bracket_end = peer_addr.rindex("]:")
                dst_ip = peer_addr[1:bracket_end]
                dst_port = int(peer_addr[bracket_end + 2 :])
            elif peer_addr.count(":") == 1:
                # IPv4
                ip_port = peer_addr.rsplit(":", 1)
                dst_ip = ip_port[0]
                dst_port = int(ip_port[1])
            else:
                return None

            # Skip loopback
            if dst_ip in ("127.0.0.1", "::1", "0.0.0.0", "*"):
                return None

            # Extract process info
            process_name = "unknown"
            pid = 0
            match = self._SS_USERS_RE.search(process_info)
            if match:
                process_name = match.group(1)
                pid = int(match.group(2))

            # Reverse DNS
            hostname = None
            try:
                hostname, _, _ = socket.gethostbyaddr(dst_ip)
            except (socket.herror, socket.gaierror, OSError):
                pass

            is_encrypted = dst_port in (443, 8443, 993, 995, 465, 587)

            return OutboundConnection(
                timestamp=datetime.now(timezone.utc),
                process_name=process_name,
                pid=pid,
                dst_ip=dst_ip,
                dst_port=dst_port,
                dst_hostname=hostname,
                protocol=proto,
                bytes_sent=0,
                bytes_received=0,
                is_encrypted=is_encrypted,
                connection_state=state,
            )
        except (ValueError, IndexError) as e:
            logger.debug("Failed to parse ss line: %s", e)
            return None

    def collect_browsing(self) -> List[BrowsingEntry]:
        """Collect browser history from Chrome and Firefox."""
        entries: List[BrowsingEntry] = []

        # Chrome history
        entries.extend(self._collect_chrome_history())

        # Firefox history
        entries.extend(self._collect_firefox_history())

        return entries

    def _collect_chrome_history(self) -> List[BrowsingEntry]:
        """Read Chrome browsing history on Linux."""
        entries: List[BrowsingEntry] = []
        home = Path.home()
        history_path = home / ".config" / "google-chrome" / "Default" / "History"

        if not history_path.exists():
            return entries

        try:
            tmp_path = Path("/tmp/amoskys_chrome_history_linux.db")
            shutil.copy2(history_path, tmp_path)

            conn = sqlite3.connect(f"file:{tmp_path}?mode=ro", uri=True)
            cursor = conn.cursor()

            chrome_epoch_offset = 11644473600
            cutoff = (time.time() + chrome_epoch_offset) * 1_000_000 - 3600 * 1_000_000

            cursor.execute(
                """
                SELECT url, title, visit_count, last_visit_time
                FROM urls
                WHERE last_visit_time > ?
                ORDER BY last_visit_time DESC
                LIMIT 500
            """,
                (int(cutoff),),
            )

            for row in cursor.fetchall():
                url = row[0]
                title = row[1]
                visit_count = row[2]
                last_visit = row[3]

                try:
                    ts_seconds = (last_visit / 1_000_000) - chrome_epoch_offset
                    parsed = urlparse(url)
                    domain = parsed.hostname or ""

                    entries.append(
                        BrowsingEntry(
                            timestamp=datetime.fromtimestamp(
                                ts_seconds, tz=timezone.utc
                            ),
                            url=url,
                            domain=domain,
                            title=title,
                            browser="chrome",
                            visit_count=visit_count,
                        )
                    )
                except Exception:
                    continue

            conn.close()
            try:
                tmp_path.unlink()
            except OSError:
                pass

        except sqlite3.OperationalError as e:
            logger.debug("Failed to read Chrome history: %s", e)
        except Exception as e:
            logger.error("Failed to collect Chrome history: %s", e)

        return entries

    def _collect_firefox_history(self) -> List[BrowsingEntry]:
        """Read Firefox browsing history on Linux."""
        entries: List[BrowsingEntry] = []
        home = Path.home()
        firefox_dir = home / ".mozilla" / "firefox"

        if not firefox_dir.exists():
            return entries

        # Find profile directories
        try:
            for profile_dir in firefox_dir.iterdir():
                if not profile_dir.is_dir():
                    continue
                places_db = profile_dir / "places.sqlite"
                if places_db.exists():
                    entries.extend(self._read_firefox_places(places_db))
                    break  # Use first profile found
        except Exception as e:
            logger.error("Failed to scan Firefox profiles: %s", e)

        return entries

    def _read_firefox_places(self, places_path: Path) -> List[BrowsingEntry]:
        """Read Firefox places.sqlite database."""
        entries: List[BrowsingEntry] = []
        try:
            tmp_path = Path("/tmp/amoskys_firefox_places.db")
            shutil.copy2(places_path, tmp_path)

            conn = sqlite3.connect(f"file:{tmp_path}?mode=ro", uri=True)
            cursor = conn.cursor()

            # Firefox uses microseconds since epoch
            cutoff = (time.time() - 3600) * 1_000_000

            cursor.execute(
                """
                SELECT
                    p.url,
                    p.title,
                    p.visit_count,
                    h.visit_date
                FROM moz_places p
                JOIN moz_historyvisits h ON p.id = h.place_id
                WHERE h.visit_date > ?
                ORDER BY h.visit_date DESC
                LIMIT 500
            """,
                (int(cutoff),),
            )

            for row in cursor.fetchall():
                url = row[0]
                title = row[1]
                visit_count = row[2]
                visit_date = row[3]

                try:
                    ts_seconds = visit_date / 1_000_000
                    parsed = urlparse(url)
                    domain = parsed.hostname or ""

                    entries.append(
                        BrowsingEntry(
                            timestamp=datetime.fromtimestamp(
                                ts_seconds, tz=timezone.utc
                            ),
                            url=url,
                            domain=domain,
                            title=title,
                            browser="firefox",
                            visit_count=visit_count,
                        )
                    )
                except Exception:
                    continue

            conn.close()
            try:
                tmp_path.unlink()
            except OSError:
                pass

        except sqlite3.OperationalError as e:
            logger.debug("Failed to read Firefox history: %s", e)
        except Exception as e:
            logger.error("Failed to collect Firefox history: %s", e)

        return entries


def get_internet_collector() -> InternetCollector:
    """Get platform-appropriate internet activity collector."""
    system = platform.system()
    if system == "Darwin":
        return MacOSInternetCollector()
    elif system == "Linux":
        return LinuxInternetCollector()
    else:
        logger.warning(
            "Unsupported platform: %s, defaulting to macOS collector", system
        )
        return MacOSInternetCollector()


# =============================================================================
# Internet Activity Agent
# =============================================================================


class InternetActivityAgent(MicroProbeAgentMixin, HardenedAgentBase):
    """Internet Activity Agent with micro-probe architecture.

    This agent hosts 8 micro-probes that each monitor a specific internet
    activity threat vector. The agent handles:
        - Outbound connection collection (platform-specific)
        - Browser history collection
        - Probe lifecycle management
        - Event aggregation and publishing
        - Circuit breaker and retry logic
        - Offline queue management

    Probes are responsible only for detection - no networking or state
    management.
    """

    # Agent color for dashboard UI
    COLOR = "#DA70D6"

    def __init__(self, collection_interval: float = 30.0):
        """Initialize Internet Activity Agent.

        Args:
            collection_interval: Seconds between collection cycles
        """
        device_id = socket.gethostname()

        # Create EventBus publisher
        publisher = EventBusPublisher(EVENTBUS_ADDRESS, CERT_DIR)

        # Create local queue
        Path(QUEUE_PATH).parent.mkdir(parents=True, exist_ok=True)
        queue_adapter = LocalQueueAdapter(
            queue_path=QUEUE_PATH,
            agent_name="internet_activity",
            device_id=device_id,
            max_bytes=50 * 1024 * 1024,
            max_retries=10,
            signing_key_path="certs/agents/internet_activity.ed25519",
        )

        # Initialize base classes
        super().__init__(
            agent_name="internet_activity",
            device_id=device_id,
            collection_interval=collection_interval,
            eventbus_publisher=publisher,
            local_queue=queue_adapter,
        )

        # Platform-specific collector
        self.internet_collector = get_internet_collector()

        # Register all internet activity probes
        self.register_probes(create_internet_activity_probes())

        logger.info(
            "InternetActivityAgent initialized with %d probes", len(self._probes)
        )

    def setup(self) -> bool:
        """Initialize agent resources.

        Verifies:
            - Certificates exist
            - Collectors work
            - Probes initialize successfully

        Returns:
            True if setup succeeded
        """
        try:
            # Verify certificates (warn but don't fail)
            required_certs = ["ca.crt", "agent.crt", "agent.key"]
            for cert in required_certs:
                cert_path = f"{CERT_DIR}/{cert}"
                if not os.path.exists(cert_path):
                    logger.warning(
                        "Certificate not found: %s (EventBus publishing will fail)",
                        cert_path,
                    )

            # Test connection collector
            try:
                test_conns = self.internet_collector.collect_connections()
                logger.info(
                    "Connection collector test: %d connections", len(test_conns)
                )
            except Exception as e:
                logger.warning("Connection collector test failed: %s", e)

            # Test browsing collector
            try:
                test_browsing = self.internet_collector.collect_browsing()
                logger.info("Browsing collector test: %d entries", len(test_browsing))
            except Exception as e:
                logger.warning("Browsing collector test failed: %s", e)

            # Setup probes
            if not self.setup_probes(
                collector_shared_data_keys=[
                    "outbound_connections",
                    "browsing_entries",
                ],
            ):
                logger.error("No probes initialized successfully")
                return False

            logger.info("InternetActivityAgent setup complete")
            return True

        except Exception as e:
            logger.error("Setup failed: %s", e)
            return False

    def collect_data(self) -> Sequence[Any]:
        """Collect internet activity and run all probes.

        Returns:
            List of DeviceTelemetry protobuf messages
        """
        timestamp_ns = int(time.time() * 1e9)

        # Collect connections and browsing data
        connections = self.internet_collector.collect_connections()
        browsing = self.internet_collector.collect_browsing()

        logger.info(
            "Collected %d connections, %d browsing entries",
            len(connections),
            len(browsing),
        )

        # Create context with collected data
        context = self._create_probe_context()
        context.shared_data["outbound_connections"] = connections
        context.shared_data["browsing_entries"] = browsing

        # Run all probes and collect events
        events: List[TelemetryEvent] = []
        for probe in self._probes:
            if not probe.enabled:
                continue

            try:
                probe_events = probe.scan(context)
                events.extend(probe_events)
                probe.last_scan = datetime.now(timezone.utc)
                probe.scan_count += 1
            except Exception as e:
                probe.error_count += 1
                probe.last_error = str(e)
                logger.error("Probe %s failed: %s", probe.name, e)

        logger.info(
            "Probes generated %d events from %d connections + %d browsing entries",
            len(events),
            len(connections),
            len(browsing),
        )

        # Build proto events
        proto_events = []

        # Collection summary metrics
        proto_events.append(
            telemetry_pb2.TelemetryEvent(
                event_id=f"inet_connections_summary_{timestamp_ns}",
                event_type="METRIC",
                severity="INFO",
                event_timestamp_ns=timestamp_ns,
                source_component="internet_activity_collector",
                tags=["internet_activity", "metric"],
                metric_data=telemetry_pb2.MetricData(
                    metric_name="inet_connections_collected",
                    metric_type="GAUGE",
                    numeric_value=float(len(connections)),
                    unit="connections",
                ),
            )
        )

        proto_events.append(
            telemetry_pb2.TelemetryEvent(
                event_id=f"inet_browsing_summary_{timestamp_ns}",
                event_type="METRIC",
                severity="INFO",
                event_timestamp_ns=timestamp_ns,
                source_component="internet_activity_collector",
                tags=["internet_activity", "metric"],
                metric_data=telemetry_pb2.MetricData(
                    metric_name="inet_browsing_entries_collected",
                    metric_type="GAUGE",
                    numeric_value=float(len(browsing)),
                    unit="entries",
                ),
            )
        )

        # Probe event count metric
        if events:
            proto_events.append(
                telemetry_pb2.TelemetryEvent(
                    event_id=f"inet_probe_events_{timestamp_ns}",
                    event_type="METRIC",
                    severity="INFO",
                    event_timestamp_ns=timestamp_ns,
                    source_component="internet_activity_agent",
                    tags=["internet_activity", "metric"],
                    metric_data=telemetry_pb2.MetricData(
                        metric_name="inet_probe_events",
                        metric_type="GAUGE",
                        numeric_value=float(len(events)),
                        unit="events",
                    ),
                )
            )

        # Convert probe events to SecurityEvent-based telemetry
        severity_map = {
            "DEBUG": "DEBUG",
            "INFO": "INFO",
            "LOW": "LOW",
            "MEDIUM": "MEDIUM",
            "HIGH": "HIGH",
            "CRITICAL": "CRITICAL",
        }

        _severity_risk = {
            "DEBUG": 0.1,
            "INFO": 0.2,
            "LOW": 0.3,
            "MEDIUM": 0.5,
            "HIGH": 0.7,
            "CRITICAL": 0.9,
        }

        for event in events:
            base_risk = _severity_risk.get(event.severity.value, 0.5)
            risk_score = base_risk * event.confidence

            security_event = telemetry_pb2.SecurityEvent(
                event_category=event.event_type,
                event_action="INTERNET_ACTIVITY",
                risk_score=round(min(risk_score, 1.0), 3),
                analyst_notes=f"Probe: {event.probe_name}, "
                f"Severity: {event.severity.value}",
            )
            security_event.mitre_techniques.extend(event.mitre_techniques)

            # Set target resource
            dst = event.data.get("dst_hostname") or event.data.get("dst_ip")
            if dst:
                security_event.target_resource = str(dst)
            elif event.data.get("url"):
                security_event.target_resource = event.data["url"]

            tel_event = telemetry_pb2.TelemetryEvent(
                event_id=f"{event.event_type}_{timestamp_ns}",
                event_type="SECURITY",
                severity=severity_map.get(event.severity.value, "INFO"),
                event_timestamp_ns=timestamp_ns,
                source_component=event.probe_name or "internet_activity_agent",
                tags=["internet_activity", "threat"],
                security_event=security_event,
                confidence_score=event.confidence,
            )

            # Populate attributes map with evidence
            if event.data:
                for key, value in event.data.items():
                    if value is not None:
                        tel_event.attributes[key] = str(value)

            proto_events.append(tel_event)

        # Create DeviceTelemetry
        telemetry = telemetry_pb2.DeviceTelemetry(
            device_id=self.device_id,
            device_type="HOST",
            protocol="INTERNET_ACTIVITY",
            events=proto_events,
            timestamp_ns=timestamp_ns,
            collection_agent="internet_activity",
            agent_version="2.0.0",
        )

        return [telemetry]

    def validate_event(self, event: Any) -> ValidationResult:
        """Validate telemetry before publishing.

        Args:
            event: DeviceTelemetry protobuf message

        Returns:
            ValidationResult
        """
        errors = []
        if not hasattr(event, "device_id") or not event.device_id:
            errors.append("Missing device_id")
        if not hasattr(event, "timestamp_ns") or event.timestamp_ns <= 0:
            errors.append("Missing or invalid timestamp_ns")
        if not event.events:
            errors.append("events list is empty")
        return ValidationResult(is_valid=len(errors) == 0, errors=errors)

    def shutdown(self) -> None:
        """Graceful shutdown."""
        logger.info("InternetActivityAgent shutting down...")

        # Close EventBus connection
        if self.eventbus_publisher:
            self.eventbus_publisher.close()

        logger.info("InternetActivityAgent shutdown complete")

    def get_health(self) -> Dict[str, Any]:
        """Get agent health status.

        Returns:
            Dict with health metrics
        """
        return {
            "agent_name": self.agent_name,
            "device_id": self.device_id,
            "is_running": self.is_running,
            "collection_count": self.collection_count,
            "error_count": self.error_count,
            "last_error": self.last_error,
            "probes": self.get_probe_health(),
            "circuit_breaker_state": self.circuit_breaker.state,
            "color": self.COLOR,
        }


# =============================================================================
# CLI Entry Point
# =============================================================================


def main():
    """Run Internet Activity Agent."""
    import argparse

    parser = argparse.ArgumentParser(description="AMOSKYS Internet Activity Agent")
    parser.add_argument(
        "--interval",
        type=float,
        default=30.0,
        help="Collection interval in seconds",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default=None,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level (overrides --debug)",
    )

    args = parser.parse_args()

    if args.log_level:
        logging.getLogger().setLevel(getattr(logging, args.log_level))
    elif args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    logger.info("=" * 70)
    logger.info("AMOSKYS Internet Activity Agent (Micro-Probe Architecture)")
    logger.info("=" * 70)

    agent = InternetActivityAgent(collection_interval=args.interval)

    try:
        agent.run_forever()
    except KeyboardInterrupt:
        logger.info("Received interrupt, shutting down...")
        agent.shutdown()


if __name__ == "__main__":
    main()
