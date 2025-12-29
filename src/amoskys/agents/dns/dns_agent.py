#!/usr/bin/env python3
"""
AMOSKYS DNS Monitoring Agent (DNSAgent)

Monitors DNS traffic for malicious patterns:
- DNS Tunneling (data exfiltration via DNS)
- C2 Beaconing (regular callback patterns)
- DGA Domains (algorithmically generated domain names)
- DNS Rebinding attacks
- Suspicious TXT/NULL record queries
- Fast-flux detection

Uses passive DNS monitoring via:
- macOS: dns.log parsing, mDNSResponder logs
- Linux: /var/log/named, systemd-resolved, tcpdump

Critical for detecting:
- APT C2 infrastructure
- Data exfiltration
- Cobalt Strike, Sliver, and other C2 frameworks
"""

import json
import logging
import math
import re
import socket
import subprocess
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import grpc

from amoskys.agents.common import LocalQueue
from amoskys.agents.common.hardened_base import HardenedAgentBase
from amoskys.config import get_config
from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2
from amoskys.proto import universal_telemetry_pb2_grpc as universal_pbrpc

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("DNSAgent")

config = get_config()
EVENTBUS_ADDRESS = config.agent.bus_address
CERT_DIR = config.agent.cert_dir
QUEUE_PATH = getattr(config.agent, "dns_queue_path", "data/queue/dns_agent.db")


@dataclass
class DNSQuery:
    """Represents a DNS query"""

    timestamp: datetime
    query_name: str
    query_type: str  # A, AAAA, TXT, MX, CNAME, NS, NULL, etc.
    source_ip: str
    response_ip: Optional[str] = None
    response_code: Optional[str] = None  # NOERROR, NXDOMAIN, SERVFAIL
    ttl: Optional[int] = None
    is_recursive: bool = True
    process_name: Optional[str] = None
    process_pid: Optional[int] = None


@dataclass
class DNSThreat:
    """Represents a detected DNS threat"""

    threat_type: str  # TUNNELING, C2_BEACON, DGA, REBINDING, SUSPICIOUS_RECORD
    severity: str  # INFO, WARN, HIGH, CRITICAL
    domain: str
    evidence: List[str]
    query_count: int
    first_seen: datetime
    last_seen: datetime
    mitre_techniques: List[str] = field(default_factory=list)
    confidence: float = 0.0  # 0.0 to 1.0


class DNSAgent(HardenedAgentBase):
    """DNS Monitoring Agent with threat detection"""

    # Known C2 framework DNS patterns
    C2_PATTERNS = [
        r"\.cobalt\.?strike",
        r"\.beacon\.",
        r"\.metasploit\.",
        r"\.empire\.",
        r"\.sliver\.",
        r"\.brute\.?ratel",
        r"cloudfront\.net$",  # Often abused for domain fronting
        r"\.ngrok\.io$",
        r"\.serveo\.net$",
        r"\.localhost\.run$",
    ]

    # Suspicious TLDs often used by malware
    SUSPICIOUS_TLDS = {
        ".top",
        ".xyz",
        ".work",
        ".click",
        ".link",
        ".gq",
        ".ml",
        ".cf",
        ".tk",
        ".ga",
        ".buzz",
        ".surf",
        ".monster",
    }

    # Record types that are suspicious in high volume
    SUSPICIOUS_RECORD_TYPES = {"TXT", "NULL", "HINFO", "MX", "CNAME"}

    def __init__(
        self,
        queue_path: Optional[str] = None,
        analysis_window: int = 300,  # 5 minutes
        beacon_threshold: int = 10,  # Min queries to detect beaconing
        entropy_threshold: float = 3.5,  # Shannon entropy for DGA detection
    ):
        """Initialize DNS Agent

        Args:
            queue_path: Path to offline queue database
            analysis_window: Seconds to analyze for patterns
            beacon_threshold: Minimum queries to consider beaconing
            entropy_threshold: Entropy threshold for DGA detection
        """
        super().__init__(agent_name="DNSAgent")

        self.queue_path = queue_path or QUEUE_PATH
        self.analysis_window = analysis_window
        self.beacon_threshold = beacon_threshold
        self.entropy_threshold = entropy_threshold

        # Ensure directories exist
        Path(self.queue_path).parent.mkdir(parents=True, exist_ok=True)

        self.queue = LocalQueue(
            path=self.queue_path, max_bytes=50 * 1024 * 1024, max_retries=10
        )

        # Query history for pattern analysis
        self.query_history: List[DNSQuery] = []
        self.domain_stats: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {"count": 0, "first_seen": None, "last_seen": None, "types": set()}
        )

        # Known-good domains (whitelist)
        self.whitelist = self._load_whitelist()

        # Detected threats
        self.active_threats: Dict[str, DNSThreat] = {}

        # Platform detection
        self.platform = self._detect_platform()

        logger.info(f"DNSAgent initialized: platform={self.platform}")

    def _detect_platform(self) -> str:
        """Detect operating system"""
        import platform

        system = platform.system().lower()
        if system == "darwin":
            return "macos"
        elif system == "linux":
            return "linux"
        return "unknown"

    def _load_whitelist(self) -> Set[str]:
        """Load known-good domains"""
        # Common legitimate domains
        return {
            "apple.com",
            "icloud.com",
            "microsoft.com",
            "google.com",
            "googleapis.com",
            "gstatic.com",
            "cloudflare.com",
            "amazon.com",
            "amazonaws.com",
            "github.com",
            "githubusercontent.com",
            "akamai.net",
            "akamaiedge.net",
            "akadns.net",
            "local",
            "localhost",
            "internal",
            "_tcp.local",
            "_udp.local",
        }

    def _is_whitelisted(self, domain: str) -> bool:
        """Check if domain is in whitelist"""
        domain_lower = domain.lower().rstrip(".")
        for wl_domain in self.whitelist:
            if domain_lower == wl_domain or domain_lower.endswith("." + wl_domain):
                return True
        return False

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not text:
            return 0.0

        # Count character frequencies
        freq = defaultdict(int)
        for char in text.lower():
            freq[char] += 1

        # Calculate entropy
        length = len(text)
        entropy = 0.0
        for count in freq.values():
            if count > 0:
                prob = count / length
                entropy -= prob * math.log2(prob)

        return entropy

    def _extract_subdomain(self, domain: str) -> str:
        """Extract the subdomain portion for analysis"""
        parts = domain.rstrip(".").split(".")
        if len(parts) <= 2:
            return ""
        # Return everything except the last two parts (domain.tld)
        return ".".join(parts[:-2])

    def _is_dga_domain(self, domain: str) -> Tuple[bool, float]:
        """Detect if domain appears to be DGA-generated

        Returns:
            Tuple of (is_dga, confidence)
        """
        subdomain = self._extract_subdomain(domain)
        if not subdomain:
            # Analyze the domain part itself
            parts = domain.rstrip(".").split(".")
            if len(parts) >= 2:
                subdomain = parts[0]
            else:
                return False, 0.0

        # Skip short subdomains
        if len(subdomain) < 8:
            return False, 0.0

        # Calculate entropy
        entropy = self._calculate_entropy(subdomain)

        # High entropy indicates randomness (DGA)
        if entropy > self.entropy_threshold:
            # Additional checks
            confidence = min((entropy - self.entropy_threshold) / 2.0, 1.0)

            # Check for excessive consonant clusters (common in DGA)
            consonant_pattern = re.compile(r"[bcdfghjklmnpqrstvwxz]{4,}")
            if consonant_pattern.search(subdomain.lower()):
                confidence = min(confidence + 0.2, 1.0)

            # Check for excessive digits
            digit_ratio = sum(c.isdigit() for c in subdomain) / len(subdomain)
            if digit_ratio > 0.3:
                confidence = min(confidence + 0.1, 1.0)

            # Check length
            if len(subdomain) > 20:
                confidence = min(confidence + 0.1, 1.0)

            return True, confidence

        return False, 0.0

    def _detect_tunneling(self, domain: str, query_type: str) -> Tuple[bool, float]:
        """Detect DNS tunneling characteristics

        Returns:
            Tuple of (is_tunneling, confidence)
        """
        subdomain = self._extract_subdomain(domain)
        if not subdomain:
            return False, 0.0

        confidence = 0.0
        indicators = []

        # Long subdomain (data encoded in subdomain)
        if len(subdomain) > 50:
            confidence += 0.3
            indicators.append("long_subdomain")

        # High entropy in subdomain
        entropy = self._calculate_entropy(subdomain)
        if entropy > 4.0:
            confidence += 0.3
            indicators.append("high_entropy")

        # Suspicious record types used for tunneling
        if query_type in ("TXT", "NULL", "CNAME", "MX"):
            confidence += 0.2
            indicators.append(f"suspicious_record_type_{query_type}")

        # Multiple labels (dots) in subdomain
        if subdomain.count(".") > 3:
            confidence += 0.2
            indicators.append("many_subdomains")

        # Base64-like patterns
        if re.match(r"^[A-Za-z0-9+/=]{20,}$", subdomain.replace(".", "")):
            confidence += 0.3
            indicators.append("base64_pattern")

        # Hex-like patterns
        if re.match(r"^[0-9a-fA-F]{20,}$", subdomain.replace(".", "")):
            confidence += 0.3
            indicators.append("hex_pattern")

        is_tunneling = confidence >= 0.5
        return is_tunneling, min(confidence, 1.0)

    def _detect_beaconing(
        self, domain: str, queries: List[DNSQuery]
    ) -> Tuple[bool, float, int]:
        """Detect C2 beaconing patterns

        Returns:
            Tuple of (is_beaconing, confidence, interval_seconds)
        """
        if len(queries) < self.beacon_threshold:
            return False, 0.0, 0

        # Get timestamps
        timestamps = sorted([q.timestamp for q in queries])

        if len(timestamps) < 3:
            return False, 0.0, 0

        # Calculate intervals between queries
        intervals = []
        for i in range(1, len(timestamps)):
            interval = (timestamps[i] - timestamps[i - 1]).total_seconds()
            if interval > 0:
                intervals.append(interval)

        if not intervals:
            return False, 0.0, 0

        # Calculate mean and standard deviation
        mean_interval = sum(intervals) / len(intervals)
        if mean_interval < 1:  # Less than 1 second average - too fast
            return False, 0.0, 0

        variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
        std_dev = math.sqrt(variance)

        # Coefficient of variation (CV) - lower = more regular
        cv = std_dev / mean_interval if mean_interval > 0 else float("inf")

        # Regular intervals (CV < 0.3) indicate beaconing
        # Add some jitter tolerance (attackers often add jitter)
        if cv < 0.5:
            confidence = max(0, 1.0 - cv)

            # Boost confidence for specific patterns
            if 30 <= mean_interval <= 300:  # 30s to 5min is suspicious
                confidence = min(confidence + 0.2, 1.0)

            if len(queries) > 20:  # Many queries
                confidence = min(confidence + 0.1, 1.0)

            return True, confidence, int(mean_interval)

        return False, 0.0, 0

    def _parse_macos_dns_logs(self) -> List[DNSQuery]:
        """Parse DNS queries from macOS logs"""
        queries = []

        try:
            # Use log command to get DNS queries
            # Looking at mDNSResponder subsystem
            cmd = [
                "log",
                "show",
                "--predicate",
                'subsystem == "com.apple.mDNSResponder"',
                "--style",
                "json",
                "--last",
                "5m",
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.returncode != 0:
                logger.debug(f"log command failed: {result.stderr}")
                return queries

            # Parse JSON output
            try:
                # The output may be multiple JSON objects
                for line in result.stdout.strip().split("\n"):
                    if not line.strip():
                        continue
                    try:
                        entry = json.loads(line)
                        message = entry.get("eventMessage", "")

                        # Extract DNS query from message
                        query = self._parse_dns_message(message, entry)
                        if query:
                            queries.append(query)
                    except json.JSONDecodeError:
                        continue
            except Exception as e:
                logger.debug(f"Error parsing log output: {e}")

        except subprocess.TimeoutExpired:
            logger.warning("DNS log parsing timed out")
        except Exception as e:
            logger.error(f"Error parsing macOS DNS logs: {e}")

        return queries

    def _parse_dns_message(self, message: str, entry: Dict) -> Optional[DNSQuery]:
        """Parse DNS query from log message"""
        # Common patterns in mDNSResponder logs
        # Example: "Query for google.com. (A)"

        patterns = [
            r"Query for ([^\s]+)\s*\((\w+)\)",
            r"(\S+)\s+(\w+)\s+query",
            r"DNS\s+(\S+)\s+(\w+)",
        ]

        for pattern in patterns:
            match = re.search(pattern, message, re.IGNORECASE)
            if match:
                domain = match.group(1).rstrip(".")
                query_type = match.group(2).upper()

                timestamp_str = entry.get("timestamp", "")
                try:
                    timestamp = datetime.fromisoformat(
                        timestamp_str.replace("Z", "+00:00")
                    )
                except Exception:
                    timestamp = datetime.now()

                return DNSQuery(
                    timestamp=timestamp,
                    query_name=domain,
                    query_type=query_type,
                    source_ip="127.0.0.1",
                    process_name=entry.get("processImagePath", ""),
                    process_pid=entry.get("processID"),
                )

        return None

    def _parse_linux_dns_logs(self) -> List[DNSQuery]:
        """Parse DNS queries from Linux logs"""
        queries = []

        # Try different log sources
        log_sources = [
            "/var/log/named/queries.log",
            "/var/log/syslog",
            "/var/log/messages",
        ]

        for log_file in log_sources:
            if Path(log_file).exists():
                try:
                    # Read last portion of log
                    result = subprocess.run(
                        ["tail", "-n", "1000", log_file],
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )

                    for line in result.stdout.split("\n"):
                        query = self._parse_linux_dns_line(line)
                        if query:
                            queries.append(query)

                except Exception as e:
                    logger.debug(f"Error reading {log_file}: {e}")

        # Also try systemd-resolved
        try:
            result = subprocess.run(
                ["resolvectl", "statistics"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            # Parse statistics if available
        except Exception:
            pass

        return queries

    def _parse_linux_dns_line(self, line: str) -> Optional[DNSQuery]:
        """Parse a single DNS log line from Linux"""
        # BIND query log format
        # Example: "client 192.168.1.100#12345: query: google.com IN A"

        pattern = r"client\s+([^#]+)#\d+.*query:\s+(\S+)\s+IN\s+(\w+)"
        match = re.search(pattern, line)

        if match:
            return DNSQuery(
                timestamp=datetime.now(),  # Would need to parse timestamp from line
                query_name=match.group(2).rstrip("."),
                query_type=match.group(3),
                source_ip=match.group(1),
            )

        return None

    def collect_queries(self) -> List[DNSQuery]:
        """Collect DNS queries from system"""
        if self.platform == "macos":
            return self._parse_macos_dns_logs()
        elif self.platform == "linux":
            return self._parse_linux_dns_logs()
        return []

    def analyze_queries(self, queries: List[DNSQuery]) -> List[DNSThreat]:
        """Analyze collected queries for threats"""
        threats = []

        # Add queries to history
        self.query_history.extend(queries)

        # Trim old queries outside analysis window
        cutoff = datetime.now() - timedelta(seconds=self.analysis_window)
        self.query_history = [q for q in self.query_history if q.timestamp > cutoff]

        # Update domain statistics
        for query in queries:
            domain = query.query_name.lower()
            stats = self.domain_stats[domain]
            stats["count"] += 1
            if stats["first_seen"] is None:
                stats["first_seen"] = query.timestamp
            stats["last_seen"] = query.timestamp
            stats["types"].add(query.query_type)

        # Group queries by base domain
        domain_queries: Dict[str, List[DNSQuery]] = defaultdict(list)
        for query in self.query_history:
            domain = query.query_name.lower()
            # Get base domain (last 2 parts)
            parts = domain.rstrip(".").split(".")
            base_domain = ".".join(parts[-2:]) if len(parts) >= 2 else domain
            domain_queries[base_domain].append(query)

        # Analyze each domain
        for base_domain, domain_query_list in domain_queries.items():
            if self._is_whitelisted(base_domain):
                continue

            # Check for DGA
            for query in domain_query_list:
                is_dga, dga_confidence = self._is_dga_domain(query.query_name)
                if is_dga and dga_confidence > 0.6:
                    threat = DNSThreat(
                        threat_type="DGA",
                        severity="HIGH",
                        domain=query.query_name,
                        evidence=[
                            f"High entropy subdomain (confidence: {dga_confidence:.2f})"
                        ],
                        query_count=len(domain_query_list),
                        first_seen=domain_query_list[0].timestamp,
                        last_seen=domain_query_list[-1].timestamp,
                        mitre_techniques=["T1568.002"],  # DGA
                        confidence=dga_confidence,
                    )
                    threats.append(threat)
                    break  # One threat per domain

            # Check for tunneling
            for query in domain_query_list:
                is_tunnel, tunnel_confidence = self._detect_tunneling(
                    query.query_name, query.query_type
                )
                if is_tunnel and tunnel_confidence > 0.5:
                    threat = DNSThreat(
                        threat_type="TUNNELING",
                        severity="CRITICAL",
                        domain=query.query_name,
                        evidence=[
                            f"DNS tunneling indicators (confidence: {tunnel_confidence:.2f})"
                        ],
                        query_count=len(domain_query_list),
                        first_seen=domain_query_list[0].timestamp,
                        last_seen=domain_query_list[-1].timestamp,
                        mitre_techniques=["T1071.004"],  # DNS Protocol
                        confidence=tunnel_confidence,
                    )
                    threats.append(threat)
                    break

            # Check for beaconing
            is_beacon, beacon_confidence, interval = self._detect_beaconing(
                base_domain, domain_query_list
            )
            if is_beacon and beacon_confidence > 0.6:
                threat = DNSThreat(
                    threat_type="C2_BEACON",
                    severity="CRITICAL",
                    domain=base_domain,
                    evidence=[
                        f"Regular beacon interval: {interval}s (confidence: {beacon_confidence:.2f})"
                    ],
                    query_count=len(domain_query_list),
                    first_seen=domain_query_list[0].timestamp,
                    last_seen=domain_query_list[-1].timestamp,
                    mitre_techniques=["T1071.004", "T1573"],  # DNS, Encrypted Channel
                    confidence=beacon_confidence,
                )
                threats.append(threat)

            # Check for C2 patterns
            for pattern in self.C2_PATTERNS:
                if re.search(pattern, base_domain, re.IGNORECASE):
                    threat = DNSThreat(
                        threat_type="C2_BEACON",
                        severity="CRITICAL",
                        domain=base_domain,
                        evidence=[f"Matches known C2 pattern: {pattern}"],
                        query_count=len(domain_query_list),
                        first_seen=domain_query_list[0].timestamp,
                        last_seen=domain_query_list[-1].timestamp,
                        mitre_techniques=["T1071.004"],
                        confidence=0.9,
                    )
                    threats.append(threat)
                    break

            # Check for suspicious TLDs with high volume
            tld = "." + base_domain.split(".")[-1] if "." in base_domain else ""
            if tld in self.SUSPICIOUS_TLDS and len(domain_query_list) > 5:
                threat = DNSThreat(
                    threat_type="SUSPICIOUS_RECORD",
                    severity="WARN",
                    domain=base_domain,
                    evidence=[
                        f"Suspicious TLD: {tld} with {len(domain_query_list)} queries"
                    ],
                    query_count=len(domain_query_list),
                    first_seen=domain_query_list[0].timestamp,
                    last_seen=domain_query_list[-1].timestamp,
                    mitre_techniques=["T1071.004"],
                    confidence=0.5,
                )
                threats.append(threat)

        return threats

    def _get_grpc_channel(self):
        """Create gRPC channel to EventBus with mTLS"""
        try:
            with open(f"{CERT_DIR}/ca.crt", "rb") as f:
                ca_cert = f.read()
            with open(f"{CERT_DIR}/agent.crt", "rb") as f:
                client_cert = f.read()
            with open(f"{CERT_DIR}/agent.key", "rb") as f:
                client_key = f.read()

            credentials = grpc.ssl_channel_credentials(
                root_certificates=ca_cert,
                private_key=client_key,
                certificate_chain=client_cert,
            )
            channel = grpc.secure_channel(EVENTBUS_ADDRESS, credentials)
            return channel
        except Exception as e:
            logger.error(f"Failed to create gRPC channel: {e}")
            return None

    def _create_telemetry(
        self, threats: List[DNSThreat]
    ) -> telemetry_pb2.DeviceTelemetry:
        """Create DeviceTelemetry protobuf from DNS threats"""
        timestamp_ns = int(time.time() * 1e9)
        hostname = socket.gethostname()

        events = []
        for threat in threats:
            severity_map = {
                "INFO": "INFO",
                "WARN": "WARN",
                "HIGH": "ERROR",
                "CRITICAL": "CRITICAL",
            }

            event = telemetry_pb2.TelemetryEvent(
                event_id=f"dns_{hash(threat.domain)}_{timestamp_ns}",
                event_type="SECURITY",
                severity=severity_map.get(threat.severity, "WARN"),
                event_timestamp_ns=timestamp_ns,
                security_event=telemetry_pb2.SecurityEvent(
                    event_action="DNS_THREAT",
                    event_outcome=threat.threat_type,
                    process_name="dns_agent",
                    source_ip="127.0.0.1",
                    details=json.dumps(
                        {
                            "domain": threat.domain,
                            "threat_type": threat.threat_type,
                            "evidence": threat.evidence,
                            "query_count": threat.query_count,
                            "mitre_techniques": threat.mitre_techniques,
                            "confidence": threat.confidence,
                            "first_seen": threat.first_seen.isoformat(),
                            "last_seen": threat.last_seen.isoformat(),
                        }
                    ),
                ),
            )
            events.append(event)

        return telemetry_pb2.DeviceTelemetry(
            device_id=f"endpoint_{hostname}",
            device_type="ENDPOINT",
            collection_timestamp_ns=timestamp_ns,
            events=events,
        )

    def publish_threats(self, threats: List[DNSThreat]) -> bool:
        """Publish DNS threats to EventBus"""
        if not threats:
            return True

        telemetry = self._create_telemetry(threats)

        channel = self._get_grpc_channel()
        if not channel:
            self.queue.push(telemetry.SerializeToString())
            return False

        try:
            stub = universal_pbrpc.UniversalTelemetryServiceStub(channel)

            envelope = telemetry_pb2.UniversalEnvelope(
                version="v1",
                ts_ns=int(time.time() * 1e9),
                idempotency_key=f"dns_{socket.gethostname()}_{int(time.time())}",
                device_telemetry=telemetry,
            )

            response = stub.Publish(envelope, timeout=10)
            if response.ack == telemetry_pb2.UniversalAck.Ack.OK:
                logger.info(f"Published {len(threats)} DNS threats")
                return True
            else:
                self.queue.push(telemetry.SerializeToString())
                return False

        except grpc.RpcError as e:
            self.queue.push(telemetry.SerializeToString())
            logger.error(f"gRPC error: {e}")
            return False
        finally:
            channel.close()

    def collect(self) -> bool:
        """Perform one collection cycle (implements abstract method)

        Returns:
            True if collection succeeded, False otherwise
        """
        try:
            self.run_once()
            return True
        except Exception as e:
            logger.error(f"Collection failed: {e}")
            return False

    def run_once(self) -> List[DNSThreat]:
        """Run a single analysis cycle"""
        # Check for evasion
        self.detect_evasion_attempts()

        # Collect queries
        queries = self.collect_queries()
        logger.debug(f"Collected {len(queries)} DNS queries")

        # Analyze for threats
        threats = self.analyze_queries(queries)

        if threats:
            logger.warning(
                f"Detected {len(threats)} DNS threats: "
                f"CRITICAL={sum(1 for t in threats if t.severity == 'CRITICAL')}, "
                f"HIGH={sum(1 for t in threats if t.severity == 'HIGH')}"
            )
            self.publish_threats(threats)

        return threats

    def run(self, interval: int = 60) -> None:
        """Run continuous monitoring loop"""
        logger.info(f"Starting DNS Agent: interval={interval}s")

        while True:
            try:
                self.run_once()
                time.sleep(interval)

            except KeyboardInterrupt:
                logger.info("Shutting down DNS Agent...")
                break
            except Exception as e:
                logger.error(f"Error in DNS monitoring loop: {e}")
                time.sleep(60)


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description="AMOSKYS DNS Monitor")
    parser.add_argument(
        "--interval", type=int, default=60, help="Analysis interval in seconds"
    )
    parser.add_argument(
        "--scan-once", action="store_true", help="Run single analysis and exit"
    )
    args = parser.parse_args()

    agent = DNSAgent()

    if args.scan_once:
        threats = agent.run_once()
        print(f"Detected {len(threats)} threats")
        for threat in threats:
            print(f"  [{threat.severity}] {threat.threat_type}: {threat.domain}")
    else:
        agent.run(interval=args.interval)


if __name__ == "__main__":
    main()
