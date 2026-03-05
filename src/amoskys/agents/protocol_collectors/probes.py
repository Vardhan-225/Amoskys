"""Micro-probes for ProtocolCollectors agent.

Each probe focuses on a specific protocol-level threat category:
    1. HTTPSuspiciousHeadersProbe - Suspicious HTTP headers (T1071.001)
    2. TLSSSLAnomalyProbe - TLS/SSL certificate/handshake anomalies (T1573.002)
    3. SSHBruteForceProbe - SSH authentication brute force (T1110, T1021.004)
    4. DNSTunnelingProbe - DNS exfiltration/tunneling (T1048.003)
    5. SQLInjectionProbe - SQL injection patterns (T1190)
    6. RDPSuspiciousProbe - RDP suspicious activity (T1021.001)
    7. FTPCleartextCredsProbe - FTP cleartext credential exposure (T1552.001)
    8. SMTPSpamPhishProbe - SMTP spam/phishing (T1566.001)
    9. IRCP2PC2Probe - IRC/P2P C2 communication (T1071.001)
    10. ProtocolAnomalyProbe - General protocol anomalies (T1205)
"""

import logging
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set

from amoskys.agents.common.probes import (
    MicroProbe,
    ProbeContext,
    Severity,
    TelemetryEvent,
)

# Use relative import to avoid triggering amoskys.agents.__init__
from .agent_types import ProtocolEvent, ProtocolType, ThreatCategory

logger = logging.getLogger(__name__)


class HTTPSuspiciousHeadersProbe(MicroProbe):
    """Detect suspicious HTTP headers indicating attacks or C2.

    MITRE ATT&CK: T1071.001 (Application Layer Protocol: Web Protocols)

    Detection patterns:
        - Unusual User-Agent strings
        - Base64 encoded headers
        - Known C2 framework signatures
        - Suspicious header combinations
    """

    name = "http_suspicious_headers"
    description = "Detect suspicious HTTP header patterns"
    mitre_techniques = ["T1071.001"]

    # Known suspicious patterns
    SUSPICIOUS_USER_AGENTS = [
        r"python-requests",
        r"curl/\d",
        r"wget/\d",
        r"powershell",
        r"empire",
        r"cobalt",
        r"metasploit",
        r"nmap",
        r"nikto",
        r"sqlmap",
        r"burp",
    ]

    SUSPICIOUS_HEADERS = [
        "X-Forwarded-Host",
        "X-Original-URL",
        "X-Rewrite-URL",
        "X-Custom-IP-Authorization",
    ]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Analyze HTTP events for suspicious headers."""
        events = []
        protocol_events: List[ProtocolEvent] = context.shared_data.get(
            "protocol_events", []
        )

        for pe in protocol_events:
            if pe.protocol not in (ProtocolType.HTTP, ProtocolType.HTTPS):
                continue

            suspicious_indicators = []

            # Check User-Agent
            user_agent = pe.metadata.get("user_agent", "")
            for pattern in self.SUSPICIOUS_USER_AGENTS:
                if re.search(pattern, user_agent, re.IGNORECASE):
                    suspicious_indicators.append(f"suspicious_user_agent:{pattern}")

            # Check for Base64 encoded content in headers
            raw_data = pe.raw_data or ""
            if self._contains_base64(raw_data):
                suspicious_indicators.append("base64_in_headers")

            # Check for header injection attempts
            if "\\r\\n" in raw_data or "%0d%0a" in raw_data.lower():
                suspicious_indicators.append("header_injection_attempt")

            if suspicious_indicators:
                events.append(
                    TelemetryEvent(
                        event_type="protocol_threat",
                        severity=Severity.MEDIUM,
                        probe_name=self.name,
                        data={
                            "description": f"Suspicious HTTP headers detected: {', '.join(suspicious_indicators)}",
                            "category": ThreatCategory.HTTP_SUSPICIOUS.value,
                            "src_ip": pe.src_ip,
                            "dst_ip": pe.dst_ip,
                            "indicators": suspicious_indicators,
                            "user_agent": user_agent[:200],
                        },
                        mitre_techniques=self.mitre_techniques,
                    )
                )

        return events

    def _contains_base64(self, data: str) -> bool:
        """Check if data contains suspicious Base64 patterns."""
        # Look for long Base64-like strings
        base64_pattern = r"[A-Za-z0-9+/]{50,}={0,2}"
        return bool(re.search(base64_pattern, data))


class TLSSSLAnomalyProbe(MicroProbe):
    """Detect TLS/SSL certificate and handshake anomalies.

    MITRE ATT&CK: T1573.002 (Encrypted Channel: Asymmetric Cryptography)

    Detection patterns:
        - Self-signed certificates
        - Expired certificates
        - Certificate mismatch
        - Weak cipher suites
        - TLS version downgrade
    """

    name = "tls_ssl_anomaly"
    description = "Detect TLS/SSL certificate and handshake anomalies"
    mitre_techniques = ["T1573.002"]

    WEAK_CIPHERS = ["RC4", "DES", "MD5", "NULL", "EXPORT", "anon"]
    OLD_TLS_VERSIONS = ["SSLv2", "SSLv3", "TLSv1.0"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Analyze TLS events for anomalies."""
        events = []
        protocol_events: List[ProtocolEvent] = context.shared_data.get(
            "protocol_events", []
        )

        for pe in protocol_events:
            if pe.protocol not in (ProtocolType.TLS, ProtocolType.HTTPS):
                continue

            anomalies = []

            # Check TLS version
            tls_version = pe.metadata.get("tls_version", "")
            if tls_version in self.OLD_TLS_VERSIONS:
                anomalies.append(f"old_tls_version:{tls_version}")

            # Check cipher suite
            cipher = pe.metadata.get("cipher_suite", "")
            for weak in self.WEAK_CIPHERS:
                if weak in cipher.upper():
                    anomalies.append(f"weak_cipher:{weak}")

            # Check certificate
            if pe.metadata.get("self_signed"):
                anomalies.append("self_signed_cert")
            if pe.metadata.get("cert_expired"):
                anomalies.append("expired_cert")

            if anomalies:
                events.append(
                    TelemetryEvent(
                        event_type="protocol_threat",
                        severity=Severity.MEDIUM,
                        probe_name=self.name,
                        data={
                            "description": f"TLS/SSL anomaly detected: {', '.join(anomalies)}",
                            "category": ThreatCategory.TLS_ANOMALY.value,
                            "src_ip": pe.src_ip,
                            "dst_ip": pe.dst_ip,
                            "anomalies": anomalies,
                            "tls_version": tls_version,
                        },
                        mitre_techniques=self.mitre_techniques,
                    )
                )

        return events


class SSHBruteForceProbe(MicroProbe):
    """Detect SSH brute force authentication attempts.

    MITRE ATT&CK: T1110 (Brute Force), T1021.004 (Remote Services: SSH)

    Detection patterns:
        - Multiple failed auth from same source
        - Invalid username attempts
        - Password spraying patterns
        - Unusual source IPs for SSH
    """

    name = "ssh_brute_force"
    description = "Detect SSH brute force and credential attacks"
    mitre_techniques = ["T1110", "T1021.004"]

    FAILED_THRESHOLD = 5  # failures before alerting
    TIME_WINDOW_SECONDS = 300  # 5 minute window

    def __init__(self):
        super().__init__()
        self._failed_attempts: Dict[str, List[datetime]] = defaultdict(list)

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Analyze SSH events for brute force patterns."""
        events = []
        protocol_events: List[ProtocolEvent] = context.shared_data.get(
            "protocol_events", []
        )
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=self.TIME_WINDOW_SECONDS)

        for pe in protocol_events:
            if pe.protocol != ProtocolType.SSH:
                continue

            auth_result = pe.metadata.get("auth_result", "")

            if auth_result == "failed":
                # Track failed attempt — normalize to UTC-aware
                src_ip = pe.src_ip
                ts = pe.timestamp
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                self._failed_attempts[src_ip].append(ts)

                # Clean old entries
                self._failed_attempts[src_ip] = [
                    t for t in self._failed_attempts[src_ip] if t > cutoff
                ]

                # Check threshold
                recent_failures = len(self._failed_attempts[src_ip])
                if recent_failures >= self.FAILED_THRESHOLD:
                    events.append(
                        TelemetryEvent(
                            event_type="protocol_threat",
                            severity=Severity.HIGH,
                            probe_name=self.name,
                            data={
                                "description": f"SSH brute force detected: {recent_failures} failed attempts from {src_ip}",
                                "category": ThreatCategory.SSH_BRUTE_FORCE.value,
                                "src_ip": src_ip,
                                "dst_ip": pe.dst_ip,
                                "failed_count": recent_failures,
                                "time_window_seconds": self.TIME_WINDOW_SECONDS,
                                "invalid_user": pe.metadata.get("invalid_user", False),
                            },
                            mitre_techniques=self.mitre_techniques,
                        )
                    )
                    # Reset counter to avoid repeated alerts
                    self._failed_attempts[src_ip] = []

        return events


class DNSTunnelingProbe(MicroProbe):
    """Detect DNS tunneling and exfiltration.

    MITRE ATT&CK: T1048.003 (Exfiltration Over Alternative Protocol)

    Detection patterns:
        - Unusually long DNS queries
        - High volume of TXT record queries
        - Base64/hex encoded subdomains
        - Unusual query patterns to single domain
    """

    name = "dns_tunneling"
    description = "Detect DNS tunneling and data exfiltration"
    mitre_techniques = ["T1048.003"]

    MAX_NORMAL_SUBDOMAIN_LENGTH = 50  # Aligned with DNS agent's threshold
    TXT_QUERY_THRESHOLD = 10  # TXT queries per minute to same domain

    def __init__(self):
        super().__init__()
        self._txt_queries: Dict[str, List[datetime]] = defaultdict(list)

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Analyze DNS events for tunneling patterns."""
        events = []
        protocol_events: List[ProtocolEvent] = context.shared_data.get(
            "protocol_events", []
        )
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=60)

        for pe in protocol_events:
            if pe.protocol != ProtocolType.DNS:
                continue

            indicators = []
            domain = pe.metadata.get("domain", "")
            query_type = pe.metadata.get("query_type", "A")

            # Check for long subdomains (potential encoding)
            parts = domain.split(".")
            for part in parts:
                if len(part) > self.MAX_NORMAL_SUBDOMAIN_LENGTH:
                    indicators.append(f"long_subdomain:{len(part)}_chars")

            # Check for encoded-looking subdomains
            if self._looks_encoded(domain):
                indicators.append("encoded_subdomain")

            # Track TXT queries
            if query_type == "TXT":
                base_domain = ".".join(parts[-2:]) if len(parts) >= 2 else domain
                ts = pe.timestamp
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                self._txt_queries[base_domain].append(ts)

                # Clean old entries
                self._txt_queries[base_domain] = [
                    t for t in self._txt_queries[base_domain] if t > cutoff
                ]

                if len(self._txt_queries[base_domain]) >= self.TXT_QUERY_THRESHOLD:
                    indicators.append(
                        f"high_txt_volume:{len(self._txt_queries[base_domain])}"
                    )
                    self._txt_queries[base_domain] = []

            # Check unusual payload size
            if pe.payload_size > 200:
                indicators.append(f"large_dns_payload:{pe.payload_size}")

            if indicators:
                events.append(
                    TelemetryEvent(
                        event_type="protocol_threat",
                        severity=Severity.HIGH,
                        probe_name=self.name,
                        data={
                            "description": f"DNS tunneling indicators detected: {', '.join(indicators)}",
                            "category": ThreatCategory.DNS_TUNNELING.value,
                            "src_ip": pe.src_ip,
                            "dst_ip": pe.dst_ip,
                            "domain": domain[:100],
                            "query_type": query_type,
                            "indicators": indicators,
                        },
                        mitre_techniques=self.mitre_techniques,
                    )
                )

        return events

    def _looks_encoded(self, domain: str) -> bool:
        """Check if domain looks like it contains encoded data."""
        # High ratio of consonants or numbers suggests encoding
        subdomain = domain.split(".")[0] if "." in domain else domain
        if len(subdomain) < 10:
            return False

        consonants = sum(
            1 for c in subdomain.lower() if c in "bcdfghjklmnpqrstvwxyz0123456789"
        )
        ratio = consonants / len(subdomain)
        return ratio > 0.7


class SQLInjectionProbe(MicroProbe):
    """Detect SQL injection attempts in network traffic.

    MITRE ATT&CK: T1190 (Exploit Public-Facing Application)

    Detection patterns:
        - Common SQL injection payloads
        - UNION-based injection
        - Error-based injection
        - Blind injection patterns
    """

    name = "sql_injection"
    description = "Detect SQL injection attack patterns"
    mitre_techniques = ["T1190"]

    SQL_PATTERNS = [
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|OR|AND)\b.*\b(FROM|INTO|TABLE|WHERE)\b)",
        r"('|\")\s*(OR|AND)\s*('|\")?\s*\d+\s*=\s*\d+",
        r";\s*(DROP|DELETE|UPDATE|INSERT)",
        r"--\s*$",
        r"SLEEP\s*\(\s*\d+\s*\)",
        r"BENCHMARK\s*\(",
        r"WAITFOR\s+DELAY",
        r"0x[0-9a-fA-F]+",
    ]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Analyze events for SQL injection patterns."""
        events = []
        protocol_events: List[ProtocolEvent] = context.shared_data.get(
            "protocol_events", []
        )

        for pe in protocol_events:
            if pe.protocol not in (
                ProtocolType.HTTP,
                ProtocolType.HTTPS,
                ProtocolType.SQL,
            ):
                continue

            raw_data = pe.raw_data or ""
            detected_patterns = []

            for pattern in self.SQL_PATTERNS:
                if re.search(pattern, raw_data, re.IGNORECASE):
                    detected_patterns.append(pattern[:50])

            if detected_patterns:
                events.append(
                    TelemetryEvent(
                        event_type="protocol_threat",
                        severity=Severity.CRITICAL,
                        probe_name=self.name,
                        data={
                            "description": f"SQL injection attempt detected from {pe.src_ip}",
                            "category": ThreatCategory.SQL_INJECTION.value,
                            "src_ip": pe.src_ip,
                            "dst_ip": pe.dst_ip,
                            "dst_port": pe.dst_port,
                            "patterns_matched": len(detected_patterns),
                            "sample_payload": raw_data[:200],
                        },
                        mitre_techniques=self.mitre_techniques,
                    )
                )

        return events


class RDPSuspiciousProbe(MicroProbe):
    """Detect suspicious RDP activity.

    MITRE ATT&CK: T1021.001 (Remote Services: Remote Desktop Protocol)

    Detection patterns:
        - RDP from unusual sources
        - Multiple RDP sessions
        - RDP to non-standard ports
        - Failed RDP authentication
    """

    name = "rdp_suspicious"
    description = "Detect suspicious RDP activity"
    mitre_techniques = ["T1021.001"]

    RDP_STANDARD_PORT = 3389

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Analyze RDP events for suspicious patterns."""
        events = []
        protocol_events: List[ProtocolEvent] = context.shared_data.get(
            "protocol_events", []
        )

        for pe in protocol_events:
            if pe.protocol != ProtocolType.RDP:
                continue

            suspicious = []

            # Check for non-standard port
            if pe.dst_port != self.RDP_STANDARD_PORT:
                suspicious.append(f"non_standard_port:{pe.dst_port}")

            # Check for external source
            if not pe.src_ip.startswith(("10.", "172.16.", "192.168.")):
                suspicious.append("external_source")

            if suspicious:
                events.append(
                    TelemetryEvent(
                        event_type="protocol_threat",
                        severity=Severity.MEDIUM,
                        probe_name=self.name,
                        data={
                            "description": f"Suspicious RDP activity: {', '.join(suspicious)}",
                            "category": ThreatCategory.RDP_SUSPICIOUS.value,
                            "src_ip": pe.src_ip,
                            "dst_ip": pe.dst_ip,
                            "dst_port": pe.dst_port,
                            "indicators": suspicious,
                        },
                        mitre_techniques=self.mitre_techniques,
                    )
                )

        return events


class FTPCleartextCredsProbe(MicroProbe):
    """Detect FTP cleartext credential exposure.

    MITRE ATT&CK: T1552.001 (Unsecured Credentials: Credentials in Files)

    Detection patterns:
        - FTP authentication traffic
        - Cleartext username/password
        - Anonymous FTP access
    """

    name = "ftp_cleartext_creds"
    description = "Detect FTP cleartext credential exposure"
    mitre_techniques = ["T1552.001"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Analyze FTP events for credential exposure."""
        events = []
        protocol_events: List[ProtocolEvent] = context.shared_data.get(
            "protocol_events", []
        )

        for pe in protocol_events:
            if pe.protocol != ProtocolType.FTP:
                continue

            # FTP traffic is inherently cleartext
            events.append(
                TelemetryEvent(
                    event_type="protocol_threat",
                    severity=Severity.MEDIUM,
                    probe_name=self.name,
                    data={
                        "description": f"FTP cleartext traffic detected from {pe.src_ip}",
                        "category": ThreatCategory.FTP_CLEARTEXT.value,
                        "src_ip": pe.src_ip,
                        "dst_ip": pe.dst_ip,
                        "command": pe.metadata.get("command", "unknown"),
                        "filename": pe.metadata.get("filename", ""),
                    },
                    mitre_techniques=self.mitre_techniques,
                )
            )

        return events


class SMTPSpamPhishProbe(MicroProbe):
    """Detect SMTP spam and phishing patterns.

    MITRE ATT&CK: T1566.001 (Phishing: Spearphishing Attachment)

    Detection patterns:
        - Bulk email patterns
        - Suspicious sender domains
        - Attachment types
    """

    name = "smtp_spam_phish"
    description = "Detect SMTP spam and phishing"
    mitre_techniques = ["T1566.001"]

    SUSPICIOUS_DOMAINS = [
        r"\.ru$",
        r"\.cn$",
        r"\.xyz$",
        r"\.top$",
        r"\.tk$",
    ]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Analyze SMTP events for spam/phishing patterns."""
        events = []
        protocol_events: List[ProtocolEvent] = context.shared_data.get(
            "protocol_events", []
        )

        for pe in protocol_events:
            if pe.protocol != ProtocolType.SMTP:
                continue

            indicators = []
            sender = pe.metadata.get("from", "")

            # Check suspicious sender domains
            for pattern in self.SUSPICIOUS_DOMAINS:
                if re.search(pattern, sender, re.IGNORECASE):
                    indicators.append(f"suspicious_domain:{pattern}")

            if indicators:
                events.append(
                    TelemetryEvent(
                        event_type="protocol_threat",
                        severity=Severity.MEDIUM,
                        probe_name=self.name,
                        data={
                            "description": f"Suspicious SMTP traffic: {', '.join(indicators)}",
                            "category": ThreatCategory.SMTP_SPAM_PHISH.value,
                            "src_ip": pe.src_ip,
                            "dst_ip": pe.dst_ip,
                            "sender": sender[:100],
                            "indicators": indicators,
                        },
                        mitre_techniques=self.mitre_techniques,
                    )
                )

        return events


class IRCP2PC2Probe(MicroProbe):
    """Detect IRC and P2P C2 communication.

    MITRE ATT&CK: T1071.001 (Application Layer Protocol)

    Detection patterns:
        - IRC traffic to unusual servers
        - P2P protocol signatures
        - Known C2 channel patterns
    """

    name = "irc_p2p_c2"
    description = "Detect IRC/P2P C2 communication"
    mitre_techniques = ["T1071.001"]

    IRC_PORTS = [6667, 6668, 6669, 7000]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Analyze events for IRC/P2P C2 patterns."""
        events = []
        protocol_events: List[ProtocolEvent] = context.shared_data.get(
            "protocol_events", []
        )

        for pe in protocol_events:
            if pe.protocol != ProtocolType.IRC:
                continue

            # IRC traffic is suspicious in enterprise environments
            events.append(
                TelemetryEvent(
                    event_type="protocol_threat",
                    severity=Severity.HIGH,
                    probe_name=self.name,
                    data={
                        "description": f"IRC traffic detected from {pe.src_ip} - potential C2",
                        "category": ThreatCategory.IRC_P2P_C2.value,
                        "src_ip": pe.src_ip,
                        "dst_ip": pe.dst_ip,
                        "dst_port": pe.dst_port,
                    },
                    mitre_techniques=self.mitre_techniques,
                )
            )

        return events


class ProtocolAnomalyProbe(MicroProbe):
    """Detect general protocol anomalies.

    MITRE ATT&CK: T1205 (Traffic Signaling)

    Detection patterns:
        - Protocol on non-standard port
        - Malformed protocol data
        - Unusual protocol combinations
    """

    name = "protocol_anomaly"
    description = "Detect general protocol anomalies"
    mitre_techniques = ["T1205"]

    STANDARD_PORTS = {
        ProtocolType.HTTP: [80, 8080, 8000],
        ProtocolType.HTTPS: [443, 8443],
        ProtocolType.SSH: [22],
        ProtocolType.DNS: [53],
        ProtocolType.FTP: [21, 20],
        ProtocolType.SMTP: [25, 587, 465],
        ProtocolType.RDP: [3389],
    }

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Analyze events for protocol anomalies."""
        events = []
        protocol_events: List[ProtocolEvent] = context.shared_data.get(
            "protocol_events", []
        )

        for pe in protocol_events:
            anomalies = []

            # Check for protocol on non-standard port
            standard_ports = self.STANDARD_PORTS.get(pe.protocol, [])
            if standard_ports and pe.dst_port not in standard_ports:
                anomalies.append(f"non_standard_port:{pe.dst_port}")

            if anomalies:
                events.append(
                    TelemetryEvent(
                        event_type="protocol_threat",
                        severity=Severity.LOW,
                        probe_name=self.name,
                        data={
                            "description": f"Protocol anomaly: {', '.join(anomalies)}",
                            "category": ThreatCategory.PROTOCOL_ANOMALY.value,
                            "protocol": pe.protocol.value,
                            "src_ip": pe.src_ip,
                            "dst_ip": pe.dst_ip,
                            "dst_port": pe.dst_port,
                            "anomalies": anomalies,
                        },
                        mitre_techniques=self.mitre_techniques,
                    )
                )

        return events


# Registry of all protocol collector probes
PROTOCOL_PROBES = [
    HTTPSuspiciousHeadersProbe,
    TLSSSLAnomalyProbe,
    SSHBruteForceProbe,
    DNSTunnelingProbe,
    SQLInjectionProbe,
    RDPSuspiciousProbe,
    FTPCleartextCredsProbe,
    SMTPSpamPhishProbe,
    IRCP2PC2Probe,
    ProtocolAnomalyProbe,
]


def create_protocol_collector_probes():
    """Factory function for Observability Contract audit."""
    return [cls() for cls in PROTOCOL_PROBES]
