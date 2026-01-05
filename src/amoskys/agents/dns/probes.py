"""DNS Agent Micro-Probes - 9 Eyes Watching Every DNS Transaction.

Each probe monitors ONE specific DNS threat vector:

    1. RawDNSQueryProbe - Captures all DNS queries for analysis
    2. DGAScoreProbe - Detects Domain Generation Algorithm patterns
    3. BeaconingPatternProbe - Identifies C2 callback patterns
    4. SuspiciousTLDProbe - Flags high-risk TLD usage
    5. NXDomainBurstProbe - Detects domain probing/enumeration
    6. LargeTXTTunnelingProbe - Detects DNS tunneling via TXT records
    7. FastFluxRebindingProbe - Identifies fast-flux DNS or rebinding
    8. NewDomainForProcessProbe - Flags first-time domain by process
    9. BlockedDomainHitProbe - Detects attempts to reach blocked domains

MITRE ATT&CK Coverage:
    - T1071.004: Application Layer Protocol: DNS
    - T1568.002: Dynamic Resolution: Domain Generation Algorithms
    - T1568.001: Dynamic Resolution: Fast Flux DNS
    - T1048.001: Exfiltration Over Alternative Protocol (DNS Tunneling)
    - T1573.002: Encrypted Channel: Asymmetric Cryptography
"""

from __future__ import annotations

import logging
import math
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from amoskys.agents.common.probes import (
    MicroProbe,
    ProbeContext,
    Severity,
    TelemetryEvent,
)

logger = logging.getLogger(__name__)


# =============================================================================
# Shared DNS Data Structures
# =============================================================================


@dataclass
class DNSQuery:
    """Represents a captured DNS query."""

    timestamp: datetime
    domain: str
    query_type: str  # A, AAAA, TXT, MX, CNAME, NS, NULL
    source_ip: str = "127.0.0.1"
    response_ips: List[str] = field(default_factory=list)
    response_code: str = "NOERROR"  # NOERROR, NXDOMAIN, SERVFAIL
    ttl: int = 0
    process_name: Optional[str] = None
    process_pid: Optional[int] = None


@dataclass
class DomainStats:
    """Statistics for a single domain."""

    domain: str
    query_count: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    query_intervals: List[float] = field(default_factory=list)
    response_ips: Set[str] = field(default_factory=set)
    processes: Set[str] = field(default_factory=set)


# =============================================================================
# 1. RawDNSQueryProbe
# =============================================================================


class RawDNSQueryProbe(MicroProbe):
    """Captures all DNS queries for baseline and analysis.

    This is the foundational probe - it gathers raw DNS data that other
    probes analyze. Produces INFO-level events for forensic correlation.

    Detection:
        - Every DNS query is logged (with rate limiting)
        - Builds shared query buffer for other probes

    MITRE: T1071.004 (DNS Protocol)
    """

    name = "raw_dns_query"
    description = "Captures DNS queries for correlation and analysis"
    mitre_techniques = ["T1071.004"]
    mitre_tactics = ["command_and_control"]
    scan_interval = 5.0
    default_enabled = True

    # Rate limiting to prevent event flood
    MAX_EVENTS_PER_CYCLE = 100

    def __init__(self) -> None:
        super().__init__()
        self.query_buffer: List[DNSQuery] = []

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Capture DNS queries from system logs.

        In real implementation, this reads from:
        - macOS: dns.log, mDNSResponder logs
        - Linux: systemd-resolved, /var/log/named, tcpdump
        - Windows: ETW DNS events
        """
        events = []

        # Get queries from shared data (populated by platform-specific collector)
        queries: List[DNSQuery] = context.shared_data.get("dns_queries", [])

        # Store in buffer for other probes
        self.query_buffer = queries

        # Emit events (rate limited)
        for query in queries[: self.MAX_EVENTS_PER_CYCLE]:
            events.append(
                self._create_event(
                    event_type="dns_query",
                    severity=Severity.DEBUG,
                    data={
                        "domain": query.domain,
                        "query_type": query.query_type,
                        "source_ip": query.source_ip,
                        "response_code": query.response_code,
                        "process": query.process_name,
                        "pid": query.process_pid,
                    },
                    confidence=1.0,
                )
            )

        return events


# =============================================================================
# 2. DGAScoreProbe
# =============================================================================


class DGAScoreProbe(MicroProbe):
    """Detects Domain Generation Algorithm (DGA) patterns.

    DGAs generate random-looking domains for C2 infrastructure. This probe
    uses Shannon entropy and character analysis to identify suspicious domains.

    Detection:
        - High entropy in domain name (randomness)
        - Unusual character distribution
        - Length anomalies
        - Consonant/vowel ratio

    MITRE: T1568.002 (Domain Generation Algorithms)
    """

    name = "dga_score"
    description = "Detects algorithmically generated domain names"
    mitre_techniques = ["T1568.002"]
    mitre_tactics = ["command_and_control"]
    scan_interval = 10.0

    # Thresholds
    ENTROPY_THRESHOLD = 3.5
    MIN_DOMAIN_LENGTH = 6
    CONSONANT_VOWEL_THRESHOLD = 5.0

    # Known legitimate high-entropy domains (CDNs, etc.)
    ENTROPY_WHITELIST = {
        "cloudflare.com",
        "akamai.net",
        "fastly.net",
        "cloudfront.net",
        "amazonaws.com",
        "googlevideo.com",
    }

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Analyze domains for DGA patterns."""
        events = []

        queries: List[DNSQuery] = context.shared_data.get("dns_queries", [])
        seen_domains: Set[str] = set()

        for query in queries:
            domain = query.domain.lower()

            # Skip duplicates in this cycle
            if domain in seen_domains:
                continue
            seen_domains.add(domain)

            # Skip whitelisted domains
            if any(domain.endswith(w) for w in self.ENTROPY_WHITELIST):
                continue

            # Analyze domain
            score, reasons = self._analyze_domain(domain)

            if score > 0.7:  # High confidence DGA
                events.append(
                    self._create_event(
                        event_type="dga_domain_detected",
                        severity=Severity.HIGH,
                        data={
                            "domain": domain,
                            "dga_score": round(score, 3),
                            "reasons": reasons,
                            "query_type": query.query_type,
                            "process": query.process_name,
                        },
                        confidence=score,
                    )
                )
            elif score > 0.5:  # Medium confidence
                events.append(
                    self._create_event(
                        event_type="suspicious_domain_entropy",
                        severity=Severity.MEDIUM,
                        data={
                            "domain": domain,
                            "dga_score": round(score, 3),
                            "reasons": reasons,
                        },
                        confidence=score,
                    )
                )

        return events

    def _analyze_domain(self, domain: str) -> Tuple[float, List[str]]:
        """Analyze domain for DGA characteristics.

        Returns:
            Tuple of (score 0.0-1.0, list of reasons)
        """
        reasons = []
        scores = []

        # Extract second-level domain (SLD)
        parts = domain.split(".")
        if len(parts) < 2:
            return 0.0, []

        # Get the subdomain + SLD for analysis
        sld = parts[-2] if len(parts) >= 2 else domain

        # 1. Shannon entropy
        entropy = self._calculate_entropy(sld)
        if entropy > self.ENTROPY_THRESHOLD:
            scores.append(min(entropy / 4.5, 1.0))  # Normalize to 0-1
            reasons.append(f"High entropy: {entropy:.2f}")

        # 2. Length check
        if len(sld) > 20:
            scores.append(0.7)
            reasons.append(f"Unusual length: {len(sld)}")

        # 3. Consonant/vowel ratio
        cv_ratio = self._consonant_vowel_ratio(sld)
        if cv_ratio > self.CONSONANT_VOWEL_THRESHOLD:
            scores.append(0.6)
            reasons.append(f"Consonant-heavy: {cv_ratio:.1f}")

        # 4. Numeric ratio
        numeric_ratio = sum(c.isdigit() for c in sld) / max(len(sld), 1)
        if numeric_ratio > 0.3:
            scores.append(0.5)
            reasons.append(f"High numeric ratio: {numeric_ratio:.2f}")

        # 5. No vowels
        vowels = set("aeiou")
        if len(sld) > 5 and not any(c in vowels for c in sld.lower()):
            scores.append(0.8)
            reasons.append("No vowels")

        # Calculate overall score
        if not scores:
            return 0.0, []

        return sum(scores) / len(scores), reasons

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text."""
        if not text:
            return 0.0

        freq = {}
        for c in text.lower():
            freq[c] = freq.get(c, 0) + 1

        entropy = 0.0
        for count in freq.values():
            p = count / len(text)
            entropy -= p * math.log2(p)

        return entropy

    def _consonant_vowel_ratio(self, text: str) -> float:
        """Calculate consonant to vowel ratio."""
        vowels = set("aeiouAEIOU")
        consonants = sum(1 for c in text if c.isalpha() and c not in vowels)
        vowel_count = sum(1 for c in text if c in vowels)
        return consonants / max(vowel_count, 1)


# =============================================================================
# 3. BeaconingPatternProbe
# =============================================================================


class BeaconingPatternProbe(MicroProbe):
    """Detects C2 beaconing patterns in DNS queries.

    Malware often "beacons" home at regular intervals. This probe identifies
    periodic query patterns that may indicate C2 communication.

    Detection:
        - Regular query intervals (±10% variance)
        - Consistent query patterns over time
        - Known C2 framework patterns

    MITRE: T1071.004 (DNS Protocol), T1573 (Encrypted Channel)
    """

    name = "beaconing_pattern"
    description = "Identifies C2 callback patterns in DNS queries"
    mitre_techniques = ["T1071.004", "T1573.002"]
    mitre_tactics = ["command_and_control"]
    scan_interval = 60.0  # Analyze every minute

    # Thresholds
    MIN_QUERIES_FOR_PATTERN = 5
    INTERVAL_VARIANCE_THRESHOLD = 0.15  # 15% variance allowed

    # Known C2 domain patterns
    C2_PATTERNS = [
        r"\.cobalt\.?strike",
        r"\.beacon\.",
        r"\.metasploit\.",
        r"\.empire\.",
        r"\.sliver\.",
        r"\.brute\.?ratel",
        r"\.ngrok\.io$",
        r"\.serveo\.net$",
    ]

    def __init__(self) -> None:
        super().__init__()
        self.domain_history: Dict[str, DomainStats] = defaultdict(
            lambda: DomainStats(domain="")
        )

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Analyze query patterns for beaconing."""
        events = []

        queries: List[DNSQuery] = context.shared_data.get("dns_queries", [])

        # Update domain statistics
        for query in queries:
            domain = query.domain.lower()
            stats = self.domain_history[domain]
            stats.domain = domain

            now = query.timestamp

            # Calculate interval if we have previous queries
            if stats.last_seen:
                interval = (now - stats.last_seen).total_seconds()
                if 1 < interval < 3600:  # Between 1s and 1h
                    stats.query_intervals.append(interval)
                    # Keep only recent intervals
                    stats.query_intervals = stats.query_intervals[-50:]

            stats.query_count += 1
            stats.first_seen = stats.first_seen or now
            stats.last_seen = now

            if query.process_name:
                stats.processes.add(query.process_name)

        # Analyze for beaconing patterns
        for domain, stats in self.domain_history.items():
            # Check for known C2 patterns
            for pattern in self.C2_PATTERNS:
                if re.search(pattern, domain, re.IGNORECASE):
                    events.append(
                        self._create_event(
                            event_type="known_c2_domain",
                            severity=Severity.CRITICAL,
                            data={
                                "domain": domain,
                                "pattern_matched": pattern,
                                "query_count": stats.query_count,
                                "processes": list(stats.processes),
                            },
                            confidence=0.95,
                        )
                    )

            # Check for beaconing (regular intervals)
            if len(stats.query_intervals) >= self.MIN_QUERIES_FOR_PATTERN:
                avg_interval = sum(stats.query_intervals) / len(stats.query_intervals)
                variance = self._calculate_variance(stats.query_intervals, avg_interval)

                if variance < self.INTERVAL_VARIANCE_THRESHOLD:
                    events.append(
                        self._create_event(
                            event_type="dns_beaconing_detected",
                            severity=Severity.HIGH,
                            data={
                                "domain": domain,
                                "avg_interval_seconds": round(avg_interval, 1),
                                "variance": round(variance, 3),
                                "query_count": stats.query_count,
                                "processes": list(stats.processes),
                            },
                            confidence=1.0 - variance,
                        )
                    )

        return events

    def _calculate_variance(self, intervals: List[float], mean: float) -> float:
        """Calculate normalized variance of intervals."""
        if not intervals or mean == 0:
            return 1.0
        squared_diff_sum = sum((x - mean) ** 2 for x in intervals)
        variance = math.sqrt(squared_diff_sum / len(intervals)) / mean
        return min(variance, 1.0)


# =============================================================================
# 4. SuspiciousTLDProbe
# =============================================================================


class SuspiciousTLDProbe(MicroProbe):
    """Flags queries to suspicious top-level domains.

    Certain TLDs are disproportionately used for malicious purposes.
    This probe flags DNS queries to high-risk TLDs.

    MITRE: T1071.004 (DNS Protocol)
    """

    name = "suspicious_tld"
    description = "Flags DNS queries to high-risk TLDs"
    mitre_techniques = ["T1071.004"]
    mitre_tactics = ["command_and_control"]
    scan_interval = 5.0

    # High-risk TLDs (free registration, lax enforcement)
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
        ".rest",
        ".icu",
        ".cam",
        ".ooo",
    }

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Flag suspicious TLD usage."""
        events = []

        queries: List[DNSQuery] = context.shared_data.get("dns_queries", [])
        seen: Set[str] = set()

        for query in queries:
            domain = query.domain.lower()
            if domain in seen:
                continue
            seen.add(domain)

            # Check TLD
            for tld in self.SUSPICIOUS_TLDS:
                if domain.endswith(tld):
                    events.append(
                        self._create_event(
                            event_type="suspicious_tld_query",
                            severity=Severity.MEDIUM,
                            data={
                                "domain": domain,
                                "tld": tld,
                                "query_type": query.query_type,
                                "process": query.process_name,
                            },
                            confidence=0.6,
                        )
                    )
                    break

        return events


# =============================================================================
# 5. NXDomainBurstProbe
# =============================================================================


class NXDomainBurstProbe(MicroProbe):
    """Detects bursts of NXDOMAIN responses.

    Many NXDOMAIN responses in a short time may indicate:
    - DGA domain probing
    - Domain enumeration
    - Misconfigured malware

    MITRE: T1568.002 (DGA), T1046 (Network Service Discovery)
    """

    name = "nxdomain_burst"
    description = "Detects NXDOMAIN response bursts (DGA probing)"
    mitre_techniques = ["T1568.002", "T1046"]
    mitre_tactics = ["discovery", "command_and_control"]
    scan_interval = 30.0

    # Thresholds
    NXDOMAIN_THRESHOLD = 10  # Per collection window
    TIME_WINDOW = 60  # Seconds

    def __init__(self) -> None:
        super().__init__()
        self.nxdomain_history: List[Tuple[datetime, str]] = []

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect NXDOMAIN bursts."""
        events = []

        queries: List[DNSQuery] = context.shared_data.get("dns_queries", [])
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=self.TIME_WINDOW)

        # Add new NXDOMAIN responses
        for query in queries:
            if query.response_code == "NXDOMAIN":
                self.nxdomain_history.append((query.timestamp, query.domain))

        # Prune old entries
        self.nxdomain_history = [
            (ts, d) for ts, d in self.nxdomain_history if ts > cutoff
        ]

        # Check for burst
        if len(self.nxdomain_history) >= self.NXDOMAIN_THRESHOLD:
            domains = [d for _, d in self.nxdomain_history]
            events.append(
                self._create_event(
                    event_type="nxdomain_burst_detected",
                    severity=Severity.HIGH,
                    data={
                        "count": len(self.nxdomain_history),
                        "time_window_seconds": self.TIME_WINDOW,
                        "sample_domains": domains[:10],
                    },
                    confidence=0.85,
                )
            )

        return events


# =============================================================================
# 6. LargeTXTTunnelingProbe
# =============================================================================


class LargeTXTTunnelingProbe(MicroProbe):
    """Detects DNS tunneling via TXT records.

    DNS tunneling encodes data in DNS queries/responses. TXT records are
    commonly abused because they can contain arbitrary data.

    Detection:
        - High volume of TXT queries
        - Long subdomain labels (data encoding)
        - Base64/hex patterns in domains

    MITRE: T1048.001 (Exfiltration Over DNS), T1071.004 (DNS Protocol)
    """

    name = "txt_tunneling"
    description = "Detects DNS tunneling via TXT record abuse"
    mitre_techniques = ["T1048.001", "T1071.004"]
    mitre_tactics = ["exfiltration", "command_and_control"]
    scan_interval = 15.0

    # Thresholds
    TXT_QUERY_THRESHOLD = 5  # Per collection window
    SUBDOMAIN_LENGTH_THRESHOLD = 50  # Characters

    # Base64 pattern (common in tunneling)
    BASE64_PATTERN = re.compile(r"^[A-Za-z0-9+/=]{20,}$")

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect TXT record abuse."""
        events = []

        queries: List[DNSQuery] = context.shared_data.get("dns_queries", [])

        # Count TXT queries
        txt_queries = [q for q in queries if q.query_type in ("TXT", "NULL")]

        if len(txt_queries) >= self.TXT_QUERY_THRESHOLD:
            events.append(
                self._create_event(
                    event_type="high_txt_query_volume",
                    severity=Severity.MEDIUM,
                    data={
                        "count": len(txt_queries),
                        "domains": list(set(q.domain for q in txt_queries))[:10],
                    },
                    confidence=0.7,
                )
            )

        # Check for encoded subdomains
        for query in queries:
            parts = query.domain.split(".")
            for part in parts[:-2]:  # Skip TLD and SLD
                if len(part) > self.SUBDOMAIN_LENGTH_THRESHOLD:
                    events.append(
                        self._create_event(
                            event_type="dns_tunneling_suspected",
                            severity=Severity.HIGH,
                            data={
                                "domain": query.domain,
                                "subdomain_length": len(part),
                                "query_type": query.query_type,
                            },
                            confidence=0.8,
                        )
                    )
                    break

                # Check for base64 encoding
                if len(part) > 20 and self.BASE64_PATTERN.match(part):
                    events.append(
                        self._create_event(
                            event_type="encoded_dns_query",
                            severity=Severity.MEDIUM,
                            data={
                                "domain": query.domain,
                                "encoded_part": part[:30] + "...",
                                "pattern": "base64",
                            },
                            confidence=0.75,
                        )
                    )

        return events


# =============================================================================
# 7. FastFluxRebindingProbe
# =============================================================================


class FastFluxRebindingProbe(MicroProbe):
    """Detects fast-flux DNS and DNS rebinding attacks.

    Fast-flux: Domain maps to many IPs that change rapidly (botnet hiding)
    DNS rebinding: Domain alternates between public and private IPs (attack)

    MITRE: T1568.001 (Fast Flux DNS)
    """

    name = "fast_flux_rebinding"
    description = "Detects fast-flux DNS and rebinding attacks"
    mitre_techniques = ["T1568.001"]
    mitre_tactics = ["command_and_control"]
    scan_interval = 30.0

    # Thresholds
    IP_CHANGE_THRESHOLD = 5  # Unique IPs for same domain

    # Private IP ranges (for rebinding detection)
    PRIVATE_RANGES = [
        re.compile(r"^10\."),
        re.compile(r"^172\.(1[6-9]|2[0-9]|3[0-1])\."),
        re.compile(r"^192\.168\."),
        re.compile(r"^127\."),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.domain_ips: Dict[str, Set[str]] = defaultdict(set)

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect fast-flux and rebinding."""
        events = []

        queries: List[DNSQuery] = context.shared_data.get("dns_queries", [])

        for query in queries:
            domain = query.domain.lower()

            for ip in query.response_ips:
                self.domain_ips[domain].add(ip)

            # Check for fast-flux (many IPs)
            if len(self.domain_ips[domain]) >= self.IP_CHANGE_THRESHOLD:
                events.append(
                    self._create_event(
                        event_type="fast_flux_detected",
                        severity=Severity.HIGH,
                        data={
                            "domain": domain,
                            "unique_ips": len(self.domain_ips[domain]),
                            "sample_ips": list(self.domain_ips[domain])[:5],
                        },
                        confidence=0.85,
                    )
                )

            # Check for rebinding (public + private IPs)
            ips = self.domain_ips[domain]
            has_private = any(
                any(r.match(ip) for r in self.PRIVATE_RANGES) for ip in ips
            )
            has_public = any(
                not any(r.match(ip) for r in self.PRIVATE_RANGES) for ip in ips
            )

            if has_private and has_public and len(ips) > 1:
                events.append(
                    self._create_event(
                        event_type="dns_rebinding_suspected",
                        severity=Severity.CRITICAL,
                        data={
                            "domain": domain,
                            "ips": list(ips),
                        },
                        confidence=0.9,
                    )
                )

        return events


# =============================================================================
# 8. NewDomainForProcessProbe
# =============================================================================


class NewDomainForProcessProbe(MicroProbe):
    """Flags first-time domain queries by process.

    Tracks which domains each process has queried. New domains from
    established processes may indicate compromise.

    MITRE: T1071.004 (DNS Protocol)
    """

    name = "new_domain_for_process"
    description = "Detects first-time domain queries by process"
    mitre_techniques = ["T1071.004"]
    mitre_tactics = ["command_and_control"]
    scan_interval = 10.0

    def __init__(self) -> None:
        super().__init__()
        self.process_domains: Dict[str, Set[str]] = defaultdict(set)

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Track new domains per process."""
        events = []

        queries: List[DNSQuery] = context.shared_data.get("dns_queries", [])

        for query in queries:
            if not query.process_name:
                continue

            proc = query.process_name
            domain = query.domain.lower()

            # Extract root domain (last 2 parts)
            parts = domain.split(".")
            root = ".".join(parts[-2:]) if len(parts) >= 2 else domain

            if root not in self.process_domains[proc]:
                # First time this process has queried this domain
                self.process_domains[proc].add(root)

                # Skip initial learning period (first 10 domains)
                if len(self.process_domains[proc]) > 10:
                    events.append(
                        self._create_event(
                            event_type="new_domain_for_process",
                            severity=Severity.LOW,
                            data={
                                "process": proc,
                                "domain": domain,
                                "root_domain": root,
                                "total_domains_for_process": len(
                                    self.process_domains[proc]
                                ),
                            },
                            confidence=0.5,
                        )
                    )

        return events


# =============================================================================
# 9. BlockedDomainHitProbe
# =============================================================================


class BlockedDomainHitProbe(MicroProbe):
    """Detects attempts to reach known-bad domains.

    Uses a blocklist of known malicious/phishing/C2 domains. Any query to
    these domains is an immediate high-severity alert.

    MITRE: T1071.004 (DNS Protocol), T1566 (Phishing)
    """

    name = "blocked_domain_hit"
    description = "Detects queries to blocklisted domains"
    mitre_techniques = ["T1071.004", "T1566"]
    mitre_tactics = ["command_and_control", "initial_access"]
    scan_interval = 5.0

    # Sample blocklist (in production, load from file/threat intel)
    BLOCKED_DOMAINS = {
        "malware.testcategory.com",
        "ransomware-payment.evil",
        "cobaltstrike-c2.com",
        "phishing-test.bad",
        "exploit-kit.landing",
    }

    BLOCKED_PATTERNS = [
        r".*\.onion$",  # Tor hidden services
        r".*\.bit$",  # Namecoin (often malware)
        r".*-paypal.*\.com$",  # Common phishing pattern
        r".*-microsoft.*\.com$",  # Common phishing pattern
    ]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Check for blocklist hits."""
        events = []

        queries: List[DNSQuery] = context.shared_data.get("dns_queries", [])

        for query in queries:
            domain = query.domain.lower()

            # Check exact match
            if domain in self.BLOCKED_DOMAINS:
                events.append(
                    self._create_event(
                        event_type="blocked_domain_query",
                        severity=Severity.CRITICAL,
                        data={
                            "domain": domain,
                            "match_type": "exact",
                            "process": query.process_name,
                            "pid": query.process_pid,
                        },
                        confidence=1.0,
                    )
                )
                continue

            # Check patterns
            for pattern in self.BLOCKED_PATTERNS:
                if re.match(pattern, domain):
                    events.append(
                        self._create_event(
                            event_type="blocked_domain_pattern",
                            severity=Severity.HIGH,
                            data={
                                "domain": domain,
                                "match_type": "pattern",
                                "pattern": pattern,
                                "process": query.process_name,
                            },
                            confidence=0.9,
                        )
                    )
                    break

        return events


# =============================================================================
# Probe Registry
# =============================================================================

DNS_PROBES = [
    RawDNSQueryProbe,
    DGAScoreProbe,
    BeaconingPatternProbe,
    SuspiciousTLDProbe,
    NXDomainBurstProbe,
    LargeTXTTunnelingProbe,
    FastFluxRebindingProbe,
    NewDomainForProcessProbe,
    BlockedDomainHitProbe,
]


def create_dns_probes() -> List[MicroProbe]:
    """Create instances of all DNS probes.

    Returns:
        List of initialized DNS probe instances
    """
    return [probe_class() for probe_class in DNS_PROBES]


__all__ = [
    "BlockedDomainHitProbe",
    "BeaconingPatternProbe",
    "create_dns_probes",
    "DGAScoreProbe",
    "DNS_PROBES",
    "DNSQuery",
    "DomainStats",
    "FastFluxRebindingProbe",
    "LargeTXTTunnelingProbe",
    "NewDomainForProcessProbe",
    "NXDomainBurstProbe",
    "RawDNSQueryProbe",
    "SuspiciousTLDProbe",
]
