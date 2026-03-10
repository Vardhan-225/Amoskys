"""macOS DNS Observatory probes — threat detection via DNS traffic analysis.

8 probes covering TA0011 Command & Control and related tactics:
    1. DGADetectionProbe       — T1568.002 Domain Generation Algorithms
    2. DNSTunnelingProbe       — T1071.004 DNS protocol tunneling
    3. BeaconingPatternProbe   — T1071.004 Periodic C2 beaconing
    4. CachePoisonProbe        — T1557.002 DNS cache poisoning indicators
    5. DNSOverHTTPSProbe       — T1572 Protocol tunneling via DoH
    6. NewDomainProbe          — T1583 First-seen domain baseline-diff
    7. FastFluxProbe           — T1568.001 Rapid IP rotation
    8. ReverseDNSReconProbe    — T1046 Internal PTR queries (recon)
"""

from __future__ import annotations

import collections
import logging
import math
import re
import time
from typing import Any, Dict, List, Optional, Set

from amoskys.agents.common.probes import (
    MicroProbe,
    ProbeContext,
    Severity,
    TelemetryEvent,
)

logger = logging.getLogger(__name__)


# ── Shared utilities ─────────────────────────────────────────────────────────


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string. Higher = more random."""
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _extract_effective_domain(domain: str) -> str:
    """Extract the registrable domain (SLD + TLD) from a FQDN.

    Simple heuristic — does not use publicsuffix list.
    'sub.example.co.uk' → 'example.co.uk'
    'foo.bar.com' → 'bar.com'
    """
    parts = domain.lower().rstrip(".").split(".")
    if len(parts) <= 2:
        return domain.lower()
    # Common multi-part TLDs
    multi_tlds = {"co.uk", "com.au", "co.nz", "co.jp", "com.br", "org.uk"}
    if len(parts) >= 3:
        potential = f"{parts[-2]}.{parts[-1]}"
        if potential in multi_tlds:
            return f"{parts[-3]}.{potential}"
    return f"{parts[-2]}.{parts[-1]}"


from amoskys.agents.common.ip_utils import is_benign_domain as _is_benign_domain
from amoskys.agents.common.ip_utils import is_private_ip as _is_private_ip

# ── Probe 1: DGA Detection ──────────────────────────────────────────────────


class DGADetectionProbe(MicroProbe):
    """Detect Domain Generation Algorithm queries via entropy analysis.

    MITRE: T1568.002 — Dynamic Resolution: Domain Generation Algorithms

    DGA domains have high entropy, unusual character distributions, and often
    resolve to many different IPs. We use Shannon entropy on the SLD (second-
    level domain) label plus consonant ratio as heuristics.
    """

    name = "macos_dns_dga"
    description = "Detects DGA-generated domains via entropy and n-gram analysis"
    platforms = ["darwin"]
    mitre_techniques = ["T1568.002"]
    mitre_tactics = ["command_and_control"]
    scan_interval = 10.0
    requires_fields = ["dns_queries"]
    maturity = "stable"
    false_positive_notes = [
        "CDN hashes (e.g., a1b2c3.cloudfront.net) can trigger high entropy",
        "Punycode internationalized domains may appear random",
    ]
    evasion_notes = [
        "Dictionary-based DGA (e.g., real word combinations) evades entropy",
        "Low-volume DGA with very few queries per domain avoids frequency triggers",
    ]

    ENTROPY_THRESHOLD = 3.5  # Shannon entropy above this → suspicious
    CONSONANT_RATIO_THRESH = 0.7  # Fraction of consonants above this → suspicious
    MIN_DOMAIN_LEN = 8  # Skip very short domains

    _VOWELS = frozenset("aeiou")

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        queries = context.shared_data.get("dns_queries", [])

        for query in queries:
            domain = query.domain.lower().rstrip(".")

            if _is_benign_domain(domain):
                continue

            # Extract SLD label for analysis
            parts = domain.split(".")
            if len(parts) < 2:
                continue
            sld = parts[-2] if len(parts) == 2 else parts[0]

            if len(sld) < self.MIN_DOMAIN_LEN:
                continue

            entropy = _shannon_entropy(sld)
            consonant_ratio = self._consonant_ratio(sld)

            if (
                entropy >= self.ENTROPY_THRESHOLD
                and consonant_ratio >= self.CONSONANT_RATIO_THRESH
            ):
                events.append(
                    self._create_event(
                        event_type="dga_domain_detected",
                        severity=Severity.HIGH,
                        data={
                            "domain": domain,
                            "sld": sld,
                            "entropy": round(entropy, 3),
                            "consonant_ratio": round(consonant_ratio, 3),
                            "record_type": query.record_type,
                            "response_ips": query.response_ips,
                            "source_process": query.source_process,
                            "source_pid": query.source_pid,
                        },
                        confidence=min(
                            0.95, 0.5 + (entropy - self.ENTROPY_THRESHOLD) * 0.3
                        ),
                    )
                )

        return events

    def _consonant_ratio(self, s: str) -> float:
        """Fraction of alphabetic characters that are consonants."""
        alpha = [c for c in s.lower() if c.isalpha()]
        if not alpha:
            return 0.0
        consonants = sum(1 for c in alpha if c not in self._VOWELS)
        return consonants / len(alpha)


# ── Probe 2: DNS Tunneling ──────────────────────────────────────────────────


class DNSTunnelingProbe(MicroProbe):
    """Detect DNS tunneling via TXT record abuse and subdomain encoding.

    MITRE: T1071.004 — Application Layer Protocol: DNS

    DNS tunneling encodes data in DNS queries (long subdomains, TXT records).
    Indicators: unusually long domain names, high TXT query rate, base64-like
    subdomain labels.
    """

    name = "macos_dns_tunneling"
    description = "Detects DNS tunneling via subdomain encoding and TXT abuse"
    platforms = ["darwin"]
    mitre_techniques = ["T1071.004"]
    mitre_tactics = ["command_and_control"]
    scan_interval = 10.0
    requires_fields = ["dns_queries"]
    maturity = "stable"
    false_positive_notes = [
        "DKIM TXT records can be very long",
        "SPF lookups generate legitimate TXT queries",
    ]
    evasion_notes = [
        "Slow-drip tunneling with short labels and low frequency",
        "Using A/AAAA records instead of TXT for data encoding",
    ]

    MAX_LABEL_LEN = 40  # Individual label > this → suspicious
    MAX_DOMAIN_LEN = 100  # Total domain length > this → suspicious
    TXT_FREQUENCY_THRESH = 5  # TXT queries to same domain in window → suspicious
    _BASE64_PATTERN = re.compile(r"^[A-Za-z0-9+/=]{20,}$")

    def __init__(self) -> None:
        super().__init__()
        self._txt_counts: Dict[str, int] = {}

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        queries = context.shared_data.get("dns_queries", [])

        txt_this_cycle: Dict[str, int] = collections.defaultdict(int)

        for query in queries:
            domain = query.domain.lower().rstrip(".")

            if _is_benign_domain(domain):
                continue

            labels = domain.split(".")
            effective = _extract_effective_domain(domain)

            # Check 1: Long subdomain labels (data encoding)
            for label in labels[:-2]:  # Skip SLD.TLD
                if len(label) > self.MAX_LABEL_LEN:
                    events.append(
                        self._create_event(
                            event_type="dns_tunnel_long_label",
                            severity=Severity.HIGH,
                            data={
                                "domain": domain,
                                "label": label,
                                "label_length": len(label),
                                "record_type": query.record_type,
                                "source_process": query.source_process,
                            },
                            confidence=0.85,
                        )
                    )
                    break

            # Check 2: Total domain length
            if len(domain) > self.MAX_DOMAIN_LEN:
                events.append(
                    self._create_event(
                        event_type="dns_tunnel_long_domain",
                        severity=Severity.MEDIUM,
                        data={
                            "domain": domain,
                            "domain_length": len(domain),
                            "record_type": query.record_type,
                        },
                        confidence=0.75,
                    )
                )

            # Check 3: Base64-like subdomain labels
            for label in labels[:-2]:
                if self._BASE64_PATTERN.match(label):
                    events.append(
                        self._create_event(
                            event_type="dns_tunnel_encoded_label",
                            severity=Severity.HIGH,
                            data={
                                "domain": domain,
                                "encoded_label": label,
                                "record_type": query.record_type,
                            },
                            confidence=0.80,
                        )
                    )
                    break

            # Check 4: TXT record frequency
            if query.record_type == "TXT":
                txt_this_cycle[effective] += 1

        # Evaluate TXT frequency
        for effective_domain, count in txt_this_cycle.items():
            self._txt_counts[effective_domain] = (
                self._txt_counts.get(effective_domain, 0) + count
            )
            if self._txt_counts[effective_domain] >= self.TXT_FREQUENCY_THRESH:
                events.append(
                    self._create_event(
                        event_type="dns_tunnel_txt_flood",
                        severity=Severity.HIGH,
                        data={
                            "domain": effective_domain,
                            "txt_query_count": self._txt_counts[effective_domain],
                            "threshold": self.TXT_FREQUENCY_THRESH,
                        },
                        confidence=0.80,
                    )
                )

        return events


# ── Probe 3: Beaconing Pattern ──────────────────────────────────────────────


class BeaconingPatternProbe(MicroProbe):
    """Detect periodic DNS query beaconing indicative of C2 communication.

    MITRE: T1071.004 — Application Layer Protocol: DNS

    C2 implants often query a domain at regular intervals. We detect this by
    tracking inter-query intervals and checking for low jitter (coefficient
    of variation).
    """

    name = "macos_dns_beaconing"
    description = "Detects periodic DNS beaconing patterns (C2 indicator)"
    platforms = ["darwin"]
    mitre_techniques = ["T1071.004"]
    mitre_tactics = ["command_and_control"]
    scan_interval = 30.0
    requires_fields = ["dns_queries"]
    maturity = "experimental"
    supports_baseline = True
    baseline_window_hours = 24
    false_positive_notes = [
        "NTP sync, heartbeat services, and monitoring tools beacon regularly",
        "macOS system services (apsd, cloudd) poll at fixed intervals",
    ]
    evasion_notes = [
        "High jitter (randomized intervals) evades periodicity detection",
        "Very long beacon intervals (>1hr) may not accumulate enough samples",
    ]

    MIN_SAMPLES = 5  # Minimum queries to analyze periodicity
    MAX_JITTER_CV = 0.15  # Coefficient of variation threshold (lower = more periodic)
    MIN_INTERVAL_S = 2.0  # Minimum interval (ignore sub-second bursts)
    MAX_INTERVAL_S = 3600.0  # Maximum interval to consider

    def __init__(self) -> None:
        super().__init__()
        # domain → list of query timestamps
        self._query_history: Dict[str, List[float]] = collections.defaultdict(list)

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        queries = context.shared_data.get("dns_queries", [])

        # Record query timestamps
        for query in queries:
            domain = _extract_effective_domain(query.domain)
            if _is_benign_domain(domain):
                continue
            self._query_history[domain].append(query.timestamp)

        # Analyze periodicity per domain
        for domain, timestamps in list(self._query_history.items()):
            # Trim old entries (keep last hour)
            cutoff = time.time() - 3600
            timestamps = [t for t in timestamps if t > cutoff]
            self._query_history[domain] = timestamps

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
            cv = std_dev / mean_interval  # Coefficient of variation

            if cv <= self.MAX_JITTER_CV:
                events.append(
                    self._create_event(
                        event_type="dns_beaconing_detected",
                        severity=Severity.HIGH,
                        data={
                            "domain": domain,
                            "mean_interval_s": round(mean_interval, 2),
                            "jitter_cv": round(cv, 4),
                            "sample_count": len(timestamps),
                            "interval_count": len(valid_intervals),
                        },
                        confidence=max(0.7, 1.0 - cv * 3),
                    )
                )

        return events


# ── Probe 4: Cache Poison Indicators ────────────────────────────────────────


class CachePoisonProbe(MicroProbe):
    """Detect DNS cache poisoning indicators via TTL anomalies.

    MITRE: T1557.002 — Adversary-in-the-Middle: ARP Cache Poisoning
    (extended to DNS cache manipulation)

    Indicators: extremely low TTLs (evasion), sudden TTL changes for known
    domains, responses from unexpected servers.
    """

    name = "macos_dns_cache_poison"
    description = "Detects DNS cache poisoning via TTL anomalies"
    platforms = ["darwin"]
    mitre_techniques = ["T1557.002"]
    mitre_tactics = ["credential_access"]
    scan_interval = 15.0
    requires_fields = ["dns_queries"]
    maturity = "experimental"
    false_positive_notes = [
        "CDNs legitimately use very short TTLs for load balancing",
        "GeoDNS services change responses based on location",
    ]

    SUSPICIOUS_TTL_LOW = 5  # TTL below this is suspicious
    SUSPICIOUS_TTL_HIGH = 604800  # TTL above 7 days is suspicious

    def __init__(self) -> None:
        super().__init__()
        self._known_ttls: Dict[str, int] = {}

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        queries = context.shared_data.get("dns_queries", [])

        for query in queries:
            if query.ttl <= 0:
                continue

            domain = _extract_effective_domain(query.domain)

            if _is_benign_domain(domain):
                # Still track TTL changes for benign domains
                prev_ttl = self._known_ttls.get(domain)
                if prev_ttl and abs(query.ttl - prev_ttl) > prev_ttl * 0.8:
                    events.append(
                        self._create_event(
                            event_type="dns_ttl_anomaly",
                            severity=Severity.MEDIUM,
                            data={
                                "domain": domain,
                                "current_ttl": query.ttl,
                                "previous_ttl": prev_ttl,
                                "change_ratio": round(
                                    abs(query.ttl - prev_ttl) / prev_ttl, 2
                                ),
                            },
                            confidence=0.6,
                        )
                    )
                self._known_ttls[domain] = query.ttl
                continue

            # Suspicious TTL ranges
            if query.ttl < self.SUSPICIOUS_TTL_LOW:
                events.append(
                    self._create_event(
                        event_type="dns_suspicious_low_ttl",
                        severity=Severity.MEDIUM,
                        data={
                            "domain": domain,
                            "ttl": query.ttl,
                            "record_type": query.record_type,
                            "response_ips": query.response_ips,
                        },
                        confidence=0.55,
                    )
                )

            if query.ttl > self.SUSPICIOUS_TTL_HIGH:
                events.append(
                    self._create_event(
                        event_type="dns_suspicious_high_ttl",
                        severity=Severity.LOW,
                        data={
                            "domain": domain,
                            "ttl": query.ttl,
                            "record_type": query.record_type,
                        },
                        confidence=0.4,
                    )
                )

            self._known_ttls[domain] = query.ttl

        return events


# ── Probe 5: DNS-over-HTTPS Detection ───────────────────────────────────────


class DNSOverHTTPSProbe(MicroProbe):
    """Detect DNS-over-HTTPS (DoH) usage that bypasses local DNS monitoring.

    MITRE: T1572 — Protocol Tunneling

    DoH encrypts DNS queries over HTTPS, making them invisible to network
    monitors. Malware uses DoH to evade DNS-based detection. We detect by
    matching DNS server IPs against known DoH providers.
    """

    name = "macos_dns_doh"
    description = "Detects DNS-over-HTTPS usage that bypasses local monitoring"
    platforms = ["darwin"]
    mitre_techniques = ["T1572"]
    mitre_tactics = ["command_and_control"]
    scan_interval = 30.0
    requires_fields = ["dns_servers"]
    maturity = "stable"
    false_positive_notes = [
        "Users may configure DoH intentionally for privacy",
        "Corporate VPN clients may route DNS through DoH endpoints",
    ]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        servers = context.shared_data.get("dns_servers", [])
        doh_providers = context.shared_data.get("doh_providers", set())

        for server in servers:
            if server.address in doh_providers:
                events.append(
                    self._create_event(
                        event_type="doh_provider_configured",
                        severity=Severity.MEDIUM,
                        data={
                            "server_address": server.address,
                            "server_port": server.port,
                            "interface": server.interface,
                            "is_default": server.is_default,
                        },
                        confidence=0.7,
                    )
                )

        return events


# ── Probe 6: New Domain (First-Seen Baseline) ───────────────────────────────


class NewDomainProbe(MicroProbe):
    """Detect first-seen domains not in the baseline.

    MITRE: T1583 — Acquire Infrastructure

    Newly registered or first-contacted domains are higher risk. We maintain
    a baseline of known domains and alert on new ones.
    """

    name = "macos_dns_new_domain"
    description = "Detects first-seen domains via baseline-diff"
    platforms = ["darwin"]
    mitre_techniques = ["T1583"]
    mitre_tactics = ["resource_development"]
    scan_interval = 10.0
    requires_fields = ["dns_queries"]
    maturity = "experimental"
    supports_baseline = True
    baseline_window_hours = 168  # 7-day baseline
    false_positive_notes = [
        "Browsing new websites triggers legitimate new domains",
        "Software updates may contact new CDN endpoints",
    ]

    BASELINE_CYCLES = 6  # Skip first N cycles to build baseline

    def __init__(self) -> None:
        super().__init__()
        self._known_domains: Set[str] = set()
        self._cycle_count = 0

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        queries = context.shared_data.get("dns_queries", [])
        self._cycle_count += 1

        new_this_cycle: Set[str] = set()

        for query in queries:
            effective = _extract_effective_domain(query.domain)

            if _is_benign_domain(effective):
                self._known_domains.add(effective)
                continue

            if effective not in self._known_domains:
                new_this_cycle.add(effective)

            self._known_domains.add(effective)

        # Only alert after baseline is established
        if self._cycle_count <= self.BASELINE_CYCLES:
            return events

        for domain in new_this_cycle:
            events.append(
                self._create_event(
                    event_type="new_domain_first_seen",
                    severity=Severity.LOW,
                    data={
                        "domain": domain,
                        "baseline_size": len(self._known_domains),
                        "cycle": self._cycle_count,
                    },
                    confidence=0.4,
                )
            )

        return events


# ── Probe 7: Fast-Flux Detection ────────────────────────────────────────────


class FastFluxProbe(MicroProbe):
    """Detect fast-flux DNS behavior (domain resolving to many IPs rapidly).

    MITRE: T1568.001 — Dynamic Resolution: Fast Flux DNS

    Fast-flux networks rapidly rotate IP addresses for a domain, making
    takedown difficult. Indicator: same domain resolving to many different
    IPs across queries.
    """

    name = "macos_dns_fast_flux"
    description = "Detects fast-flux DNS via rapid IP rotation"
    platforms = ["darwin"]
    mitre_techniques = ["T1568.001"]
    mitre_tactics = ["command_and_control"]
    scan_interval = 30.0
    requires_fields = ["dns_queries"]
    maturity = "experimental"
    false_positive_notes = [
        "CDN load balancers legitimately use many IPs (Akamai, Cloudflare)",
        "Round-robin DNS for high-availability services",
    ]

    IP_COUNT_THRESHOLD = 5  # Unique IPs per domain to trigger
    WINDOW_SECONDS = 300  # 5-minute observation window

    def __init__(self) -> None:
        super().__init__()
        # domain → set of (ip, timestamp)
        self._ip_history: Dict[str, List[tuple[str, float]]] = collections.defaultdict(
            list
        )
        self._alerted: Set[str] = set()

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        queries = context.shared_data.get("dns_queries", [])
        now = time.time()

        for query in queries:
            if not query.response_ips:
                continue

            effective = _extract_effective_domain(query.domain)

            if _is_benign_domain(effective):
                continue

            for ip in query.response_ips:
                self._ip_history[effective].append((ip, now))

        # Analyze per domain
        cutoff = now - self.WINDOW_SECONDS

        for domain, ip_entries in list(self._ip_history.items()):
            # Trim old entries
            ip_entries = [(ip, ts) for ip, ts in ip_entries if ts > cutoff]
            self._ip_history[domain] = ip_entries

            unique_ips = {ip for ip, _ in ip_entries}

            if (
                len(unique_ips) >= self.IP_COUNT_THRESHOLD
                and domain not in self._alerted
            ):
                events.append(
                    self._create_event(
                        event_type="fast_flux_detected",
                        severity=Severity.HIGH,
                        data={
                            "domain": domain,
                            "unique_ip_count": len(unique_ips),
                            "ips": sorted(unique_ips)[:10],  # Cap for readability
                            "observation_window_s": self.WINDOW_SECONDS,
                        },
                        confidence=0.75,
                    )
                )
                self._alerted.add(domain)

        return events


# ── Probe 8: Reverse DNS Reconnaissance ─────────────────────────────────────


class ReverseDNSReconProbe(MicroProbe):
    """Detect internal reverse DNS queries indicative of network reconnaissance.

    MITRE: T1046 — Network Service Discovery

    Attackers use reverse DNS (PTR) queries to map internal network topology.
    A burst of PTR queries for private IP ranges is a strong recon indicator.
    """

    name = "macos_dns_reverse_recon"
    description = "Detects reverse DNS reconnaissance via PTR query bursts"
    platforms = ["darwin"]
    mitre_techniques = ["T1046"]
    mitre_tactics = ["discovery"]
    scan_interval = 15.0
    requires_fields = ["dns_queries"]
    maturity = "stable"
    false_positive_notes = [
        "Network monitoring tools (Wireshark, nmap) do legitimate PTR lookups",
        "macOS Finder does PTR lookups when browsing network shares",
    ]

    PTR_BURST_THRESHOLD = 10  # PTR queries in single cycle → suspicious

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        queries = context.shared_data.get("dns_queries", [])

        reverse_queries = [q for q in queries if q.is_reverse]
        internal_reverse = [
            q for q in reverse_queries if self._is_internal_ptr(q.domain)
        ]

        if len(internal_reverse) >= self.PTR_BURST_THRESHOLD:
            queried_domains = [q.domain for q in internal_reverse]
            events.append(
                self._create_event(
                    event_type="reverse_dns_recon",
                    severity=Severity.HIGH,
                    data={
                        "ptr_query_count": len(internal_reverse),
                        "total_reverse_queries": len(reverse_queries),
                        "sample_queries": queried_domains[:10],
                        "threshold": self.PTR_BURST_THRESHOLD,
                    },
                    confidence=0.80,
                )
            )

        return events

    @staticmethod
    def _is_internal_ptr(domain: str) -> bool:
        """Check if PTR query targets a private IP range."""
        d = domain.lower()
        # 10.x.x.x → x.x.x.10.in-addr.arpa
        # 192.168.x.x → x.x.168.192.in-addr.arpa
        # 172.16-31.x.x → x.x.N.172.in-addr.arpa
        if d.endswith(".10.in-addr.arpa"):
            return True
        if d.endswith(".168.192.in-addr.arpa"):
            return True
        if ".in-addr.arpa" in d:
            parts = d.replace(".in-addr.arpa", "").split(".")
            if len(parts) >= 3:
                try:
                    second_octet = int(parts[-2])
                    first_octet = int(parts[-1])
                    if first_octet == 172 and 16 <= second_octet <= 31:
                        return True
                except (ValueError, IndexError):
                    pass
        return False


# ── Factory ──────────────────────────────────────────────────────────────────


def create_dns_probes() -> List[MicroProbe]:
    """Create all macOS DNS Observatory probes."""
    return [
        DGADetectionProbe(),
        DNSTunnelingProbe(),
        BeaconingPatternProbe(),
        CachePoisonProbe(),
        DNSOverHTTPSProbe(),
        NewDomainProbe(),
        FastFluxProbe(),
        ReverseDNSReconProbe(),
    ]
