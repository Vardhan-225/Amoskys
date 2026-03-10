#!/usr/bin/env python3
"""Internet Activity Micro-Probes - 8 Eyes on Every Outbound Connection.

Each probe monitors ONE specific internet activity threat vector:

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
    - T1567.002: Exfiltration to Cloud Storage
    - T1090.003: Multi-hop Proxy (TOR)
    - T1496: Resource Hijacking (Mining)
    - T1105: Ingress Tool Transfer
    - T1071: Application Layer Protocol
    - T1572: Protocol Tunneling
    - T1071.004: Application Layer Protocol: DNS
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

from amoskys.agents.common.probes import (
    MicroProbe,
    ProbeContext,
    Severity,
    TelemetryEvent,
)
from amoskys.agents.shared.internet_activity.agent_types import (
    BrowsingEntry,
    OutboundConnection,
)

logger = logging.getLogger(__name__)


# =============================================================================
# Detection Constants
# =============================================================================

# Cloud storage patterns for exfiltration detection
CLOUD_STORAGE_PATTERNS: List[re.Pattern] = [
    re.compile(r"\.s3\.amazonaws\.com$", re.IGNORECASE),
    re.compile(r"\.s3[.-]", re.IGNORECASE),
    re.compile(r"\.blob\.core\.windows\.net$", re.IGNORECASE),
    re.compile(r"\.storage\.googleapis\.com$", re.IGNORECASE),
    re.compile(r"(^|\.)dropbox\.com$", re.IGNORECASE),
    re.compile(r"(^|\.)mega\.nz$", re.IGNORECASE),
    re.compile(r"(^|\.)mega\.io$", re.IGNORECASE),
    re.compile(r"(^|\.)box\.com$", re.IGNORECASE),
    re.compile(r"(^|\.)onedrive\.live\.com$", re.IGNORECASE),
    re.compile(r"(^|\.)drive\.google\.com$", re.IGNORECASE),
    re.compile(r"(^|\.)icloud\.com$", re.IGNORECASE),
    re.compile(r"(^|\.)mediafire\.com$", re.IGNORECASE),
    re.compile(r"(^|\.)transfer\.sh$", re.IGNORECASE),
    re.compile(r"(^|\.)file\.io$", re.IGNORECASE),
    re.compile(r"(^|\.)anonfiles\.com$", re.IGNORECASE),
    re.compile(r"(^|\.)gofile\.io$", re.IGNORECASE),
]

# Cloud exfil threshold
CLOUD_EXFIL_BYTES_THRESHOLD = 10 * 1024 * 1024  # 10 MB

# Known TOR guard node ports and common VPN ports
TOR_PORTS = frozenset({9001, 9030, 9050, 9051, 9150})
VPN_PORTS = frozenset(
    {
        1194,  # OpenVPN
        500,  # IKEv2/IPSec
        4500,  # IKEv2 NAT-T
        51820,  # WireGuard
        1701,  # L2TP
        1723,  # PPTP
        443,  # SSTP / OpenVPN over HTTPS
    }
)

# Known TOR directory authorities and relay indicators
TOR_HOSTNAMES = frozenset(
    {
        "tor-exit",
        "tor-relay",
        "tor-guard",
    }
)

# VPN provider domains
VPN_DOMAINS = frozenset(
    {
        "nordvpn.com",
        "expressvpn.com",
        "surfshark.com",
        "protonvpn.com",
        "cyberghostvpn.com",
        "privateinternetaccess.com",
        "mullvad.net",
        "windscribe.com",
        "tunnelbear.com",
        "ipvanish.com",
    }
)

# Mining pool ports
MINING_PORTS = frozenset(
    {
        3333,
        4444,
        5555,
        7777,
        8333,
        8888,
        9999,
        14444,
        14433,
        45560,
        45700,
    }
)

# Known mining pool domains
MINING_POOL_DOMAINS = frozenset(
    {
        "pool.minexmr.com",
        "xmr.nanopool.org",
        "monerohash.com",
        "xmrpool.eu",
        "supportxmr.com",
        "pool.hashvault.pro",
        "moneroocean.stream",
        "2miners.com",
        "ethermine.org",
        "f2pool.com",
        "poolin.com",
        "antpool.com",
        "viabtc.com",
        "slushpool.com",
        "btc.com",
        "emcd.io",
        "minergate.com",
        "nicehash.com",
        "unmineable.com",
        "pool.binance.com",
        "mining.bitcoin.cz",
        "stratum+tcp",
    }
)

# Dangerous download extensions
DANGEROUS_DOWNLOAD_EXTENSIONS = frozenset(
    {
        ".exe",
        ".msi",
        ".dll",
        ".scr",
        ".com",
        ".bat",
        ".cmd",
        ".ps1",
        ".psm1",
        ".psd1",
        ".vbs",
        ".vbe",
        ".js",
        ".jse",
        ".wsf",
        ".wsh",
        ".hta",
        ".sh",
        ".bash",
        ".zsh",
        ".csh",
        ".dmg",
        ".pkg",
        ".app",
        ".deb",
        ".rpm",
        ".appimage",
        ".py",
        ".pl",
        ".rb",
        ".iso",
        ".img",
    }
)

# Shadow IT / personal service domains
PERSONAL_EMAIL_DOMAINS = frozenset(
    {
        "mail.google.com",
        "gmail.com",
        "outlook.live.com",
        "outlook.com",
        "hotmail.com",
        "mail.yahoo.com",
        "yahoo.com",
        "protonmail.com",
        "proton.me",
        "tutanota.com",
        "tuta.io",
        "mail.aol.com",
    }
)

FILE_SHARING_DOMAINS = frozenset(
    {
        "wetransfer.com",
        "sendspace.com",
        "zippyshare.com",
        "filebin.net",
        "uploadfiles.io",
        "file.io",
        "temp.sh",
        "transfer.sh",
        "0x0.st",
        "catbox.moe",
        "litterbox.catbox.moe",
        "pixeldrain.com",
        "gofile.io",
    }
)

MESSAGING_DOMAINS = frozenset(
    {
        "telegram.org",
        "web.telegram.org",
        "t.me",
        "signal.org",
        "signal.group",
        "discord.com",
        "discordapp.com",
        "slack.com",  # If org uses Teams, Slack is shadow IT
        "element.io",
        "matrix.org",
        "wire.com",
        "threema.ch",
        "whatsapp.com",
        "web.whatsapp.com",
    }
)

# Known adversary nations for geo-detection (ISO 3166-1 alpha-2)
HIGH_RISK_COUNTRIES = frozenset(
    {
        "KP",
        "IR",
        "SY",
        "CU",
        "RU",
        "CN",
    }
)

# Large cloud/CDN providers (not suspicious for long connections)
CDN_PROVIDER_DOMAINS = frozenset(
    {
        "google.com",
        "googleapis.com",
        "gstatic.com",
        "amazon.com",
        "amazonaws.com",
        "cloudfront.net",
        "microsoft.com",
        "azure.com",
        "msftconnecttest.com",
        "apple.com",
        "icloud.com",
        "akamai.net",
        "akamaized.net",
        "cloudflare.com",
        "cloudflare-dns.com",
        "fastly.net",
        "fastlylb.net",
        "github.com",
        "githubusercontent.com",
        "facebook.com",
        "fbcdn.net",
        "twitter.com",
        "twimg.com",
        "linkedin.com",
    }
)

# DNS-over-HTTPS endpoints
DOH_ENDPOINTS = frozenset(
    {
        "1.1.1.1",  # Cloudflare
        "1.0.0.1",  # Cloudflare secondary
        "8.8.8.8",  # Google
        "8.8.4.4",  # Google secondary
        "9.9.9.9",  # Quad9
        "149.112.112.112",  # Quad9 secondary
        "208.67.222.222",  # OpenDNS
        "208.67.220.220",  # OpenDNS secondary
    }
)

DOH_HOSTNAMES = frozenset(
    {
        "dns.google",
        "dns.google.com",
        "cloudflare-dns.com",
        "one.one.one.one",
        "dns.quad9.net",
        "doh.opendns.com",
        "doh.cleanbrowsing.org",
        "dns.nextdns.io",
        "dns.adguard.com",
    }
)


def _matches_domain_set(hostname: Optional[str], domain_set: frozenset) -> bool:
    """Check if hostname matches any domain in the set."""
    if not hostname:
        return False
    hostname_lower = hostname.lower()
    for domain in domain_set:
        if hostname_lower == domain or hostname_lower.endswith("." + domain):
            return True
    return False


def _is_cdn_provider(hostname: Optional[str]) -> bool:
    """Check if hostname belongs to a major CDN/cloud provider."""
    return _matches_domain_set(hostname, CDN_PROVIDER_DOMAINS)


# =============================================================================
# Probe 1: CloudExfilProbe
# =============================================================================


class CloudExfilProbe(MicroProbe):
    """Detects data exfiltration to cloud storage services.

    Matches destination hosts against cloud storage patterns (S3, Azure Blob,
    GCS, Dropbox, Mega) and flags connections with significant outbound data.

    MITRE ATT&CK: T1567 (Exfiltration Over Web Service)
    """

    name = "cloud_exfil"
    description = "Detects data exfiltration to cloud storage services"
    mitre_techniques = ["T1567"]
    mitre_tactics = ["exfiltration"]
    default_enabled = True
    scan_interval = 30.0
    requires_root = False
    platforms = ["linux", "darwin"]
    requires_fields = ["outbound_connections"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Scan outbound connections for cloud exfiltration."""
        events: List[TelemetryEvent] = []
        connections: List[OutboundConnection] = context.shared_data.get(
            "outbound_connections", []
        )

        for conn in connections:
            hostname = conn.dst_hostname or ""

            # Check if destination matches cloud storage
            is_cloud = False
            matched_service = ""
            for pattern in CLOUD_STORAGE_PATTERNS:
                if pattern.search(hostname):
                    is_cloud = True
                    matched_service = hostname
                    break

            if not is_cloud:
                continue

            # Flag if significant data was sent
            if conn.bytes_sent > CLOUD_EXFIL_BYTES_THRESHOLD:
                size_mb = conn.bytes_sent / (1024 * 1024)
                events.append(
                    self._create_event(
                        event_type="internet_cloud_exfiltration",
                        severity=Severity.HIGH,
                        data={
                            "process_name": conn.process_name,
                            "pid": conn.pid,
                            "dst_ip": conn.dst_ip,
                            "dst_hostname": hostname,
                            "dst_port": conn.dst_port,
                            "bytes_sent": conn.bytes_sent,
                            "size_mb": round(size_mb, 2),
                            "cloud_service": matched_service,
                            "protocol": conn.protocol,
                            "reason": f"Large upload ({size_mb:.1f}MB) to cloud storage: {matched_service}",
                        },
                        confidence=0.85,
                        tags=["correlation_group:data_exfiltration"],
                    )
                )

        return events


# =============================================================================
# Probe 2: TORVPNUsageProbe
# =============================================================================


class TORVPNUsageProbe(MicroProbe):
    """Detects TOR, VPN, and anonymization tool usage.

    Matches connections against TOR ports, known VPN ports (WireGuard 51820,
    OpenVPN 1194), and VPN provider domains.

    MITRE ATT&CK: T1090.003 (Multi-hop Proxy)
    """

    name = "tor_vpn_usage"
    description = "Detects TOR and VPN usage"
    mitre_techniques = ["T1090.003"]
    mitre_tactics = ["command_and_control"]
    default_enabled = True
    scan_interval = 30.0
    requires_root = False
    platforms = ["linux", "darwin"]
    requires_fields = ["outbound_connections"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Scan outbound connections for TOR/VPN usage."""
        events: List[TelemetryEvent] = []
        connections: List[OutboundConnection] = context.shared_data.get(
            "outbound_connections", []
        )

        for conn in connections:
            tor_vpn_indicators: List[str] = []
            is_tor = False

            # Check for TOR ports
            if conn.dst_port in TOR_PORTS:
                tor_vpn_indicators.append(f"TOR port detected: {conn.dst_port}")
                is_tor = True

            # Check for TOR-related hostnames
            hostname = (conn.dst_hostname or "").lower()
            for tor_indicator in TOR_HOSTNAMES:
                if tor_indicator in hostname:
                    tor_vpn_indicators.append(f"TOR hostname: {hostname}")
                    is_tor = True
                    break

            # Check for VPN ports (exclude HTTPS 443 unless going to VPN domain)
            if conn.dst_port in VPN_PORTS and conn.dst_port != 443:
                tor_vpn_indicators.append(f"VPN port detected: {conn.dst_port}")

            # Check for VPN provider domains
            if _matches_domain_set(hostname, VPN_DOMAINS):
                tor_vpn_indicators.append(f"VPN provider domain: {hostname}")

            # WireGuard specific (UDP port 51820)
            if conn.dst_port == 51820 and conn.protocol == "UDP":
                tor_vpn_indicators.append("WireGuard connection (UDP/51820)")

            if tor_vpn_indicators:
                severity = Severity.HIGH if is_tor else Severity.HIGH

                events.append(
                    self._create_event(
                        event_type="internet_tor_vpn_detected",
                        severity=severity,
                        data={
                            "process_name": conn.process_name,
                            "pid": conn.pid,
                            "dst_ip": conn.dst_ip,
                            "dst_hostname": hostname,
                            "dst_port": conn.dst_port,
                            "protocol": conn.protocol,
                            "indicators": tor_vpn_indicators,
                            "is_tor": is_tor,
                            "reason": f"Anonymization tool: {tor_vpn_indicators[0]}",
                        },
                        confidence=0.85,
                    )
                )

        return events


# =============================================================================
# Probe 3: CryptoMiningProbe
# =============================================================================


class CryptoMiningProbe(MicroProbe):
    """Detects cryptocurrency mining activity.

    Monitors for connections to mining pool ports (3333, 4444, 8333, etc.)
    and known mining pool domains.

    MITRE ATT&CK: T1496 (Resource Hijacking)
    """

    name = "crypto_mining"
    description = "Detects cryptocurrency mining connections"
    mitre_techniques = ["T1496"]
    mitre_tactics = ["impact"]
    default_enabled = True
    scan_interval = 30.0
    requires_root = False
    platforms = ["linux", "darwin"]
    requires_fields = ["outbound_connections"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Scan outbound connections for mining activity."""
        events: List[TelemetryEvent] = []
        connections: List[OutboundConnection] = context.shared_data.get(
            "outbound_connections", []
        )

        for conn in connections:
            mining_indicators: List[str] = []
            hostname = (conn.dst_hostname or "").lower()

            # Check for mining pool ports
            if conn.dst_port in MINING_PORTS:
                mining_indicators.append(f"Mining pool port: {conn.dst_port}")

            # Check for known mining pool domains
            if _matches_domain_set(hostname, MINING_POOL_DOMAINS):
                mining_indicators.append(f"Known mining pool: {hostname}")

            # Check for stratum protocol indicators in hostname
            if "stratum" in hostname or "pool" in hostname and "mining" in hostname:
                mining_indicators.append(f"Mining-related hostname: {hostname}")

            if mining_indicators:
                events.append(
                    self._create_event(
                        event_type="internet_crypto_mining",
                        severity=Severity.CRITICAL,
                        data={
                            "process_name": conn.process_name,
                            "pid": conn.pid,
                            "dst_ip": conn.dst_ip,
                            "dst_hostname": hostname,
                            "dst_port": conn.dst_port,
                            "protocol": conn.protocol,
                            "mining_indicators": mining_indicators,
                            "reason": f"Crypto mining: {mining_indicators[0]}",
                        },
                        confidence=0.90,
                    )
                )

        return events


# =============================================================================
# Probe 4: SuspiciousDownloadProbe
# =============================================================================


class SuspiciousDownloadProbe(MicroProbe):
    """Detects suspicious file downloads from untrusted sources.

    Checks browsing entries for downloads of executable/script files
    from domains not in the top trusted sites list.

    MITRE ATT&CK: T1105 (Ingress Tool Transfer)
    """

    name = "suspicious_download"
    description = "Detects dangerous file downloads from untrusted sources"
    mitre_techniques = ["T1105"]
    mitre_tactics = ["command_and_control"]
    default_enabled = True
    scan_interval = 30.0
    requires_root = False
    platforms = ["linux", "darwin"]
    requires_fields = ["browsing_entries"]

    # Well-known trusted download domains
    TRUSTED_DOMAINS = frozenset(
        {
            "microsoft.com",
            "apple.com",
            "google.com",
            "mozilla.org",
            "github.com",
            "gitlab.com",
            "bitbucket.org",
            "python.org",
            "nodejs.org",
            "npmjs.com",
            "docker.com",
            "brew.sh",
            "homebrew.github.io",
            "ubuntu.com",
            "debian.org",
            "fedoraproject.org",
            "adobe.com",
            "oracle.com",
            "jetbrains.com",
            "visualstudio.com",
            "vs-cdn.com",
            "amazonaws.com",
            "cloudfront.net",
            "sourceforge.net",
            "cnet.com",
        }
    )

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Scan browsing entries for suspicious downloads."""
        events: List[TelemetryEvent] = []
        browsing_entries: List[BrowsingEntry] = context.shared_data.get(
            "browsing_entries", []
        )

        for entry in browsing_entries:
            url_lower = entry.url.lower()

            # Check if URL points to a dangerous file type
            has_dangerous_ext = False
            matched_ext = ""
            for ext in DANGEROUS_DOWNLOAD_EXTENSIONS:
                if url_lower.endswith(ext) or f"{ext}?" in url_lower:
                    has_dangerous_ext = True
                    matched_ext = ext
                    break

            if not has_dangerous_ext:
                continue

            # Check if domain is trusted
            domain = entry.domain.lower()
            is_trusted = _matches_domain_set(domain, self.TRUSTED_DOMAINS)

            if not is_trusted:
                events.append(
                    self._create_event(
                        event_type="internet_suspicious_download",
                        severity=Severity.HIGH,
                        data={
                            "url": entry.url,
                            "domain": domain,
                            "extension": matched_ext,
                            "title": entry.title,
                            "browser": entry.browser,
                            "visit_count": entry.visit_count,
                            "reason": f"Dangerous file download ({matched_ext}) "
                            f"from untrusted domain: {domain}",
                        },
                        confidence=0.80,
                    )
                )

        return events


# =============================================================================
# Probe 5: ShadowITSaaSProbe
# =============================================================================


class ShadowITSaaSProbe(MicroProbe):
    """Detects shadow IT and unauthorized SaaS usage.

    Monitors connections to personal email services, file sharing platforms,
    and unapproved messaging applications.

    MITRE ATT&CK: T1567.002 (Exfiltration to Cloud Storage)
    """

    name = "shadow_it_saas"
    description = "Detects unauthorized SaaS and personal service usage"
    mitre_techniques = ["T1567.002"]
    mitre_tactics = ["exfiltration"]
    default_enabled = True
    scan_interval = 30.0
    requires_root = False
    platforms = ["linux", "darwin"]
    requires_fields = ["outbound_connections"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Scan outbound connections for shadow IT services."""
        events: List[TelemetryEvent] = []
        connections: List[OutboundConnection] = context.shared_data.get(
            "outbound_connections", []
        )

        for conn in connections:
            hostname = (conn.dst_hostname or "").lower()
            if not hostname:
                continue

            shadow_it_type = None
            service_category = ""

            # Check personal email
            if _matches_domain_set(hostname, PERSONAL_EMAIL_DOMAINS):
                shadow_it_type = "personal_email"
                service_category = f"Personal email: {hostname}"

            # Check file sharing
            elif _matches_domain_set(hostname, FILE_SHARING_DOMAINS):
                shadow_it_type = "file_sharing"
                service_category = f"File sharing: {hostname}"

            # Check messaging
            elif _matches_domain_set(hostname, MESSAGING_DOMAINS):
                shadow_it_type = "messaging"
                service_category = f"Messaging: {hostname}"

            if shadow_it_type:
                events.append(
                    self._create_event(
                        event_type="internet_shadow_it",
                        severity=Severity.MEDIUM,
                        data={
                            "process_name": conn.process_name,
                            "pid": conn.pid,
                            "dst_ip": conn.dst_ip,
                            "dst_hostname": hostname,
                            "dst_port": conn.dst_port,
                            "shadow_it_type": shadow_it_type,
                            "service_category": service_category,
                            "bytes_sent": conn.bytes_sent,
                            "bytes_received": conn.bytes_received,
                            "reason": f"Shadow IT detected: {service_category}",
                        },
                        confidence=0.75,
                    )
                )

        return events


# =============================================================================
# Probe 6: UnusualGeoConnectionProbe
# =============================================================================


class UnusualGeoConnectionProbe(MicroProbe):
    """Detects connections to unusual geographic locations.

    Maintains a baseline of connection countries and flags first-time
    countries, especially those in high-risk nation lists.

    MITRE ATT&CK: T1071 (Application Layer Protocol)
    """

    name = "unusual_geo_connection"
    description = "Detects connections to unusual geographic locations"
    mitre_techniques = ["T1071"]
    mitre_tactics = ["command_and_control"]
    default_enabled = True
    scan_interval = 30.0
    requires_root = False
    platforms = ["linux", "darwin"]
    requires_fields = ["outbound_connections"]

    def __init__(self) -> None:
        """Initialize with empty country baseline."""
        super().__init__()
        self._known_countries: Set[str] = set()
        self._baseline_built = False

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Scan outbound connections for unusual geographic destinations."""
        events: List[TelemetryEvent] = []
        connections: List[OutboundConnection] = context.shared_data.get(
            "outbound_connections", []
        )

        # Collect current countries
        current_countries: Set[str] = set()
        for conn in connections:
            if conn.geo_country:
                current_countries.add(conn.geo_country.upper())

        # First cycle: build baseline
        if not self._baseline_built:
            self._known_countries = current_countries.copy()
            self._baseline_built = True
            logger.info(
                "Geo baseline established: %d countries", len(self._known_countries)
            )
            return events

        # Check for new countries
        for conn in connections:
            if not conn.geo_country:
                continue

            country = conn.geo_country.upper()

            # Flag first-time countries
            if country not in self._known_countries:
                is_high_risk = country in HIGH_RISK_COUNTRIES
                severity = Severity.HIGH if is_high_risk else Severity.MEDIUM

                events.append(
                    self._create_event(
                        event_type="internet_unusual_geo",
                        severity=severity,
                        data={
                            "process_name": conn.process_name,
                            "pid": conn.pid,
                            "dst_ip": conn.dst_ip,
                            "dst_hostname": conn.dst_hostname,
                            "dst_port": conn.dst_port,
                            "country": country,
                            "is_high_risk": is_high_risk,
                            "known_countries": sorted(self._known_countries),
                            "reason": f"First-time connection to country: {country}"
                            f"{' (HIGH RISK)' if is_high_risk else ''}",
                        },
                        confidence=0.70 if not is_high_risk else 0.85,
                    )
                )

                # Add to known countries to avoid repeat alerts
                self._known_countries.add(country)

        return events


# =============================================================================
# Probe 7: LongLivedConnectionProbe
# =============================================================================


class LongLivedConnectionProbe(MicroProbe):
    """Detects suspiciously persistent outbound connections.

    Flags connections lasting > 1 hour to non-CDN, non-major-provider hosts,
    which may indicate C2 channels or data exfiltration.

    MITRE ATT&CK: T1572 (Protocol Tunneling)
    """

    name = "long_lived_connection"
    description = "Detects persistent outbound connections"
    mitre_techniques = ["T1572"]
    mitre_tactics = ["command_and_control"]
    default_enabled = True
    scan_interval = 30.0
    requires_root = False
    platforms = ["linux", "darwin"]
    requires_fields = ["outbound_connections"]

    # Duration threshold: 1 hour
    DURATION_THRESHOLD_SECONDS = 3600.0

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Scan outbound connections for long-lived sessions."""
        events: List[TelemetryEvent] = []
        connections: List[OutboundConnection] = context.shared_data.get(
            "outbound_connections", []
        )

        for conn in connections:
            if conn.duration_seconds is None:
                continue

            if conn.duration_seconds < self.DURATION_THRESHOLD_SECONDS:
                continue

            hostname = conn.dst_hostname or ""

            # Skip known CDN/cloud providers
            if _is_cdn_provider(hostname):
                continue

            hours = conn.duration_seconds / 3600.0
            events.append(
                self._create_event(
                    event_type="internet_long_lived_connection",
                    severity=Severity.MEDIUM,
                    data={
                        "process_name": conn.process_name,
                        "pid": conn.pid,
                        "dst_ip": conn.dst_ip,
                        "dst_hostname": hostname,
                        "dst_port": conn.dst_port,
                        "duration_seconds": conn.duration_seconds,
                        "duration_hours": round(hours, 2),
                        "bytes_sent": conn.bytes_sent,
                        "bytes_received": conn.bytes_received,
                        "protocol": conn.protocol,
                        "reason": f"Long-lived connection ({hours:.1f}h) to {hostname or conn.dst_ip}",
                    },
                    confidence=0.70,
                )
            )

        return events


# =============================================================================
# Probe 8: DNSOverHTTPSProbe
# =============================================================================


class DNSOverHTTPSProbe(MicroProbe):
    """Detects DNS-over-HTTPS (DoH) usage that bypasses DNS monitoring.

    Identifies connections to known DoH endpoints (Cloudflare 1.1.1.1,
    Google 8.8.8.8, Quad9 9.9.9.9) on port 443.

    MITRE ATT&CK: T1071.004 (Application Layer Protocol: DNS)
    """

    name = "dns_over_https"
    description = "Detects DNS-over-HTTPS bypass"
    mitre_techniques = ["T1071.004"]
    mitre_tactics = ["command_and_control"]
    default_enabled = True
    scan_interval = 30.0
    requires_root = False
    platforms = ["linux", "darwin"]
    requires_fields = ["outbound_connections"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Scan outbound connections for DoH endpoints."""
        events: List[TelemetryEvent] = []
        connections: List[OutboundConnection] = context.shared_data.get(
            "outbound_connections", []
        )

        for conn in connections:
            doh_indicators: List[str] = []

            # Check IP-based DoH endpoints (must be on port 443)
            if conn.dst_port == 443 and conn.dst_ip in DOH_ENDPOINTS:
                doh_indicators.append(f"DoH endpoint IP: {conn.dst_ip}")

            # Check hostname-based DoH endpoints
            hostname = (conn.dst_hostname or "").lower()
            if hostname in DOH_HOSTNAMES:
                doh_indicators.append(f"DoH hostname: {hostname}")

            # Also check for dns-query path in known DoH format
            if _matches_domain_set(hostname, DOH_HOSTNAMES) and conn.dst_port == 443:
                doh_indicators.append(f"DoH service: {hostname}:443")

            if doh_indicators:
                events.append(
                    self._create_event(
                        event_type="internet_doh_detected",
                        severity=Severity.MEDIUM,
                        data={
                            "process_name": conn.process_name,
                            "pid": conn.pid,
                            "dst_ip": conn.dst_ip,
                            "dst_hostname": hostname,
                            "dst_port": conn.dst_port,
                            "doh_indicators": doh_indicators,
                            "protocol": conn.protocol,
                            "reason": f"DNS-over-HTTPS bypass: {doh_indicators[0]}",
                        },
                        confidence=0.80,
                    )
                )

        return events


# =============================================================================
# Probe Registry
# =============================================================================

INTERNET_ACTIVITY_PROBES = [
    CloudExfilProbe,
    TORVPNUsageProbe,
    CryptoMiningProbe,
    SuspiciousDownloadProbe,
    ShadowITSaaSProbe,
    UnusualGeoConnectionProbe,
    LongLivedConnectionProbe,
    DNSOverHTTPSProbe,
]


def create_internet_activity_probes() -> List[MicroProbe]:
    """Create instances of all internet activity probes.

    Returns:
        List of instantiated probes
    """
    return [probe_class() for probe_class in INTERNET_ACTIVITY_PROBES]


# =============================================================================
# Exports
# =============================================================================

__all__ = [
    "CloudExfilProbe",
    "TORVPNUsageProbe",
    "CryptoMiningProbe",
    "SuspiciousDownloadProbe",
    "ShadowITSaaSProbe",
    "UnusualGeoConnectionProbe",
    "LongLivedConnectionProbe",
    "DNSOverHTTPSProbe",
    "INTERNET_ACTIVITY_PROBES",
    "create_internet_activity_probes",
]
