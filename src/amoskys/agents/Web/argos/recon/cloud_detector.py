"""Cloud / CDN IP classification — passive, zero target-touch.

Before we probe an IP, we classify it. Why: if the IP is a Cloudflare
edge node, a :443 probe tells us nothing about the customer's origin
— it tells us Cloudflare's edge handshake. Worse, repeated probes
against Cloudflare from one source get our source IP soft-blocked.

This module answers "who owns this IP" from embedded IP-range data.

Providers covered in v1:
    - AWS        (us-east-1, eu-west-1, ... regions inferred)
    - Cloudflare (single classification — their edge is global)
    - Google Cloud / Google services
    - Microsoft Azure
    - Akamai
    - Fastly

Data source:
    Embedded snapshot of public IP-range feeds. The authoritative URLs:
        https://ip-ranges.amazonaws.com/ip-ranges.json
        https://www.cloudflare.com/ips-v4
        https://www.cloudflare.com/ips-v6
        https://www.gstatic.com/ipranges/cloud.json
        https://download.microsoft.com/download/...ServiceTags...
        https://api.fastly.com/public-ip-list

For v1, we ship a pinned snapshot. A future `refresh()` method will
pull the upstream feeds weekly. An IP not matching any embedded range
is classified `UNKNOWN` — which almost always means "customer-owned
or small hosting provider" (good — these are scannable).

Classification decides:
    - Whether to attempt :443 cert pivot (skip on CDN edges)
    - How to interpret recon findings (CDN IPs aren't customer infra)
    - What stealth rate to use (CDNs block faster than most targets)
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Tuple

logger = logging.getLogger("amoskys.argos.recon.cloud")


class Provider(str, Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    CLOUDFLARE = "cloudflare"
    AKAMAI = "akamai"
    FASTLY = "fastly"
    DIGITALOCEAN = "digitalocean"
    LINODE = "linode"
    UNKNOWN = "unknown"


class CDNBehavior(str, Enum):
    """How this provider affects recon strategy."""
    CDN_PROXY = "cdn_proxy"           # Cloudflare, Akamai, Fastly — origin hidden
    CLOUD_HOSTING = "cloud_hosting"   # AWS/Azure/GCP — customer may own this IP
    UNKNOWN = "unknown"


@dataclass
class Classification:
    provider: Provider
    behavior: CDNBehavior
    matched_cidr: Optional[str] = None
    notes: List[str] = field(default_factory=list)

    @property
    def is_cdn_proxy(self) -> bool:
        return self.behavior == CDNBehavior.CDN_PROXY

    @property
    def should_attempt_tls_pivot(self) -> bool:
        """Is a :443 cert probe likely to yield customer info?

        - UNKNOWN → yes (probably customer or small host)
        - CLOUD_HOSTING → yes (customer might own this specific IP)
        - CDN_PROXY → no (you'll get the CDN's edge cert at best)
        """
        return self.behavior != CDNBehavior.CDN_PROXY


# ── Core classifier ────────────────────────────────────────────────


class CloudDetector:
    """Decides if an IP belongs to a known cloud/CDN provider."""

    def __init__(self) -> None:
        # Pre-parse all CIDRs once at construction.
        # (provider, behavior, cidr)
        self._ranges: List[Tuple[Provider, CDNBehavior, ipaddress.IPv4Network]] = []
        self._ranges6: List[Tuple[Provider, CDNBehavior, ipaddress.IPv6Network]] = []
        self._load_embedded()

    def classify(self, ip: str) -> Classification:
        try:
            parsed = ipaddress.ip_address(ip)
        except ValueError:
            return Classification(
                provider=Provider.UNKNOWN,
                behavior=CDNBehavior.UNKNOWN,
                notes=[f"not a valid IP: {ip!r}"],
            )

        if parsed.is_private or parsed.is_loopback or parsed.is_link_local:
            return Classification(
                provider=Provider.UNKNOWN,
                behavior=CDNBehavior.UNKNOWN,
                notes=["private / loopback / link-local — skip"],
            )

        if parsed.version == 4:
            for provider, behavior, net in self._ranges:
                if parsed in net:
                    return Classification(
                        provider=provider,
                        behavior=behavior,
                        matched_cidr=str(net),
                    )
        else:
            for provider, behavior, net in self._ranges6:
                if parsed in net:
                    return Classification(
                        provider=provider,
                        behavior=behavior,
                        matched_cidr=str(net),
                    )

        return Classification(
            provider=Provider.UNKNOWN,
            behavior=CDNBehavior.UNKNOWN,
        )

    # ── Embedded ranges ────────────────────────────────────────────

    def _load_embedded(self) -> None:
        for cidr, provider, behavior in _EMBEDDED_RANGES:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            if isinstance(net, ipaddress.IPv4Network):
                self._ranges.append((provider, behavior, net))
            else:
                self._ranges6.append((provider, behavior, net))


# ── Embedded range data (v1 snapshot) ─────────────────────────────
#
# Philosophy: ship a SMALL, CURATED set covering the big providers.
# Not exhaustive — if we miss a specific AWS region's netblock, the
# classifier says "unknown" which is safe (we'll probe it, discover
# via :443 that it's an AWS cloudfront, and log that learning).
#
# When refreshing: prefer provider-official JSON feeds over third-party
# scrapers. See module docstring for upstream URLs.

_EMBEDDED_RANGES: List[Tuple[str, Provider, CDNBehavior]] = [
    # ── Cloudflare (IPv4) — stable, publicly documented ────────────
    # https://www.cloudflare.com/ips-v4
    ("173.245.48.0/20",    Provider.CLOUDFLARE, CDNBehavior.CDN_PROXY),
    ("103.21.244.0/22",    Provider.CLOUDFLARE, CDNBehavior.CDN_PROXY),
    ("103.22.200.0/22",    Provider.CLOUDFLARE, CDNBehavior.CDN_PROXY),
    ("103.31.4.0/22",      Provider.CLOUDFLARE, CDNBehavior.CDN_PROXY),
    ("141.101.64.0/18",    Provider.CLOUDFLARE, CDNBehavior.CDN_PROXY),
    ("108.162.192.0/18",   Provider.CLOUDFLARE, CDNBehavior.CDN_PROXY),
    ("190.93.240.0/20",    Provider.CLOUDFLARE, CDNBehavior.CDN_PROXY),
    ("188.114.96.0/20",    Provider.CLOUDFLARE, CDNBehavior.CDN_PROXY),
    ("197.234.240.0/22",   Provider.CLOUDFLARE, CDNBehavior.CDN_PROXY),
    ("198.41.128.0/17",    Provider.CLOUDFLARE, CDNBehavior.CDN_PROXY),
    ("162.158.0.0/15",     Provider.CLOUDFLARE, CDNBehavior.CDN_PROXY),
    ("104.16.0.0/13",      Provider.CLOUDFLARE, CDNBehavior.CDN_PROXY),
    ("104.24.0.0/14",      Provider.CLOUDFLARE, CDNBehavior.CDN_PROXY),
    ("172.64.0.0/13",      Provider.CLOUDFLARE, CDNBehavior.CDN_PROXY),
    ("131.0.72.0/22",      Provider.CLOUDFLARE, CDNBehavior.CDN_PROXY),

    # ── Cloudflare (IPv6) ──────────────────────────────────────────
    ("2400:cb00::/32",     Provider.CLOUDFLARE, CDNBehavior.CDN_PROXY),
    ("2606:4700::/32",     Provider.CLOUDFLARE, CDNBehavior.CDN_PROXY),
    ("2803:f800::/32",     Provider.CLOUDFLARE, CDNBehavior.CDN_PROXY),
    ("2405:b500::/32",     Provider.CLOUDFLARE, CDNBehavior.CDN_PROXY),
    ("2405:8100::/32",     Provider.CLOUDFLARE, CDNBehavior.CDN_PROXY),
    ("2a06:98c0::/29",     Provider.CLOUDFLARE, CDNBehavior.CDN_PROXY),
    ("2c0f:f248::/32",     Provider.CLOUDFLARE, CDNBehavior.CDN_PROXY),

    # ── AWS major blocks (sample; not exhaustive) ──────────────────
    # The full AWS feed is ~7 MB. v1 covers the highest-traffic blocks.
    ("3.0.0.0/8",          Provider.AWS, CDNBehavior.CLOUD_HOSTING),
    ("13.32.0.0/15",       Provider.AWS, CDNBehavior.CLOUD_HOSTING),   # CloudFront
    ("13.224.0.0/14",      Provider.AWS, CDNBehavior.CDN_PROXY),       # CloudFront
    ("18.32.0.0/11",       Provider.AWS, CDNBehavior.CLOUD_HOSTING),
    ("34.192.0.0/10",      Provider.AWS, CDNBehavior.CLOUD_HOSTING),
    ("35.71.0.0/16",       Provider.AWS, CDNBehavior.CLOUD_HOSTING),
    ("52.0.0.0/8",         Provider.AWS, CDNBehavior.CLOUD_HOSTING),
    ("54.0.0.0/8",         Provider.AWS, CDNBehavior.CLOUD_HOSTING),
    ("99.78.128.0/17",     Provider.AWS, CDNBehavior.CLOUD_HOSTING),
    ("107.20.0.0/14",      Provider.AWS, CDNBehavior.CLOUD_HOSTING),
    ("184.72.0.0/15",      Provider.AWS, CDNBehavior.CLOUD_HOSTING),
    ("204.236.128.0/17",   Provider.AWS, CDNBehavior.CLOUD_HOSTING),

    # ── Azure major blocks (sample) ────────────────────────────────
    ("13.64.0.0/11",       Provider.AZURE, CDNBehavior.CLOUD_HOSTING),
    ("20.0.0.0/8",         Provider.AZURE, CDNBehavior.CLOUD_HOSTING),
    ("40.64.0.0/10",       Provider.AZURE, CDNBehavior.CLOUD_HOSTING),
    ("51.0.0.0/8",         Provider.AZURE, CDNBehavior.CLOUD_HOSTING),
    ("65.52.0.0/14",       Provider.AZURE, CDNBehavior.CLOUD_HOSTING),
    ("104.40.0.0/13",      Provider.AZURE, CDNBehavior.CLOUD_HOSTING),
    ("137.116.0.0/15",     Provider.AZURE, CDNBehavior.CLOUD_HOSTING),
    ("157.54.0.0/15",      Provider.AZURE, CDNBehavior.CLOUD_HOSTING),
    ("168.61.0.0/16",      Provider.AZURE, CDNBehavior.CLOUD_HOSTING),

    # ── Google Cloud + Google services ─────────────────────────────
    ("8.8.4.0/24",         Provider.GCP, CDNBehavior.CLOUD_HOSTING),  # dns
    ("8.8.8.0/24",         Provider.GCP, CDNBehavior.CLOUD_HOSTING),  # dns
    ("34.64.0.0/10",       Provider.GCP, CDNBehavior.CLOUD_HOSTING),
    ("35.184.0.0/13",      Provider.GCP, CDNBehavior.CLOUD_HOSTING),
    ("35.192.0.0/14",      Provider.GCP, CDNBehavior.CLOUD_HOSTING),
    ("35.196.0.0/15",      Provider.GCP, CDNBehavior.CLOUD_HOSTING),
    ("35.198.0.0/16",      Provider.GCP, CDNBehavior.CLOUD_HOSTING),
    ("104.196.0.0/14",     Provider.GCP, CDNBehavior.CLOUD_HOSTING),
    ("107.178.192.0/18",   Provider.GCP, CDNBehavior.CLOUD_HOSTING),
    ("130.211.0.0/16",     Provider.GCP, CDNBehavior.CLOUD_HOSTING),
    ("146.148.0.0/17",     Provider.GCP, CDNBehavior.CLOUD_HOSTING),
    ("162.216.148.0/22",   Provider.GCP, CDNBehavior.CLOUD_HOSTING),
    ("162.222.176.0/21",   Provider.GCP, CDNBehavior.CLOUD_HOSTING),

    # ── Akamai (CDN) ───────────────────────────────────────────────
    ("23.32.0.0/11",       Provider.AKAMAI, CDNBehavior.CDN_PROXY),
    ("23.192.0.0/11",      Provider.AKAMAI, CDNBehavior.CDN_PROXY),
    ("96.16.0.0/15",       Provider.AKAMAI, CDNBehavior.CDN_PROXY),
    ("184.24.0.0/13",      Provider.AKAMAI, CDNBehavior.CDN_PROXY),
    ("104.64.0.0/10",      Provider.AKAMAI, CDNBehavior.CDN_PROXY),

    # ── Fastly (CDN) ───────────────────────────────────────────────
    ("23.235.32.0/20",     Provider.FASTLY, CDNBehavior.CDN_PROXY),
    ("43.249.72.0/22",     Provider.FASTLY, CDNBehavior.CDN_PROXY),
    ("103.244.50.0/24",    Provider.FASTLY, CDNBehavior.CDN_PROXY),
    ("103.245.222.0/23",   Provider.FASTLY, CDNBehavior.CDN_PROXY),
    ("103.245.224.0/24",   Provider.FASTLY, CDNBehavior.CDN_PROXY),
    ("146.75.0.0/17",      Provider.FASTLY, CDNBehavior.CDN_PROXY),
    ("151.101.0.0/16",     Provider.FASTLY, CDNBehavior.CDN_PROXY),
    ("157.52.64.0/18",     Provider.FASTLY, CDNBehavior.CDN_PROXY),
    ("167.82.0.0/17",      Provider.FASTLY, CDNBehavior.CDN_PROXY),
    ("167.82.128.0/20",    Provider.FASTLY, CDNBehavior.CDN_PROXY),
    ("167.82.160.0/20",    Provider.FASTLY, CDNBehavior.CDN_PROXY),
    ("167.82.224.0/20",    Provider.FASTLY, CDNBehavior.CDN_PROXY),
    ("172.111.64.0/18",    Provider.FASTLY, CDNBehavior.CDN_PROXY),
    ("185.31.16.0/22",     Provider.FASTLY, CDNBehavior.CDN_PROXY),
    ("199.27.72.0/21",     Provider.FASTLY, CDNBehavior.CDN_PROXY),
    ("199.232.0.0/16",     Provider.FASTLY, CDNBehavior.CDN_PROXY),

    # ── DigitalOcean (small hosting) ───────────────────────────────
    ("45.55.0.0/16",       Provider.DIGITALOCEAN, CDNBehavior.CLOUD_HOSTING),
    ("138.68.0.0/16",      Provider.DIGITALOCEAN, CDNBehavior.CLOUD_HOSTING),
    ("157.230.0.0/16",     Provider.DIGITALOCEAN, CDNBehavior.CLOUD_HOSTING),
    ("159.65.0.0/16",      Provider.DIGITALOCEAN, CDNBehavior.CLOUD_HOSTING),
    ("159.89.0.0/16",      Provider.DIGITALOCEAN, CDNBehavior.CLOUD_HOSTING),
    ("165.22.0.0/16",      Provider.DIGITALOCEAN, CDNBehavior.CLOUD_HOSTING),
    ("167.99.0.0/16",      Provider.DIGITALOCEAN, CDNBehavior.CLOUD_HOSTING),
    ("178.62.0.0/17",      Provider.DIGITALOCEAN, CDNBehavior.CLOUD_HOSTING),
    ("206.189.0.0/16",     Provider.DIGITALOCEAN, CDNBehavior.CLOUD_HOSTING),

    # ── Linode ────────────────────────────────────────────────────
    ("50.116.0.0/16",      Provider.LINODE, CDNBehavior.CLOUD_HOSTING),
    ("66.175.208.0/20",    Provider.LINODE, CDNBehavior.CLOUD_HOSTING),
    ("96.126.96.0/19",     Provider.LINODE, CDNBehavior.CLOUD_HOSTING),
    ("139.162.0.0/16",     Provider.LINODE, CDNBehavior.CLOUD_HOSTING),
    ("172.104.0.0/15",     Provider.LINODE, CDNBehavior.CLOUD_HOSTING),
    ("173.255.192.0/18",   Provider.LINODE, CDNBehavior.CLOUD_HOSTING),
    ("198.58.96.0/19",     Provider.LINODE, CDNBehavior.CLOUD_HOSTING),
]


# ── Cloud-generic hostname patterns ───────────────────────────────
#
# Used by reverse_dns.py to recognize that a PTR result is a provider
# default hostname (not a customer-configured name). These suffixes
# should never be treated as customer-owned domains.

GENERIC_CLOUD_HOSTNAME_SUFFIXES: Tuple[str, ...] = (
    # AWS
    ".compute.amazonaws.com",
    ".compute-1.amazonaws.com",
    ".ec2.internal",
    ".elb.amazonaws.com",
    ".cloudfront.net",
    # Azure
    ".cloudapp.net",
    ".cloudapp.azure.com",
    ".azurewebsites.net",
    # GCP
    ".googleusercontent.com",
    ".bc.googleusercontent.com",
    ".appspot.com",
    # DigitalOcean / Linode
    ".ip.linodeusercontent.com",
    ".members.linode.com",
    # Generic PTR patterns
    ".in-addr.arpa",
)


def is_generic_cloud_hostname(hostname: str) -> bool:
    """True if hostname is a provider-default PTR, not a customer name."""
    if not hostname:
        return True
    h = hostname.lower().rstrip(".")
    for suffix in GENERIC_CLOUD_HOSTNAME_SUFFIXES:
        if h.endswith(suffix):
            return True
    return False
