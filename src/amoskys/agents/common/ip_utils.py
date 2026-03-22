"""Shared IP classification utilities for AMOSKYS agents.

Centralizes private/public IP detection and benign domain classification
used across DNS, Network, Discovery, Internet Activity, Correlation,
and HTTP Inspector probes.
"""

from __future__ import annotations

from typing import FrozenSet, Tuple

# RFC 1918 + RFC 6598 + loopback + link-local
PRIVATE_PREFIXES: Tuple[str, ...] = (
    "10.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.20.",
    "172.21.",
    "172.22.",
    "172.23.",
    "172.24.",
    "172.25.",
    "172.26.",
    "172.27.",
    "172.28.",
    "172.29.",
    "172.30.",
    "172.31.",
    "192.168.",
    "127.",
    "169.254.",  # link-local
    "100.64.",  # CGN (RFC 6598)
    "fd",  # IPv6 ULA
    "fe80:",  # IPv6 link-local
    "::1",  # IPv6 loopback
)


def is_private_ip(ip: str) -> bool:
    """Check if an IP address is in a private/reserved range."""
    if not ip:
        return True  # Empty/missing IP is non-routable
    ip_clean = ip.strip("[]")
    if ip_clean in ("0.0.0.0", "::", "::1", "127.0.0.1"):
        return True
    return any(ip_clean.startswith(p) for p in PRIVATE_PREFIXES)


def is_public_ip(ip: str) -> bool:
    """Check if an IP address is publicly routable."""
    if not ip or ip == "0.0.0.0" or ip == "::":
        return False
    return not is_private_ip(ip)


# ── Benign Domain Classification ────────────────────────────────────────────

BENIGN_DOMAINS: FrozenSet[str] = frozenset(
    {
        # Apple
        "apple.com",
        "icloud.com",
        "mzstatic.com",
        "apple-dns.net",
        "cdn-apple.com",
        "push.apple.com",
        "aaplimg.com",
        # Google
        "google.com",
        "googleapis.com",
        "gstatic.com",
        "youtube.com",
        "googlevideo.com",
        "googleusercontent.com",
        "google-analytics.com",
        # Microsoft
        "microsoft.com",
        "windows.com",
        "office.com",
        "live.com",
        "microsoftonline.com",
        "azure.com",
        "msedge.net",
        # CDN / Infrastructure
        "cloudflare.com",
        "cloudfront.net",
        "akamaiedge.net",
        "fastly.net",
        "edgecastcdn.net",
        "jsdelivr.net",
        # AI / LLM
        "anthropic.com",
        "openai.com",
        # Development
        "github.com",
        "githubusercontent.com",
        "npmjs.org",
        "pypi.org",
        "docker.com",
        "docker.io",
        # Common services
        "amazonaws.com",
        "slack.com",
        "zoom.us",
        "dropbox.com",
    }
)

BENIGN_SUFFIXES: Tuple[str, ...] = tuple(f".{d}" for d in BENIGN_DOMAINS)


def is_benign_domain(domain: str) -> bool:
    """Check if a domain belongs to a known benign service."""
    if not domain:
        return False
    d = domain.lower().rstrip(".")
    # Extract effective domain (last 2 or 3 parts)
    parts = d.split(".")
    if len(parts) >= 2:
        effective = ".".join(parts[-2:])
    else:
        effective = d
    if effective in BENIGN_DOMAINS:
        return True
    return d.endswith(BENIGN_SUFFIXES)
