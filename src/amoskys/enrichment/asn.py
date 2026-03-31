"""
ASN Enrichment for AMOSKYS (A4.2)

Resolves IP addresses to Autonomous System Number (ASN) and organization,
then classifies the network type.

Usage:
    enricher = ASNEnricher("/path/to/GeoLite2-ASN.mmdb")
    result = enricher.lookup("8.8.8.8")
    # → {"number": 15169, "org": "Google LLC", "network_type": "hosting"}
"""

from __future__ import annotations

import logging
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Optional, Set

logger = logging.getLogger(__name__)

# Default MaxMind ASN DB paths
_DEFAULT_DB_PATHS = [
    "/usr/share/GeoIP/GeoLite2-ASN.mmdb",
    "/var/lib/GeoIP/GeoLite2-ASN.mmdb",
    "/var/lib/amoskys/geoip/GeoLite2-ASN.mmdb",
    "/Library/Amoskys/data/geoip/GeoLite2-ASN.mmdb",
    "data/geoip/GeoLite2-ASN.mmdb",
    "geoip/GeoLite2-ASN.mmdb",
]

# Well-known hosting / cloud provider ASNs
_HOSTING_ASNS: Set[int] = {
    # Major cloud providers
    16509,  # Amazon AWS
    14618,  # Amazon
    15169,  # Google Cloud
    8075,  # Microsoft Azure
    13335,  # Cloudflare
    20940,  # Akamai
    54113,  # Fastly
    396982,  # Google Cloud
    # Major hosting providers
    63949,  # Linode
    14061,  # DigitalOcean
    20473,  # Vultr
    24940,  # Hetzner
    16276,  # OVH
}

# Known Tor exit relay ASNs (partial, well-known)
_TOR_ASNS: Set[int] = {
    680,  # DFN (common Tor relay host)
    553,  # BelWue
}

# Known VPN provider ASNs (partial)
_VPN_ASNS: Set[int] = {
    9009,  # M247 (NordVPN, etc.)
    212238,  # Datacamp / Surfshark
    20473,  # Vultr (commonly VPN)
}

# Network type keywords in org names
_HOSTING_KEYWORDS = {"hosting", "cloud", "server", "datacenter", "data center", "vps"}
_EDUCATION_KEYWORDS = {"university", "college", "academic", "education", ".edu"}
_GOVERNMENT_KEYWORDS = {"government", "federal", "military", ".gov", ".mil"}


def _classify_network(asn_number: Optional[int], asn_org: Optional[str]) -> str:
    """Classify a network based on ASN number and organization name.

    Returns one of: hosting, tor, vpn, education, government,
    corporate, residential, unknown.
    """
    if asn_number:
        if asn_number in _HOSTING_ASNS:
            return "hosting"
        if asn_number in _TOR_ASNS:
            return "tor"
        if asn_number in _VPN_ASNS:
            return "vpn"

    org_lower = (asn_org or "").lower()

    if any(kw in org_lower for kw in _HOSTING_KEYWORDS):
        return "hosting"
    if any(kw in org_lower for kw in _EDUCATION_KEYWORDS):
        return "education"
    if any(kw in org_lower for kw in _GOVERNMENT_KEYWORDS):
        return "government"

    # ISPs / telcos → residential
    for kw in ("telecom", "comcast", "verizon", "at&t", "isp", "broadband"):
        if kw in org_lower:
            return "residential"

    return "corporate"


class ASNEnricher:
    """Resolve IP addresses to ASN information and network classification.

    Wraps MaxMind GeoLite2-ASN with LRU cache and classification.
    """

    def __init__(
        self,
        db_path: Optional[str] = None,
        cache_size: int = 10_000,
    ) -> None:
        self._reader: Any = None
        self._available = False

        paths_to_try = [db_path] if db_path else _DEFAULT_DB_PATHS
        for candidate in paths_to_try:
            if candidate and Path(candidate).is_file():
                try:
                    import maxminddb

                    self._reader = maxminddb.open_database(candidate)
                    self._available = True
                    logger.info("ASN enricher loaded: %s", candidate)
                except ImportError:
                    logger.warning(
                        "maxminddb package not installed — ASN enrichment disabled"
                    )
                except Exception:
                    logger.warning("Failed to open ASN database", exc_info=True)
                break

        if not self._available:
            logger.info("ASN database not found — enrichment disabled")

        self._lookup_cached = lru_cache(maxsize=cache_size)(self._lookup_impl)

    @property
    def available(self) -> bool:
        return self._available

    def lookup(self, ip: str) -> Optional[Dict[str, Any]]:
        """Look up ASN data for an IP address.

        Returns:
            Dict with keys: number, org, network_type,
            is_hosting, is_tor, is_vpn — or None.
        """
        if not ip or not self._available:
            return None

        # Skip private IPs
        from amoskys.enrichment.geoip import _is_private_ip

        if _is_private_ip(ip):
            return None

        return self._lookup_cached(ip)

    def _lookup_impl(self, ip: str) -> Optional[Dict[str, Any]]:
        try:
            record = self._reader.get(ip)
            if not record:
                return None

            asn_number = record.get("autonomous_system_number")
            asn_org = record.get("autonomous_system_organization")
            network_type = _classify_network(asn_number, asn_org)

            return {
                "number": asn_number,
                "org": asn_org,
                "network_type": network_type,
                "is_hosting": network_type == "hosting",
                "is_tor": network_type == "tor",
                "is_vpn": network_type == "vpn",
            }
        except Exception:
            logger.debug("ASN lookup failed for %s", ip, exc_info=True)
            return None

    def enrich_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich event with ASN data for IP fields."""
        for ip_field, prefix in [
            ("src_ip", "asn_src_"),
            ("dst_ip", "asn_dst_"),
            ("source_ip", "asn_src_"),
        ]:
            ip = event.get(ip_field)
            if ip:
                asn = self.lookup(ip)
                if asn:
                    for k, v in asn.items():
                        event[f"{prefix}{k}"] = v
        return event

    def cache_info(self) -> Dict[str, int]:
        info = self._lookup_cached.cache_info()
        return {
            "hits": info.hits,
            "misses": info.misses,
            "size": info.currsize,
            "maxsize": info.maxsize,
        }

    def close(self) -> None:
        if self._reader:
            self._reader.close()
            self._reader = None
            self._available = False
