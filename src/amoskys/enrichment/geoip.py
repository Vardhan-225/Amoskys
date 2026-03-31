"""
GeoIP Enrichment for AMOSKYS (A4.1)

Resolves IP addresses to geographic location using MaxMind GeoLite2-City.

Usage:
    enricher = GeoIPEnricher("/path/to/GeoLite2-City.mmdb")
    result = enricher.lookup("8.8.8.8")
    # → {"country": "US", "city": "Mountain View", "latitude": 37.386, ...}

The enricher uses an LRU cache (default 10K entries) for performance.
If the MaxMind database is unavailable, lookups return None gracefully.
"""

from __future__ import annotations

import ipaddress
import logging
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# Default MaxMind DB paths (checked in order)
_DEFAULT_DB_PATHS = [
    "/usr/share/GeoIP/GeoLite2-City.mmdb",
    "/var/lib/GeoIP/GeoLite2-City.mmdb",
    "/var/lib/amoskys/geoip/GeoLite2-City.mmdb",
    "/Library/Amoskys/data/geoip/GeoLite2-City.mmdb",
    "data/geoip/GeoLite2-City.mmdb",
    "geoip/GeoLite2-City.mmdb",
]

# Private / reserved ranges that should never be geo-looked up
_SKIP_PREFIXES = ("127.", "10.", "192.168.", "172.16.", "0.", "::1", "fe80:")


def _is_private_ip(ip: str) -> bool:
    """Return True if the IP is private, loopback, or link-local."""
    if any(ip.startswith(p) for p in _SKIP_PREFIXES):
        return True
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True  # unparseable → skip


class GeoIPEnricher:
    """Resolve IP addresses to geographic coordinates and metadata.

    Wraps the ``maxminddb`` reader (or ``geoip2``) with:
      - LRU cache (configurable size, default 10 000)
      - Graceful degradation when DB is missing
      - Private-IP short-circuit
    """

    def __init__(
        self,
        db_path: Optional[str] = None,
        cache_size: int = 10_000,
    ) -> None:
        self._reader: Any = None
        self._available = False
        self._db_path: Optional[str] = None

        # Resolve database path
        paths_to_try = [db_path] if db_path else _DEFAULT_DB_PATHS
        for candidate in paths_to_try:
            if candidate and Path(candidate).is_file():
                self._db_path = candidate
                break

        if self._db_path:
            try:
                import maxminddb

                self._reader = maxminddb.open_database(self._db_path)
                self._available = True
                logger.info("GeoIP enricher loaded: %s", self._db_path)
            except ImportError:
                logger.warning(
                    "maxminddb package not installed — GeoIP enrichment disabled. "
                    "Install with: pip install maxminddb"
                )
            except Exception:
                logger.warning("Failed to open GeoIP database", exc_info=True)
        else:
            logger.info(
                "GeoIP database not found — enrichment disabled. "
                "Download GeoLite2-City.mmdb from MaxMind."
            )

        # Build cached lookup with configurable size
        self._lookup_cached = lru_cache(maxsize=cache_size)(self._lookup_impl)

    @property
    def available(self) -> bool:
        """True if GeoIP database is loaded and ready."""
        return self._available

    def lookup(self, ip: str) -> Optional[Dict[str, Any]]:
        """Look up geographic data for an IP address.

        Args:
            ip: IPv4 or IPv6 address string.

        Returns:
            Dict with keys: country, city, latitude, longitude, continent,
            timezone — or None if unavailable / private IP.
        """
        if not ip or _is_private_ip(ip):
            return None
        if not self._available:
            return None
        return self._lookup_cached(ip)

    def _lookup_impl(self, ip: str) -> Optional[Dict[str, Any]]:
        """Actual lookup (wrapped by LRU cache)."""
        try:
            record = self._reader.get(ip)
            if not record:
                return None

            country = record.get("country", {})
            city = record.get("city", {})
            location = record.get("location", {})
            continent = record.get("continent", {})

            return {
                "country": country.get("iso_code"),
                "country_name": (country.get("names") or {}).get("en"),
                "city": (city.get("names") or {}).get("en"),
                "latitude": location.get("latitude"),
                "longitude": location.get("longitude"),
                "continent": (continent.get("names") or {}).get("en"),
                "timezone": location.get("time_zone"),
            }
        except Exception:
            logger.debug("GeoIP lookup failed for %s", ip, exc_info=True)
            return None

    def enrich_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich an event dict with GeoIP data for IP fields.

        Looks for src_ip, dst_ip, source_ip fields and adds geo_* prefixed
        results.

        Args:
            event: Mutable event dictionary.

        Returns:
            The same event dict, enriched in place.
        """
        for ip_field, prefix in [
            ("src_ip", "geo_src_"),
            ("dst_ip", "geo_dst_"),
            ("source_ip", "geo_src_"),
        ]:
            ip = event.get(ip_field)
            if ip:
                geo = self.lookup(ip)
                if geo:
                    for k, v in geo.items():
                        event[f"{prefix}{k}"] = v
        return event

    def cache_info(self) -> Dict[str, int]:
        """Return LRU cache statistics."""
        info = self._lookup_cached.cache_info()
        return {
            "hits": info.hits,
            "misses": info.misses,
            "size": info.currsize,
            "maxsize": info.maxsize,
        }

    def close(self) -> None:
        """Close the MaxMind database reader."""
        if self._reader:
            self._reader.close()
            self._reader = None
            self._available = False
