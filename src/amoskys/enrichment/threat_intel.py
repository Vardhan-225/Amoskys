"""
Threat Intelligence Enrichment for AMOSKYS (A4.3)

Local SQLite-backed indicator store with matching against event fields.

Supports indicator types: IP, domain, file_hash (SHA256), URL.
Feed format: CSV with columns (indicator, type, severity, source, expiry).

Usage:
    enricher = ThreatIntelEnricher("data/threat_intel.db")
    enricher.load_csv("feeds/blocklist.csv")
    result = enricher.check_indicator("evil.example.com", "domain")
    # → {"matched": True, "severity": "high", "source": "blocklist", ...}
"""

from __future__ import annotations

import csv
import logging
import sqlite3
import time
from datetime import datetime, timezone
from functools import lru_cache
from io import StringIO
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_INDICATOR_TYPES = {"ip", "domain", "file_hash", "url"}

_SCHEMA = """\
CREATE TABLE IF NOT EXISTS indicators (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator TEXT NOT NULL,
    type TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'medium',
    source TEXT,
    description TEXT,
    added_at TEXT NOT NULL,
    expires_at TEXT,
    UNIQUE(indicator, type)
);
CREATE INDEX IF NOT EXISTS idx_indicator_value ON indicators(indicator);
CREATE INDEX IF NOT EXISTS idx_indicator_type ON indicators(type);
CREATE INDEX IF NOT EXISTS idx_indicator_expiry ON indicators(expires_at);
"""


class ThreatIntelEnricher:
    """Local threat intelligence indicator store and matcher.

    Stores indicators in SQLite for persistence across restarts.
    Supports loading from CSV files and checking events against
    the indicator database.
    """

    def __init__(
        self,
        db_path: str = "data/threat_intel.db",
        cache_size: int = 10_000,
        cache_ttl_seconds: int = 3600,
    ) -> None:
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._db_path = db_path
        self._cache_ttl = cache_ttl_seconds
        self._cache_epoch = time.monotonic()

        self._conn = sqlite3.connect(db_path, check_same_thread=False, timeout=5.0)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

        self._check_cached = lru_cache(maxsize=cache_size)(self._check_impl)
        self._available = True
        logger.info("ThreatIntel enricher initialized: %s", db_path)

    @property
    def available(self) -> bool:
        return self._available

    def _maybe_expire_cache(self) -> None:
        """Clear cache if TTL has elapsed."""
        if time.monotonic() - self._cache_epoch > self._cache_ttl:
            self._check_cached.cache_clear()
            self._cache_epoch = time.monotonic()

    def add_indicator(
        self,
        indicator: str,
        indicator_type: str,
        severity: str = "medium",
        source: Optional[str] = None,
        description: Optional[str] = None,
        expires_at: Optional[str] = None,
    ) -> bool:
        """Add a single indicator to the store.

        Returns True if added, False if duplicate.
        """
        indicator_type = indicator_type.lower()
        if indicator_type not in _INDICATOR_TYPES:
            logger.warning("Unknown indicator type: %s", indicator_type)
            return False

        try:
            self._conn.execute(
                "INSERT OR REPLACE INTO indicators "
                "(indicator, type, severity, source, description, added_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    indicator.strip().lower(),
                    indicator_type,
                    severity.lower(),
                    source,
                    description,
                    datetime.now(timezone.utc).isoformat(),
                    expires_at,
                ),
            )
            self._conn.commit()
            return True
        except sqlite3.Error:
            logger.exception("Failed to add indicator: %s", indicator)
            return False

    def load_csv(self, csv_path_or_text: str, source: Optional[str] = None) -> int:
        """Load indicators from CSV file or CSV text.

        Expected columns: indicator, type, severity, source, expiry
        (source and expiry are optional).

        Returns number of indicators loaded.
        """
        count = 0

        if Path(csv_path_or_text).is_file():
            text = Path(csv_path_or_text).read_text()
        else:
            text = csv_path_or_text

        reader = csv.DictReader(StringIO(text))
        for row in reader:
            indicator = row.get("indicator", "").strip()
            itype = row.get("type", "").strip()
            severity = row.get("severity", "medium").strip()
            src = row.get("source", source or "csv_import")
            expiry = row.get("expiry") or row.get("expires_at")

            if indicator and itype:
                if self.add_indicator(
                    indicator, itype, severity, src, expires_at=expiry
                ):
                    count += 1

        logger.info("Loaded %d indicators from CSV", count)
        self._check_cached.cache_clear()
        self._cache_epoch = time.monotonic()
        return count

    def check_indicator(
        self, value: str, indicator_type: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Check if a value matches any known indicator.

        Args:
            value: The value to check (IP, domain, hash, URL).
            indicator_type: Optional type filter.

        Returns:
            Match dict with severity, source, etc. — or None.
        """
        if not value:
            return None
        self._maybe_expire_cache()
        key = (value.strip().lower(), indicator_type or "")
        return self._check_cached(key)

    def _check_impl(self, key: tuple) -> Optional[Dict[str, Any]]:
        """Actual DB lookup (wrapped by LRU cache)."""
        value, itype = key
        try:
            if itype:
                row = self._conn.execute(
                    "SELECT * FROM indicators WHERE indicator = ? AND type = ? "
                    "AND (expires_at IS NULL OR expires_at > ?) LIMIT 1",
                    (value, itype, datetime.now(timezone.utc).isoformat()),
                ).fetchone()
            else:
                row = self._conn.execute(
                    "SELECT * FROM indicators WHERE indicator = ? "
                    "AND (expires_at IS NULL OR expires_at > ?) LIMIT 1",
                    (value, datetime.now(timezone.utc).isoformat()),
                ).fetchone()

            if row:
                return {
                    "matched": True,
                    "indicator": row["indicator"],
                    "type": row["type"],
                    "severity": row["severity"],
                    "source": row["source"],
                    "description": row["description"],
                }
            return None
        except sqlite3.Error:
            logger.debug("ThreatIntel lookup failed for %s", value, exc_info=True)
            return None

    def enrich_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich event by checking IP, domain, and hash fields.

        Sets ``threat_intel_match`` (bool) and ``threat_source`` on the event.
        """
        matches: List[Dict[str, Any]] = []

        # Check IP fields
        for field in ("src_ip", "dst_ip", "source_ip"):
            ip = event.get(field)
            if ip:
                result = self.check_indicator(ip, "ip")
                if result:
                    matches.append(result)

        # Check domain fields
        for field in ("domain", "hostname"):
            domain = event.get(field)
            if domain:
                result = self.check_indicator(domain, "domain")
                if result:
                    matches.append(result)

        # Check hash fields
        for field in ("file_hash", "sha256", "new_hash"):
            h = event.get(field)
            if h:
                result = self.check_indicator(h, "file_hash")
                if result:
                    matches.append(result)

        if matches:
            event["threat_intel_match"] = True
            # Use the highest severity match
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            best = min(matches, key=lambda m: severity_order.get(m["severity"], 99))
            event["threat_source"] = best["source"]
            event["threat_severity"] = best["severity"]
        else:
            event["threat_intel_match"] = False

        return event

    def indicator_count(self) -> int:
        """Return total number of active (non-expired) indicators."""
        try:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM indicators "
                "WHERE expires_at IS NULL OR expires_at > ?",
                (datetime.now(timezone.utc).isoformat(),),
            ).fetchone()
            return row[0]
        except sqlite3.Error:
            return 0

    def cache_info(self) -> Dict[str, Any]:
        info = self._check_cached.cache_info()
        return {
            "hits": info.hits,
            "misses": info.misses,
            "size": info.currsize,
            "maxsize": info.maxsize,
            "ttl_seconds": self._cache_ttl,
        }

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None
            self._available = False
