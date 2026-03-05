"""
BLAKE2b Content-Hash Event Deduplicator

Generates semantic fingerprints from event content (device_id, event_category,
event_action, target_resource) — ignoring timestamps. Maintains a TTL cache
to suppress repeated identical events within a configurable window.

This sits between WAL ingestion and storage INSERT, preventing the same
detection from being stored hundreds of times per scan cycle.
"""

from __future__ import annotations

import hashlib
import logging
import time
from typing import Any, Dict

logger = logging.getLogger(__name__)


class EventDeduplicator:
    """BLAKE2b content-hash deduplication at WAL ingestion.

    Generates a semantic fingerprint from (device_id, event_category,
    event_action, target_resource) — ignoring timestamps. Maintains a
    TTL cache (default 300s) to suppress repeated identical events.

    Usage:
        dedup = EventDeduplicator(ttl_seconds=300)
        if dedup.is_duplicate(event_dict):
            return  # skip storage
        dedup.record(event_dict)
        store.insert_security_event(event_dict)
    """

    def __init__(self, ttl_seconds: int = 300, max_cache: int = 50000) -> None:
        self._ttl = ttl_seconds
        self._max_cache = max_cache
        # fingerprint → last_seen_ts
        self._cache: Dict[str, float] = {}
        self._total_seen = 0
        self._total_deduped = 0
        self._last_cleanup = 0.0

    def fingerprint(self, event_dict: Dict[str, Any]) -> str:
        """Generate BLAKE2b semantic fingerprint ignoring timestamps.

        Fields used for fingerprinting:
        - device_id: which device
        - event_category: type of event (suid_bit_added, auth_failure, etc.)
        - event_action: what happened (FILE_INTEGRITY, AUTH, etc.)
        - target_resource: what was targeted (/usr/bin/sudo, sshd, etc.)
        - source_ip: who did it (if network-related)
        - indicators: enrichment data (JSON string)

        This means the same detection on the same target from the same source
        within the TTL window is deduplicated, even if the raw event has a
        different timestamp.
        """
        parts = [
            event_dict.get("device_id", ""),
            event_dict.get("event_category", ""),
            event_dict.get("event_action", ""),
            event_dict.get("target_resource", ""),
            event_dict.get("source_ip", ""),
            event_dict.get("collection_agent", ""),
        ]
        content = "|".join(str(p) for p in parts)
        return hashlib.blake2b(content.encode(), digest_size=16).hexdigest()

    def is_duplicate(self, event_dict: Dict[str, Any]) -> bool:
        """Check if this event is a duplicate within the TTL window.

        Returns True if a semantically identical event was seen within
        the last ttl_seconds. Does NOT record the event — call record()
        separately after deciding to store it.
        """
        self._total_seen += 1
        now = time.time()

        # Periodic cleanup
        if now - self._last_cleanup > 60:
            self._cleanup(now)

        fp = self.fingerprint(event_dict)
        last_seen = self._cache.get(fp)

        if last_seen is not None and (now - last_seen) < self._ttl:
            self._total_deduped += 1
            return True

        return False

    def record(self, event_dict: Dict[str, Any]) -> None:
        """Record this event's fingerprint in the cache."""
        fp = self.fingerprint(event_dict)
        self._cache[fp] = time.time()

    def _cleanup(self, now: float) -> None:
        """Remove expired entries from cache. Called periodically."""
        self._last_cleanup = now
        cutoff = now - self._ttl

        expired = [k for k, ts in self._cache.items() if ts < cutoff]
        for k in expired:
            del self._cache[k]

        # If still over max, evict oldest entries
        if len(self._cache) > self._max_cache:
            sorted_entries = sorted(self._cache.items(), key=lambda x: x[1])
            to_remove = len(self._cache) - self._max_cache
            for k, _ in sorted_entries[:to_remove]:
                del self._cache[k]

        if expired:
            logger.debug(
                "Dedup cleanup: removed %d expired, cache size %d",
                len(expired),
                len(self._cache),
            )

    def stats(self) -> Dict[str, Any]:
        """Return deduplication statistics."""
        return {
            "total_seen": self._total_seen,
            "total_deduped": self._total_deduped,
            "dedup_rate": (
                f"{self._total_deduped / self._total_seen * 100:.1f}%"
                if self._total_seen > 0
                else "0.0%"
            ),
            "cache_size": len(self._cache),
            "ttl_seconds": self._ttl,
        }
