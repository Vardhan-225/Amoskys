"""Balanced observation shaping policy for high-volume telemetry domains."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any, Dict, Tuple


@dataclass(frozen=True, slots=True)
class ObservationDecision:
    """Decision result for a single observation event."""

    store_raw: bool
    domain: str
    fingerprint: str
    window_start_ns: int
    window_end_ns: int


class ObservationShaper:
    """Adaptive observation shaper used under pressure in Balanced mode.

    Policy:
      - Preserve first-seen observations.
      - Preserve risk-relevant observations.
      - Preserve up to N raw observations per (domain, fingerprint, minute window).
      - Roll up additional repeats in observation_rollups.
    """

    _WINDOW_NS = 60_000_000_000  # 60s windows
    _KEEP_WINDOWS = 4

    def __init__(self) -> None:
        default_max = int(os.getenv("AMOSKYS_OBS_MAX_RAW_PER_WINDOW", "200"))
        self._limits: Dict[str, int] = {
            "default": default_max,
            "flow": int(os.getenv("AMOSKYS_OBS_MAX_RAW_FLOW", "800")),
            "process": int(os.getenv("AMOSKYS_OBS_MAX_RAW_PROCESS", "500")),
            "dns": int(os.getenv("AMOSKYS_OBS_MAX_RAW_DNS", "500")),
            "auth": int(os.getenv("AMOSKYS_OBS_MAX_RAW_AUTH", "250")),
            "filesystem": int(os.getenv("AMOSKYS_OBS_MAX_RAW_FILESYSTEM", "300")),
            "persistence": int(os.getenv("AMOSKYS_OBS_MAX_RAW_PERSISTENCE", "300")),
            "peripheral": int(os.getenv("AMOSKYS_OBS_MAX_RAW_PERIPHERAL", "300")),
        }
        self._first_seen: set[str] = set()
        self._counts: Dict[Tuple[str, int, str], int] = {}
        self._latest_window_start = 0

    def decide(
        self, domain: str, attrs: Dict[str, Any], ts_ns: int
    ) -> ObservationDecision:
        """Return whether to keep this observation raw or roll it up."""
        domain = (domain or "unknown").strip().lower()
        window_start = ts_ns - (ts_ns % self._WINDOW_NS)
        window_end = window_start + self._WINDOW_NS
        fingerprint = self._fingerprint(domain, attrs)
        key = (domain, window_start, fingerprint)

        if window_start > self._latest_window_start:
            self._latest_window_start = window_start
            self._evict_stale()

        self._counts[key] = self._counts.get(key, 0) + 1
        seen_count = self._counts[key]
        max_raw = self._limits.get(domain, self._limits["default"])

        if fingerprint not in self._first_seen:
            self._first_seen.add(fingerprint)
            return ObservationDecision(
                True, domain, fingerprint, window_start, window_end
            )

        if self._is_risk_relevant(attrs):
            return ObservationDecision(
                True, domain, fingerprint, window_start, window_end
            )

        return ObservationDecision(
            store_raw=seen_count <= max_raw,
            domain=domain,
            fingerprint=fingerprint,
            window_start_ns=window_start,
            window_end_ns=window_end,
        )

    @staticmethod
    def _is_risk_relevant(attrs: Dict[str, Any]) -> bool:
        risk_keys = (
            "risk_score",
            "threat_intel_match",
            "is_suspicious",
            "requires_investigation",
        )
        for key in risk_keys:
            value = attrs.get(key)
            if isinstance(value, (int, float)) and value > 0:
                return True
            if isinstance(value, str) and value.lower() in {"true", "1", "yes"}:
                return True
            if value is True:
                return True
        return False

    @staticmethod
    def _fingerprint(domain: str, attrs: Dict[str, Any]) -> str:
        ignored = {"timestamp", "event_timestamp_ns", "collection_time_ms"}
        stable = {k: attrs[k] for k in sorted(attrs.keys()) if k not in ignored}
        payload = json.dumps(
            {"domain": domain, "attrs": stable}, sort_keys=True, default=str
        )
        return hashlib.blake2b(payload.encode("utf-8"), digest_size=16).hexdigest()

    def _evict_stale(self) -> None:
        if self._latest_window_start <= 0:
            return
        cutoff = self._latest_window_start - (self._KEEP_WINDOWS * self._WINDOW_NS)
        stale = [k for k in self._counts if k[1] < cutoff]
        for key in stale:
            del self._counts[key]
