"""Collector ABC — the formal contract for all AMOSKYS data collectors.

Every agent domain has a Collector that gathers raw OS data. Probes then
analyze that data to detect threats. The separation is strict:
    - Collectors observe. They never make detection decisions.
    - Probes detect. They never call OS APIs directly.

Collectors receive an OSLayer instance for all platform-specific calls,
making them testable via StubOSLayer injection (no subprocess mocking).

Usage:
    class MacOSProcessCollector(Collector):
        def collect(self) -> Dict[str, Any]:
            processes = self.os_layer.list_processes()
            return {"processes": processes, "count": len(processes)}

        def get_capabilities(self) -> Dict[str, CapabilityBadge]:
            return {"process_enumeration": CapabilityBadge.REAL}

Ground rules:
    1. collect() MUST return a dict — keys become ProbeContext.shared_data keys
    2. collect() MUST include collection_time_ms for observability
    3. collect() MUST NOT raise — return empty/degraded data on failure
    4. get_capabilities() declares what the collector can see (REAL/DEGRADED/BLIND)
    5. Collectors are stateless across cycles (no mutable instance state between calls)
"""

from __future__ import annotations

import enum
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class CapabilityBadge(enum.Enum):
    """What a collector can see on the current platform.

    REAL:     Full fidelity, ground-truth verified.
    DEGRADED: Works but with known gaps (e.g., TCC without FDA).
    BLIND:    Cannot see this data source at all (e.g., kernel audit on macOS 26).
    STUB:     Code exists but not implemented/tested.
    """

    REAL = "REAL"
    DEGRADED = "DEGRADED"
    BLIND = "BLIND"
    STUB = "STUB"


@dataclass
class CollectorCapability:
    """A single capability declaration from a collector."""

    name: str
    badge: CapabilityBadge
    source: str = ""  # API/tool used (e.g., "psutil", "lsof -i -nP")
    notes: str = ""  # Why degraded/blind, permission requirements
    data_keys: List[str] = field(default_factory=list)  # shared_data keys this provides


@dataclass
class CollectionResult:
    """Structured result from a collection cycle.

    Wraps the raw shared_data dict with metadata for observability.
    """

    shared_data: Dict[str, Any]
    collection_time_ms: float
    capabilities: Dict[str, CapabilityBadge]
    errors: List[str] = field(default_factory=list)
    degraded_sources: List[str] = field(default_factory=list)
    items_collected: int = 0

    @property
    def is_healthy(self) -> bool:
        """True if collection completed without critical errors."""
        return len(self.errors) == 0

    @property
    def has_data(self) -> bool:
        """True if any data was collected (not empty)."""
        return self.items_collected > 0


class Collector(ABC):
    """Base collector — gathers raw OS data for probes to analyze.

    Subclasses implement collect() to return a shared_data dict that probes
    consume via ProbeContext. The OSLayer provides all platform-specific calls.

    Args:
        device_id: Device identifier (hostname by default).
        os_layer: Optional OSLayer for platform calls. If None, collector
                  uses its own platform-specific implementation (backward compat).
        collection_timeout: Max seconds before collection aborts.
    """

    def __init__(
        self,
        device_id: str = "",
        os_layer: Optional[Any] = None,
        collection_timeout: float = 30.0,
    ) -> None:
        self.device_id = device_id or _get_default_device_id()
        self.os_layer = os_layer
        self.collection_timeout = collection_timeout
        self._last_collection_time_ms: float = 0.0
        self._last_error: Optional[str] = None

    @abstractmethod
    def collect(self) -> Dict[str, Any]:
        """Gather raw data from OS. Returns shared_data dict for probes.

        Contract:
            - MUST return a dict (never raise)
            - MUST include 'collection_time_ms' key
            - On failure, return dict with empty data + error info
            - Keys in the returned dict become ProbeContext.shared_data keys
        """
        ...

    def collect_safe(self) -> CollectionResult:
        """Collect with structured error handling and timing.

        Wraps collect() with timing, error capture, and capability reporting.
        Agents can call this instead of collect() for richer observability.
        """
        start = time.monotonic()
        errors: List[str] = []
        shared_data: Dict[str, Any] = {}

        try:
            shared_data = self.collect()
        except Exception as exc:
            error_msg = f"{type(exc).__name__}: {exc}"
            errors.append(error_msg)
            logger.error(
                "COLLECTOR_FAILURE: collector=%s error=%s",
                type(self).__name__,
                error_msg,
            )
            shared_data = self._empty_result()

        elapsed_ms = (time.monotonic() - start) * 1000
        self._last_collection_time_ms = elapsed_ms

        # Ensure collection_time_ms is always present
        shared_data.setdefault("collection_time_ms", elapsed_ms)

        # Get capabilities
        try:
            capabilities = self.get_capabilities()
        except Exception:
            capabilities = {}

        # Count items (heuristic: sum lengths of list-valued entries)
        items = 0
        for v in shared_data.values():
            if isinstance(v, (list, tuple)):
                items += len(v)

        # Identify degraded sources
        degraded = [
            name
            for name, badge in capabilities.items()
            if badge in (CapabilityBadge.DEGRADED, CapabilityBadge.BLIND)
        ]

        return CollectionResult(
            shared_data=shared_data,
            collection_time_ms=elapsed_ms,
            capabilities=capabilities,
            errors=errors,
            degraded_sources=degraded,
            items_collected=items,
        )

    def get_capabilities(self) -> Dict[str, CapabilityBadge]:
        """Declare what this collector can see on the current platform.

        Override in subclasses. Returns dict of capability_name → badge.
        Used by probe contract validation and agent heartbeat reporting.

        Default: empty (no capabilities declared — forces subclasses to be explicit).
        """
        return {}

    def get_capability_details(self) -> List[CollectorCapability]:
        """Detailed capability declarations with source and notes.

        Override for richer capability reporting. Default derives from
        get_capabilities() with no extra detail.
        """
        return [
            CollectorCapability(name=name, badge=badge)
            for name, badge in self.get_capabilities().items()
        ]

    def _empty_result(self) -> Dict[str, Any]:
        """Return an empty-but-valid shared_data dict on collection failure.

        Override in subclasses to provide domain-specific empty structures.
        """
        return {"collection_time_ms": 0.0}

    @property
    def last_collection_time_ms(self) -> float:
        """Duration of the most recent collect() call."""
        return self._last_collection_time_ms


def _get_default_device_id() -> str:
    """Get default device ID (hostname)."""
    import socket

    try:
        return socket.gethostname()
    except Exception:
        return "unknown"
