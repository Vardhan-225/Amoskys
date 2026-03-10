"""Probe contract registry for runtime conformance checks."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass(frozen=True, slots=True)
class ProbeContract:
    """Registered probe contract metadata."""

    probe_name: str
    requires_fields: tuple[str, ...] = field(default_factory=tuple)
    degraded_without: tuple[str, ...] = field(default_factory=tuple)
    requires_event_types: tuple[str, ...] = field(default_factory=tuple)
    field_semantics: Dict[str, str] = field(default_factory=dict)
    expected_cardinality: str = "unknown"
    baseline_max_rate: float = 0.0
    registered_at_ns: int = 0
    last_seen_ns: int = 0


class ProbeContractRegistry:
    """In-memory registry for probe contracts and registry health."""

    def __init__(self) -> None:
        self._contracts: Dict[str, ProbeContract] = {}
        self._lock = threading.Lock()

    def register_probe(
        self,
        probe: Any,
        *,
        expected_cardinality: str = "unknown",
        baseline_max_rate: float = 0.0,
    ) -> ProbeContract:
        """Register or update a probe contract from probe attributes."""
        contract = ProbeContract(
            probe_name=getattr(probe, "name", "unknown"),
            requires_fields=tuple(getattr(probe, "requires_fields", []) or ()),
            degraded_without=tuple(getattr(probe, "degraded_without", []) or ()),
            requires_event_types=tuple(
                getattr(probe, "requires_event_types", []) or ()
            ),
            field_semantics=dict(getattr(probe, "field_semantics", {}) or {}),
            expected_cardinality=expected_cardinality,
            baseline_max_rate=float(baseline_max_rate or 0.0),
            registered_at_ns=int(time.time() * 1e9),
            last_seen_ns=int(time.time() * 1e9),
        )
        with self._lock:
            self._contracts[contract.probe_name] = contract
        return contract

    def refresh_probe(self, probe_name: str) -> bool:
        """Heartbeat a registered probe to mark it alive."""
        now_ns = int(time.time() * 1e9)
        with self._lock:
            contract = self._contracts.get(probe_name)
            if contract is None:
                return False
            self._contracts[probe_name] = ProbeContract(
                probe_name=contract.probe_name,
                requires_fields=contract.requires_fields,
                degraded_without=contract.degraded_without,
                requires_event_types=contract.requires_event_types,
                field_semantics=contract.field_semantics,
                expected_cardinality=contract.expected_cardinality,
                baseline_max_rate=contract.baseline_max_rate,
                registered_at_ns=contract.registered_at_ns,
                last_seen_ns=now_ns,
            )
            return True

    def deregister_probe(self, probe_name: str) -> bool:
        """Remove one probe contract."""
        with self._lock:
            return self._contracts.pop(probe_name, None) is not None

    def expire_stale(self, ttl_seconds: int = 600) -> int:
        """Expire contracts whose heartbeat is older than ttl_seconds."""
        now_ns = int(time.time() * 1e9)
        cutoff = now_ns - int(ttl_seconds * 1e9)
        removed = 0
        with self._lock:
            stale = [
                name
                for name, contract in self._contracts.items()
                if contract.last_seen_ns and contract.last_seen_ns < cutoff
            ]
            for name in stale:
                self._contracts.pop(name, None)
                removed += 1
        return removed

    def snapshot(self) -> Dict[str, Dict[str, Any]]:
        """Return a serializable snapshot for conformance manifests."""
        with self._lock:
            return {
                name: {
                    "requires_fields": list(contract.requires_fields),
                    "degraded_without": list(contract.degraded_without),
                    "requires_event_types": list(contract.requires_event_types),
                    "field_semantics": dict(contract.field_semantics),
                    "expected_cardinality": contract.expected_cardinality,
                    "baseline_max_rate": contract.baseline_max_rate,
                    "registered_at_ns": contract.registered_at_ns,
                    "last_seen_ns": contract.last_seen_ns,
                }
                for name, contract in self._contracts.items()
            }

    def is_registered(self, probe_name: str) -> bool:
        with self._lock:
            return probe_name in self._contracts

    def get_contract(self, probe_name: str) -> Optional[ProbeContract]:
        with self._lock:
            return self._contracts.get(probe_name)

    def get_health(self) -> Dict[str, Any]:
        with self._lock:
            required_fields_total = sum(
                len(c.requires_fields) for c in self._contracts.values()
            )
            degraded_fields_total = sum(
                len(c.degraded_without) for c in self._contracts.values()
            )
            return {
                "registered_probes": len(self._contracts),
                "required_fields_total": required_fields_total,
                "degraded_fields_total": degraded_fields_total,
                "probes": sorted(self._contracts.keys()),
            }


_REGISTRY = ProbeContractRegistry()


def get_probe_contract_registry() -> ProbeContractRegistry:
    """Return singleton probe contract registry."""
    return _REGISTRY
