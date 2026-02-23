"""FlowStateTable — stateful connection tracking across lsof snapshots.

Transforms point-in-time lsof snapshots into stateful flows with:
  - Real duration (first_seen_ns → last_seen_ns across snapshots)
  - Observation count (seen_count as proxy for packet_count)
  - Per-flow byte estimation (distributing nettop per-process deltas)

The FlowStateTable is the "memory" that turns snapshot Eyes into
a Vision of connection behaviour over time.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Flow key: 5-tuple uniquely identifying a connection
FlowKey = Tuple[
    str, int, str, int, str
]  # (src_ip, src_port, dst_ip, dst_port, protocol)


@dataclass
class FlowState:
    """Tracked state for a single connection across snapshots."""

    key: FlowKey
    pid: Optional[int]
    first_seen_ns: int
    last_seen_ns: int
    seen_count: int = 1
    bytes_tx_estimated: int = 0
    bytes_rx_estimated: int = 0


class FlowStateTable:
    """Maintains connection state across lsof snapshots.

    Usage::

        table = FlowStateTable()
        # Each collection cycle:
        enriched = table.update(raw_flows, nettop_records)
        # enriched flows now have real duration, seen_count, and byte estimates
    """

    def __init__(self, max_idle_cycles: int = 3) -> None:
        self._states: Dict[FlowKey, FlowState] = {}
        self._prev_nettop: Dict[int, int] = {}  # pid → prev bytes_out total
        self._prev_nettop_rx: Dict[int, int] = {}  # pid → prev bytes_in total
        self._max_idle_cycles = max_idle_cycles
        self._cycle_count = 0

    def update(
        self,
        flows: list,
        nettop_records: Optional[Dict[int, object]] = None,
    ) -> list:
        """Merge new snapshot with existing state and estimate bytes.

        Args:
            flows: Raw FlowEvent list from lsof collector
            nettop_records: Dict[pid, NettopRecord] from nettop collector

        Returns:
            The same flow list, mutated in-place with enriched fields:
              - first_seen_ns: from first observation (not current snapshot)
              - last_seen_ns: current snapshot time
              - packet_count: set to seen_count (proxy)
              - bytes_tx/bytes_rx: estimated per-flow delta
        """
        self._cycle_count += 1
        seen_keys: set = set()

        # --- Phase 1: Compute per-PID byte deltas from nettop ---
        pid_byte_delta_tx: Dict[int, int] = {}
        pid_byte_delta_rx: Dict[int, int] = {}

        if nettop_records:
            for pid, rec in nettop_records.items():
                current_tx = rec.bytes_out
                current_rx = rec.bytes_in

                if pid in self._prev_nettop:
                    delta_tx = max(0, current_tx - self._prev_nettop[pid])
                    pid_byte_delta_tx[pid] = delta_tx
                if pid in self._prev_nettop_rx:
                    delta_rx = max(0, current_rx - self._prev_nettop_rx[pid])
                    pid_byte_delta_rx[pid] = delta_rx

                self._prev_nettop[pid] = current_tx
                self._prev_nettop_rx[pid] = current_rx

        # --- Phase 2: Count flows per PID (for byte distribution) ---
        pid_flow_count: Dict[int, int] = defaultdict(int)
        for flow in flows:
            if flow.pid:
                pid_flow_count[flow.pid] += 1

        # --- Phase 3: Update state and enrich flows ---
        for flow in flows:
            key = (
                flow.src_ip,
                flow.src_port,
                flow.dst_ip,
                flow.dst_port,
                flow.protocol,
            )
            seen_keys.add(key)

            if key in self._states:
                # Existing connection — update state
                state = self._states[key]
                state.last_seen_ns = flow.last_seen_ns
                state.seen_count += 1
            else:
                # New connection — initialize
                state = FlowState(
                    key=key,
                    pid=flow.pid,
                    first_seen_ns=flow.first_seen_ns,
                    last_seen_ns=flow.last_seen_ns,
                )
                self._states[key] = state

            # Enrich the flow with stateful data
            flow.first_seen_ns = state.first_seen_ns
            flow.packet_count = state.seen_count

            # Distribute byte deltas across flows for this PID
            if flow.pid and flow.pid in pid_byte_delta_tx:
                n_flows = pid_flow_count[flow.pid]
                if n_flows > 0:
                    flow.bytes_tx = pid_byte_delta_tx[flow.pid] // n_flows
                    state.bytes_tx_estimated += flow.bytes_tx
            if flow.pid and flow.pid in pid_byte_delta_rx:
                n_flows = pid_flow_count[flow.pid]
                if n_flows > 0:
                    flow.bytes_rx = pid_byte_delta_rx[flow.pid] // n_flows
                    state.bytes_rx_estimated += flow.bytes_rx

        # --- Phase 4: Evict stale connections ---
        stale_keys = [
            k
            for k, s in self._states.items()
            if k not in seen_keys
            and (self._cycle_count - s.seen_count) > self._max_idle_cycles
        ]
        for k in stale_keys:
            del self._states[k]

        if stale_keys:
            logger.debug("Evicted %d stale flow states", len(stale_keys))

        return flows

    @property
    def tracked_count(self) -> int:
        """Number of currently tracked connections."""
        return len(self._states)
