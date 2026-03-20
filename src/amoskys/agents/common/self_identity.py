"""AMOSKYS Self-Recognition — prevents the platform from flagging its own activity.

AMOSKYS agents, the dashboard, and IGRIS create network connections, spawn processes,
and query DNS at regular intervals. Without self-recognition, these activities trigger
false positives (DNS beaconing from API calls, process spawn alerts for agent workers,
C2 beacon detection for our own heartbeat intervals).

This module maintains a "self-portrait" that probes check before creating events.

Usage:
    from amoskys.agents.common.self_identity import self_identity

    # During agent startup
    self_identity.register_agent("dns", pid=12345, interval=30.0)

    # In probe scan()
    if self_identity.is_self_process(pid=12345, name="python3"):
        return []  # Don't flag our own processes

    if self_identity.is_self_destination("api.anthropic.com"):
        return []  # Don't flag our own API calls

    if self_identity.is_self_beacon_interval(29.99):
        return []  # Don't flag our own collection intervals
"""

from __future__ import annotations

import logging
import os
from typing import Dict, FrozenSet, Optional, Set

logger = logging.getLogger(__name__)


class SelfIdentity:
    """Singleton that knows AMOSKYS's own footprint on the system."""

    _instance: Optional["SelfIdentity"] = None

    def __new__(cls) -> "SelfIdentity":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self) -> None:
        if self._initialized:
            return
        self._initialized = True

        # PIDs of AMOSKYS processes (updated each cycle)
        self._own_pids: Set[int] = set()

        # Process names that are always "us"
        self._own_process_names: Set[str] = {
            "python3",
            "python3.13",
            "python3.12",
            "python3.11",
            "python",
            "amoskys",
        }

        # Agent collection intervals (agent_id → interval_seconds)
        self._agent_intervals: Dict[str, float] = {}

        # API destinations we talk to (not threats)
        self._own_destinations: FrozenSet[str] = frozenset(
            {
                "anthropic.com",
                "api.anthropic.com",
                "localhost",
                "127.0.0.1",
            }
        )

        # Known AMOSKYS destination IPs
        self._own_destination_ips: Set[str] = set()

        # Register our own PID
        self._own_pids.add(os.getpid())

    def register_agent(
        self,
        agent_id: str,
        pid: Optional[int] = None,
        interval: Optional[float] = None,
    ) -> None:
        """Register an AMOSKYS agent's PID and collection interval."""
        if pid is not None:
            self._own_pids.add(pid)
        if interval is not None:
            self._agent_intervals[agent_id] = interval
        logger.debug(
            "SelfIdentity: registered agent=%s pid=%s interval=%s",
            agent_id,
            pid,
            interval,
        )

    def update_pid(self, pid: int) -> None:
        """Track a new AMOSKYS process PID (e.g., forked worker)."""
        self._own_pids.add(pid)

    def add_destination_ip(self, ip: str) -> None:
        """Register an IP we connect to as known-self traffic."""
        self._own_destination_ips.add(ip)

    def is_self_process(
        self,
        pid: Optional[int] = None,
        name: Optional[str] = None,
        exe: Optional[str] = None,
    ) -> bool:
        """Check if a process is part of AMOSKYS.

        Uses PID as primary check (most reliable), falls back to name+exe heuristic.
        """
        # PID match is authoritative
        if pid is not None and pid in self._own_pids:
            return True

        # Name match — only if exe points to our venv or project
        if name and exe:
            name_matches = any(name.startswith(n) for n in self._own_process_names)
            exe_is_ours = (
                "amoskys" in exe.lower() or ".venv" in exe or "site-packages" in exe
            )
            if name_matches and exe_is_ours:
                return True

        return False

    def is_self_destination(self, domain: str) -> bool:
        """Check if a domain/hostname is an AMOSKYS API destination."""
        if not domain:
            return False
        d = domain.lower().rstrip(".")
        # Exact match or suffix match
        for own_domain in self._own_destinations:
            if d == own_domain or d.endswith(f".{own_domain}"):
                return True
        return False

    def is_self_destination_ip(self, ip: str) -> bool:
        """Check if an IP is a known AMOSKYS destination."""
        return ip in self._own_destination_ips

    def is_self_beacon_interval(
        self,
        interval_seconds: float,
        tolerance: float = 2.0,
    ) -> bool:
        """Check if a detected beacon interval matches an AMOSKYS collection interval.

        Args:
            interval_seconds: The detected beacon interval
            tolerance: Maximum delta (seconds) to consider a match
        """
        for agent_id, agent_interval in self._agent_intervals.items():
            if abs(interval_seconds - agent_interval) <= tolerance:
                return True
        return False

    @property
    def own_pids(self) -> Set[int]:
        """Current set of known AMOSKYS PIDs."""
        return set(self._own_pids)

    @property
    def agent_intervals(self) -> Dict[str, float]:
        """Registered agent collection intervals."""
        return dict(self._agent_intervals)


# Module-level singleton
self_identity = SelfIdentity()
