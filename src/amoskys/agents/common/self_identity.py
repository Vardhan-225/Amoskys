"""AMOSKYS Self-Recognition — prevents the platform from flagging its own activity.

Per the Agent Observability Mandate v1.0:
- Every agent MUST implement self-exclusion
- AMOSKYS must NEVER detect its own activity as a threat
- Self-exclusion is NOT optional — it is a correctness requirement
- An agent that detects itself produces false positives that poison training data

The self-exclusion contract requires every agent to:
1. Maintain known AMOSKYS process names (refreshed)
2. Maintain known AMOSKYS PIDs (from data/pids/)
3. Check BOTH process name AND ancestry (ppid chain)
4. For log-based agents: filter by process field
5. For network agents: filter by local PID
6. For file agents: filter AMOSKYS data directories

CONTRACT_SELF_DETECTION: 3 self-detection events from same agent
within one collection cycle triggers AMRDR reliability downgrade.
"""

from __future__ import annotations

import glob
import logging
import os
from pathlib import Path
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

        # Process names that are always "us" (per mandate)
        self._own_process_names: FrozenSet[str] = frozenset(
            {
                "python3",
                "python3.13",
                "python3.12",
                "python3.11",
                "python",
                "amoskys",
                "collect_and_store",
                "analyzer_main",
                "collector_main",
                "wal_processor",
            }
        )

        # Cmdline/exe substrings that identify AMOSKYS processes
        self._own_indicators: FrozenSet[str] = frozenset(
            {
                "amoskys",
                "collect_and_store",
                "analyzer_main",
                "collector_main",
                "wal_processor",
                "/amoskys/",
                "amoskys-venv",
            }
        )

        # AMOSKYS data directories — file events here are self-activity
        self._own_data_dirs: FrozenSet[str] = frozenset(
            {
                "data/queue/",
                "data/wal/",
                "data/telemetry.db",
                "data/igris/",
                "data/intel/",
                "data/heartbeats/",
                "data/pids/",
                "/queue/",
                "/wal/",
            }
        )

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

        # Register our own PID + parent
        self._own_pids.add(os.getpid())
        ppid = os.getppid()
        if ppid > 1:
            self._own_pids.add(ppid)

        # Load PIDs from data/pids/ if available
        self._load_pid_files()

    def _load_pid_files(self) -> None:
        """Load AMOSKYS PIDs from data/pids/*.pid files."""
        pid_dir = Path("data/pids")
        if not pid_dir.exists():
            return
        for pid_file in pid_dir.glob("*.pid"):
            try:
                pid_text = pid_file.read_text().strip()
                if pid_text.isdigit():
                    self._own_pids.add(int(pid_text))
            except (OSError, ValueError):
                pass

    def refresh(self) -> None:
        """Refresh PID set from pid files — call once per collection cycle."""
        self._load_pid_files()
        # Also add current process
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

    def update_pid(self, pid: int) -> None:
        """Track a new AMOSKYS process PID."""
        self._own_pids.add(pid)

    def add_destination_ip(self, ip: str) -> None:
        """Register an IP we connect to as known-self traffic."""
        self._own_destination_ips.add(ip)

    def is_self_process(
        self,
        pid: Optional[int] = None,
        name: Optional[str] = None,
        exe: Optional[str] = None,
        cmdline: Optional[str] = None,
        ppid: Optional[int] = None,
    ) -> bool:
        """Check if a process is part of AMOSKYS.

        Per mandate: check BOTH process name AND ancestry.
        PID match is authoritative. Then name+exe heuristic.
        Then cmdline indicator check. Then ppid ancestry.
        """
        # 1. PID match — authoritative
        if pid is not None and pid in self._own_pids:
            return True

        # 2. Cmdline indicator match — catches all AMOSKYS processes
        if cmdline:
            cmd_lower = str(cmdline).lower()
            if any(ind in cmd_lower for ind in self._own_indicators):
                # Cache the PID so future checks are faster
                if pid is not None:
                    self._own_pids.add(pid)
                return True

        # 3. Exe path indicator match
        if exe:
            exe_lower = str(exe).lower()
            if any(ind in exe_lower for ind in self._own_indicators):
                if pid is not None:
                    self._own_pids.add(pid)
                return True

        # 4. Name match with exe confirmation
        if name and exe:
            name_lower = name.lower() if isinstance(name, str) else ""
            name_matches = name_lower in self._own_process_names
            exe_lower = str(exe).lower()
            exe_is_ours = any(ind in exe_lower for ind in self._own_indicators)
            if name_matches and exe_is_ours:
                if pid is not None:
                    self._own_pids.add(pid)
                return True

        # 5. Parent PID ancestry — if parent is AMOSKYS, child is too
        if ppid is not None and ppid in self._own_pids:
            if pid is not None:
                self._own_pids.add(pid)
            return True

        return False

    def is_self_file_path(self, path: str) -> bool:
        """Check if a file path is in an AMOSKYS data directory.

        Per mandate: exclude writes to data/queue/, data/telemetry.db,
        data/igris/, etc.
        """
        if not path:
            return False
        path_lower = path.lower()
        return any(d in path_lower for d in self._own_data_dirs)

    def is_self_destination(self, domain: str) -> bool:
        """Check if a domain/hostname is an AMOSKYS API destination."""
        if not domain:
            return False
        d = domain.lower().rstrip(".")
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
        """Check if a detected beacon interval matches an AMOSKYS collection interval."""
        for _agent_id, agent_interval in self._agent_intervals.items():
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
