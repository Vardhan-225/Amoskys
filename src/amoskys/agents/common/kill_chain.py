"""AMOSKYS Kill-Chain Tracker — multi-stage attack progression across agents.

Tracks the Lockheed Martin Cyber Kill Chain stages as observed by AMOSKYS
agents. When an agent detects activity mapped to a kill-chain stage, it
records it here. The Correlation agent reads the full picture.

Kill-chain stages:
    1. Reconnaissance — scanning, enumeration, OSINT
    2. Weaponization — building payload (usually not observable)
    3. Delivery — phishing, drive-by, USB drop
    4. Exploitation — vulnerability exploit, code execution
    5. Installation — persistence mechanism creation
    6. Command & Control — C2 channel establishment
    7. Actions on Objectives — data theft, destruction, ransom

Usage:
    tracker = KillChainTracker()

    # Any agent can record stages
    tracker.record_stage("macbook-pro", "reconnaissance",
                         event=telemetry_event, agent="macos_discovery")

    # Correlation agent reads the full picture
    state = tracker.get_progression("macbook-pro")
    if state.stages_reached >= 3:
        # Multi-stage attack in progress
        ...

    # Get all active chains
    for chain in tracker.get_active_chains():
        print(f"{chain.device_id}: {chain.stages_reached} stages")
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


KILL_CHAIN_STAGES = [
    "reconnaissance",
    "weaponization",
    "delivery",
    "exploitation",
    "installation",
    "command_and_control",
    "actions_on_objectives",
]

# Map MITRE ATT&CK tactics to kill-chain stages
TACTIC_TO_STAGE: Dict[str, str] = {
    "reconnaissance": "reconnaissance",
    "resource_development": "weaponization",
    "initial_access": "delivery",
    "execution": "exploitation",
    "persistence": "installation",
    "privilege_escalation": "exploitation",
    "defense_evasion": "exploitation",
    "credential_access": "exploitation",
    "discovery": "reconnaissance",
    "lateral_movement": "actions_on_objectives",
    "collection": "actions_on_objectives",
    "command_and_control": "command_and_control",
    "exfiltration": "actions_on_objectives",
    "impact": "actions_on_objectives",
}


@dataclass
class StageObservation:
    """A single observation of a kill-chain stage."""

    stage: str
    timestamp_ns: int
    agent_name: str
    event_type: str = ""
    mitre_technique: str = ""
    confidence: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class KillChainState:
    """Current kill-chain progression state for a device."""

    device_id: str
    observations: List[StageObservation] = field(default_factory=list)
    first_seen_ns: int = 0
    last_updated_ns: int = 0

    @property
    def stages_reached(self) -> int:
        """Number of unique kill-chain stages observed."""
        return len(self.unique_stages)

    @property
    def unique_stages(self) -> Set[str]:
        """Set of unique stages observed."""
        return {obs.stage for obs in self.observations}

    @property
    def stage_sequence(self) -> List[str]:
        """Chronologically ordered stages (first observation of each)."""
        seen: Set[str] = set()
        sequence: List[str] = []
        for obs in sorted(self.observations, key=lambda o: o.timestamp_ns):
            if obs.stage not in seen:
                seen.add(obs.stage)
                sequence.append(obs.stage)
        return sequence

    @property
    def max_confidence(self) -> float:
        """Highest confidence observation across all stages."""
        if not self.observations:
            return 0.0
        return max(obs.confidence for obs in self.observations)

    @property
    def is_multi_stage(self) -> bool:
        """Whether 3+ stages have been observed (attack likely in progress)."""
        return self.stages_reached >= 3

    def to_dict(self) -> Dict[str, Any]:
        """Serialize for telemetry event data."""
        return {
            "device_id": self.device_id,
            "stages_reached": self.stages_reached,
            "unique_stages": sorted(self.unique_stages),
            "stage_sequence": self.stage_sequence,
            "observation_count": len(self.observations),
            "first_seen_ns": self.first_seen_ns,
            "last_updated_ns": self.last_updated_ns,
            "is_multi_stage": self.is_multi_stage,
            "max_confidence": self.max_confidence,
        }


class KillChainTracker:
    """Track multi-stage attack progression across agents.

    Thread-safe. Observations are auto-expired after TTL to prevent
    stale data from persisting indefinitely.
    """

    def __init__(self, ttl_seconds: float = 3600.0) -> None:
        """Initialize tracker.

        Args:
            ttl_seconds: Time-to-live for observations (default: 1 hour).
        """
        self._chains: Dict[str, KillChainState] = {}
        self._lock = threading.Lock()
        self._ttl_ns = int(ttl_seconds * 1e9)

    def record_stage(
        self,
        device_id: str,
        stage: str,
        agent_name: str,
        event_type: str = "",
        mitre_technique: str = "",
        confidence: float = 0.0,
        details: Optional[Dict[str, Any]] = None,
    ) -> KillChainState:
        """Record an observed kill-chain stage for a device.

        Args:
            device_id: Device/host identifier.
            stage: Kill-chain stage name (from KILL_CHAIN_STAGES).
            agent_name: Agent that made the observation.
            event_type: Event type that triggered this observation.
            mitre_technique: MITRE ATT&CK technique ID.
            confidence: Detection confidence (0.0-1.0).
            details: Additional context data.

        Returns:
            Updated KillChainState for the device.
        """
        if stage not in KILL_CHAIN_STAGES:
            logger.warning("Unknown kill-chain stage: %s", stage)

        now_ns = int(time.time() * 1e9)

        observation = StageObservation(
            stage=stage,
            timestamp_ns=now_ns,
            agent_name=agent_name,
            event_type=event_type,
            mitre_technique=mitre_technique,
            confidence=confidence,
            details=details or {},
        )

        with self._lock:
            if device_id not in self._chains:
                self._chains[device_id] = KillChainState(
                    device_id=device_id,
                    first_seen_ns=now_ns,
                )

            state = self._chains[device_id]
            state.observations.append(observation)
            state.last_updated_ns = now_ns

            # Auto-expire old observations
            cutoff_ns = now_ns - self._ttl_ns
            state.observations = [
                obs for obs in state.observations if obs.timestamp_ns > cutoff_ns
            ]

            if state.is_multi_stage:
                logger.warning(
                    "KILL-CHAIN: %s has %d stages — %s",
                    device_id,
                    state.stages_reached,
                    state.stage_sequence,
                )

            return state

    def record_from_tactic(
        self,
        device_id: str,
        mitre_tactic: str,
        agent_name: str,
        event_type: str = "",
        mitre_technique: str = "",
        confidence: float = 0.0,
        details: Optional[Dict[str, Any]] = None,
    ) -> Optional[KillChainState]:
        """Record a kill-chain stage from a MITRE ATT&CK tactic name.

        Automatically maps tactic → kill-chain stage.
        """
        stage = TACTIC_TO_STAGE.get(mitre_tactic)
        if not stage:
            return None

        return self.record_stage(
            device_id=device_id,
            stage=stage,
            agent_name=agent_name,
            event_type=event_type,
            mitre_technique=mitre_technique,
            confidence=confidence,
            details=details,
        )

    def get_progression(self, device_id: str) -> Optional[KillChainState]:
        """Get current kill-chain state for a device."""
        with self._lock:
            state = self._chains.get(device_id)
            if state:
                # Expire stale observations
                cutoff_ns = int(time.time() * 1e9) - self._ttl_ns
                state.observations = [
                    obs for obs in state.observations if obs.timestamp_ns > cutoff_ns
                ]
                if not state.observations:
                    del self._chains[device_id]
                    return None
            return state

    def get_active_chains(self) -> List[KillChainState]:
        """Get all devices with active kill-chain observations."""
        now_ns = int(time.time() * 1e9)
        cutoff_ns = now_ns - self._ttl_ns

        with self._lock:
            active: List[KillChainState] = []
            expired: List[str] = []

            for device_id, state in self._chains.items():
                state.observations = [
                    obs for obs in state.observations if obs.timestamp_ns > cutoff_ns
                ]
                if state.observations:
                    active.append(state)
                else:
                    expired.append(device_id)

            for device_id in expired:
                del self._chains[device_id]

            return active

    def get_multi_stage_chains(self, min_stages: int = 3) -> List[KillChainState]:
        """Get devices with multi-stage attack progression."""
        return [
            chain
            for chain in self.get_active_chains()
            if chain.stages_reached >= min_stages
        ]

    def clear(self, device_id: Optional[str] = None) -> None:
        """Clear kill-chain state.

        Args:
            device_id: If specified, clear only for this device. Otherwise clear all.
        """
        with self._lock:
            if device_id:
                self._chains.pop(device_id, None)
            else:
                self._chains.clear()
