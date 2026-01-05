"""Authentication and authorization monitoring agent.

This module provides two implementations:
    - AuthGuardAgent: Original monolithic implementation
    - AuthGuardAgentV2: Micro-probe architecture with 8 specialized detectors

The v2 agent uses the "swarm of eyes" pattern with probes for:
    - SSH brute force and password spraying
    - Geographic impossible travel
    - Sudo elevation and suspicious commands
    - Off-hours login detection
    - MFA bypass/fatigue attacks
    - Account lockout storms
"""

from amoskys.agents.auth.auth_agent import AuthGuardAgent
from amoskys.agents.auth.auth_guard_agent_v2 import AuthGuardAgentV2
from amoskys.agents.auth.probes import (
    AuthEvent,
    create_auth_probes,
    SSHBruteForceProbe,
    SSHPasswordSprayProbe,
    SSHGeoImpossibleTravelProbe,
    SudoElevationProbe,
    SudoSuspiciousCommandProbe,
    OffHoursLoginProbe,
    MFABypassOrAnomalyProbe,
    AccountLockoutStormProbe,
)

__all__ = [
    "AuthGuardAgent",
    "AuthGuardAgentV2",
    "AuthEvent",
    "create_auth_probes",
    "SSHBruteForceProbe",
    "SSHPasswordSprayProbe",
    "SSHGeoImpossibleTravelProbe",
    "SudoElevationProbe",
    "SudoSuspiciousCommandProbe",
    "OffHoursLoginProbe",
    "MFABypassOrAnomalyProbe",
    "AccountLockoutStormProbe",
]
