"""Authentication and authorization monitoring agent.

Micro-probe architecture with 8 specialized detectors:
    - SSH brute force and password spraying
    - Geographic impossible travel
    - Sudo elevation and suspicious commands
    - Off-hours login detection
    - MFA bypass/fatigue attacks
    - Account lockout storms
"""

from amoskys.agents.auth.auth_guard_agent import AuthGuardAgent
from amoskys.agents.auth.probes import (
    AccountLockoutStormProbe,
    AuthEvent,
    MFABypassOrAnomalyProbe,
    OffHoursLoginProbe,
    SSHBruteForceProbe,
    SSHGeoImpossibleTravelProbe,
    SSHPasswordSprayProbe,
    SudoElevationProbe,
    SudoSuspiciousCommandProbe,
    create_auth_probes,
)

# B5.1: Deprecated alias
AuthGuardAgentV2 = AuthGuardAgent

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
