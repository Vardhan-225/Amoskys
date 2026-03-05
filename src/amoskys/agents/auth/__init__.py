"""Authentication and authorization monitoring agent.

Micro-probe architecture with 7 specialized detectors:
    - SSH password spraying
    - Geographic impossible travel
    - Sudo elevation and suspicious commands
    - Off-hours login detection
    - MFA bypass/fatigue attacks
    - Account lockout storms

Note: SSHBruteForceProbe moved to protocol_collectors (canonical location).
"""

from amoskys.agents.auth.auth_guard_agent import AuthGuardAgent
from amoskys.agents.auth.probes import (
    AccountLockoutStormProbe,
    AuthEvent,
    MFABypassOrAnomalyProbe,
    OffHoursLoginProbe,
    SSHGeoImpossibleTravelProbe,
    SSHPasswordSprayProbe,
    SudoElevationProbe,
    SudoSuspiciousCommandProbe,
    create_auth_probes,
)

__all__ = [
    "AuthGuardAgent",
    "AuthEvent",
    "create_auth_probes",
    "SSHPasswordSprayProbe",
    "SSHGeoImpossibleTravelProbe",
    "SudoElevationProbe",
    "SudoSuspiciousCommandProbe",
    "OffHoursLoginProbe",
    "MFABypassOrAnomalyProbe",
    "AccountLockoutStormProbe",
]
