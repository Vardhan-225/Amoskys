"""Shared (cross-platform) Authentication Agent.

This package contains the platform-independent AuthGuardAgent and its
micro-probes.  Platform-specific wrappers (macOS Observatory, etc.) live
under ``amoskys.agents.os.<platform>.auth`` and may delegate to these
shared implementations.

Usage:
    from amoskys.agents.shared.auth import AuthGuardAgent
    from amoskys.agents.shared.auth.probes import SSHPasswordSprayProbe
"""

from amoskys.agents.shared.auth.agent import AuthGuardAgent  # noqa: F401
from amoskys.agents.shared.auth.probes import (  # noqa: F401
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
