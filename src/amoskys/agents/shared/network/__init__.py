"""Shared Network Agent — cross-platform flow monitoring implementation.

Provides the platform-agnostic FlowAgent and its micro-probes for network
flow analysis. Platform-specific agents (e.g. macOS Observatory) can extend
or replace this implementation via the routing shim in agents/flow/__init__.py.

Usage:
    from amoskys.agents.shared.network import FlowAgent
    from amoskys.agents.shared.network import FlowEvent, create_flow_probes
"""

from amoskys.agents.shared.network.agent import (  # noqa: F401
    EventBusPublisher,
    FlowAgent,
    MacOSFlowCollector,
)
from amoskys.agents.shared.network.flow_state import FlowStateTable  # noqa: F401
from amoskys.agents.shared.network.nettop_collector import (  # noqa: F401
    MacOSNettopCollector,
    NettopRecord,
)
from amoskys.agents.shared.network.probes import (  # noqa: F401
    C2BeaconFlowProbe,
    CleartextCredentialLeakProbe,
    DataExfilVolumeSpikeProbe,
    FlowEvent,
    InternalReconDNSFlowProbe,
    LateralSMBWinRMProbe,
    NewExternalServiceProbe,
    PortScanSweepProbe,
    SuspiciousTunnelProbe,
    TransparentProxyProbe,
    create_flow_probes,
)

__all__ = [
    "FlowAgent",
    "EventBusPublisher",
    "MacOSFlowCollector",
    "FlowStateTable",
    "MacOSNettopCollector",
    "NettopRecord",
    "FlowEvent",
    "create_flow_probes",
    "PortScanSweepProbe",
    "LateralSMBWinRMProbe",
    "DataExfilVolumeSpikeProbe",
    "C2BeaconFlowProbe",
    "CleartextCredentialLeakProbe",
    "SuspiciousTunnelProbe",
    "InternalReconDNSFlowProbe",
    "NewExternalServiceProbe",
    "TransparentProxyProbe",
]
