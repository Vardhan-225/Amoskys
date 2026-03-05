"""Network flow monitoring agent.

Micro-probe architecture with 8 specialized detectors.
"""

from amoskys.agents.flow.flow_agent import FlowAgent, MacOSFlowCollector
from amoskys.agents.flow.probes import (
    C2BeaconFlowProbe,
    CleartextCredentialLeakProbe,
    DataExfilVolumeSpikeProbe,
    FlowEvent,
    InternalReconDNSFlowProbe,
    LateralSMBWinRMProbe,
    NewExternalServiceProbe,
    PortScanSweepProbe,
    SuspiciousTunnelProbe,
    create_flow_probes,
)

__all__ = [
    "FlowAgent",
    "MacOSFlowCollector",
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
]
