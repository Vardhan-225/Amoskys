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

# B5.1: Deprecated alias
FlowAgentV2 = FlowAgent

__all__ = [
    "FlowAgent",
    "FlowAgentV2",
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
