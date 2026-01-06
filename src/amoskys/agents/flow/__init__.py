"""Network flow monitoring agent.

This module provides network traffic monitoring with micro-probe architecture:
    - FlowAgentV2: Micro-probe architecture with 8 specialized detectors

The v2 agent uses the "swarm of eyes" pattern with probes for:
    - Port scanning and reconnaissance
    - Lateral movement via admin protocols (SMB, RDP, WinRM, SSH)
    - Data exfiltration volume spikes
    - C2 beaconing patterns
    - Cleartext credential leaks
    - Suspicious tunnels and proxies
    - DNS-based internal reconnaissance
    - New external service connections
"""

from amoskys.agents.flow.flow_agent_v2 import FlowAgentV2, FlowCollector
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
    "FlowAgentV2",
    "FlowCollector",
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
