"""AMOSKYS Peripheral Monitoring Agent

Monitors physical devices connected to endpoints with micro-probe architecture.

Probes:
    - USBInventoryProbe: Complete device inventory
    - USBConnectionEdgeProbe: Connect/disconnect events
    - USBStorageProbe: Storage device monitoring
    - USBNetworkAdapterProbe: Network adapter detection
    - HIDKeyboardMouseAnomalyProbe: Keystroke injection detection
    - BluetoothDeviceProbe: Bluetooth monitoring
    - HighRiskPeripheralScoreProbe: Composite risk scoring
"""

from .peripheral_agent import PeripheralAgent
from .peripheral_agent_v2 import PeripheralAgentV2
from .probes import (
    PERIPHERAL_PROBES,
    BluetoothDeviceProbe,
    HIDKeyboardMouseAnomalyProbe,
    HighRiskPeripheralScoreProbe,
    USBConnectionEdgeProbe,
    USBInventoryProbe,
    USBNetworkAdapterProbe,
    USBStorageProbe,
    create_peripheral_probes,
)

__all__ = [
    # Original agent
    "PeripheralAgent",
    # V2 agent (micro-probe architecture)
    "PeripheralAgentV2",
    # Probes
    "BluetoothDeviceProbe",
    "create_peripheral_probes",
    "HighRiskPeripheralScoreProbe",
    "HIDKeyboardMouseAnomalyProbe",
    "PERIPHERAL_PROBES",
    "USBConnectionEdgeProbe",
    "USBInventoryProbe",
    "USBNetworkAdapterProbe",
    "USBStorageProbe",
]
