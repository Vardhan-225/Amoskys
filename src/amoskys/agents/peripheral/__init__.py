"""AMOSKYS Peripheral Monitoring Agent

Monitors physical devices connected to endpoints with micro-probe architecture.
"""

from .peripheral_agent import PeripheralAgent
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

# B5.1: Deprecated alias
PeripheralAgentV2 = PeripheralAgent

__all__ = [
    "PeripheralAgent",
    "PeripheralAgentV2",
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
