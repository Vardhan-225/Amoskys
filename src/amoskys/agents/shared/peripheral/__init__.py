"""Shared (cross-platform) Peripheral Agent implementation.

This package contains the platform-agnostic peripheral monitoring agent and
its 7 micro-probes.  Platform-specific wrappers live under agents/os/<platform>/
and the routing shim at agents/peripheral/__init__.py selects the right class
at import time.

Direct usage (bypasses platform routing):
    from amoskys.agents.shared.peripheral.agent import PeripheralAgent
    from amoskys.agents.shared.peripheral.probes import USBInventoryProbe
"""

from .agent import EventBusPublisher, PeripheralAgent
from .probes import (
    PERIPHERAL_PROBES,
    BluetoothDevice,
    BluetoothDeviceProbe,
    HIDKeyboardMouseAnomalyProbe,
    HighRiskPeripheralScoreProbe,
    USBCollector,
    USBConnectionEdgeProbe,
    USBDevice,
    USBInventoryProbe,
    USBNetworkAdapterProbe,
    USBStorageProbe,
    create_peripheral_probes,
)

__all__ = [
    "BluetoothDevice",
    "BluetoothDeviceProbe",
    "create_peripheral_probes",
    "EventBusPublisher",
    "HighRiskPeripheralScoreProbe",
    "HIDKeyboardMouseAnomalyProbe",
    "PERIPHERAL_PROBES",
    "PeripheralAgent",
    "USBCollector",
    "USBConnectionEdgeProbe",
    "USBDevice",
    "USBInventoryProbe",
    "USBNetworkAdapterProbe",
    "USBStorageProbe",
]
