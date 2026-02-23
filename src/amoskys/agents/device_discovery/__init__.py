"""AMOSKYS Device Discovery Agent - Network Asset Discovery and Risk Assessment."""

from .device_discovery import DeviceDiscovery
from .probes import DEVICE_DISCOVERY_PROBES

# B5.1: Deprecated alias
DeviceDiscoveryV2 = DeviceDiscovery

__all__ = [
    "DeviceDiscovery",
    "DeviceDiscoveryV2",
    "DEVICE_DISCOVERY_PROBES",
]
