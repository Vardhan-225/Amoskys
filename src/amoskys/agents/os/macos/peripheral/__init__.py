"""AMOSKYS macOS Peripheral Observatory.

Monitors USB devices, Bluetooth peripherals, and removable media mounts on macOS.
Uses system_profiler for hardware enumeration and /Volumes/ monitoring for mounts.

Ground truth (macOS 26.0, uid=501, Apple Silicon):
    - system_profiler SPUSBDataType -json: USB tree with vendor_id, product_id, serial
    - system_profiler SPBluetoothDataType -json: paired/connected BT devices
    - /Volumes/: real-time removable media detection (no root required)
    - No IOKit subscription needed (polling via system_profiler)

Coverage: T1200 (Hardware Additions), T1052.001 (Exfiltration Over USB)
"""

from amoskys.agents.os.macos.peripheral.agent import MacOSPeripheralAgent

__all__ = ["MacOSPeripheralAgent"]
