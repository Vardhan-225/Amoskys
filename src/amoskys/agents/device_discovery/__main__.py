"""AMOSKYS Device Discovery Agent - Module Entry Point

Run with: python -m amoskys.agents.device_discovery [options]
"""

from amoskys.agents.common.cli import agent_main

from .device_discovery import DeviceDiscovery


def main() -> None:
    """Entry point for device discovery agent module."""
    agent_main(
        agent_class=DeviceDiscovery,
        agent_name="device_discovery",
        description="Network asset discovery agent - detects new devices, "
        "rogue servers, shadow IT, and vulnerable services",
    )


if __name__ == "__main__":
    main()
