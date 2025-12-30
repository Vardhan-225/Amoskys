"""
AMOSKYS Peripheral Agent - Module Entry Point

Run with: python -m amoskys.agents.peripheral [options]
"""

from amoskys.agents.common.cli import agent_main

from .peripheral_agent import PeripheralAgent


def main() -> None:
    """Entry point for peripheral agent module."""
    agent_main(
        agent_class=PeripheralAgent,
        agent_name="peripheral_agent",
        description="Peripheral device monitoring - tracks USB devices, "
        "Bluetooth connections, and detects unauthorized hardware",
    )


if __name__ == "__main__":
    main()
