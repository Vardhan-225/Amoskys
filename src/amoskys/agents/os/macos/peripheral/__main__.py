"""AMOSKYS macOS Peripheral Observatory - Module Entry Point

Run with: python -m amoskys.agents.os.macos.peripheral [options]
"""

from amoskys.agents.common.cli import agent_main

from .agent import MacOSPeripheralAgent


def main() -> None:
    """Entry point for macOS Peripheral Observatory agent."""
    agent_main(
        agent_class=MacOSPeripheralAgent,
        agent_name="macos_peripheral",
        description="macOS Peripheral Observatory - monitors USB, Bluetooth, "
        "and external devices",
    )


if __name__ == "__main__":
    main()
