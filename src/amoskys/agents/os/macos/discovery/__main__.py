"""AMOSKYS macOS Discovery Observatory - Module Entry Point

Run with: python -m amoskys.agents.os.macos.discovery [options]
"""

from amoskys.agents.common.cli import agent_main

from .agent import MacOSDiscoveryAgent


def main() -> None:
    """Entry point for macOS Discovery Observatory agent."""
    agent_main(
        agent_class=MacOSDiscoveryAgent,
        agent_name="macos_discovery",
        description="macOS Discovery Observatory - discovers network devices "
        "and services",
    )


if __name__ == "__main__":
    main()
