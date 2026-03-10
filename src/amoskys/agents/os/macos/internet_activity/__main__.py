"""AMOSKYS macOS Internet Activity Observatory - Module Entry Point

Run with: python -m amoskys.agents.os.macos.internet_activity [options]
"""

from amoskys.agents.common.cli import agent_main

from .agent import MacOSInternetActivityAgent


def main() -> None:
    """Entry point for macOS Internet Activity Observatory agent."""
    agent_main(
        agent_class=MacOSInternetActivityAgent,
        agent_name="macos_internet_activity",
        description="macOS Internet Activity Observatory - monitors internet "
        "connections and browsing patterns",
    )


if __name__ == "__main__":
    main()
