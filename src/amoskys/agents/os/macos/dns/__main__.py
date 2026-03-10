"""AMOSKYS macOS DNS Observatory - Module Entry Point

Run with: python -m amoskys.agents.os.macos.dns [options]
"""

from amoskys.agents.common.cli import agent_main

from .agent import MacOSDNSAgent


def main() -> None:
    """Entry point for macOS DNS Observatory agent."""
    agent_main(
        agent_class=MacOSDNSAgent,
        agent_name="macos_dns",
        description="macOS DNS Observatory - monitors DNS queries with "
        "DGA, beaconing, and tunneling detection",
    )


if __name__ == "__main__":
    main()
