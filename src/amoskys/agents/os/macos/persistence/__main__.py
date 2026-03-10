"""AMOSKYS macOS Persistence Observatory - Module Entry Point

Run with: python -m amoskys.agents.os.macos.persistence [options]
"""

from amoskys.agents.common.cli import agent_main

from .agent import MacOSPersistenceAgent


def main() -> None:
    """Entry point for macOS Persistence Observatory agent."""
    agent_main(
        agent_class=MacOSPersistenceAgent,
        agent_name="macos_persistence",
        description="macOS Persistence Observatory - monitors LaunchAgents, "
        "LaunchDaemons, cron, and login items",
    )


if __name__ == "__main__":
    main()
