"""AMOSKYS Persistence Agent - Module Entry Point

Run with: python -m amoskys.agents.persistence [options]
"""

from amoskys.agents.common.cli import agent_main

from .persistence_agent import PersistenceGuard


def main() -> None:
    """Entry point for persistence agent module."""
    agent_main(
        agent_class=PersistenceGuard,
        agent_name="persistence",
        description="Persistence mechanism monitoring - detects launchd, cron, "
        "systemd, and other persistence techniques used by attackers",
    )


if __name__ == "__main__":
    main()
