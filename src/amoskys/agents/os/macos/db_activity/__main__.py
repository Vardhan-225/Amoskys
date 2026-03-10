"""AMOSKYS macOS DB Activity Observatory - Module Entry Point

Run with: python -m amoskys.agents.os.macos.db_activity [options]
"""

from amoskys.agents.common.cli import agent_main

from .agent import MacOSDBActivityAgent


def main() -> None:
    """Entry point for macOS DB Activity Observatory agent."""
    agent_main(
        agent_class=MacOSDBActivityAgent,
        agent_name="macos_db_activity",
        description="macOS DB Activity Observatory - monitors database "
        "connections and queries",
    )


if __name__ == "__main__":
    main()
