"""AMOSKYS Database Activity Agent - Module Entry Point

Run with: python -m amoskys.agents.db_activity [options]
"""

from amoskys.agents.common.cli import agent_main

from .agent import DBActivityAgent


def main() -> None:
    """Entry point for Database Activity agent module."""
    agent_main(
        agent_class=DBActivityAgent,
        agent_name="db_activity",
        description="Database activity monitoring agent - detects SQL injection, "
        "privilege escalation, bulk extraction, schema enumeration, "
        "and unauthorized database access",
    )


if __name__ == "__main__":
    main()
