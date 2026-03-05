"""AMOSKYS AppLog Agent - Module Entry Point

Run with: python -m amoskys.agents.applog [options]
"""

from amoskys.agents.common.cli import agent_main

from .applog_agent import AppLogAgent


def main() -> None:
    """Entry point for AppLog agent module."""
    agent_main(
        agent_class=AppLogAgent,
        agent_name="applog",
        description="Application log monitoring agent - detects log tampering, "
        "credential leaks, web shells, error spikes, and container escape attempts",
    )


if __name__ == "__main__":
    main()
