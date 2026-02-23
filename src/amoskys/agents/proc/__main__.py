"""AMOSKYS Process Agent - Module Entry Point

Run with: python -m amoskys.agents.proc [options]
"""

from amoskys.agents.common.cli import agent_main

from .proc_agent import ProcAgent


def main() -> None:
    """Entry point for proc agent module."""
    agent_main(
        agent_class=ProcAgent,
        agent_name="proc_agent",
        description="Process monitoring agent - tracks running processes, "
        "detects suspicious behavior, and monitors resource usage",
    )


if __name__ == "__main__":
    main()
