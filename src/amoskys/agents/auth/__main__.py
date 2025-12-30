"""
AMOSKYS Auth Agent - Module Entry Point

Run with: python -m amoskys.agents.auth [options]
"""

from amoskys.agents.common.cli import agent_main

from .auth_agent import AuthGuardAgent


def main() -> None:
    """Entry point for auth agent module."""
    agent_main(
        agent_class=AuthGuardAgent,
        agent_name="auth_agent",
        description="Authentication monitoring agent - tracks login attempts, "
        "SSH sessions, sudo usage, and authentication anomalies",
    )


if __name__ == "__main__":
    main()
