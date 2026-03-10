"""AMOSKYS macOS Auth Observatory - Module Entry Point

Run with: python -m amoskys.agents.os.macos.auth [options]
"""

from amoskys.agents.common.cli import agent_main

from .agent import MacOSAuthAgent


def main() -> None:
    """Entry point for macOS Auth Observatory agent."""
    agent_main(
        agent_class=MacOSAuthAgent,
        agent_name="macos_auth",
        description="macOS Auth Observatory - monitors authentication events "
        "with brute-force and privilege escalation detection",
    )


if __name__ == "__main__":
    main()
