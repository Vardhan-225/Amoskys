"""AMOSKYS Internet Activity Agent - Module Entry Point

Run with: python -m amoskys.agents.internet_activity [options]
"""

from amoskys.agents.common.cli import agent_main

from .internet_activity_agent import InternetActivityAgent


def main() -> None:
    """Entry point for Internet Activity agent module."""
    agent_main(
        agent_class=InternetActivityAgent,
        agent_name="internet_activity",
        description="Internet activity monitoring agent - detects cloud exfiltration, "
        "TOR/VPN usage, crypto mining, suspicious downloads, and shadow IT",
    )


if __name__ == "__main__":
    main()
