"""
AMOSKYS DNS Agent - Module Entry Point

Run with: python -m amoskys.agents.dns [options]
"""

from amoskys.agents.common.cli import agent_main

from .dns_agent import DNSAgent


def main() -> None:
    """Entry point for DNS agent module."""
    agent_main(
        agent_class=DNSAgent,
        agent_name="dns_agent",
        description="DNS monitoring agent - detects C2 communication, "
        "DGA domains, DNS tunneling, and suspicious DNS patterns",
    )


if __name__ == "__main__":
    main()
