"""AMOSKYS Protocol Collectors Agent - Module Entry Point

Run with: python -m amoskys.agents.protocol_collectors [options]
"""

from amoskys.agents.common.cli import agent_main

from .protocol_collectors import ProtocolCollectors


def main() -> None:
    """Entry point for protocol collectors agent module."""
    agent_main(
        agent_class=ProtocolCollectors,
        agent_name="protocol_collectors",
        description="Protocol plane monitoring agent - detects HTTP exploits, "
        "DNS tunneling, SSH brute force, and TLS anomalies",
    )


if __name__ == "__main__":
    main()
