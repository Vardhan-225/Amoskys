"""AMOSKYS Network Scanner Agent - Module Entry Point

Run with: python -m amoskys.agents.net_scanner [options]
"""

from amoskys.agents.common.cli import agent_main

from .net_scanner_agent import NetScannerAgent


def main() -> None:
    """Entry point for network scanner agent module."""
    agent_main(
        agent_class=NetScannerAgent,
        agent_name="net_scanner",
        description="Network topology and service monitoring agent - detects "
        "rogue services, vulnerable banners, SSL issues, unauthorized "
        "listeners, and ARP spoofing",
    )


if __name__ == "__main__":
    main()
