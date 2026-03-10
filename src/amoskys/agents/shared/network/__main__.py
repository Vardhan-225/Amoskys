"""AMOSKYS Network Agent - Module Entry Point

Run with: python -m amoskys.agents.shared.network [options]
"""

from amoskys.agents.common.cli import agent_main

from .agent import FlowAgent


def main() -> None:
    """Entry point for network agent module."""
    agent_main(
        agent_class=FlowAgent,
        agent_name="flow",
        description="Network flow analysis agent - detects C2 beaconing, "
        "lateral movement, data exfiltration, and tunnel detection",
    )


if __name__ == "__main__":
    main()
