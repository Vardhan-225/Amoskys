"""AMOSKYS Flow Agent - Module Entry Point

Run with: python -m amoskys.agents.flow [options]
"""

from amoskys.agents.common.cli import agent_main

from .flow_agent import FlowAgent


def main() -> None:
    """Entry point for flow agent module."""
    agent_main(
        agent_class=FlowAgent,
        agent_name="flow_agent",
        description="Network flow analysis agent - detects C2 beaconing, "
        "lateral movement, data exfiltration, and tunnel detection",
    )


if __name__ == "__main__":
    main()
