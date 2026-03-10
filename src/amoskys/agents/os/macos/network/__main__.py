"""AMOSKYS macOS Network Observatory - Module Entry Point

Run with: python -m amoskys.agents.os.macos.network [options]
"""

from amoskys.agents.common.cli import agent_main

from .agent import MacOSNetworkAgent


def main() -> None:
    """Entry point for macOS Network Observatory agent."""
    agent_main(
        agent_class=MacOSNetworkAgent,
        agent_name="macos_network",
        description="macOS Network Observatory - monitors connections and "
        "bandwidth with 8 detection probes",
    )


if __name__ == "__main__":
    main()
