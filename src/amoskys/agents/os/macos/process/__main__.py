"""AMOSKYS macOS Process Observatory - Module Entry Point

Run with: python -m amoskys.agents.os.macos.process [options]
"""

from amoskys.agents.common.cli import agent_main

from .agent import MacOSProcessAgent


def main() -> None:
    """Entry point for macOS Process Observatory agent."""
    agent_main(
        agent_class=MacOSProcessAgent,
        agent_name="macos_process",
        description="macOS Process Observatory - monitors all processes with "
        "10 detection probes and full observability",
    )


if __name__ == "__main__":
    main()
