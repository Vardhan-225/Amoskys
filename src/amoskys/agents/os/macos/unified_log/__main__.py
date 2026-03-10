"""AMOSKYS macOS Unified Log Observatory - Module Entry Point

Run with: python -m amoskys.agents.os.macos.unified_log [options]
"""

from amoskys.agents.common.cli import agent_main

from .agent import MacOSUnifiedLogAgent


def main() -> None:
    """Entry point for macOS Unified Log Observatory agent."""
    agent_main(
        agent_class=MacOSUnifiedLogAgent,
        agent_name="macos_unified_log",
        description="macOS Unified Log Observatory - monitors system logs "
        "for security events",
    )


if __name__ == "__main__":
    main()
