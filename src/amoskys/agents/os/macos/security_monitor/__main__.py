"""AMOSKYS macOS Security Monitor Observatory - Module Entry Point

Run with: python -m amoskys.agents.os.macos.security_monitor [options]
"""

from amoskys.agents.common.cli import agent_main

from .security_monitor_agent import MacOSSecurityMonitorAgent


def main() -> None:
    """Entry point for macOS Security Monitor Observatory agent."""
    agent_main(
        agent_class=MacOSSecurityMonitorAgent,
        agent_name="macos_security_monitor",
        description="macOS Security Monitor Observatory - monitors security "
        "framework events and system integrity",
    )


if __name__ == "__main__":
    main()
