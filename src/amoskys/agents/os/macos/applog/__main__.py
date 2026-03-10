"""AMOSKYS macOS AppLog Observatory - Module Entry Point

Run with: python -m amoskys.agents.os.macos.applog [options]
"""

from amoskys.agents.common.cli import agent_main

from .agent import MacOSAppLogAgent


def main() -> None:
    """Entry point for macOS AppLog Observatory agent."""
    agent_main(
        agent_class=MacOSAppLogAgent,
        agent_name="macos_applog",
        description="macOS AppLog Observatory - monitors application logs "
        "for security-relevant events",
    )


if __name__ == "__main__":
    main()
