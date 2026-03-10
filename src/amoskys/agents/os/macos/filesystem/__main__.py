"""AMOSKYS macOS Filesystem Observatory - Module Entry Point

Run with: python -m amoskys.agents.os.macos.filesystem [options]
"""

from amoskys.agents.common.cli import agent_main

from .agent import MacOSFileAgent


def main() -> None:
    """Entry point for macOS Filesystem Observatory agent."""
    agent_main(
        agent_class=MacOSFileAgent,
        agent_name="macos_filesystem",
        description="macOS Filesystem Observatory - file integrity monitoring "
        "with tamper and webshell detection",
    )


if __name__ == "__main__":
    main()
