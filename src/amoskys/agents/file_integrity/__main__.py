"""
AMOSKYS File Integrity Agent - Module Entry Point

Run with: python -m amoskys.agents.file_integrity [options]
"""

from amoskys.agents.common.cli import agent_main

from .file_integrity_agent import FIMAgent


def main() -> None:
    """Entry point for file integrity agent module."""
    agent_main(
        agent_class=FIMAgent,
        agent_name="fim_agent",
        description="File integrity monitoring agent - detects unauthorized "
        "modifications to critical system files and configurations",
    )


if __name__ == "__main__":
    main()
