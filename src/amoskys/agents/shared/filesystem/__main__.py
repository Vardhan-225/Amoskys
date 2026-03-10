"""AMOSKYS FIM Agent - Module Entry Point

Run with: python -m amoskys.agents.shared.filesystem [options]
"""

from amoskys.agents.common.cli import agent_main

from .agent import FIMAgent


def main() -> None:
    """Entry point for FIM agent module."""
    agent_main(
        agent_class=FIMAgent,
        agent_name="fim",
        description="File integrity monitoring agent - detects SUID escalation, "
        "webshell drops, config backdoors, library hijacking, and bootloader tampering",
    )


if __name__ == "__main__":
    main()
