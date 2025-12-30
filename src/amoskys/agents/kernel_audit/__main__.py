"""
AMOSKYS Kernel Audit Agent - Module Entry Point

Run with: python -m amoskys.agents.kernel_audit [options]
"""

from amoskys.agents.common.cli import agent_main

from .kernel_audit_agent import KernelAuditAgent


def main() -> None:
    """Entry point for kernel audit agent module."""
    agent_main(
        agent_class=KernelAuditAgent,
        agent_name="kernel_audit_agent",
        description="Kernel-level monitoring agent - detects privilege escalation, "
        "container escapes, and kernel-level attacks",
    )


if __name__ == "__main__":
    main()
