"""
AMOSKYS Kernel Audit Agent - Module Entry Point

Run with: python -m amoskys.agents.os.linux.kernel_audit [options]
"""

from amoskys.agents.common.cli import agent_main
from amoskys.agents.os.linux.kernel_audit.kernel_audit_agent import KernelAuditAgent


def main():
    agent_main(KernelAuditAgent, "kernel_audit", "Linux kernel audit monitoring agent")


if __name__ == "__main__":
    main()
