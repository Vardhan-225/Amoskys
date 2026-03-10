"""AMOSKYS HTTP Inspector Agent - Module Entry Point

Run with: python -m amoskys.agents.http_inspector [options]
"""

from amoskys.agents.common.cli import agent_main

from .agent import HTTPInspectorAgent


def main() -> None:
    """Entry point for HTTP Inspector agent module."""
    agent_main(
        agent_class=HTTPInspectorAgent,
        agent_name="http_inspector",
        description="HTTP transaction monitoring agent - detects XSS, SSRF, "
        "path traversal, API abuse, data exfiltration, and web shell uploads",
    )


if __name__ == "__main__":
    main()
