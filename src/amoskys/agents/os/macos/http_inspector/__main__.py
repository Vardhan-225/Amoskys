"""AMOSKYS macOS HTTP Inspector Observatory - Module Entry Point

Run with: python -m amoskys.agents.os.macos.http_inspector [options]
"""

from amoskys.agents.common.cli import agent_main

from .agent import MacOSHTTPInspectorAgent


def main() -> None:
    """Entry point for macOS HTTP Inspector Observatory agent."""
    agent_main(
        agent_class=MacOSHTTPInspectorAgent,
        agent_name="macos_http_inspector",
        description="macOS HTTP Inspector Observatory - inspects HTTP/HTTPS "
        "traffic patterns",
    )


if __name__ == "__main__":
    main()
