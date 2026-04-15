#!/usr/bin/env python3
"""AMOSKYS MCP Server — IGRIS Fleet Command & Control.

Exposes 30+ tools over the Model Context Protocol, giving any MCP-compatible
client (Claude Code, Claude Desktop, custom agents) full access to:

    - Fleet device management
    - Telemetry search across all event tables
    - Threat detection & incident management
    - IGRIS intelligence (posture, hunt, cross-device correlation)
    - Remote agent lifecycle control
    - Autonomous response (isolate, block, kill, quarantine)

The IGRIS Cloud Brain runs as a background thread, providing fleet-wide
autonomous observation and confidence-gated response.

Usage:
    # Direct run (SSE transport on port 8444):
    python -m amoskys.mcp.server

    # With auth:
    MCP_API_KEYS=key1,key2 python -m amoskys.mcp.server

    # Behind nginx (production):
    MCP_AUTH_ENABLED=true MCP_API_KEYS=... python -m amoskys.mcp.server

    # Connect from Claude Code (add to ~/.claude/settings.json):
    {
      "mcpServers": {
        "amoskys": {
          "type": "sse",
          "url": "https://ops.amoskys.com:8444/sse"
        }
      }
    }
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

# Ensure project root is on PYTHONPATH
_project_root = Path(__file__).resolve().parents[3]
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root / "src"))

from mcp.server.fastmcp import FastMCP

from .config import cfg

# ── Logging ────────────────────────────────────────────────────────

logging.basicConfig(
    level=getattr(logging, cfg.log_level, logging.INFO),
    format="%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
)
logger = logging.getLogger("amoskys.mcp.server")

# ── MCP Instance ───────────────────────────────────────────────────

mcp = FastMCP(
    "AMOSKYS IGRIS",
    instructions=(
        "You are connected to the AMOSKYS fleet security platform via IGRIS — "
        "an autonomous network defense system. You have access to fleet telemetry, "
        "threat detection, incident management, and response capabilities across "
        "all enrolled devices. Use the tools to observe, hunt, correlate, and "
        "respond to threats. The Cloud Brain runs autonomously in the background, "
        "but you can query its status and override its decisions."
    ),
)


# ── Resources ──────────────────────────────────────────────────────


@mcp.resource("fleet://status")
def fleet_status_resource() -> str:
    """Current fleet posture — device counts, threat level, active incidents."""
    from .tools.fleet import fleet_status
    import json
    return json.dumps(fleet_status(), indent=2, default=str)


@mcp.resource("fleet://brain")
def brain_status_resource() -> str:
    """IGRIS Cloud Brain status — cycle count, posture, signals, actions."""
    from .brain import get_brain_status
    import json
    return json.dumps(get_brain_status(), indent=2, default=str)


# ── Tool Registration ──────────────────────────────────────────────
# Importing the tools module triggers all @mcp.tool() decorators

from . import tools  # noqa: F401, E402


# ── Startup ────────────────────────────────────────────────────────

def main():
    """Entry point — validate config, start brain, run MCP server."""

    # Validate
    problems = cfg.validate()
    if problems:
        for p in problems:
            logger.warning("Config: %s", p)

    logger.info("AMOSKYS MCP Server v1.0.0")
    logger.info("Fleet DB:  %s", cfg.fleet_db)
    logger.info("Transport: SSE on %s:%d", cfg.host, cfg.port)
    logger.info("Auth:      %s", "enabled" if cfg.auth_enabled else "DISABLED")
    logger.info("Brain:     %s (interval=%ds)",
                "enabled" if cfg.brain_enabled else "disabled", cfg.brain_interval)

    # Start Cloud Brain
    if cfg.brain_enabled:
        from .brain import start_brain
        try:
            start_brain()
            logger.info("IGRIS Cloud Brain started")
        except Exception:
            logger.exception("Failed to start Cloud Brain — continuing without it")

    # Run MCP server
    mcp.run(transport="sse")


if __name__ == "__main__":
    main()
