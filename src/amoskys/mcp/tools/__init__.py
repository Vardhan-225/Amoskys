"""MCP tool registration — imports all tool modules so decorators fire."""

from . import fleet, telemetry, detect, igris, agent, respond, heal, web  # noqa: F401
