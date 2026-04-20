"""MCP tool registration — imports all tool modules so decorators fire."""

from . import fleet, telemetry, detect, igris, agent, respond, heal, web  # noqa: F401

# Kali-native red-team toolset. Imported best-effort — if a non-Kali host
# is running the server, the import succeeds (tool fires will fail
# cleanly with "tool not installed" at call time).
try:
    from . import kali  # noqa: F401
except Exception:
    pass
