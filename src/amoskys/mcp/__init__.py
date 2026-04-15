"""AMOSKYS MCP Server — IGRIS Fleet Command & Control.

Exposes the full AMOSKYS intelligence platform as MCP tools,
giving IGRIS (or any MCP-compatible client) god-mode access
to fleet telemetry, threat detection, agent control, and
autonomous response across every enrolled device.

Transport: SSE over HTTPS (port 8444)
Auth:      API-key bearer token
Brain:     Fleet-wide autonomous observation loop (60s cycle)
"""

__version__ = "1.0.0"
