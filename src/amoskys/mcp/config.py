"""MCP Server configuration — all tunables in one place."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class MCPConfig:
    """Immutable server configuration, sourced from environment."""

    # ── Database ───────────────────────────────────────────────
    fleet_db: str = os.getenv(
        "MCP_FLEET_DB",
        os.getenv("CC_DB_PATH", "server/fleet.db"),
    )

    # ── Network ────────────────────────────────────────────────
    host: str = os.getenv("MCP_HOST", "0.0.0.0")
    port: int = int(os.getenv("MCP_PORT", "8444"))

    # ── Auth ───────────────────────────────────────────────────
    api_keys: frozenset[str] = field(default_factory=lambda: frozenset(
        k.strip()
        for k in os.getenv("MCP_API_KEYS", "").split(",")
        if k.strip()
    ))
    auth_enabled: bool = os.getenv("MCP_AUTH_ENABLED", "true").lower() == "true"

    # ── Brain ──────────────────────────────────────────────────
    brain_enabled: bool = os.getenv("MCP_BRAIN_ENABLED", "true").lower() == "true"
    brain_interval: int = int(os.getenv("MCP_BRAIN_INTERVAL", "60"))
    brain_correlation_window: int = int(os.getenv("MCP_BRAIN_CORRELATION_WINDOW", "300"))

    # ── Limits ─────────────────────────────────────────────────
    max_query_rows: int = int(os.getenv("MCP_MAX_QUERY_ROWS", "500"))
    command_ttl: int = int(os.getenv("MCP_COMMAND_TTL", "300"))

    # ── Logging ────────────────────────────────────────────────
    log_level: str = os.getenv("MCP_LOG_LEVEL", "INFO")

    def validate(self) -> list[str]:
        """Return list of config problems (empty = OK)."""
        problems: list[str] = []
        if not Path(self.fleet_db).exists():
            problems.append(f"fleet_db not found: {self.fleet_db}")
        if self.auth_enabled and not self.api_keys:
            problems.append("auth enabled but MCP_API_KEYS is empty")
        if self.brain_interval < 10:
            problems.append("brain_interval must be >= 10 seconds")
        return problems


# Singleton — import this everywhere
cfg = MCPConfig()
