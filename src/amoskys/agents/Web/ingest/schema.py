"""Pydantic schemas for the /v1/events ingest endpoint.

Matches the canonical envelope emitted by Aegis's class-aegis-emitter.php
and by Argos's engine.py. See docs/web/HANDOVER_PROTOCOL.md for the spec.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    WARN = "warn"          # Aegis emits 'warn' (WordPress convention)
    HIGH = "high"
    CRITICAL = "critical"


class Origin(str, Enum):
    AEGIS = "aegis"
    ARGOS = "argos"


class RequestContext(BaseModel):
    """Optional request context attached by the defensive side."""

    method: Optional[str] = None
    uri: Optional[str] = None
    ip: Optional[str] = None
    ua: Optional[str] = None


class EventEnvelope(BaseModel):
    """Canonical event envelope, v1 schema."""

    schema_version: str = Field(..., description="Envelope schema version, currently '1'")
    event_id: str
    event_type: str
    event_timestamp_ns: int
    severity: Severity
    site_id: str
    site_url: Optional[str] = None
    wp_version: Optional[str] = None
    plugin_version: Optional[str] = None

    # Per-origin metadata
    origin: Optional[Origin] = None  # aegis emits implicit via the plugin, argos sets it

    # Chain integrity
    prev_sig: Optional[str] = None
    sig: str

    # Payload + context
    request: Optional[RequestContext] = None
    attributes: Dict[str, Any] = Field(default_factory=dict)

    # Set server-side from bearer token — clients cannot set this
    tenant_id: Optional[str] = None

    @field_validator("event_type")
    @classmethod
    def validate_event_type(cls, v: str) -> str:
        # Must be a dotted namespace like "aegis.auth.login_failed" or "argos.finding.cve"
        parts = v.split(".")
        if len(parts) < 2 or not parts[0].isalnum():
            raise ValueError(f"event_type must be dotted (e.g. 'aegis.auth.login_failed'), got: {v}")
        return v

    @field_validator("schema_version")
    @classmethod
    def validate_schema_version(cls, v: str) -> str:
        if v not in ("1",):
            raise ValueError(f"unsupported schema_version: {v}")
        return v

    @field_validator("event_timestamp_ns")
    @classmethod
    def validate_timestamp(cls, v: int) -> int:
        # Nanoseconds since epoch, must be a plausible value
        # (between 2020-01-01 and 2100-01-01)
        if v < 1_577_836_800_000_000_000 or v > 4_102_444_800_000_000_000:
            raise ValueError(f"event_timestamp_ns out of plausible range: {v}")
        return v


class IngestResponse(BaseModel):
    """Response body for successful POST /v1/events."""

    accepted: bool
    event_id: str
    persisted_at: int  # ns
    chain_ok: bool
    tenant_id: str
    warnings: list[str] = Field(default_factory=list)
