"""
AMOSKYS Agent Data Models

SQLAlchemy models for agent tokens, registration, and tracking.
These models support:
- Agent deployment tokens (user-specific)
- Agent registration and health tracking
- Multi-platform agent deployment

Design Principles:
    1. Each user can deploy multiple agents
    2. Agent tokens are tied to users for accountability
    3. Agents report health via heartbeat mechanism
    4. Support Windows, Linux, macOS, Docker platforms

Schema Version: 1.0.0 (Agent Distribution)
"""

from __future__ import annotations

import enum
import secrets
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from amoskys.db import Base, TimestampMixin

__all__ = [
    "AgentPlatform",
    "AgentStatus",
    "AgentToken",
    "DeployedAgent",
]


# =============================================================================
# Enum Types
# =============================================================================


class AgentPlatform(str, enum.Enum):
    """Supported agent platforms."""

    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    DOCKER = "docker"


class AgentStatus(str, enum.Enum):
    """Agent health status."""

    PENDING = "pending"      # Token created, not yet registered
    ONLINE = "online"        # Agent is healthy and reporting
    STALE = "stale"          # No heartbeat in 5 minutes
    OFFLINE = "offline"      # No heartbeat in 15 minutes
    REVOKED = "revoked"      # Token manually revoked


# =============================================================================
# Agent Token Model
# =============================================================================


class AgentToken(TimestampMixin, Base):
    """
    Agent deployment token for user agent provisioning.

    A token is generated when a user requests to deploy a new agent.
    The token is embedded in the agent package and used for registration.

    Security Features:
        - Token is a cryptographically secure random string
        - Token hash stored (not plaintext) for validation
        - One-time use: token consumed on agent registration
        - Tied to specific user for accountability
        - Optional expiration for time-limited deployments

    Attributes:
        id: UUID primary key
        user_id: Foreign key to user who created the token
        token_hash: SHA-256 hash of the token (for validation)
        label: User-friendly name for this deployment
        platform: Target platform (windows/linux/macos/docker)
        is_consumed: Whether token has been used
        expires_at: Optional expiration timestamp
        consumed_at: When the token was used
        consumed_by_agent_id: ID of agent that consumed this token
    """

    __tablename__ = "agent_tokens"

    # Primary key
    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )

    # Foreign key to user
    user_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Token (stored as hash)
    token_hash: Mapped[str] = mapped_column(
        String(64),  # SHA-256 hex = 64 chars
        unique=True,
        nullable=False,
        index=True,
    )

    # Deployment metadata
    label: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    platform: Mapped[AgentPlatform] = mapped_column(
        Enum(AgentPlatform, name="agent_platform", create_constraint=True),
        nullable=False,
    )
    description: Mapped[Optional[str]] = mapped_column(Text)

    # Token lifecycle
    is_consumed: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    consumed_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    consumed_by_agent_id: Mapped[Optional[str]] = mapped_column(String(36))

    # Indexes
    __table_args__ = (
        Index("ix_agent_tokens_user_platform", "user_id", "platform"),
    )

    @classmethod
    def generate_token(cls) -> str:
        """Generate a cryptographically secure agent token."""
        # 32 bytes = 256 bits of entropy, URL-safe base64
        return secrets.token_urlsafe(32)

    @classmethod
    def hash_token(cls, token: str) -> str:
        """Hash a token for storage."""
        import hashlib
        return hashlib.sha256(token.encode()).hexdigest()

    def is_valid(self) -> bool:
        """Check if token is still valid (not consumed, not expired)."""
        if self.is_consumed:
            return False
        if self.expires_at:
            # Handle both timezone-aware and naive datetimes
            now = datetime.now(timezone.utc)
            expires = self.expires_at
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            if now > expires:
                return False
        return True


# =============================================================================
# Deployed Agent Model
# =============================================================================


class DeployedAgent(TimestampMixin, Base):
    """
    Registered agent instance.

    Created when an agent registers with a valid deployment token.
    Tracks agent health, capabilities, and last known state.

    Attributes:
        id: UUID primary key (agent_id)
        user_id: Foreign key to owning user
        token_id: Foreign key to token used for registration
        hostname: Agent's hostname
        ip_address: Last known IP address
        platform: Actual platform (may differ from token if Docker)
        version: Agent version string
        status: Current health status
        capabilities: JSON list of agent capabilities
        last_heartbeat_at: Last successful heartbeat
        metadata: Additional agent metadata (JSON)
    """

    __tablename__ = "deployed_agents"

    # Primary key
    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )

    # Foreign keys
    user_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    token_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("agent_tokens.id", ondelete="SET NULL"),
    )

    # Agent identity
    hostname: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    ip_address: Mapped[Optional[str]] = mapped_column(String(45))  # IPv6 max length
    
    # Platform and version
    platform: Mapped[AgentPlatform] = mapped_column(
        Enum(AgentPlatform, name="agent_platform", create_constraint=True),
        nullable=False,
    )
    version: Mapped[str] = mapped_column(
        String(50),
        default="1.0.0",
        nullable=False,
    )

    # Status
    status: Mapped[AgentStatus] = mapped_column(
        Enum(AgentStatus, name="agent_status", create_constraint=True),
        default=AgentStatus.ONLINE,
        nullable=False,
    )

    # Capabilities (JSON array stored as text)
    capabilities: Mapped[Optional[str]] = mapped_column(Text)

    # Health tracking
    last_heartbeat_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    heartbeat_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    # Extra data (JSON object stored as text) - renamed to avoid SQLAlchemy conflict
    extra_data: Mapped[Optional[str]] = mapped_column(Text)

    # Indexes
    __table_args__ = (
        Index("ix_deployed_agents_user_status", "user_id", "status"),
        Index("ix_deployed_agents_heartbeat", "last_heartbeat_at"),
    )

    def update_heartbeat(self) -> None:
        """Record a heartbeat from this agent."""
        self.last_heartbeat_at = datetime.now(timezone.utc)
        self.heartbeat_count += 1
        self.status = AgentStatus.ONLINE

    def calculate_status(self) -> AgentStatus:
        """Calculate current status based on last heartbeat."""
        if self.status == AgentStatus.REVOKED:
            return AgentStatus.REVOKED
        
        if not self.last_heartbeat_at:
            return AgentStatus.PENDING
        
        now = datetime.now(timezone.utc)
        last_hb = self.last_heartbeat_at
        # Handle timezone-naive datetimes from DB
        if last_hb.tzinfo is None:
            last_hb = last_hb.replace(tzinfo=timezone.utc)
        delta = now - last_hb
        
        if delta.total_seconds() < 300:  # 5 minutes
            return AgentStatus.ONLINE
        elif delta.total_seconds() < 900:  # 15 minutes
            return AgentStatus.STALE
        else:
            return AgentStatus.OFFLINE
