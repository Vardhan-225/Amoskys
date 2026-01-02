"""
AMOSKYS Agent Distribution Service

Handles agent token generation, package building, and deployment tracking.

Features:
    - Generate secure agent deployment tokens
    - Build platform-specific agent packages
    - Track agent deployments per user
    - Monitor agent health and status

Example Usage:
    >>> from amoskys.agents.distribution import AgentDistributionService
    >>> from amoskys.db import get_session_context
    >>>
    >>> with get_session_context() as db:
    ...     service = AgentDistributionService(db)
    ...     result = service.create_deployment_token(
    ...         user_id="user-uuid",
    ...         label="Production Server 1",
    ...         platform="linux"
    ...     )
    ...     print(result.token)  # One-time display token
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from sqlalchemy.orm import Session

from amoskys.common.logging import get_logger

from .models import AgentPlatform, AgentStatus, AgentToken, DeployedAgent

__all__ = [
    "AgentDistributionService",
    "TokenCreationResult",
    "AgentListResult",
    "AgentRegistrationResult",
]

logger = get_logger(__name__)


# =============================================================================
# Result Types
# =============================================================================


@dataclass
class TokenCreationResult:
    """Result of creating a deployment token."""

    success: bool
    token: Optional[str] = None  # Plaintext token (show once!)
    token_id: Optional[str] = None
    error: Optional[str] = None
    error_code: Optional[str] = None


@dataclass
class AgentInfo:
    """Agent information for display."""

    id: str
    hostname: str
    ip_address: Optional[str]
    platform: str
    version: str
    status: str
    capabilities: List[str]
    last_heartbeat_at: Optional[str]
    created_at: str
    heartbeat_count: int


@dataclass
class AgentListResult:
    """Result of listing user's agents."""

    success: bool
    agents: List[AgentInfo]
    total: int
    by_status: dict
    error: Optional[str] = None


@dataclass
class TokenInfo:
    """Token information for display."""

    id: str
    label: str
    platform: str
    is_consumed: bool
    expires_at: Optional[str]
    created_at: str
    consumed_by_agent_id: Optional[str]


@dataclass
class TokenListResult:
    """Result of listing user's tokens."""

    success: bool
    tokens: List[TokenInfo]
    total: int
    active_count: int
    consumed_count: int
    error: Optional[str] = None


@dataclass
class AgentRegistrationResult:
    """Result of agent registration."""

    success: bool
    agent_id: Optional[str] = None
    agent_info: Optional[dict] = None
    error: Optional[str] = None
    error_code: Optional[str] = None


# =============================================================================
# Agent Distribution Service
# =============================================================================


class AgentDistributionService:
    """
    Service for managing agent deployment and distribution.

    Handles the complete lifecycle:
    1. User creates deployment token
    2. User downloads agent package with embedded token
    3. Agent registers with token (consumes it)
    4. Agent sends heartbeats
    5. User monitors agent status
    """

    # Default token validity: 7 days
    DEFAULT_TOKEN_EXPIRY_DAYS = 7

    def __init__(self, db: Session):
        """
        Initialize distribution service.

        Args:
            db: SQLAlchemy database session
        """
        self.db = db

    # =========================================================================
    # Token Management
    # =========================================================================

    def create_deployment_token(
        self,
        user_id: str,
        label: str,
        platform: str,
        description: Optional[str] = None,
        expires_in_days: Optional[int] = None,
    ) -> TokenCreationResult:
        """
        Create a new agent deployment token.

        Args:
            user_id: UUID of the user creating the token
            label: User-friendly name for this deployment
            platform: Target platform (windows/linux/macos/docker)
            description: Optional description
            expires_in_days: Days until token expires (default: 7)

        Returns:
            TokenCreationResult with plaintext token (show once!)
        """
        try:
            # Validate platform
            try:
                platform_enum = AgentPlatform(platform.lower())
            except ValueError:
                return TokenCreationResult(
                    success=False,
                    error=f"Invalid platform: {platform}",
                    error_code="INVALID_PLATFORM",
                )

            # Generate token
            plaintext_token = AgentToken.generate_token()
            token_hash = AgentToken.hash_token(plaintext_token)

            # Calculate expiration
            expires_at = None
            if expires_in_days is None:
                expires_in_days = self.DEFAULT_TOKEN_EXPIRY_DAYS
            if expires_in_days > 0:
                expires_at = datetime.now(timezone.utc) + timedelta(
                    days=expires_in_days
                )

            # Create token record
            token = AgentToken(
                user_id=user_id,
                token_hash=token_hash,
                label=label,
                platform=platform_enum,
                description=description,
                expires_at=expires_at,
            )

            self.db.add(token)
            self.db.commit()

            logger.info(
                "agent_token_created",
                user_id=user_id,
                token_id=token.id,
                platform=platform,
                label=label,
            )

            return TokenCreationResult(
                success=True,
                token=plaintext_token,  # Show this ONCE to user
                token_id=token.id,
            )

        except Exception as e:
            logger.error("agent_token_creation_failed", error=str(e))
            self.db.rollback()
            return TokenCreationResult(
                success=False,
                error="Failed to create deployment token",
                error_code="TOKEN_CREATION_FAILED",
            )

    def list_user_tokens(self, user_id: str) -> TokenListResult:
        """
        List all deployment tokens for a user.

        Args:
            user_id: UUID of the user

        Returns:
            TokenListResult with token list
        """
        try:
            tokens = (
                self.db.query(AgentToken)
                .filter(AgentToken.user_id == user_id)
                .order_by(AgentToken.created_at.desc())
                .all()
            )

            token_infos = []
            active_count = 0
            consumed_count = 0

            for t in tokens:
                if t.is_consumed:
                    consumed_count += 1
                elif t.is_valid():
                    active_count += 1

                token_infos.append(
                    TokenInfo(
                        id=t.id,
                        label=t.label,
                        platform=t.platform.value,
                        is_consumed=t.is_consumed,
                        expires_at=t.expires_at.isoformat() if t.expires_at else None,
                        created_at=t.created_at.isoformat(),
                        consumed_by_agent_id=t.consumed_by_agent_id,
                    )
                )

            return TokenListResult(
                success=True,
                tokens=token_infos,
                total=len(tokens),
                active_count=active_count,
                consumed_count=consumed_count,
            )

        except Exception as e:
            logger.error("list_tokens_failed", error=str(e))
            return TokenListResult(
                success=False,
                tokens=[],
                total=0,
                active_count=0,
                consumed_count=0,
                error="Failed to list tokens",
            )

    def revoke_token(self, user_id: str, token_id: str) -> bool:
        """
        Revoke a deployment token.

        Args:
            user_id: UUID of the user (for authorization)
            token_id: UUID of the token to revoke

        Returns:
            True if revoked, False otherwise
        """
        try:
            token = (
                self.db.query(AgentToken)
                .filter(
                    AgentToken.id == token_id,
                    AgentToken.user_id == user_id,
                )
                .first()
            )

            if not token:
                return False

            # Mark as consumed (effectively revoked)
            token.is_consumed = True
            token.consumed_at = datetime.now(timezone.utc)
            self.db.commit()

            logger.info("agent_token_revoked", token_id=token_id, user_id=user_id)
            return True

        except Exception as e:
            logger.error("token_revocation_failed", error=str(e))
            self.db.rollback()
            return False

    # =========================================================================
    # Agent Registration
    # =========================================================================

    def register_agent(
        self,
        token: str,
        hostname: str,
        ip_address: Optional[str] = None,
        platform: Optional[str] = None,
        version: str = "1.0.0",
        capabilities: Optional[List[str]] = None,
        metadata: Optional[dict] = None,
    ) -> AgentRegistrationResult:
        """
        Register a new agent using a deployment token.

        This consumes the token (one-time use).

        Args:
            token: Plaintext deployment token
            hostname: Agent's hostname
            ip_address: Agent's IP address
            platform: Actual platform (may override token platform)
            version: Agent version string
            capabilities: List of agent capabilities
            metadata: Additional metadata

        Returns:
            AgentRegistrationResult with agent ID
        """
        try:
            # Hash the token for lookup
            token_hash = AgentToken.hash_token(token)

            # Find the token
            token_record = (
                self.db.query(AgentToken)
                .filter(AgentToken.token_hash == token_hash)
                .first()
            )

            if not token_record:
                return AgentRegistrationResult(
                    success=False,
                    error="Invalid deployment token",
                    error_code="INVALID_TOKEN",
                )

            if not token_record.is_valid():
                if token_record.is_consumed:
                    return AgentRegistrationResult(
                        success=False,
                        error="Token has already been used",
                        error_code="TOKEN_CONSUMED",
                    )
                else:
                    return AgentRegistrationResult(
                        success=False,
                        error="Token has expired",
                        error_code="TOKEN_EXPIRED",
                    )

            # Determine platform
            if platform:
                try:
                    platform_enum = AgentPlatform(platform.lower())
                except ValueError:
                    platform_enum = token_record.platform
            else:
                platform_enum = token_record.platform

            # Create agent record
            agent = DeployedAgent(
                user_id=token_record.user_id,
                token_id=token_record.id,
                hostname=hostname,
                ip_address=ip_address,
                platform=platform_enum,
                version=version,
                status=AgentStatus.ONLINE,
                capabilities=json.dumps(capabilities or []),
                extra_data=json.dumps(metadata or {}),
                last_heartbeat_at=datetime.now(timezone.utc),
                heartbeat_count=1,
            )

            self.db.add(agent)

            # Consume the token
            token_record.is_consumed = True
            token_record.consumed_at = datetime.now(timezone.utc)
            token_record.consumed_by_agent_id = agent.id

            self.db.commit()

            logger.info(
                "agent_registered",
                agent_id=agent.id,
                user_id=token_record.user_id,
                hostname=hostname,
                platform=platform_enum.value,
            )

            return AgentRegistrationResult(
                success=True,
                agent_id=agent.id,
                agent_info={
                    "id": agent.id,
                    "hostname": agent.hostname,
                    "platform": agent.platform.value,
                    "status": agent.status.value,
                },
            )

        except Exception as e:
            logger.error("agent_registration_failed", error=str(e))
            self.db.rollback()
            return AgentRegistrationResult(
                success=False,
                error="Failed to register agent",
                error_code="REGISTRATION_FAILED",
            )

    # =========================================================================
    # Agent Monitoring
    # =========================================================================

    def list_user_agents(self, user_id: str) -> AgentListResult:
        """
        List all agents for a user.

        Args:
            user_id: UUID of the user

        Returns:
            AgentListResult with agent list and status counts
        """
        try:
            agents = (
                self.db.query(DeployedAgent)
                .filter(DeployedAgent.user_id == user_id)
                .order_by(DeployedAgent.created_at.desc())
                .all()
            )

            agent_infos = []
            by_status = {
                "online": 0,
                "stale": 0,
                "offline": 0,
                "pending": 0,
                "revoked": 0,
            }

            for a in agents:
                # Calculate current status
                current_status = a.calculate_status()
                if current_status != a.status:
                    a.status = current_status

                by_status[current_status.value] = (
                    by_status.get(current_status.value, 0) + 1
                )

                # Parse capabilities
                try:
                    caps = json.loads(a.capabilities) if a.capabilities else []
                except json.JSONDecodeError:
                    caps = []

                agent_infos.append(
                    AgentInfo(
                        id=a.id,
                        hostname=a.hostname,
                        ip_address=a.ip_address,
                        platform=a.platform.value,
                        version=a.version,
                        status=current_status.value,
                        capabilities=caps,
                        last_heartbeat_at=(
                            a.last_heartbeat_at.isoformat()
                            if a.last_heartbeat_at
                            else None
                        ),
                        created_at=a.created_at.isoformat(),
                        heartbeat_count=a.heartbeat_count,
                    )
                )

            # Commit any status updates
            self.db.commit()

            return AgentListResult(
                success=True,
                agents=agent_infos,
                total=len(agents),
                by_status=by_status,
            )

        except Exception as e:
            logger.error("list_agents_failed", error=str(e))
            return AgentListResult(
                success=False,
                agents=[],
                total=0,
                by_status={},
                error="Failed to list agents",
            )

    def record_heartbeat(
        self,
        agent_id: str,
        ip_address: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> bool:
        """
        Record a heartbeat from an agent.

        Args:
            agent_id: UUID of the agent
            ip_address: Current IP address
            metadata: Optional updated metadata

        Returns:
            True if recorded, False otherwise
        """
        try:
            agent = (
                self.db.query(DeployedAgent)
                .filter(DeployedAgent.id == agent_id)
                .first()
            )

            if not agent:
                return False

            if agent.status == AgentStatus.REVOKED:
                return False

            agent.update_heartbeat()
            if ip_address:
                agent.ip_address = ip_address
            if metadata:
                agent.extra_data = json.dumps(metadata)

            self.db.commit()
            return True

        except Exception as e:
            logger.error("heartbeat_failed", error=str(e), agent_id=agent_id)
            self.db.rollback()
            return False

    def revoke_agent(self, user_id: str, agent_id: str) -> bool:
        """
        Revoke an agent.

        Args:
            user_id: UUID of the user (for authorization)
            agent_id: UUID of the agent to revoke

        Returns:
            True if revoked, False otherwise
        """
        try:
            agent = (
                self.db.query(DeployedAgent)
                .filter(
                    DeployedAgent.id == agent_id,
                    DeployedAgent.user_id == user_id,
                )
                .first()
            )

            if not agent:
                return False

            agent.status = AgentStatus.REVOKED
            self.db.commit()

            logger.info("agent_revoked", agent_id=agent_id, user_id=user_id)
            return True

        except Exception as e:
            logger.error("agent_revocation_failed", error=str(e))
            self.db.rollback()
            return False

    # =========================================================================
    # Statistics
    # =========================================================================

    def get_user_stats(self, user_id: str) -> dict:
        """
        Get agent statistics for a user.

        Args:
            user_id: UUID of the user

        Returns:
            Dictionary with statistics
        """
        try:
            # Count agents by status
            agents_result = self.list_user_agents(user_id)
            tokens_result = self.list_user_tokens(user_id)

            return {
                "total_agents": agents_result.total,
                "online_agents": agents_result.by_status.get("online", 0),
                "stale_agents": agents_result.by_status.get("stale", 0),
                "offline_agents": agents_result.by_status.get("offline", 0),
                "total_tokens": tokens_result.total,
                "active_tokens": tokens_result.active_count,
                "consumed_tokens": tokens_result.consumed_count,
            }

        except Exception as e:
            logger.error("get_stats_failed", error=str(e))
            return {
                "total_agents": 0,
                "online_agents": 0,
                "stale_agents": 0,
                "offline_agents": 0,
                "total_tokens": 0,
                "active_tokens": 0,
                "consumed_tokens": 0,
            }
