"""
AMOSKYS Organization Models

Multi-tenant organization system supporting three tiers:
    1. Individual — personal email users, one person, their devices
    2. Enterprise — company email domain, team management, IAM
    3. Global — AMOSKYS operator view across all organizations

Organizations are auto-created on signup based on email domain:
    - Personal domains (gmail, outlook, etc.) → INDIVIDUAL org per user
    - Custom domains (@company.com) → ENTERPRISE org, auto-grouped

Schema Version: 1.0.0 (Multi-Tenant Foundation)
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import List, Optional

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from amoskys.db import Base, TimestampMixin

__all__ = [
    "OrgType",
    "OrgTier",
    "OrgRole",
    "Organization",
    "OrgMembership",
    "classify_email_domain",
]


# =============================================================================
# Enum Types
# =============================================================================


class OrgType(str, enum.Enum):
    """Organization type — determined by email domain on signup."""

    INDIVIDUAL = "individual"   # Personal email (gmail, outlook, etc.)
    ENTERPRISE = "enterprise"   # Company email domain (@company.com)


class OrgTier(str, enum.Enum):
    """Organization subscription tier."""

    FREE = "free"               # Individual: up to 3 devices
    PRO = "pro"                 # Individual: up to 10 devices
    ENTERPRISE = "enterprise"   # Enterprise: unlimited devices, IAM, SLA


class OrgRole(str, enum.Enum):
    """User's role within an organization.

    Permissions:
        OWNER   — full control: billing, delete org, manage admins
        ADMIN   — manage members, manage agents, view all telemetry
        ANALYST — view telemetry, manage alerts, investigate incidents
        VIEWER  — read-only: view dashboards, no configuration changes
    """

    OWNER = "owner"
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


# =============================================================================
# Organization Model
# =============================================================================


class Organization(TimestampMixin, Base):
    """
    Multi-tenant organization.

    Every user belongs to exactly one organization. Organizations are
    auto-created on signup based on the user's email domain.

    For individual users (gmail, outlook, etc.), a personal org is created
    with the user as OWNER. For enterprise users (@company.com), the first
    user creates the org; subsequent users with the same domain join it.

    Attributes:
        id: UUID primary key
        name: Display name (e.g., "Akash's Devices" or "Amoskys Inc")
        slug: URL-safe identifier (e.g., "amoskys-com")
        type: INDIVIDUAL or ENTERPRISE
        domain: Email domain (NULL for individual, "amoskys.com" for enterprise)
        tier: Subscription tier (FREE, PRO, ENTERPRISE)
        max_devices: Device limit for this tier
        is_active: Organization active flag
    """

    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )

    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    slug: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
    )

    type: Mapped[OrgType] = mapped_column(
        Enum(OrgType, name="org_type", create_constraint=True),
        nullable=False,
    )

    # Email domain — NULL for individual, "company.com" for enterprise
    domain: Mapped[Optional[str]] = mapped_column(
        String(255),
        unique=True,
        index=True,
    )

    tier: Mapped[OrgTier] = mapped_column(
        Enum(OrgTier, name="org_tier", create_constraint=True),
        default=OrgTier.FREE,
        nullable=False,
    )

    max_devices: Mapped[int] = mapped_column(
        Integer,
        default=3,  # Free tier: 3 devices
        nullable=False,
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )

    # Relationships
    memberships: Mapped[List["OrgMembership"]] = relationship(
        "OrgMembership",
        back_populates="organization",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )

    def __repr__(self) -> str:
        return f"<Organization id={self.id[:8]}... name={self.name} type={self.type.value}>"


# =============================================================================
# Organization Membership (User ↔ Organization)
# =============================================================================


class OrgMembership(TimestampMixin, Base):
    """
    Links users to organizations with a specific role.

    Every user has exactly one active membership. The membership defines
    what the user can see and do within the organization's scope.

    For individual orgs: one membership (OWNER).
    For enterprise orgs: multiple memberships with different roles.

    Attributes:
        id: UUID primary key
        user_id: FK to users
        org_id: FK to organizations
        role: User's role in this organization
        is_active: Membership active flag (for soft-disable)
        invited_by: Who invited this user (NULL for org creators)
    """

    __tablename__ = "org_memberships"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )

    user_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    org_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    role: Mapped[OrgRole] = mapped_column(
        Enum(OrgRole, name="org_role", create_constraint=True),
        default=OrgRole.VIEWER,
        nullable=False,
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )

    invited_by: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="SET NULL"),
    )

    # Relationships
    organization: Mapped[Organization] = relationship(
        "Organization",
        back_populates="memberships",
    )

    __table_args__ = (
        # Each user can only have one membership per org
        Index("ix_org_memberships_user_org", "user_id", "org_id", unique=True),
    )

    def __repr__(self) -> str:
        return f"<OrgMembership user={self.user_id[:8]}... org={self.org_id[:8]}... role={self.role.value}>"


# =============================================================================
# Email Domain Classification
# =============================================================================

# Personal email providers — users with these domains get INDIVIDUAL orgs.
# Everything else is treated as a potential enterprise domain.
PERSONAL_DOMAINS: frozenset[str] = frozenset({
    # Google
    "gmail.com",
    "googlemail.com",
    # Microsoft
    "outlook.com",
    "hotmail.com",
    "live.com",
    "msn.com",
    # Yahoo
    "yahoo.com",
    "yahoo.co.uk",
    "yahoo.co.in",
    "ymail.com",
    "rocketmail.com",
    # Apple
    "icloud.com",
    "me.com",
    "mac.com",
    # Privacy-focused
    "protonmail.com",
    "proton.me",
    "tutanota.com",
    "tutamail.com",
    # Other major providers
    "aol.com",
    "zoho.com",
    "mail.com",
    "gmx.com",
    "gmx.net",
    "yandex.com",
    "yandex.ru",
    "fastmail.com",
    "hushmail.com",
    # Regional
    "qq.com",
    "163.com",
    "126.com",
    "naver.com",
    "daum.net",
    "rediffmail.com",
    "web.de",
    "t-online.de",
    "laposte.net",
    "free.fr",
    "libero.it",
    # ISP-based
    "comcast.net",
    "verizon.net",
    "att.net",
    "sbcglobal.net",
    "cox.net",
    "charter.net",
    "earthlink.net",
    "optonline.net",
})


def classify_email_domain(email: str) -> tuple[str, OrgType]:
    """Classify an email address as individual or enterprise.

    Args:
        email: User's email address

    Returns:
        Tuple of (domain, OrgType):
            - ("gmail.com", OrgType.INDIVIDUAL) for personal emails
            - ("amoskys.com", OrgType.ENTERPRISE) for company emails
    """
    domain = email.strip().lower().split("@")[-1]
    if domain in PERSONAL_DOMAINS:
        return domain, OrgType.INDIVIDUAL
    return domain, OrgType.ENTERPRISE


def generate_org_slug(name: str, domain: str | None = None) -> str:
    """Generate a URL-safe slug for an organization.

    Args:
        name: Organization display name
        domain: Email domain (used for enterprise orgs)

    Returns:
        URL-safe slug like "amoskys-com" or "akash-a1b2c3"
    """
    import re
    if domain:
        # Enterprise: use domain as slug base
        slug = domain.replace(".", "-")
    else:
        # Individual: use name + short uuid
        base = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:30]
        slug = f"{base}-{uuid.uuid4().hex[:6]}"
    return slug
