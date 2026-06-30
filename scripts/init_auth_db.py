#!/usr/bin/env python3
"""
Initialize Authentication Database Tables

Creates all SQLAlchemy tables for the authentication system:
- users
- sessions
- email_verification_tokens
- password_reset_tokens
- auth_audit_log

Usage:
    .venv/bin/python scripts/init_auth_db.py
"""

import os
import sys

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# Import agent models (Phase 3 - Agent Distribution)
from amoskys.agents.models import AgentToken, DeployedAgent  # noqa: F401

# Import models to register them with SQLAlchemy
from amoskys.auth.models import (  # noqa: F401
    AuthAuditLog,
    EmailVerificationToken,
    PasswordResetToken,
    Session,
    User,
)
from amoskys.db import Base, get_engine


def init_db():
    """Create all authentication database tables."""
    print("🧠⚡ AMOSKYS Authentication Database Initialization")
    print("=" * 60)

    # Get engine
    engine = get_engine()
    print(f"✅ Connected to database: {engine.url}")

    # Create all tables
    print("\n📋 Creating tables...")
    Base.metadata.create_all(engine)

    # Verify tables were created
    from sqlalchemy import inspect

    inspector = inspect(engine)
    tables = inspector.get_table_names()

    print("\n✅ Tables created successfully:")
    expected_tables = [
        "users",
        "sessions",
        "email_verification_tokens",
        "password_reset_tokens",
        "auth_audit_log",
        "agent_tokens",
        "deployed_agents",
    ]

    for table in expected_tables:
        if table in tables:
            # Get column count
            columns = inspector.get_columns(table)
            print(f"   • {table} ({len(columns)} columns)")
        else:
            print(f"   ⚠️  {table} - NOT FOUND")

    print("\n" + "=" * 60)
    print("✅ Authentication database initialization complete!")
    print("\nNext steps:")
    print("  1. Start Flask app: .venv/bin/flask run")
    print("  2. Test signup: curl -X POST http://localhost:5000/api/auth/signup \\")
    print('       -H "Content-Type: application/json" \\')
    print('       -d \'{"email": "test@example.com", "password": "SecurePass123!"}\'')


if __name__ == "__main__":
    init_db()
