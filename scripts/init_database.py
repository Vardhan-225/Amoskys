#!/usr/bin/env python3
"""
Initialize AMOSKYS Database

Creates all authentication tables in the database.
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from sqlalchemy import create_engine, inspect
from amoskys.auth.models import Base
from amoskys.common.logging import get_logger

logger = get_logger(__name__)

def init_database(database_url: str = "sqlite:///data/amoskys.db"):
    """Initialize database with all tables."""
    print(f"Initializing database: {database_url}")

    # Create engine
    engine = create_engine(database_url, echo=False)

    # Create all tables
    Base.metadata.create_all(engine)

    # Verify tables were created
    inspector = inspect(engine)
    tables = inspector.get_table_names()

    print(f"\n✅ Database initialized successfully!")
    print(f"\nTables created ({len(tables)}):")
    for table in sorted(tables):
        print(f"  - {table}")

    return True

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Initialize AMOSKYS database")
    parser.add_argument(
        "--database-url",
        default="sqlite:///data/amoskys.db",
        help="Database URL (default: sqlite:///data/amoskys.db)"
    )

    args = parser.parse_args()

    try:
        init_database(args.database_url)
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error initializing database: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
