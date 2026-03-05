"""Database Activity Agent Types - Normalized representation of database queries.

This module provides the core data structures for database activity events,
normalized from various sources (SQLite, PostgreSQL, MySQL).

Design:
    - Platform-agnostic normalized format
    - All optional fields handle varying source richness
    - Supports SQLite WAL, PostgreSQL logs, MySQL general log
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional


@dataclass
class DatabaseQuery:
    """Normalized database query record.

    This is the canonical format passed to micro-probes for analysis.
    Collectors parse platform-specific database logs into this format.

    Attributes:
        timestamp: When the query was executed
        db_type: Database engine (sqlite, postgresql, mysql)
        database_name: Name of the database accessed
        query_text: The SQL query text
        query_type: Classified query type (SELECT, INSERT, UPDATE, DELETE, DDL, DCL)
        user: Database user who executed the query
        source_ip: IP address of the client connection
        rows_affected: Number of rows affected by the query
        execution_time_ms: Query execution time in milliseconds
        process_name: Name of the process that issued the query
        file_path: Path to database file (SQLite) or log file
    """

    timestamp: datetime
    db_type: str  # "sqlite", "postgresql", "mysql"
    database_name: str
    query_text: str
    query_type: str  # "SELECT", "INSERT", "UPDATE", "DELETE", "DDL", "DCL"
    user: Optional[str] = None
    source_ip: Optional[str] = None
    rows_affected: Optional[int] = None
    execution_time_ms: Optional[float] = None
    process_name: Optional[str] = None
    file_path: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "db_type": self.db_type,
            "database_name": self.database_name,
            "query_text": self.query_text,
            "query_type": self.query_type,
            "user": self.user,
            "source_ip": self.source_ip,
            "rows_affected": self.rows_affected,
            "execution_time_ms": self.execution_time_ms,
            "process_name": self.process_name,
            "file_path": self.file_path,
        }


# =============================================================================
# Database Constants
# =============================================================================

# Standard database ports
DB_PORTS = {
    3306: "mysql",
    5432: "postgresql",
    27017: "mongodb",
    6379: "redis",
    5984: "couchdb",
    9042: "cassandra",
}

# Query type classification keywords
QUERY_TYPE_MAP = {
    "SELECT": "SELECT",
    "INSERT": "INSERT",
    "UPDATE": "UPDATE",
    "DELETE": "DELETE",
    "CREATE": "DDL",
    "ALTER": "DDL",
    "DROP": "DDL",
    "TRUNCATE": "DDL",
    "GRANT": "DCL",
    "REVOKE": "DCL",
    "SET": "DCL",
}

# Known database process names
DB_PROCESSES = frozenset(
    {
        "postgres",
        "postgresql",
        "mysqld",
        "mysql",
        "mongod",
        "redis-server",
        "sqlite3",
        "psql",
        "pgbench",
        "pg_dump",
        "mysqldump",
        "mongodump",
    }
)


# =============================================================================
# Exports
# =============================================================================

__all__ = [
    "DatabaseQuery",
    "DB_PORTS",
    "DB_PROCESSES",
    "QUERY_TYPE_MAP",
]
