"""AMOSKYS macOS Database Activity Observatory.

Purpose-built database threat detection for macOS (Darwin 25.0.0+, Apple Silicon).
Monitors local database processes via psutil and Unified Logging for database
process messages.

Probes:
    - Bulk data extraction (SELECT * without WHERE, large LIMIT)
    - Schema enumeration (INFORMATION_SCHEMA, SHOW TABLES, pg_catalog)
    - Privilege escalation queries (GRANT, ALTER USER, CREATE ROLE)
    - SQL injection patterns (UNION SELECT, OR 1=1, error-based)
    - Credential table queries (users, passwords, auth_tokens)
    - Data destruction (DROP TABLE, TRUNCATE, DELETE without WHERE)
    - Unauthorized database access (unusual user/connection)
    - Exfiltration via database (INTO OUTFILE, COPY TO, exports)

Coverage: T1005, T1087, T1078, T1190, T1555, T1485, T1078.004, T1048
"""

from amoskys.agents.os.macos.db_activity.agent import MacOSDBActivityAgent

__all__ = ["MacOSDBActivityAgent"]
