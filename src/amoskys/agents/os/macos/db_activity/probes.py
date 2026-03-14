"""macOS Database Activity Observatory probes — threat detection via database monitoring.

8 probes covering database-targeted attack techniques:
    1. BulkExtractionProbe     — T1005 Data from Local System (bulk extraction)
    2. SchemaEnumProbe         — T1087 Account/Schema Discovery
    3. PrivEscQueryProbe       — T1078 Valid Accounts (privilege escalation)
    4. SQLInjectionProbe       — T1190 Exploit Public-Facing Application
    5. CredentialQueryProbe    — T1555 Credentials from Password Stores
    6. DataDestructionProbe    — T1485 Data Destruction
    7. UnauthorizedAccessProbe — T1078.004 Valid Accounts: Cloud Accounts
    8. ExfilViaDBProbe         — T1048 Exfiltration Over Alternative Protocol
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any, Dict, List, Optional, Set

from amoskys.agents.common.probes import (
    MicroProbe,
    ProbeContext,
    Severity,
    TelemetryEvent,
)

logger = logging.getLogger(__name__)


# ── Shared utilities ─────────────────────────────────────────────────────────


# Benign system databases/schemas that should not trigger alerts
_SYSTEM_DATABASES = frozenset(
    {
        "information_schema",
        "mysql",
        "performance_schema",
        "sys",
        "pg_catalog",
        "pg_toast",
        "template0",
        "template1",
        "admin",
        "local",
        "config",  # MongoDB system databases
    }
)

# Common administrative users that may perform privileged operations
_ADMIN_USERS = frozenset(
    {
        "root",
        "postgres",
        "mysql",
        "mongod",
        "redis",
        "admin",
        "dba",
        "rdsadmin",
        "cloudsqladmin",
    }
)


def _normalize_query(query: str) -> str:
    """Normalize a SQL query for pattern matching (uppercase, collapse whitespace)."""
    return re.sub(r"\s+", " ", query.upper().strip())


# ── Probe 1: Bulk Data Extraction ────────────────────────────────────────────


class BulkExtractionProbe(MicroProbe):
    """Detect large result set queries indicative of bulk data extraction.

    MITRE: T1005 — Data from Local System

    Attackers exfiltrate data by running SELECT * with no WHERE clause or
    queries with extremely large LIMIT values. This probe detects both
    patterns in database log entries.
    """

    name = "macos_db_bulk_extraction"
    description = (
        "Detects large result set queries (SELECT * without WHERE, large LIMIT)"
    )
    platforms = ["darwin"]
    mitre_techniques = ["T1005"]
    mitre_tactics = ["collection"]
    scan_interval = 10.0
    requires_fields = ["db_logs"]
    maturity = "stable"
    false_positive_notes = [
        "Backup tools (pg_dump, mysqldump) run SELECT * during scheduled backups",
        "ORM frameworks may generate SELECT * queries during migrations",
    ]
    evasion_notes = [
        "Paginated queries with moderate LIMIT values avoid the threshold",
        "Using cursors or streaming reads does not appear in query logs",
    ]

    LIMIT_THRESHOLD = 10000  # LIMIT values above this are suspicious

    _SELECT_STAR_NO_WHERE = re.compile(
        r"SELECT\s+\*\s+FROM\s+\S+(?:\s*;|\s*$)",
        re.IGNORECASE,
    )
    _LARGE_LIMIT = re.compile(
        r"LIMIT\s+(\d+)",
        re.IGNORECASE,
    )

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        db_logs = context.shared_data.get("db_logs", [])

        for entry in db_logs:
            query = entry.query or entry.message
            if not query:
                continue

            normalized = _normalize_query(query)

            # Check 1: SELECT * without WHERE
            if self._SELECT_STAR_NO_WHERE.search(query) and "WHERE" not in normalized:
                events.append(
                    self._create_event(
                        event_type="bulk_extraction_select_star",
                        severity=Severity.HIGH,
                        data={
                            "query": query[:500],
                            "db_type": entry.db_type,
                            "user": entry.user,
                            "database": entry.database,
                        },
                        confidence=0.80,
                    )
                )

            # Check 2: Large LIMIT value
            limit_match = self._LARGE_LIMIT.search(query)
            if limit_match:
                limit_val = int(limit_match.group(1))
                if limit_val > self.LIMIT_THRESHOLD:
                    events.append(
                        self._create_event(
                            event_type="bulk_extraction_large_limit",
                            severity=Severity.MEDIUM,
                            data={
                                "query": query[:500],
                                "limit_value": limit_val,
                                "threshold": self.LIMIT_THRESHOLD,
                                "db_type": entry.db_type,
                                "user": entry.user,
                                "database": entry.database,
                            },
                            confidence=0.70,
                        )
                    )

        return events


# ── Probe 2: Schema Enumeration ──────────────────────────────────────────────


class SchemaEnumProbe(MicroProbe):
    """Detect schema enumeration queries used for reconnaissance.

    MITRE: T1087 — Account Discovery (extended to schema/table discovery)

    Attackers enumerate database structure before data exfiltration. Indicators
    include INFORMATION_SCHEMA queries, SHOW TABLES, pg_catalog access, and
    metadata table enumeration.
    """

    name = "macos_db_schema_enum"
    description = "Detects INFORMATION_SCHEMA queries, SHOW TABLES, pg_catalog access"
    platforms = ["darwin"]
    mitre_techniques = ["T1087"]
    mitre_tactics = ["discovery"]
    scan_interval = 10.0
    requires_fields = ["db_logs"]
    maturity = "stable"
    false_positive_notes = [
        "ORMs (SQLAlchemy, Django) query INFORMATION_SCHEMA on startup",
        "Database admin tools (pgAdmin, phpMyAdmin) enumerate schemas regularly",
    ]
    evasion_notes = [
        "Querying individual tables by known name bypasses schema enumeration detection",
        "Using application-layer APIs instead of raw SQL avoids log-based detection",
    ]

    _SCHEMA_PATTERNS = [
        re.compile(r"INFORMATION_SCHEMA\.\w+", re.IGNORECASE),
        re.compile(r"SHOW\s+(TABLES|DATABASES|COLUMNS|INDEX|SCHEMAS)", re.IGNORECASE),
        re.compile(r"PG_CATALOG\.\w+", re.IGNORECASE),
        re.compile(r"PG_TABLES|PG_VIEWS|PG_INDEXES", re.IGNORECASE),
        re.compile(r"DESCRIBE\s+\w+", re.IGNORECASE),
        re.compile(r"\\d[tivs]?\s+", re.IGNORECASE),  # psql meta-commands
        re.compile(r"SHOW\s+CREATE\s+TABLE", re.IGNORECASE),
        re.compile(r"SELECT\s+.*FROM\s+ALL_TABLES", re.IGNORECASE),
    ]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        db_logs = context.shared_data.get("db_logs", [])

        for entry in db_logs:
            query = entry.query or entry.message
            if not query:
                continue

            for pattern in self._SCHEMA_PATTERNS:
                if pattern.search(query):
                    events.append(
                        self._create_event(
                            event_type="schema_enumeration_detected",
                            severity=Severity.MEDIUM,
                            data={
                                "query": query[:500],
                                "pattern_matched": pattern.pattern,
                                "db_type": entry.db_type,
                                "user": entry.user,
                                "database": entry.database,
                            },
                            confidence=0.65,
                        )
                    )
                    break  # One alert per log entry

        return events


# ── Probe 3: Privilege Escalation Queries ────────────────────────────────────


class PrivEscQueryProbe(MicroProbe):
    """Detect privilege escalation attempts via database commands.

    MITRE: T1078 — Valid Accounts

    Attackers escalate privileges by granting roles, altering user permissions,
    or creating new privileged accounts within the database.
    """

    name = "macos_db_priv_escalation"
    description = "Detects GRANT, ALTER USER, CREATE ROLE privilege escalation patterns"
    platforms = ["darwin"]
    mitre_techniques = ["T1078"]
    mitre_tactics = ["persistence"]
    scan_interval = 10.0
    requires_fields = ["db_logs"]
    maturity = "stable"
    false_positive_notes = [
        "Database provisioning scripts run GRANT statements during setup",
        "CI/CD pipelines may create temporary roles for testing",
    ]
    evasion_notes = [
        "Using stored procedures to modify permissions avoids direct GRANT detection",
        "Modifying system tables directly instead of using DDL commands",
    ]

    _PRIV_ESC_PATTERNS = [
        re.compile(r"GRANT\s+(ALL|SUPER|ADMIN|DBA|REPLICATION)", re.IGNORECASE),
        re.compile(r"GRANT\s+\w+\s+ON\s+\*\.\*", re.IGNORECASE),
        re.compile(
            r"ALTER\s+USER\s+\w+\s+.*(?:SUPERUSER|CREATEDB|CREATEROLE)", re.IGNORECASE
        ),
        re.compile(
            r"CREATE\s+(?:USER|ROLE)\s+\w+\s+.*(?:SUPERUSER|ADMIN|LOGIN)", re.IGNORECASE
        ),
        re.compile(
            r"ALTER\s+ROLE\s+\w+\s+.*(?:SUPERUSER|CREATEDB|CREATEROLE)", re.IGNORECASE
        ),
        re.compile(r"SET\s+ROLE\s+", re.IGNORECASE),
        re.compile(r"db\.grantRolesToUser", re.IGNORECASE),  # MongoDB
        re.compile(r"ACL\s+SETUSER", re.IGNORECASE),  # Redis
    ]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        db_logs = context.shared_data.get("db_logs", [])

        for entry in db_logs:
            query = entry.query or entry.message
            if not query:
                continue

            for pattern in self._PRIV_ESC_PATTERNS:
                if pattern.search(query):
                    events.append(
                        self._create_event(
                            event_type="privilege_escalation_query",
                            severity=Severity.CRITICAL,
                            data={
                                "query": query[:500],
                                "pattern_matched": pattern.pattern,
                                "db_type": entry.db_type,
                                "user": entry.user,
                                "database": entry.database,
                            },
                            confidence=0.85,
                        )
                    )
                    break  # One alert per log entry

        return events


# ── Probe 4: SQL Injection Detection ─────────────────────────────────────────


class SQLInjectionProbe(MicroProbe):
    """Detect SQL injection patterns in database logs.

    MITRE: T1190 — Exploit Public-Facing Application

    SQL injection attacks insert malicious SQL via user input. Indicators:
    UNION SELECT, OR 1=1, tautologies, stacked queries, error-based extraction,
    and comment injection.
    """

    name = "macos_db_sql_injection"
    description = "Detects SQL injection patterns (UNION SELECT, OR 1=1, error-based)"
    platforms = ["darwin"]
    mitre_techniques = ["T1190"]
    mitre_tactics = ["initial_access"]
    scan_interval = 10.0
    requires_fields = ["db_logs"]
    maturity = "stable"
    false_positive_notes = [
        "Application queries with UNION for legitimate data aggregation",
        "Debug/test queries with OR 1=1 for data inspection",
    ]
    evasion_notes = [
        "Obfuscated SQL using CHAR() encoding or hex representations",
        "Time-based blind injection without visible error patterns",
    ]

    _SQLI_PATTERNS = [
        re.compile(r"UNION\s+(ALL\s+)?SELECT", re.IGNORECASE),
        re.compile(r"OR\s+1\s*=\s*1", re.IGNORECASE),
        re.compile(r"OR\s+'[^']*'\s*=\s*'[^']*'", re.IGNORECASE),
        re.compile(r"OR\s+\"[^\"]*\"\s*=\s*\"[^\"]*\"", re.IGNORECASE),
        re.compile(r";\s*(DROP|DELETE|INSERT|UPDATE|ALTER|CREATE)\s+", re.IGNORECASE),
        re.compile(r"--\s*$", re.MULTILINE),
        re.compile(r"EXTRACTVALUE\s*\(", re.IGNORECASE),
        re.compile(r"UPDATEXML\s*\(", re.IGNORECASE),
        re.compile(r"LOAD_FILE\s*\(", re.IGNORECASE),
        re.compile(r"SLEEP\s*\(\s*\d+\s*\)", re.IGNORECASE),
        re.compile(r"BENCHMARK\s*\(\s*\d+", re.IGNORECASE),
        re.compile(r"WAITFOR\s+DELAY", re.IGNORECASE),
        re.compile(r"CONVERT\s*\(\s*INT", re.IGNORECASE),
    ]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        db_logs = context.shared_data.get("db_logs", [])

        for entry in db_logs:
            query = entry.query or entry.message
            if not query:
                continue

            matched_patterns = []
            for pattern in self._SQLI_PATTERNS:
                if pattern.search(query):
                    matched_patterns.append(pattern.pattern)

            if matched_patterns:
                # More patterns matched = higher confidence
                confidence = min(0.95, 0.6 + len(matched_patterns) * 0.1)
                events.append(
                    self._create_event(
                        event_type="sql_injection_detected",
                        severity=Severity.CRITICAL,
                        data={
                            "query": query[:500],
                            "patterns_matched": matched_patterns[:5],
                            "pattern_count": len(matched_patterns),
                            "db_type": entry.db_type,
                            "user": entry.user,
                            "database": entry.database,
                        },
                        confidence=confidence,
                    )
                )

        return events


# ── Probe 5: Credential Table Queries ────────────────────────────────────────


class CredentialQueryProbe(MicroProbe):
    """Detect queries targeting credential/authentication tables.

    MITRE: T1555 — Credentials from Password Stores

    Attackers query tables storing user credentials, auth tokens, API keys,
    and session data. This probe matches SELECT queries against known
    credential table and column names.
    """

    name = "macos_db_credential_query"
    description = (
        "Detects queries targeting credential tables (users, passwords, auth_tokens)"
    )
    platforms = ["darwin"]
    mitre_techniques = ["T1555"]
    mitre_tactics = ["credential_access"]
    scan_interval = 10.0
    requires_fields = ["db_logs"]
    maturity = "stable"
    false_positive_notes = [
        "Authentication services legitimately query user/password tables",
        "Password rotation scripts access credential stores",
    ]
    evasion_notes = [
        "Querying via application ORM layer does not expose table names in logs",
        "Using views or stored procedures to abstract credential access",
    ]

    _CREDENTIAL_TABLE_PATTERNS = [
        re.compile(r"FROM\s+\w*(?:users|accounts|credentials|auth)\w*", re.IGNORECASE),
        re.compile(r"FROM\s+\w*(?:passwords?|secrets?|tokens?)\w*", re.IGNORECASE),
        re.compile(
            r"FROM\s+\w*(?:api_keys?|access_keys?|auth_tokens?)\w*", re.IGNORECASE
        ),
        re.compile(r"FROM\s+\w*(?:sessions?|login|oauth)\w*", re.IGNORECASE),
    ]
    _CREDENTIAL_COLUMN_PATTERNS = [
        re.compile(r"SELECT\s+.*(?:password|passwd|pwd|secret|hash)", re.IGNORECASE),
        re.compile(
            r"SELECT\s+.*(?:api_key|access_key|token|auth_token)", re.IGNORECASE
        ),
        re.compile(r"SELECT\s+.*(?:private_key|encryption_key|salt)", re.IGNORECASE),
    ]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        db_logs = context.shared_data.get("db_logs", [])

        for entry in db_logs:
            query = entry.query or entry.message
            if not query:
                continue

            normalized = _normalize_query(query)

            # Must be a SELECT query
            if "SELECT" not in normalized:
                continue

            # Check table-level patterns
            table_match = None
            for pattern in self._CREDENTIAL_TABLE_PATTERNS:
                match = pattern.search(query)
                if match:
                    table_match = match.group(0)
                    break

            # Check column-level patterns
            column_match = None
            for pattern in self._CREDENTIAL_COLUMN_PATTERNS:
                match = pattern.search(query)
                if match:
                    column_match = match.group(0)
                    break

            if table_match or column_match:
                severity = (
                    Severity.CRITICAL
                    if (table_match and column_match)
                    else Severity.HIGH
                )
                confidence = 0.85 if (table_match and column_match) else 0.70

                events.append(
                    self._create_event(
                        event_type="credential_table_query",
                        severity=severity,
                        data={
                            "query": query[:500],
                            "table_match": table_match or "",
                            "column_match": column_match or "",
                            "db_type": entry.db_type,
                            "user": entry.user,
                            "database": entry.database,
                        },
                        confidence=confidence,
                    )
                )

        return events


# ── Probe 6: Data Destruction ────────────────────────────────────────────────


class DataDestructionProbe(MicroProbe):
    """Detect data destruction commands (DROP, TRUNCATE, unqualified DELETE).

    MITRE: T1485 — Data Destruction

    Attackers destroy data to cover tracks or cause impact. Indicators:
    DROP TABLE, TRUNCATE TABLE, DELETE FROM without WHERE clause.
    """

    name = "macos_db_data_destruction"
    description = "Detects DROP TABLE, TRUNCATE, DELETE FROM without WHERE"
    platforms = ["darwin"]
    mitre_techniques = ["T1485"]
    mitre_tactics = ["impact"]
    scan_interval = 10.0
    requires_fields = ["db_logs"]
    maturity = "stable"
    false_positive_notes = [
        "Database migration tools (Flyway, Alembic) may DROP/TRUNCATE during migrations",
        "Cleanup scripts that DELETE old data run on schedules",
    ]
    evasion_notes = [
        "Using UPDATE to overwrite data instead of DELETE/DROP",
        "Dropping individual rows with WHERE clause to avoid detection",
    ]

    _DESTRUCTION_PATTERNS = [
        re.compile(r"DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?\w+", re.IGNORECASE),
        re.compile(r"DROP\s+DATABASE\s+(?:IF\s+EXISTS\s+)?\w+", re.IGNORECASE),
        re.compile(r"TRUNCATE\s+(?:TABLE\s+)?\w+", re.IGNORECASE),
        re.compile(r"DROP\s+SCHEMA\s+(?:IF\s+EXISTS\s+)?\w+", re.IGNORECASE),
        re.compile(r"DROP\s+INDEX\s+(?:IF\s+EXISTS\s+)?\w+", re.IGNORECASE),
    ]
    _DELETE_NO_WHERE = re.compile(
        r"DELETE\s+FROM\s+\w+\s*(?:;|\s*$)",
        re.IGNORECASE,
    )

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        db_logs = context.shared_data.get("db_logs", [])

        for entry in db_logs:
            query = entry.query or entry.message
            if not query:
                continue

            normalized = _normalize_query(query)

            # Check destructive DDL patterns
            for pattern in self._DESTRUCTION_PATTERNS:
                if pattern.search(query):
                    severity = (
                        Severity.CRITICAL if "DATABASE" in normalized else Severity.HIGH
                    )
                    events.append(
                        self._create_event(
                            event_type="data_destruction_detected",
                            severity=severity,
                            data={
                                "query": query[:500],
                                "pattern_matched": pattern.pattern,
                                "db_type": entry.db_type,
                                "user": entry.user,
                                "database": entry.database,
                            },
                            confidence=0.85,
                        )
                    )
                    break  # One alert per log entry

            # Check DELETE without WHERE
            if self._DELETE_NO_WHERE.search(query) and "WHERE" not in normalized:
                events.append(
                    self._create_event(
                        event_type="delete_without_where",
                        severity=Severity.HIGH,
                        data={
                            "query": query[:500],
                            "db_type": entry.db_type,
                            "user": entry.user,
                            "database": entry.database,
                        },
                        confidence=0.80,
                    )
                )

        return events


# ── Probe 7: Unauthorized Access ─────────────────────────────────────────────


class UnauthorizedAccessProbe(MicroProbe):
    """Detect unusual user/connection patterns accessing the database.

    MITRE: T1078.003 — Valid Accounts: Local Accounts

    Attackers use stolen or default credentials to access databases.
    Indicators: authentication failures, connections from non-admin users
    performing admin operations, unusual database user/client combinations.
    Note: T1078.004 (Cloud Accounts) is for cloud/SaaS platforms, not endpoint.
    """

    name = "macos_db_unauthorized_access"
    description = "Detects unusual user/connection accessing database"
    platforms = ["darwin"]
    mitre_techniques = ["T1078.003"]
    mitre_tactics = ["persistence"]
    scan_interval = 10.0
    requires_fields = ["db_logs"]
    maturity = "experimental"
    supports_baseline = True
    baseline_window_hours = 24
    false_positive_notes = [
        "New legitimate users trigger first-seen alerts until baseline stabilizes",
        "Service account rotation may appear as unauthorized access",
    ]
    evasion_notes = [
        "Using compromised legitimate credentials avoids unknown-user detection",
        "Connecting through application connection pools masks the actual user",
    ]

    _AUTH_FAIL_PATTERNS = [
        re.compile(r"(?:authentication|login)\s+fail", re.IGNORECASE),
        re.compile(r"access\s+denied\s+for\s+user", re.IGNORECASE),
        re.compile(r"password\s+authentication\s+failed", re.IGNORECASE),
        re.compile(r"invalid\s+(?:user|username|password)", re.IGNORECASE),
        re.compile(r"WRONGPASS", re.IGNORECASE),  # Redis
        re.compile(r"Authentication\s+failed", re.IGNORECASE),  # MongoDB
    ]
    _CONNECTION_PATTERN = re.compile(
        r"connection\s+(?:received|authorized|established)",
        re.IGNORECASE,
    )

    AUTH_FAIL_THRESHOLD = 5  # Failures in single cycle → suspicious

    def __init__(self) -> None:
        super().__init__()
        self._known_users: Set[str] = set()
        self._cycle_count = 0
        self._baseline_cycles = 6

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        db_logs = context.shared_data.get("db_logs", [])
        self._cycle_count += 1

        auth_failures: List[Dict[str, Any]] = []
        new_users: Set[str] = set()

        for entry in db_logs:
            message = entry.message or ""
            user = entry.user

            # Check for authentication failures
            for pattern in self._AUTH_FAIL_PATTERNS:
                if pattern.search(message):
                    auth_failures.append(
                        {
                            "message": message[:300],
                            "db_type": entry.db_type,
                            "user": user,
                            "database": entry.database,
                        }
                    )
                    break

            # Track user baseline
            if user and user not in self._known_users:
                if self._cycle_count > self._baseline_cycles:
                    new_users.add(user)
                self._known_users.add(user)

        # Alert on auth failure bursts
        if len(auth_failures) >= self.AUTH_FAIL_THRESHOLD:
            events.append(
                self._create_event(
                    event_type="auth_failure_burst",
                    severity=Severity.HIGH,
                    data={
                        "failure_count": len(auth_failures),
                        "threshold": self.AUTH_FAIL_THRESHOLD,
                        "sample_failures": auth_failures[:5],
                    },
                    confidence=0.80,
                )
            )

        # Alert on new/unknown users (after baseline)
        for user in new_users:
            if user not in _ADMIN_USERS:
                events.append(
                    self._create_event(
                        event_type="unknown_db_user_detected",
                        severity=Severity.MEDIUM,
                        data={
                            "user": user,
                            "known_user_count": len(self._known_users),
                            "cycle": self._cycle_count,
                        },
                        confidence=0.55,
                    )
                )

        return events


# ── Probe 8: Exfiltration via Database ───────────────────────────────────────


class ExfilViaDBProbe(MicroProbe):
    """Detect data exfiltration via database export commands.

    MITRE: T1048 — Exfiltration Over Alternative Protocol

    Attackers use database export features to extract data to files or external
    systems. Indicators: INTO OUTFILE, COPY TO, mongodump, data export utilities.
    """

    name = "macos_db_exfiltration"
    description = "Detects INTO OUTFILE, COPY TO, data export patterns"
    platforms = ["darwin"]
    mitre_techniques = ["T1048"]
    mitre_tactics = ["exfiltration"]
    scan_interval = 10.0
    requires_fields = ["db_logs"]
    maturity = "stable"
    false_positive_notes = [
        "Scheduled database backups use COPY TO and export commands",
        "ETL pipelines legitimately export data via INTO OUTFILE",
    ]
    evasion_notes = [
        "Using application-layer export (SELECT then write via app) avoids SQL-level detection",
        "Exfiltrating via database replication streams is not visible in query logs",
    ]

    _EXFIL_PATTERNS = [
        re.compile(r"INTO\s+OUTFILE\s+", re.IGNORECASE),
        re.compile(r"INTO\s+DUMPFILE\s+", re.IGNORECASE),
        re.compile(r"COPY\s+\w+\s+TO\s+", re.IGNORECASE),
        re.compile(r"COPY\s+\(.*\)\s+TO\s+", re.IGNORECASE),
        re.compile(r"\\copy\s+\w+\s+TO\s+", re.IGNORECASE),  # psql \copy
        re.compile(r"SELECT\s+.*INTO\s+OUTFILE", re.IGNORECASE),
        re.compile(r"pg_dump", re.IGNORECASE),
        re.compile(r"mysqldump", re.IGNORECASE),
        re.compile(r"mongodump", re.IGNORECASE),
        re.compile(r"mongoexport", re.IGNORECASE),
        re.compile(r"BACKUP\s+DATABASE", re.IGNORECASE),
        re.compile(r"xp_cmdshell", re.IGNORECASE),
    ]
    _SENSITIVE_PATH_PATTERN = re.compile(
        r"(?:/tmp/|/var/tmp/|/dev/shm/|/Users/\w+/|\\\\|https?://)",
        re.IGNORECASE,
    )

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        db_logs = context.shared_data.get("db_logs", [])

        for entry in db_logs:
            query = entry.query or entry.message
            if not query:
                continue

            for pattern in self._EXFIL_PATTERNS:
                if pattern.search(query):
                    # Higher severity if exporting to suspicious path
                    has_sensitive_path = bool(
                        self._SENSITIVE_PATH_PATTERN.search(query)
                    )
                    severity = (
                        Severity.CRITICAL if has_sensitive_path else Severity.HIGH
                    )

                    events.append(
                        self._create_event(
                            event_type="db_exfiltration_detected",
                            severity=severity,
                            data={
                                "query": query[:500],
                                "pattern_matched": pattern.pattern,
                                "sensitive_path": has_sensitive_path,
                                "db_type": entry.db_type,
                                "user": entry.user,
                                "database": entry.database,
                            },
                            confidence=0.80 if has_sensitive_path else 0.70,
                        )
                    )
                    break  # One alert per log entry

        return events


# ── Factory ──────────────────────────────────────────────────────────────────


def create_db_activity_probes() -> List[MicroProbe]:
    """Create all macOS Database Activity Observatory probes."""
    return [
        BulkExtractionProbe(),
        SchemaEnumProbe(),
        PrivEscQueryProbe(),
        SQLInjectionProbe(),
        CredentialQueryProbe(),
        DataDestructionProbe(),
        UnauthorizedAccessProbe(),
        ExfilViaDBProbe(),
    ]
