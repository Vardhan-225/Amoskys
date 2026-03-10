"""Database Activity Agent Micro-Probes - 8 Eyes Watching Every Database Query.

Each probe monitors ONE specific database threat vector:

    1. PrivilegeEscalationQueryProbe - GRANT/ALTER USER/CREATE ROLE detection
    2. BulkDataExtractionProbe - SELECT * without WHERE, INTO OUTFILE, dumps
    3. SchemaEnumerationProbe - information_schema/pg_catalog enumeration
    4. StoredProcAbuseProbe - xp_cmdshell, OS command execution via DB
    5. CredentialQueryProbe - Queries targeting credential tables
    6. SQLInjectionPayloadProbe - UNION SELECT, OR 1=1, SLEEP() patterns
    7. UnauthorizedDBAccessProbe - New source_ip+user combo detection
    8. DatabaseDDLChangeProbe - DROP/ALTER/TRUNCATE table detection

MITRE ATT&CK Coverage:
    - T1078: Valid Accounts
    - T1005: Data from Local System
    - T1087: Account Discovery
    - T1059: Command and Scripting Interpreter
    - T1555: Credentials from Password Stores
    - T1190: Exploit Public-Facing Application
    - T1078.004: Valid Accounts: Cloud Accounts
    - T1485: Data Destruction
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from amoskys.agents.common.probes import (
    MicroProbe,
    ProbeContext,
    Severity,
    TelemetryEvent,
)

from .agent_types import DatabaseQuery

logger = logging.getLogger(__name__)


# =============================================================================
# 1. PrivilegeEscalationQueryProbe
# =============================================================================


class PrivilegeEscalationQueryProbe(MicroProbe):
    """Detects database privilege escalation queries.

    Matches GRANT, ALTER USER, CREATE ROLE, SET ROLE queries that may
    indicate an attacker elevating their database permissions.

    MITRE: T1078 (Valid Accounts)
    """

    name = "db_privilege_escalation"
    description = "Detects GRANT/ALTER USER/CREATE ROLE privilege escalation queries"
    mitre_techniques = ["T1078"]
    mitre_tactics = ["privilege_escalation", "persistence"]
    default_enabled = True
    scan_interval = 15.0
    requires_root = False
    platforms = ["linux", "darwin"]
    requires_fields = ["database_queries"]

    # Privilege escalation patterns
    PRIVESC_PATTERNS = [
        (
            "grant_all",
            re.compile(
                r"\bGRANT\s+ALL\b",
                re.IGNORECASE,
            ),
        ),
        (
            "grant_superuser",
            re.compile(
                r"\bGRANT\s+(?:SUPERUSER|DBA|SUPER)\b",
                re.IGNORECASE,
            ),
        ),
        (
            "grant_admin",
            re.compile(
                r"\bGRANT\b.*\bWITH\s+(?:GRANT|ADMIN)\s+OPTION\b",
                re.IGNORECASE,
            ),
        ),
        (
            "alter_user",
            re.compile(
                r"\bALTER\s+(?:USER|ROLE)\b.*(?:SUPERUSER|CREATEDB|CREATEROLE|LOGIN|PASSWORD)",
                re.IGNORECASE,
            ),
        ),
        (
            "create_role",
            re.compile(
                r"\bCREATE\s+(?:USER|ROLE)\b",
                re.IGNORECASE,
            ),
        ),
        (
            "set_role",
            re.compile(
                r"\bSET\s+ROLE\b",
                re.IGNORECASE,
            ),
        ),
        (
            "grant_to",
            re.compile(
                r"\bGRANT\s+\w+.*\bTO\b",
                re.IGNORECASE,
            ),
        ),
    ]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect privilege escalation queries."""
        events = []

        queries: List[DatabaseQuery] = context.shared_data.get("database_queries", [])

        for query in queries:
            if query.query_type not in ("DCL", "DDL"):
                continue

            query_text = query.query_text

            for pattern_name, pattern in self.PRIVESC_PATTERNS:
                if pattern.search(query_text):
                    events.append(
                        self._create_event(
                            event_type="db_privilege_escalation",
                            severity=Severity.CRITICAL,
                            data={
                                "pattern_type": pattern_name,
                                "db_type": query.db_type,
                                "database_name": query.database_name,
                                "query_text": query_text[:500],
                                "user": query.user,
                                "source_ip": query.source_ip,
                                "process": query.process_name,
                            },
                            confidence=0.90,
                        )
                    )
                    break  # One detection per query

        return events


# =============================================================================
# 2. BulkDataExtractionProbe
# =============================================================================


class BulkDataExtractionProbe(MicroProbe):
    """Detects bulk data extraction patterns.

    Identifies queries that may indicate data exfiltration:
        - SELECT * without WHERE or LIMIT
        - INTO OUTFILE / INTO DUMPFILE (MySQL)
        - COPY TO (PostgreSQL)
        - mysqldump / pg_dump patterns
        - Large result sets (rows_affected > threshold)

    MITRE: T1005 (Data from Local System)
    """

    name = "bulk_data_extraction"
    description = "Detects SELECT * without WHERE, INTO OUTFILE, COPY TO, dumps"
    mitre_techniques = ["T1005"]
    mitre_tactics = ["collection"]
    default_enabled = True
    scan_interval = 15.0
    requires_root = False
    platforms = ["linux", "darwin"]
    requires_fields = ["database_queries"]

    # Row threshold for large result alerts
    LARGE_RESULT_THRESHOLD = 10000

    # Bulk extraction patterns
    BULK_PATTERNS = [
        (
            "select_star_no_where",
            re.compile(
                r"\bSELECT\s+\*\s+FROM\s+\S+\s*(?:;|$)",
                re.IGNORECASE,
            ),
        ),
        (
            "into_outfile",
            re.compile(
                r"\bINTO\s+(?:OUTFILE|DUMPFILE)\b",
                re.IGNORECASE,
            ),
        ),
        (
            "copy_to",
            re.compile(
                r"\bCOPY\s+\S+\s+TO\b",
                re.IGNORECASE,
            ),
        ),
        (
            "mysqldump",
            re.compile(
                r"\bmysqldump\b",
                re.IGNORECASE,
            ),
        ),
        (
            "pg_dump",
            re.compile(
                r"\bpg_dump\b",
                re.IGNORECASE,
            ),
        ),
        (
            "select_into",
            re.compile(
                r"\bSELECT\b.*\bINTO\b.*\bFROM\b",
                re.IGNORECASE,
            ),
        ),
    ]

    def _has_where_or_limit(self, query_text: str) -> bool:
        """Check if query has WHERE or LIMIT clause."""
        upper = query_text.upper()
        return "WHERE" in upper or "LIMIT" in upper or "TOP" in upper

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect bulk data extraction patterns."""
        events = []

        queries: List[DatabaseQuery] = context.shared_data.get("database_queries", [])

        for query in queries:
            query_text = query.query_text

            # Check pattern-based detection
            for pattern_name, pattern in self.BULK_PATTERNS:
                if pattern.search(query_text):
                    # For select_star_no_where, verify no WHERE/LIMIT
                    if pattern_name == "select_star_no_where":
                        if self._has_where_or_limit(query_text):
                            continue

                    events.append(
                        self._create_event(
                            event_type="bulk_data_extraction",
                            severity=Severity.HIGH,
                            data={
                                "pattern_type": pattern_name,
                                "db_type": query.db_type,
                                "database_name": query.database_name,
                                "query_text": query_text[:500],
                                "user": query.user,
                                "source_ip": query.source_ip,
                                "rows_affected": query.rows_affected,
                            },
                            confidence=0.80,
                        )
                    )
                    break

            # Check for large result sets
            if (
                query.rows_affected
                and query.rows_affected > self.LARGE_RESULT_THRESHOLD
                and query.query_type == "SELECT"
            ):
                events.append(
                    self._create_event(
                        event_type="large_result_set",
                        severity=Severity.HIGH,
                        data={
                            "db_type": query.db_type,
                            "database_name": query.database_name,
                            "query_text": query_text[:500],
                            "user": query.user,
                            "source_ip": query.source_ip,
                            "rows_affected": query.rows_affected,
                            "threshold": self.LARGE_RESULT_THRESHOLD,
                        },
                        confidence=0.75,
                    )
                )

        return events


# =============================================================================
# 3. SchemaEnumerationProbe
# =============================================================================


class SchemaEnumerationProbe(MicroProbe):
    """Detects schema enumeration queries.

    Identifies bursts of information_schema, pg_catalog, sqlite_master,
    SHOW TABLES, and other schema discovery queries that may indicate
    reconnaissance.

    MITRE: T1087 (Account Discovery)
    """

    name = "schema_enumeration"
    description = (
        "Detects information_schema/pg_catalog/sqlite_master enumeration bursts"
    )
    mitre_techniques = ["T1087"]
    mitre_tactics = ["discovery"]
    default_enabled = True
    scan_interval = 15.0
    requires_root = False
    platforms = ["linux", "darwin"]
    requires_fields = ["database_queries"]

    # Burst threshold for schema queries per scan window
    BURST_THRESHOLD = 5

    # Schema enumeration patterns
    SCHEMA_PATTERNS = re.compile(
        r"\b(?:information_schema|pg_catalog|pg_tables|pg_roles|pg_user|"
        r"sqlite_master|sqlite_schema|sys\.objects|sysobjects|"
        r"sys\.tables|sys\.columns|syscolumns|systables|"
        r"SHOW\s+(?:TABLES|DATABASES|COLUMNS|GRANTS|USERS|PRIVILEGES|"
        r"CREATE\s+TABLE|INDEX|PROCESSLIST)|"
        r"DESCRIBE\s+\S+|"
        r"\\d[t+]?\s|"
        r"EXPLAIN\s+SELECT|"
        r"pg_stat_user_tables|pg_stat_activity)\b",
        re.IGNORECASE,
    )

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect schema enumeration bursts."""
        events = []

        queries: List[DatabaseQuery] = context.shared_data.get("database_queries", [])

        # Count schema queries per user+source
        schema_counts: Dict[str, List[str]] = defaultdict(list)

        for query in queries:
            if self.SCHEMA_PATTERNS.search(query.query_text):
                key = f"{query.user or 'unknown'}@{query.source_ip or 'local'}"
                schema_counts[key].append(query.query_text[:200])

        # Alert on bursts
        for key, query_texts in schema_counts.items():
            if len(query_texts) >= self.BURST_THRESHOLD:
                user, source_ip = key.split("@", 1)
                events.append(
                    self._create_event(
                        event_type="schema_enumeration_burst",
                        severity=Severity.MEDIUM,
                        data={
                            "user": user,
                            "source_ip": source_ip,
                            "query_count": len(query_texts),
                            "threshold": self.BURST_THRESHOLD,
                            "sample_queries": query_texts[:5],
                        },
                        confidence=0.75,
                    )
                )

        return events


# =============================================================================
# 4. StoredProcAbuseProbe
# =============================================================================


class StoredProcAbuseProbe(MicroProbe):
    """Detects stored procedure abuse for OS command execution.

    Matches dangerous stored procedures and functions that allow
    operating system interaction:
        - xp_cmdshell (MSSQL)
        - sp_execute_external_script (MSSQL)
        - CREATE FUNCTION with OS commands
        - LOAD DATA INFILE (MySQL)
        - COPY FROM PROGRAM (PostgreSQL)

    MITRE: T1059 (Command and Scripting Interpreter)
    """

    name = "stored_proc_abuse"
    description = (
        "Detects xp_cmdshell, sp_execute_external_script, OS command execution"
    )
    mitre_techniques = ["T1059"]
    mitre_tactics = ["execution"]
    default_enabled = True
    scan_interval = 15.0
    requires_root = False
    platforms = ["linux", "darwin"]
    requires_fields = ["database_queries"]

    # Dangerous stored procedures and function patterns
    ABUSE_PATTERNS = [
        (
            "xp_cmdshell",
            re.compile(
                r"\bxp_cmdshell\b",
                re.IGNORECASE,
            ),
        ),
        (
            "sp_execute_external_script",
            re.compile(
                r"\bsp_execute_external_script\b",
                re.IGNORECASE,
            ),
        ),
        (
            "sp_oacreate",
            re.compile(
                r"\bsp_OACreate\b",
                re.IGNORECASE,
            ),
        ),
        (
            "openrowset",
            re.compile(
                r"\bOPENROWSET\b",
                re.IGNORECASE,
            ),
        ),
        (
            "create_function_os",
            re.compile(
                r"\bCREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\b.*"
                r"(?:LANGUAGE\s+(?:plpythonu?|plperlu?|plsh)|"
                r"os\.(?:system|popen|exec)|subprocess|"
                r"sys_exec|sys_eval)",
                re.IGNORECASE | re.DOTALL,
            ),
        ),
        (
            "load_data_infile",
            re.compile(
                r"\bLOAD\s+DATA\s+(?:LOCAL\s+)?INFILE\b",
                re.IGNORECASE,
            ),
        ),
        (
            "copy_from_program",
            re.compile(
                r"\bCOPY\s+\S+\s+FROM\s+PROGRAM\b",
                re.IGNORECASE,
            ),
        ),
        (
            "into_outfile",
            re.compile(
                r"\bINTO\s+(?:OUTFILE|DUMPFILE)\s+['\"]",
                re.IGNORECASE,
            ),
        ),
        (
            "dbms_scheduler",
            re.compile(
                r"\bDBMS_SCHEDULER\b",
                re.IGNORECASE,
            ),
        ),
    ]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect stored procedure abuse patterns."""
        events = []

        queries: List[DatabaseQuery] = context.shared_data.get("database_queries", [])

        for query in queries:
            query_text = query.query_text

            for pattern_name, pattern in self.ABUSE_PATTERNS:
                if pattern.search(query_text):
                    events.append(
                        self._create_event(
                            event_type="stored_proc_abuse",
                            severity=Severity.CRITICAL,
                            data={
                                "pattern_type": pattern_name,
                                "db_type": query.db_type,
                                "database_name": query.database_name,
                                "query_text": query_text[:500],
                                "user": query.user,
                                "source_ip": query.source_ip,
                                "process": query.process_name,
                            },
                            confidence=0.90,
                        )
                    )
                    break  # One detection per query

        return events


# =============================================================================
# 5. CredentialQueryProbe
# =============================================================================


class CredentialQueryProbe(MicroProbe):
    """Detects queries targeting credential-related tables.

    Identifies SELECT queries that reference tables/columns commonly used
    to store authentication credentials.

    MITRE: T1555 (Credentials from Password Stores)
    """

    name = "credential_query"
    description = (
        "Detects queries referencing users/passwords/credentials/tokens tables"
    )
    mitre_techniques = ["T1555"]
    mitre_tactics = ["credential_access"]
    default_enabled = True
    scan_interval = 15.0
    requires_root = False
    platforms = ["linux", "darwin"]
    requires_fields = ["database_queries"]

    # Credential-related table/column patterns
    CREDENTIAL_PATTERNS = re.compile(
        r"\b(?:FROM|JOIN|INTO|UPDATE)\s+(?:\S+\.)?(?:"
        r"users?|accounts?|credentials?|auth(?:entication)?|"
        r"passwords?|tokens?|secrets?|api_keys?|"
        r"session(?:s|_tokens)?|oauth_tokens?|"
        r"user_credentials|admin_users?|"
        r"auth_tokens?|refresh_tokens?|access_tokens?|"
        r"private_keys?|ssh_keys?|certificates?)\b",
        re.IGNORECASE,
    )

    # Password column access patterns
    PASSWORD_COLUMN_PATTERN = re.compile(
        r"\bSELECT\b.*\b(?:password|passwd|pwd|hash|"
        r"salt|secret|token|api_key|private_key|"
        r"credential|auth_token)\b",
        re.IGNORECASE,
    )

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect credential table queries."""
        events = []

        queries: List[DatabaseQuery] = context.shared_data.get("database_queries", [])

        for query in queries:
            if query.query_type != "SELECT":
                continue

            query_text = query.query_text

            # Check for credential table access
            if self.CREDENTIAL_PATTERNS.search(query_text):
                # Extra confidence if also selecting password columns
                confidence = 0.80
                if self.PASSWORD_COLUMN_PATTERN.search(query_text):
                    confidence = 0.90

                events.append(
                    self._create_event(
                        event_type="credential_table_query",
                        severity=Severity.HIGH,
                        data={
                            "db_type": query.db_type,
                            "database_name": query.database_name,
                            "query_text": query_text[:500],
                            "user": query.user,
                            "source_ip": query.source_ip,
                            "rows_affected": query.rows_affected,
                        },
                        confidence=confidence,
                    )
                )

        return events


# =============================================================================
# 6. SQLInjectionPayloadProbe
# =============================================================================


class SQLInjectionPayloadProbe(MicroProbe):
    """Detects SQL injection payload patterns in queries.

    Identifies classic SQL injection patterns:
        - UNION SELECT
        - OR 1=1 / OR '1'='1'
        - SLEEP() / BENCHMARK() (blind injection)
        - Stacked queries (;SELECT / ;DROP)
        - Comment-based injection (--', #)
        - Hex/char encoding (CHAR(), 0x)

    MITRE: T1190 (Exploit Public-Facing Application)
    """

    name = "sql_injection_payload"
    description = "Detects UNION SELECT, OR 1=1, SLEEP(), stacked queries"
    mitre_techniques = ["T1190"]
    mitre_tactics = ["initial_access"]
    default_enabled = True
    scan_interval = 15.0
    requires_root = False
    platforms = ["linux", "darwin"]
    requires_fields = ["database_queries"]

    # SQL injection patterns
    SQLI_PATTERNS = [
        (
            "union_select",
            re.compile(
                r"\bUNION\s+(?:ALL\s+)?SELECT\b",
                re.IGNORECASE,
            ),
        ),
        (
            "or_always_true",
            re.compile(
                r"\bOR\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?",
                re.IGNORECASE,
            ),
        ),
        (
            "or_string_true",
            re.compile(
                r"\bOR\s+'[^']*'\s*=\s*'[^']*'",
                re.IGNORECASE,
            ),
        ),
        (
            "sleep_injection",
            re.compile(
                r"\bSLEEP\s*\(\s*\d+\s*\)",
                re.IGNORECASE,
            ),
        ),
        (
            "benchmark_injection",
            re.compile(
                r"\bBENCHMARK\s*\(\s*\d+\s*,",
                re.IGNORECASE,
            ),
        ),
        (
            "waitfor_delay",
            re.compile(
                r"\bWAITFOR\s+DELAY\b",
                re.IGNORECASE,
            ),
        ),
        (
            "stacked_select",
            re.compile(
                r";\s*SELECT\b",
                re.IGNORECASE,
            ),
        ),
        (
            "stacked_drop",
            re.compile(
                r";\s*(?:DROP|DELETE|UPDATE|INSERT)\b",
                re.IGNORECASE,
            ),
        ),
        (
            "comment_injection",
            re.compile(
                r"(?:'|\")--\s|/\*.*\*/",
            ),
        ),
        (
            "char_encoding",
            re.compile(
                r"\bCHAR\s*\(\s*\d+(?:\s*,\s*\d+)+\s*\)",
                re.IGNORECASE,
            ),
        ),
        (
            "hex_encoding",
            re.compile(
                r"0x[0-9a-fA-F]{6,}",
            ),
        ),
        (
            "extractvalue_updatexml",
            re.compile(
                r"\b(?:EXTRACTVALUE|UPDATEXML)\s*\(",
                re.IGNORECASE,
            ),
        ),
    ]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect SQL injection payloads."""
        events = []

        queries: List[DatabaseQuery] = context.shared_data.get("database_queries", [])

        for query in queries:
            query_text = query.query_text

            for pattern_name, pattern in self.SQLI_PATTERNS:
                if pattern.search(query_text):
                    events.append(
                        self._create_event(
                            event_type="sql_injection_detected",
                            severity=Severity.CRITICAL,
                            data={
                                "pattern_type": pattern_name,
                                "db_type": query.db_type,
                                "database_name": query.database_name,
                                "query_text": query_text[:500],
                                "user": query.user,
                                "source_ip": query.source_ip,
                                "process": query.process_name,
                            },
                            confidence=0.85,
                        )
                    )
                    break  # One detection per query

        return events


# =============================================================================
# 7. UnauthorizedDBAccessProbe
# =============================================================================


class UnauthorizedDBAccessProbe(MicroProbe):
    """Detects unauthorized database access from new source_ip+user combinations.

    Tracks unique source_ip+user pairs and flags new ones not seen in the
    established baseline. New combinations may indicate credential theft
    or lateral movement.

    MITRE: T1078.004 (Valid Accounts: Cloud Accounts)
    """

    name = "unauthorized_db_access"
    description = "Flags new source_ip+user combos not in baseline"
    mitre_techniques = ["T1078.004"]
    mitre_tactics = ["initial_access", "persistence"]
    default_enabled = True
    scan_interval = 15.0
    requires_root = False
    platforms = ["linux", "darwin"]
    requires_fields = ["database_queries"]

    # Minimum baseline size before alerting (avoid startup noise)
    MIN_BASELINE_SIZE = 5
    # Number of cycles before baseline stabilizes
    WARMUP_CYCLES = 3

    def __init__(self) -> None:
        super().__init__()
        self.known_combos: Set[str] = set()
        self.warmup_count: int = 0

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect new database access combinations."""
        events = []

        queries: List[DatabaseQuery] = context.shared_data.get("database_queries", [])

        # Build set of current combos
        current_combos: Dict[str, DatabaseQuery] = {}
        for query in queries:
            if not query.source_ip or not query.user:
                continue

            combo_key = f"{query.source_ip}:{query.user}:{query.db_type}"
            if combo_key not in current_combos:
                current_combos[combo_key] = query

        # During warmup, only build baseline
        if self.warmup_count < self.WARMUP_CYCLES:
            self.known_combos.update(current_combos.keys())
            self.warmup_count += 1
            return events

        # After warmup, flag new combos
        for combo_key, query in current_combos.items():
            if combo_key not in self.known_combos:
                # Only alert if baseline has enough entries
                if len(self.known_combos) >= self.MIN_BASELINE_SIZE:
                    events.append(
                        self._create_event(
                            event_type="unauthorized_db_access",
                            severity=Severity.HIGH,
                            data={
                                "source_ip": query.source_ip,
                                "user": query.user,
                                "db_type": query.db_type,
                                "database_name": query.database_name,
                                "query_text": query.query_text[:200],
                                "known_combos_count": len(self.known_combos),
                            },
                            confidence=0.80,
                        )
                    )

                # Add to baseline (learn over time)
                self.known_combos.add(combo_key)

        return events


# =============================================================================
# 8. DatabaseDDLChangeProbe
# =============================================================================


class DatabaseDDLChangeProbe(MicroProbe):
    """Detects destructive DDL operations on databases.

    Matches DROP TABLE, ALTER TABLE, TRUNCATE, DROP DATABASE operations
    that may indicate data destruction or schema manipulation.

    MITRE: T1485 (Data Destruction)
    """

    name = "database_ddl_change"
    description = "Detects DROP TABLE, ALTER TABLE, TRUNCATE, DROP DATABASE"
    mitre_techniques = ["T1485"]
    mitre_tactics = ["impact"]
    default_enabled = True
    scan_interval = 15.0
    requires_root = False
    platforms = ["linux", "darwin"]
    requires_fields = ["database_queries"]

    # DDL change patterns with severity weighting
    DDL_PATTERNS = [
        (
            "drop_database",
            re.compile(
                r"\bDROP\s+DATABASE\b",
                re.IGNORECASE,
            ),
            Severity.CRITICAL,
        ),
        (
            "drop_table",
            re.compile(
                r"\bDROP\s+TABLE\b",
                re.IGNORECASE,
            ),
            Severity.HIGH,
        ),
        (
            "drop_index",
            re.compile(
                r"\bDROP\s+INDEX\b",
                re.IGNORECASE,
            ),
            Severity.HIGH,
        ),
        (
            "truncate_table",
            re.compile(
                r"\bTRUNCATE\s+(?:TABLE\s+)?\S+",
                re.IGNORECASE,
            ),
            Severity.HIGH,
        ),
        (
            "alter_table_drop_column",
            re.compile(
                r"\bALTER\s+TABLE\b.*\bDROP\s+(?:COLUMN\s+)?\S+",
                re.IGNORECASE,
            ),
            Severity.HIGH,
        ),
        (
            "alter_table",
            re.compile(
                r"\bALTER\s+TABLE\b",
                re.IGNORECASE,
            ),
            Severity.HIGH,
        ),
        (
            "drop_view",
            re.compile(
                r"\bDROP\s+VIEW\b",
                re.IGNORECASE,
            ),
            Severity.HIGH,
        ),
        (
            "delete_no_where",
            re.compile(
                r"\bDELETE\s+FROM\s+\S+\s*(?:;|$)",
                re.IGNORECASE,
            ),
            Severity.HIGH,
        ),
    ]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect destructive DDL operations."""
        events = []

        queries: List[DatabaseQuery] = context.shared_data.get("database_queries", [])

        for query in queries:
            query_text = query.query_text

            for pattern_name, pattern, severity in self.DDL_PATTERNS:
                if pattern.search(query_text):
                    # Extra check: DELETE without WHERE is suspicious
                    if pattern_name == "delete_no_where":
                        upper = query_text.upper()
                        if "WHERE" in upper:
                            continue

                    events.append(
                        self._create_event(
                            event_type="database_ddl_change",
                            severity=severity,
                            data={
                                "operation": pattern_name,
                                "db_type": query.db_type,
                                "database_name": query.database_name,
                                "query_text": query_text[:500],
                                "user": query.user,
                                "source_ip": query.source_ip,
                                "process": query.process_name,
                            },
                            confidence=0.85,
                        )
                    )
                    break  # One detection per query

        return events


# =============================================================================
# Probe Registry
# =============================================================================

DB_ACTIVITY_PROBES = [
    PrivilegeEscalationQueryProbe,
    BulkDataExtractionProbe,
    SchemaEnumerationProbe,
    StoredProcAbuseProbe,
    CredentialQueryProbe,
    SQLInjectionPayloadProbe,
    UnauthorizedDBAccessProbe,
    DatabaseDDLChangeProbe,
]


def create_db_activity_probes() -> List[MicroProbe]:
    """Create instances of all Database Activity probes.

    Returns:
        List of initialized Database Activity probe instances
    """
    return [probe_class() for probe_class in DB_ACTIVITY_PROBES]


__all__ = [
    "BulkDataExtractionProbe",
    "create_db_activity_probes",
    "CredentialQueryProbe",
    "DatabaseDDLChangeProbe",
    "DatabaseQuery",
    "DB_ACTIVITY_PROBES",
    "PrivilegeEscalationQueryProbe",
    "SchemaEnumerationProbe",
    "SQLInjectionPayloadProbe",
    "StoredProcAbuseProbe",
    "UnauthorizedDBAccessProbe",
]
