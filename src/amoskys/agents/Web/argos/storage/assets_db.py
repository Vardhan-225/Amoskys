"""Customer + surface-asset storage.

One SQLite database per Argos deployment holds every customer, every
recon run, every discovered asset, and a complete audit log of what
was done on whose behalf.

Design choices:

  - **SQLite, not Postgres.** One deployment, one operator. Portability
    (a single .db file is the state of record) beats horizontal scale
    at this stage. Migration path to Postgres is the same schema.

  - **File mode 0600.** Customer data. Readable only by the running
    user. Enforced at open time; we refuse to run if the file is
    world-readable.

  - **WAL mode.** Recon sources may crash mid-run. WAL ensures a
    partial write never corrupts the DB.

  - **UNIQUE(customer_id, kind, value)** on assets — re-discovering the
    same asset from a new source updates `last_seen_ns` and the
    confidence score rather than duplicating.

  - **Audit log is append-only.** No delete, no update. A customer's
    right to forget is fulfilled by purging the entire customer row
    (cascades), which itself is logged.

Not done here (deferred):

  - Field-level encryption for sensitive metadata (e.g. `consent_token`).
    The DB-level 0600 perm is our v1 floor.
  - Multi-tenant isolation (separate DB per customer org). v2+.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import stat
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("amoskys.argos.storage")


# ── Enums ──────────────────────────────────────────────────────────


class ConsentMethod(str, Enum):
    """How the customer authorized us to perform this work.

    Each method produces the same outcome (consent_verified_at_ns set)
    but carries different audit evidence. The `consent_token` field
    stores method-specific metadata:

        DNS_TXT         : the random token we told them to publish
        SIGNED_CONTRACT : artifact reference (DocuSign ID, contract number)
        EMAIL           : artifact reference (Message-ID, email subject, screenshot path)
        LAB_SELF        : None (dev only)

    Bug-bounty hunting is NOT a customer consent method — it's internal
    AMOSKYS tooling gated by operator identity. See argos/operators.py.
    """
    DNS_TXT = "dns_txt"
    EMAIL = "email"
    SIGNED_CONTRACT = "signed_contract"
    LAB_SELF = "lab_self"  # dev only — our own lab targets


class OperatorRole(str, Enum):
    """AMOSKYS user role — controls which commands they can run.

    ADMIN   : full access including operator management + hunt mode
    ANALYST : hunt mode + customer recon + customer scan; cannot manage operators
    VIEWER  : read-only (list customers, view findings); no active commands
    """
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class AssetKind(str, Enum):
    DOMAIN = "domain"          # apex, e.g. example.com
    SUBDOMAIN = "subdomain"    # www.example.com, api.example.com
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    NETBLOCK = "netblock"      # 203.0.113.0/24
    ASN = "asn"                # AS15169
    SERVICE = "service"        # host:port/proto discovered as listening
    URL = "url"                # fully-qualified HTTP resource
    CERT = "cert"              # a specific TLS certificate (SHA-256)


# ── DTOs ───────────────────────────────────────────────────────────


@dataclass
class Customer:
    customer_id: str
    name: str
    seed: str
    consent_method: ConsentMethod
    consent_token: Optional[str]
    consent_verified_at_ns: Optional[int]
    created_at_ns: int

    @classmethod
    def new(
        cls,
        name: str,
        seed: str,
        consent_method: ConsentMethod,
        consent_token: Optional[str] = None,
    ) -> "Customer":
        return cls(
            customer_id=str(uuid.uuid4()),
            name=name,
            seed=seed,
            consent_method=consent_method,
            consent_token=consent_token,
            consent_verified_at_ns=None,
            created_at_ns=int(time.time() * 1e9),
        )


@dataclass
class ReconRun:
    run_id: str
    customer_id: str
    started_at_ns: int
    completed_at_ns: Optional[int]
    sources_attempted: List[str]
    sources_completed: List[str]
    assets_discovered: int
    errors: List[str]

    @classmethod
    def new(cls, customer_id: str) -> "ReconRun":
        return cls(
            run_id=str(uuid.uuid4()),
            customer_id=customer_id,
            started_at_ns=int(time.time() * 1e9),
            completed_at_ns=None,
            sources_attempted=[],
            sources_completed=[],
            assets_discovered=0,
            errors=[],
        )


@dataclass
class SurfaceAsset:
    asset_id: str
    customer_id: str
    kind: AssetKind
    value: str
    parent_id: Optional[str]
    source: str
    confidence: float
    first_seen_ns: int
    last_seen_ns: int
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def new(
        cls,
        customer_id: str,
        kind: AssetKind,
        value: str,
        source: str,
        confidence: float = 0.8,
        parent_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "SurfaceAsset":
        now_ns = int(time.time() * 1e9)
        return cls(
            asset_id=str(uuid.uuid4()),
            customer_id=customer_id,
            kind=kind,
            value=value,
            parent_id=parent_id,
            source=source,
            confidence=max(0.0, min(1.0, confidence)),
            first_seen_ns=now_ns,
            last_seen_ns=now_ns,
            metadata=metadata or {},
        )


@dataclass
class AuditEntry:
    log_id: Optional[int]  # autoincrement
    customer_id: Optional[str]
    run_id: Optional[str]
    timestamp_ns: int
    actor: str       # e.g. "ct_logs.crtsh", "cli.recon", "engine.consent"
    action: str      # e.g. "http_get", "dns_query", "consent_verify"
    target: Optional[str]
    result: str      # e.g. "ok", "403", "timeout"
    details: Dict[str, Any] = field(default_factory=dict)
    operator_id: Optional[str] = None  # AMOSKYS user who initiated the action


@dataclass
class Operator:
    """An AMOSKYS employee with authorization to run active tooling."""
    operator_id: str
    email: str
    name: str
    role: OperatorRole
    created_at_ns: int
    last_active_at_ns: Optional[int] = None
    disabled_at_ns: Optional[int] = None

    @classmethod
    def new(cls, email: str, name: str, role: OperatorRole) -> "Operator":
        return cls(
            operator_id=str(uuid.uuid4()),
            email=email.strip().lower(),
            name=name.strip(),
            role=role,
            created_at_ns=int(time.time() * 1e9),
        )

    @property
    def is_active(self) -> bool:
        return self.disabled_at_ns is None


@dataclass
class OperatorAgreement:
    """One record of an operator accepting the terms-of-use agreement.

    Versioned so bumping the agreement text forces re-acceptance.
    We store a SHA-256 of the agreement text at acceptance time so the
    operator can't later claim they saw a different version.
    """
    operator_id: str
    version: str
    accepted_at_ns: int
    agreement_sha256: str
    ip_at_accept: Optional[str] = None  # captured for audit (CLI host addr)


@dataclass
class ScanQueue:
    """A batch of per-asset scans for one customer, kicked off together.

    The queue is the unit of "one customer scan" — even though each
    asset becomes its own Engagement, the customer thinks of them as a
    single run. The consolidated report covers the whole queue.
    """
    queue_id: str
    customer_id: str
    operator_id: str
    created_at_ns: int
    completed_at_ns: Optional[int] = None
    total_jobs: int = 0
    # Denormalized tool-bundle name for display (e.g. "wp-full-ast")
    tool_bundle: str = "wp-full-ast"

    @classmethod
    def new(
        cls,
        customer_id: str,
        operator_id: str,
        tool_bundle: str = "wp-full-ast",
    ) -> "ScanQueue":
        return cls(
            queue_id=str(uuid.uuid4()),
            customer_id=customer_id,
            operator_id=operator_id,
            created_at_ns=int(time.time() * 1e9),
            tool_bundle=tool_bundle,
        )


@dataclass
class ScanJob:
    """One asset → one Engagement mapping inside a ScanQueue.

    Jobs flow: pending → running → (complete | failed | skipped).
    Findings count and engagement_id are set when the job transitions
    out of `running`.
    """
    job_id: str
    queue_id: str
    customer_id: str
    asset_id: str
    asset_value: str   # denormalized (e.g. "api.acme.com")
    asset_kind: str    # denormalized
    status: str        # pending | running | complete | failed | skipped
    engagement_id: Optional[str] = None
    started_at_ns: Optional[int] = None
    completed_at_ns: Optional[int] = None
    findings_count: int = 0
    skip_reason: Optional[str] = None
    error: Optional[str] = None

    @classmethod
    def new(
        cls,
        queue_id: str,
        customer_id: str,
        asset_id: str,
        asset_value: str,
        asset_kind: str,
    ) -> "ScanJob":
        return cls(
            job_id=str(uuid.uuid4()),
            queue_id=queue_id,
            customer_id=customer_id,
            asset_id=asset_id,
            asset_value=asset_value,
            asset_kind=asset_kind,
            status="pending",
        )


# ── Core DB ────────────────────────────────────────────────────────


class AssetsDB:
    """Thread-safe customer-asset store.

    Usage:
        db = AssetsDB(Path.home() / ".argos" / "customer.db")
        db.initialize()  # creates schema + enforces file perms

        c = Customer.new("Acme Corp", "acme.com", ConsentMethod.DNS_TXT)
        db.create_customer(c)

        run = ReconRun.new(c.customer_id)
        db.start_recon_run(run)
        ...
        db.upsert_asset(SurfaceAsset.new(c.customer_id, AssetKind.SUBDOMAIN, ...))
        ...
        db.complete_recon_run(run.run_id, assets_discovered=12)

    Concurrency:
        SQLite's shared-cache + WAL gives us multi-reader / single-writer.
        A single threading.Lock guards writes in Python to keep BEGIN
        EXCLUSIVE cheap.
    """

    DEFAULT_PATH = Path.home() / ".argos" / "customer.db"

    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = Path(path or self.DEFAULT_PATH).resolve()
        self._lock = threading.Lock()
        self._conn: Optional[sqlite3.Connection] = None

    # ── Lifecycle ──────────────────────────────────────────────────

    def initialize(self) -> None:
        """Create schema + enforce 0600 file perms. Idempotent.

        Also runs any needed additive migrations for columns added
        after the initial schema (operator_id on audit_log).
        """
        self.path.parent.mkdir(parents=True, exist_ok=True)

        # Create the file (if absent) with a restrictive mask BEFORE
        # sqlite3 opens and writes to it. This avoids a race where a
        # fresh DB briefly exists 0644 before we chmod it.
        if not self.path.exists():
            old_mask = os.umask(0o077)
            try:
                self.path.touch(mode=0o600)
            finally:
                os.umask(old_mask)

        self._verify_perms()

        conn = self._open()
        try:
            conn.executescript(_SCHEMA_SQL)
            self._run_migrations(conn)
            conn.commit()
        finally:
            conn.close()

    def _run_migrations(self, conn: sqlite3.Connection) -> None:
        """Additive-only migrations. Never drops or renames; only adds."""
        # operator_id on audit_log (added when operator model was introduced)
        cols = {row["name"] for row in conn.execute("PRAGMA table_info(audit_log)").fetchall()}
        if "operator_id" not in cols:
            conn.execute("ALTER TABLE audit_log ADD COLUMN operator_id TEXT")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_operator ON audit_log(operator_id)")

    def _open(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self.path,
            isolation_level=None,    # autocommit + explicit BEGIN
            check_same_thread=False, # we guard with self._lock
            timeout=30.0,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    def _verify_perms(self) -> None:
        """Refuse to run if the DB file is accessible beyond the owner."""
        st = self.path.stat()
        # Guard the world+group perm bits. Owner bits can be rw-.
        bad = st.st_mode & (stat.S_IRGRP | stat.S_IWGRP | stat.S_IXGRP |
                            stat.S_IROTH | stat.S_IWOTH | stat.S_IXOTH)
        if bad:
            raise PermissionError(
                f"refusing to open {self.path}: permissive mode "
                f"{oct(st.st_mode & 0o777)}. "
                f"Run: chmod 600 '{self.path}' and retry."
            )

    def _conn_ctx(self) -> sqlite3.Connection:
        """Open a fresh connection per-call.

        SQLite connections are cheap; keeping one-per-thread avoids
        the 'SQLite objects created in a thread can only be used in
        that same thread' trap while WAL handles concurrent reads.
        """
        self._verify_perms()
        return self._open()

    # ── Customer CRUD ──────────────────────────────────────────────

    def create_customer(self, customer: Customer) -> None:
        conn = self._conn_ctx()
        try:
            with self._lock:
                conn.execute(
                    "INSERT INTO customers "
                    "(customer_id, name, seed, consent_method, consent_token, "
                    " consent_verified_at_ns, created_at_ns) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        customer.customer_id,
                        customer.name,
                        customer.seed,
                        customer.consent_method.value,
                        customer.consent_token,
                        customer.consent_verified_at_ns,
                        customer.created_at_ns,
                    ),
                )
                self._audit_unsafe(
                    conn,
                    AuditEntry(
                        log_id=None,
                        customer_id=customer.customer_id,
                        run_id=None,
                        timestamp_ns=int(time.time() * 1e9),
                        actor="storage.create_customer",
                        action="create_customer",
                        target=customer.seed,
                        result="ok",
                        details={"consent_method": customer.consent_method.value},
                    ),
                )
        finally:
            conn.close()

    def get_customer(self, customer_id: str) -> Optional[Customer]:
        conn = self._conn_ctx()
        try:
            row = conn.execute(
                "SELECT * FROM customers WHERE customer_id = ?",
                (customer_id,),
            ).fetchone()
            return _customer_from_row(row) if row else None
        finally:
            conn.close()

    def get_customer_by_name(self, name: str) -> Optional[Customer]:
        conn = self._conn_ctx()
        try:
            row = conn.execute(
                "SELECT * FROM customers WHERE name = ?",
                (name,),
            ).fetchone()
            return _customer_from_row(row) if row else None
        finally:
            conn.close()

    def list_customers(self) -> List[Customer]:
        conn = self._conn_ctx()
        try:
            rows = conn.execute(
                "SELECT * FROM customers ORDER BY created_at_ns DESC"
            ).fetchall()
            return [_customer_from_row(r) for r in rows]
        finally:
            conn.close()

    def mark_consent_verified(self, customer_id: str) -> None:
        conn = self._conn_ctx()
        try:
            now_ns = int(time.time() * 1e9)
            with self._lock:
                conn.execute(
                    "UPDATE customers SET consent_verified_at_ns = ? "
                    "WHERE customer_id = ?",
                    (now_ns, customer_id),
                )
                self._audit_unsafe(
                    conn,
                    AuditEntry(
                        log_id=None,
                        customer_id=customer_id,
                        run_id=None,
                        timestamp_ns=now_ns,
                        actor="storage.mark_consent_verified",
                        action="consent_verify",
                        target=None,
                        result="ok",
                        details={},
                    ),
                )
        finally:
            conn.close()

    # ── Recon run tracking ─────────────────────────────────────────

    def start_recon_run(self, run: ReconRun) -> None:
        conn = self._conn_ctx()
        try:
            with self._lock:
                conn.execute(
                    "INSERT INTO recon_runs "
                    "(run_id, customer_id, started_at_ns, completed_at_ns, "
                    " sources_attempted, sources_completed, assets_discovered, errors) "
                    "VALUES (?, ?, ?, NULL, ?, ?, 0, ?)",
                    (
                        run.run_id,
                        run.customer_id,
                        run.started_at_ns,
                        json.dumps(run.sources_attempted),
                        json.dumps(run.sources_completed),
                        json.dumps(run.errors),
                    ),
                )
        finally:
            conn.close()

    def complete_recon_run(
        self,
        run_id: str,
        sources_completed: List[str],
        assets_discovered: int,
        errors: List[str],
    ) -> None:
        conn = self._conn_ctx()
        try:
            with self._lock:
                conn.execute(
                    "UPDATE recon_runs SET "
                    "  completed_at_ns = ?, "
                    "  sources_completed = ?, "
                    "  assets_discovered = ?, "
                    "  errors = ? "
                    "WHERE run_id = ?",
                    (
                        int(time.time() * 1e9),
                        json.dumps(sources_completed),
                        assets_discovered,
                        json.dumps(errors),
                        run_id,
                    ),
                )
        finally:
            conn.close()

    def list_recon_runs(self, customer_id: str) -> List[ReconRun]:
        conn = self._conn_ctx()
        try:
            rows = conn.execute(
                "SELECT * FROM recon_runs WHERE customer_id = ? "
                "ORDER BY started_at_ns DESC",
                (customer_id,),
            ).fetchall()
            return [_recon_run_from_row(r) for r in rows]
        finally:
            conn.close()

    # ── Asset upsert ──────────────────────────────────────────────

    def upsert_asset(self, asset: SurfaceAsset) -> str:
        """Insert or update an asset, returning its stable asset_id.

        If (customer_id, kind, value) already exists, update last_seen_ns
        and bump confidence toward `asset.confidence` (taking max) —
        multiple sources corroborating an asset is stronger evidence, not
        weaker.
        """
        conn = self._conn_ctx()
        try:
            with self._lock:
                existing = conn.execute(
                    "SELECT asset_id, confidence FROM surface_assets "
                    "WHERE customer_id = ? AND kind = ? AND value = ?",
                    (asset.customer_id, asset.kind.value, asset.value),
                ).fetchone()

                if existing:
                    new_conf = max(existing["confidence"], asset.confidence)
                    conn.execute(
                        "UPDATE surface_assets SET "
                        "  last_seen_ns = ?, confidence = ?, "
                        "  metadata = ? "
                        "WHERE asset_id = ?",
                        (
                            asset.last_seen_ns,
                            new_conf,
                            json.dumps(asset.metadata),
                            existing["asset_id"],
                        ),
                    )
                    return existing["asset_id"]

                conn.execute(
                    "INSERT INTO surface_assets "
                    "(asset_id, customer_id, kind, value, parent_id, source, "
                    " confidence, first_seen_ns, last_seen_ns, metadata) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        asset.asset_id,
                        asset.customer_id,
                        asset.kind.value,
                        asset.value,
                        asset.parent_id,
                        asset.source,
                        asset.confidence,
                        asset.first_seen_ns,
                        asset.last_seen_ns,
                        json.dumps(asset.metadata),
                    ),
                )
                return asset.asset_id
        finally:
            conn.close()

    def list_assets(
        self,
        customer_id: str,
        kind: Optional[AssetKind] = None,
    ) -> List[SurfaceAsset]:
        conn = self._conn_ctx()
        try:
            if kind is None:
                rows = conn.execute(
                    "SELECT * FROM surface_assets WHERE customer_id = ? "
                    "ORDER BY kind, value",
                    (customer_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM surface_assets "
                    "WHERE customer_id = ? AND kind = ? "
                    "ORDER BY value",
                    (customer_id, kind.value),
                ).fetchall()
            return [_asset_from_row(r) for r in rows]
        finally:
            conn.close()

    def asset_counts(self, customer_id: str) -> Dict[str, int]:
        conn = self._conn_ctx()
        try:
            rows = conn.execute(
                "SELECT kind, COUNT(*) AS n FROM surface_assets "
                "WHERE customer_id = ? GROUP BY kind",
                (customer_id,),
            ).fetchall()
            return {row["kind"]: int(row["n"]) for row in rows}
        finally:
            conn.close()

    # ── Audit log ─────────────────────────────────────────────────

    def audit(self, entry: AuditEntry) -> None:
        conn = self._conn_ctx()
        try:
            with self._lock:
                self._audit_unsafe(conn, entry)
        finally:
            conn.close()

    def _audit_unsafe(self, conn: sqlite3.Connection, entry: AuditEntry) -> None:
        """Append an audit row. Caller MUST hold self._lock + provide conn."""
        conn.execute(
            "INSERT INTO audit_log "
            "(customer_id, run_id, operator_id, timestamp_ns, actor, action, "
            " target, result, details) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                entry.customer_id,
                entry.run_id,
                entry.operator_id,
                entry.timestamp_ns,
                entry.actor,
                entry.action,
                entry.target,
                entry.result,
                json.dumps(entry.details),
            ),
        )

    # ── Operator CRUD ─────────────────────────────────────────────

    def create_operator(self, operator: Operator) -> None:
        conn = self._conn_ctx()
        try:
            with self._lock:
                conn.execute(
                    "INSERT INTO operators "
                    "(operator_id, email, name, role, created_at_ns, "
                    " last_active_at_ns, disabled_at_ns) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        operator.operator_id,
                        operator.email,
                        operator.name,
                        operator.role.value,
                        operator.created_at_ns,
                        operator.last_active_at_ns,
                        operator.disabled_at_ns,
                    ),
                )
                self._audit_unsafe(
                    conn,
                    AuditEntry(
                        log_id=None,
                        customer_id=None,
                        run_id=None,
                        operator_id=operator.operator_id,
                        timestamp_ns=int(time.time() * 1e9),
                        actor="storage.create_operator",
                        action="operator_create",
                        target=operator.email,
                        result="ok",
                        details={"role": operator.role.value, "name": operator.name},
                    ),
                )
        finally:
            conn.close()

    def get_operator(self, operator_id: str) -> Optional[Operator]:
        conn = self._conn_ctx()
        try:
            row = conn.execute(
                "SELECT * FROM operators WHERE operator_id = ?",
                (operator_id,),
            ).fetchone()
            return _operator_from_row(row) if row else None
        finally:
            conn.close()

    def get_operator_by_email(self, email: str) -> Optional[Operator]:
        conn = self._conn_ctx()
        try:
            row = conn.execute(
                "SELECT * FROM operators WHERE email = ?",
                (email.strip().lower(),),
            ).fetchone()
            return _operator_from_row(row) if row else None
        finally:
            conn.close()

    def list_operators(self, include_disabled: bool = False) -> List[Operator]:
        conn = self._conn_ctx()
        try:
            if include_disabled:
                rows = conn.execute(
                    "SELECT * FROM operators ORDER BY created_at_ns DESC"
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM operators WHERE disabled_at_ns IS NULL "
                    "ORDER BY created_at_ns DESC"
                ).fetchall()
            return [_operator_from_row(r) for r in rows]
        finally:
            conn.close()

    def touch_operator_active(self, operator_id: str) -> None:
        """Update last_active_at_ns. Use whenever an operator runs a command."""
        conn = self._conn_ctx()
        try:
            with self._lock:
                conn.execute(
                    "UPDATE operators SET last_active_at_ns = ? "
                    "WHERE operator_id = ?",
                    (int(time.time() * 1e9), operator_id),
                )
        finally:
            conn.close()

    def disable_operator(self, operator_id: str) -> None:
        conn = self._conn_ctx()
        try:
            with self._lock:
                now_ns = int(time.time() * 1e9)
                conn.execute(
                    "UPDATE operators SET disabled_at_ns = ? "
                    "WHERE operator_id = ?",
                    (now_ns, operator_id),
                )
                self._audit_unsafe(
                    conn,
                    AuditEntry(
                        log_id=None,
                        customer_id=None,
                        run_id=None,
                        operator_id=operator_id,
                        timestamp_ns=now_ns,
                        actor="storage.disable_operator",
                        action="operator_disable",
                        target=None,
                        result="ok",
                        details={},
                    ),
                )
        finally:
            conn.close()

    # ── Operator agreements ───────────────────────────────────────

    def record_agreement(self, agreement: OperatorAgreement) -> None:
        conn = self._conn_ctx()
        try:
            with self._lock:
                conn.execute(
                    "INSERT INTO operator_agreements "
                    "(operator_id, version, accepted_at_ns, agreement_sha256, ip_at_accept) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        agreement.operator_id,
                        agreement.version,
                        agreement.accepted_at_ns,
                        agreement.agreement_sha256,
                        agreement.ip_at_accept,
                    ),
                )
                self._audit_unsafe(
                    conn,
                    AuditEntry(
                        log_id=None,
                        customer_id=None,
                        run_id=None,
                        operator_id=agreement.operator_id,
                        timestamp_ns=agreement.accepted_at_ns,
                        actor="storage.record_agreement",
                        action="agreement_accept",
                        target=agreement.version,
                        result="ok",
                        details={
                            "agreement_sha256": agreement.agreement_sha256,
                            "ip_at_accept": agreement.ip_at_accept,
                        },
                    ),
                )
        finally:
            conn.close()

    def latest_agreement(self, operator_id: str) -> Optional[OperatorAgreement]:
        conn = self._conn_ctx()
        try:
            row = conn.execute(
                "SELECT * FROM operator_agreements WHERE operator_id = ? "
                "ORDER BY accepted_at_ns DESC LIMIT 1",
                (operator_id,),
            ).fetchone()
            return _agreement_from_row(row) if row else None
        finally:
            conn.close()

    # ── Scan queues + jobs ────────────────────────────────────────

    def create_scan_queue(self, queue: ScanQueue) -> None:
        conn = self._conn_ctx()
        try:
            with self._lock:
                conn.execute(
                    "INSERT INTO scan_queues "
                    "(queue_id, customer_id, operator_id, created_at_ns, "
                    " completed_at_ns, total_jobs, tool_bundle) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        queue.queue_id,
                        queue.customer_id,
                        queue.operator_id,
                        queue.created_at_ns,
                        queue.completed_at_ns,
                        queue.total_jobs,
                        queue.tool_bundle,
                    ),
                )
        finally:
            conn.close()

    def get_scan_queue(self, queue_id: str) -> Optional[ScanQueue]:
        conn = self._conn_ctx()
        try:
            row = conn.execute(
                "SELECT * FROM scan_queues WHERE queue_id = ?",
                (queue_id,),
            ).fetchone()
            return _scan_queue_from_row(row) if row else None
        finally:
            conn.close()

    def list_scan_queues(self, customer_id: str) -> List[ScanQueue]:
        conn = self._conn_ctx()
        try:
            rows = conn.execute(
                "SELECT * FROM scan_queues WHERE customer_id = ? "
                "ORDER BY created_at_ns DESC",
                (customer_id,),
            ).fetchall()
            return [_scan_queue_from_row(r) for r in rows]
        finally:
            conn.close()

    def complete_scan_queue(self, queue_id: str, total_jobs: int) -> None:
        conn = self._conn_ctx()
        try:
            with self._lock:
                conn.execute(
                    "UPDATE scan_queues SET completed_at_ns = ?, total_jobs = ? "
                    "WHERE queue_id = ?",
                    (int(time.time() * 1e9), total_jobs, queue_id),
                )
        finally:
            conn.close()

    def create_scan_job(self, job: ScanJob) -> None:
        conn = self._conn_ctx()
        try:
            with self._lock:
                conn.execute(
                    "INSERT INTO scan_jobs "
                    "(job_id, queue_id, customer_id, asset_id, asset_value, "
                    " asset_kind, status, engagement_id, started_at_ns, "
                    " completed_at_ns, findings_count, skip_reason, error) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        job.job_id,
                        job.queue_id,
                        job.customer_id,
                        job.asset_id,
                        job.asset_value,
                        job.asset_kind,
                        job.status,
                        job.engagement_id,
                        job.started_at_ns,
                        job.completed_at_ns,
                        job.findings_count,
                        job.skip_reason,
                        job.error,
                    ),
                )
        finally:
            conn.close()

    def update_scan_job(self, job: ScanJob) -> None:
        """Update every mutable field for a job (simple, idempotent)."""
        conn = self._conn_ctx()
        try:
            with self._lock:
                conn.execute(
                    "UPDATE scan_jobs SET "
                    "  status = ?, engagement_id = ?, started_at_ns = ?, "
                    "  completed_at_ns = ?, findings_count = ?, "
                    "  skip_reason = ?, error = ? "
                    "WHERE job_id = ?",
                    (
                        job.status,
                        job.engagement_id,
                        job.started_at_ns,
                        job.completed_at_ns,
                        job.findings_count,
                        job.skip_reason,
                        job.error,
                        job.job_id,
                    ),
                )
        finally:
            conn.close()

    def list_scan_jobs(
        self,
        queue_id: str,
        status: Optional[str] = None,
    ) -> List[ScanJob]:
        conn = self._conn_ctx()
        try:
            if status is None:
                rows = conn.execute(
                    "SELECT * FROM scan_jobs WHERE queue_id = ? "
                    "ORDER BY asset_kind, asset_value",
                    (queue_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM scan_jobs WHERE queue_id = ? AND status = ? "
                    "ORDER BY asset_kind, asset_value",
                    (queue_id, status),
                ).fetchall()
            return [_scan_job_from_row(r) for r in rows]
        finally:
            conn.close()

    def scan_queue_status_counts(self, queue_id: str) -> Dict[str, int]:
        conn = self._conn_ctx()
        try:
            rows = conn.execute(
                "SELECT status, COUNT(*) AS n FROM scan_jobs "
                "WHERE queue_id = ? GROUP BY status",
                (queue_id,),
            ).fetchall()
            return {row["status"]: int(row["n"]) for row in rows}
        finally:
            conn.close()

    def list_audit(
        self,
        customer_id: Optional[str] = None,
        limit: int = 500,
    ) -> List[AuditEntry]:
        conn = self._conn_ctx()
        try:
            if customer_id:
                rows = conn.execute(
                    "SELECT * FROM audit_log WHERE customer_id = ? "
                    "ORDER BY log_id DESC LIMIT ?",
                    (customer_id, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM audit_log ORDER BY log_id DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            return [_audit_from_row(r) for r in rows]
        finally:
            conn.close()


# ── Row -> DTO mappers ─────────────────────────────────────────────


def _customer_from_row(row: sqlite3.Row) -> Customer:
    return Customer(
        customer_id=row["customer_id"],
        name=row["name"],
        seed=row["seed"],
        consent_method=ConsentMethod(row["consent_method"]),
        consent_token=row["consent_token"],
        consent_verified_at_ns=row["consent_verified_at_ns"],
        created_at_ns=row["created_at_ns"],
    )


def _recon_run_from_row(row: sqlite3.Row) -> ReconRun:
    return ReconRun(
        run_id=row["run_id"],
        customer_id=row["customer_id"],
        started_at_ns=row["started_at_ns"],
        completed_at_ns=row["completed_at_ns"],
        sources_attempted=json.loads(row["sources_attempted"] or "[]"),
        sources_completed=json.loads(row["sources_completed"] or "[]"),
        assets_discovered=int(row["assets_discovered"] or 0),
        errors=json.loads(row["errors"] or "[]"),
    )


def _asset_from_row(row: sqlite3.Row) -> SurfaceAsset:
    return SurfaceAsset(
        asset_id=row["asset_id"],
        customer_id=row["customer_id"],
        kind=AssetKind(row["kind"]),
        value=row["value"],
        parent_id=row["parent_id"],
        source=row["source"],
        confidence=float(row["confidence"]),
        first_seen_ns=row["first_seen_ns"],
        last_seen_ns=row["last_seen_ns"],
        metadata=json.loads(row["metadata"] or "{}"),
    )


def _audit_from_row(row: sqlite3.Row) -> AuditEntry:
    return AuditEntry(
        log_id=int(row["log_id"]),
        customer_id=row["customer_id"],
        run_id=row["run_id"],
        operator_id=_row_get(row, "operator_id"),
        timestamp_ns=row["timestamp_ns"],
        actor=row["actor"],
        action=row["action"],
        target=row["target"],
        result=row["result"],
        details=json.loads(row["details"] or "{}"),
    )


def _operator_from_row(row: sqlite3.Row) -> Operator:
    return Operator(
        operator_id=row["operator_id"],
        email=row["email"],
        name=row["name"],
        role=OperatorRole(row["role"]),
        created_at_ns=row["created_at_ns"],
        last_active_at_ns=_row_get(row, "last_active_at_ns"),
        disabled_at_ns=_row_get(row, "disabled_at_ns"),
    )


def _agreement_from_row(row: sqlite3.Row) -> OperatorAgreement:
    return OperatorAgreement(
        operator_id=row["operator_id"],
        version=row["version"],
        accepted_at_ns=row["accepted_at_ns"],
        agreement_sha256=row["agreement_sha256"],
        ip_at_accept=_row_get(row, "ip_at_accept"),
    )


def _scan_queue_from_row(row: sqlite3.Row) -> ScanQueue:
    return ScanQueue(
        queue_id=row["queue_id"],
        customer_id=row["customer_id"],
        operator_id=row["operator_id"],
        created_at_ns=row["created_at_ns"],
        completed_at_ns=_row_get(row, "completed_at_ns"),
        total_jobs=int(row["total_jobs"] or 0),
        tool_bundle=row["tool_bundle"],
    )


def _scan_job_from_row(row: sqlite3.Row) -> ScanJob:
    return ScanJob(
        job_id=row["job_id"],
        queue_id=row["queue_id"],
        customer_id=row["customer_id"],
        asset_id=row["asset_id"],
        asset_value=row["asset_value"],
        asset_kind=row["asset_kind"],
        status=row["status"],
        engagement_id=_row_get(row, "engagement_id"),
        started_at_ns=_row_get(row, "started_at_ns"),
        completed_at_ns=_row_get(row, "completed_at_ns"),
        findings_count=int(row["findings_count"] or 0),
        skip_reason=_row_get(row, "skip_reason"),
        error=_row_get(row, "error"),
    )


def _row_get(row: sqlite3.Row, key: str) -> Any:
    """Safe row access for columns that may not exist on older schemas."""
    try:
        return row[key]
    except (IndexError, KeyError):
        return None


# ── Schema ─────────────────────────────────────────────────────────

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS customers (
    customer_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    seed TEXT NOT NULL,
    consent_method TEXT NOT NULL,
    consent_token TEXT,
    consent_verified_at_ns INTEGER,
    created_at_ns INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_customers_name ON customers(name);

CREATE TABLE IF NOT EXISTS recon_runs (
    run_id TEXT PRIMARY KEY,
    customer_id TEXT NOT NULL,
    started_at_ns INTEGER NOT NULL,
    completed_at_ns INTEGER,
    sources_attempted TEXT,
    sources_completed TEXT,
    assets_discovered INTEGER DEFAULT 0,
    errors TEXT,
    FOREIGN KEY (customer_id) REFERENCES customers(customer_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_recon_runs_customer ON recon_runs(customer_id);
CREATE INDEX IF NOT EXISTS idx_recon_runs_started ON recon_runs(started_at_ns);

CREATE TABLE IF NOT EXISTS surface_assets (
    asset_id TEXT PRIMARY KEY,
    customer_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    parent_id TEXT,
    source TEXT NOT NULL,
    confidence REAL NOT NULL,
    first_seen_ns INTEGER NOT NULL,
    last_seen_ns INTEGER NOT NULL,
    metadata TEXT,
    UNIQUE(customer_id, kind, value),
    FOREIGN KEY (customer_id) REFERENCES customers(customer_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_assets_customer ON surface_assets(customer_id);
CREATE INDEX IF NOT EXISTS idx_assets_kind ON surface_assets(kind);

CREATE TABLE IF NOT EXISTS audit_log (
    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
    customer_id TEXT,
    run_id TEXT,
    operator_id TEXT,
    timestamp_ns INTEGER NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    result TEXT NOT NULL,
    details TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_customer ON audit_log(customer_id);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(timestamp_ns);
CREATE INDEX IF NOT EXISTS idx_audit_operator ON audit_log(operator_id);

CREATE TABLE IF NOT EXISTS operators (
    operator_id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at_ns INTEGER NOT NULL,
    last_active_at_ns INTEGER,
    disabled_at_ns INTEGER
);
CREATE INDEX IF NOT EXISTS idx_operators_email ON operators(email);

CREATE TABLE IF NOT EXISTS operator_agreements (
    agreement_id INTEGER PRIMARY KEY AUTOINCREMENT,
    operator_id TEXT NOT NULL,
    version TEXT NOT NULL,
    accepted_at_ns INTEGER NOT NULL,
    agreement_sha256 TEXT NOT NULL,
    ip_at_accept TEXT,
    FOREIGN KEY (operator_id) REFERENCES operators(operator_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_agreements_operator ON operator_agreements(operator_id);

CREATE TABLE IF NOT EXISTS scan_queues (
    queue_id TEXT PRIMARY KEY,
    customer_id TEXT NOT NULL,
    operator_id TEXT NOT NULL,
    created_at_ns INTEGER NOT NULL,
    completed_at_ns INTEGER,
    total_jobs INTEGER NOT NULL DEFAULT 0,
    tool_bundle TEXT NOT NULL DEFAULT 'wp-full-ast',
    FOREIGN KEY (customer_id) REFERENCES customers(customer_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_scan_queues_customer ON scan_queues(customer_id);
CREATE INDEX IF NOT EXISTS idx_scan_queues_operator ON scan_queues(operator_id);

CREATE TABLE IF NOT EXISTS scan_jobs (
    job_id TEXT PRIMARY KEY,
    queue_id TEXT NOT NULL,
    customer_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    asset_value TEXT NOT NULL,
    asset_kind TEXT NOT NULL,
    status TEXT NOT NULL,
    engagement_id TEXT,
    started_at_ns INTEGER,
    completed_at_ns INTEGER,
    findings_count INTEGER NOT NULL DEFAULT 0,
    skip_reason TEXT,
    error TEXT,
    FOREIGN KEY (queue_id) REFERENCES scan_queues(queue_id) ON DELETE CASCADE,
    FOREIGN KEY (customer_id) REFERENCES customers(customer_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_queue ON scan_jobs(queue_id);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_status ON scan_jobs(status);
"""
