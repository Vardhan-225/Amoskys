"""AMOSKYS operator identity + agreement.

Bug-bounty hunting is internal tooling. It's not a customer product and
doesn't need customer consent. The authorization comes from:

    1. Being a registered AMOSKYS employee (Operator row)
    2. Having accepted the current operator agreement (current version)
    3. Every action recorded against the operator's identity

This module provides:

    - `Operator`           — the employee identity (email, name, role)
    - `OperatorRole`       — admin / analyst / viewer
    - `AGREEMENT_V1`       — the current agreement text
    - `OperatorService`    — register, accept agreement, whoami, authorize

## Command authorization

The `OperatorService.authorize(operator_id, required_role)` call is what
every CLI/API entry point uses to check whether the current operator
can run a given command. Role ordering is:

    VIEWER  < ANALYST < ADMIN

Required-role ≤ operator's-role ⇒ authorized.

## Agreement versioning

If we amend the agreement, bump `CURRENT_AGREEMENT_VERSION` and update
`AGREEMENT_V1` (or add `AGREEMENT_V2`). Operators whose latest
acceptance is for a prior version are treated as not-accepted until
they run `argos operator accept` again. Their previous acceptance
stays in history as audit evidence.

## Identifying the current operator

The CLI picks the current operator in this order:

    1. --operator <id-or-email>   flag on the command
    2. ARGOS_OPERATOR              environment variable
    3. None — command fails with an explicit error for commands that
       require one (hunt, active recon); read-only commands (list,
       whoami) can run without

## Why not OS-level auth

At this stage Argos is a local CLI. The host-OS login is the first
gate (the DB is 0600 — only its owner can read it). Operators are an
application-layer record of WHO among the company did WHAT, so a small
team sharing a host or CI box can still be attributed correctly.
"""

from __future__ import annotations

import hashlib
import logging
import os
import socket
import time
from dataclasses import dataclass
from typing import Optional

from amoskys.agents.Web.argos.storage import (
    AssetsDB,
    AuditEntry,
    Operator,
    OperatorAgreement,
    OperatorRole,
)

logger = logging.getLogger("amoskys.argos.operators")


# ── Agreement text ─────────────────────────────────────────────────
#
# Short + clear, not legalese. The operator is acknowledging they know
# what this tool does and accepts responsibility for using it
# appropriately. The sha256 of the text is stored at acceptance so the
# operator can't later claim they saw a different version.

CURRENT_AGREEMENT_VERSION = "v1.0"

AGREEMENT_V1 = """\
AMOSKYS OPERATOR AGREEMENT (v1.0)
=================================

By accepting this agreement you acknowledge that:

1. You are an authorized AMOSKYS employee operating this tool on behalf
   of the company.

2. Aggressive / offensive modes of this tool (bug-bounty hunt, red-team
   operations against customer infrastructure) MUST only be run against:

     a. Public bug-bounty programs whose scope you have read and whose
        rules you will honor. Violating scope can get AMOSKYS banned
        from the program.

     b. Customer infrastructure where we have a verified consent
        record (DNS-TXT, signed contract, email authorization, or
        lab self-ownership). No exceptions.

     c. AMOSKYS's own lab infrastructure (lab.amoskys.com) for R&D.

3. Every action you take is written to the audit log against your
   operator identity. This audit log is the record of record — if
   legal, a customer, or a bug-bounty program asks what happened,
   this is the answer.

4. You will NOT:
     - Run offensive modes against targets outside the three cases in (2)
     - Disable or bypass the stealth primitives (rate limiter, identity
       pool) to produce higher-rate traffic than the target expects
     - Use findings discovered during a customer engagement for any
       purpose other than the customer report
     - Share customer data or findings outside AMOSKYS without the
       customer's written permission

5. If you are unsure whether an action is authorized, you will stop and
   ask. The cost of pausing is lower than the cost of being wrong.

By running `argos operator accept` you affirm all of the above.
"""


def agreement_text(version: str = CURRENT_AGREEMENT_VERSION) -> str:
    """Return the agreement text for the given version."""
    if version == CURRENT_AGREEMENT_VERSION:
        return AGREEMENT_V1
    raise ValueError(f"unknown agreement version: {version!r}")


def agreement_sha256(version: str = CURRENT_AGREEMENT_VERSION) -> str:
    return hashlib.sha256(agreement_text(version).encode("utf-8")).hexdigest()


# ── Errors ─────────────────────────────────────────────────────────


class OperatorNotFoundError(LookupError):
    pass


class AgreementNotAcceptedError(PermissionError):
    """Operator exists but hasn't accepted the current agreement version."""


class InsufficientRoleError(PermissionError):
    """Operator is registered but their role doesn't permit this command."""


# ── Service ────────────────────────────────────────────────────────


# Role order — higher index = more permissions.
_ROLE_RANK = {
    OperatorRole.VIEWER: 0,
    OperatorRole.ANALYST: 1,
    OperatorRole.ADMIN: 2,
}


@dataclass
class WhoamiResult:
    operator: Operator
    agreement_current: bool
    agreement_version_seen: Optional[str]


class OperatorService:
    """Operator lifecycle + authorization checks."""

    def __init__(self, db: AssetsDB) -> None:
        self.db = db

    # ── Registration ──────────────────────────────────────────────

    def register(
        self,
        email: str,
        name: str,
        role: OperatorRole,
        accept_agreement: bool = False,
        client_ip: Optional[str] = None,
    ) -> Operator:
        """Create a new operator.

        `accept_agreement`: if True, accepts the current agreement in
        the same transaction. The CLI typically enrolls + accepts in
        one step after showing the agreement text, because forcing a
        separate `accept` run immediately after register is friction.
        """
        existing = self.db.get_operator_by_email(email)
        if existing is not None:
            raise ValueError(
                f"operator with email {email!r} already exists "
                f"(id={existing.operator_id}). Use accept_agreement to update."
            )

        op = Operator.new(email=email, name=name, role=role)
        self.db.create_operator(op)

        if accept_agreement:
            self.accept_agreement(op.operator_id, client_ip=client_ip)

        return op

    # ── Agreement ─────────────────────────────────────────────────

    def accept_agreement(
        self,
        operator_id: str,
        version: str = CURRENT_AGREEMENT_VERSION,
        client_ip: Optional[str] = None,
    ) -> OperatorAgreement:
        op = self._require_operator(operator_id)
        if not op.is_active:
            raise PermissionError(
                f"operator {op.email!r} is disabled; re-enable before accepting."
            )

        agreement = OperatorAgreement(
            operator_id=operator_id,
            version=version,
            accepted_at_ns=int(time.time() * 1e9),
            agreement_sha256=agreement_sha256(version),
            ip_at_accept=client_ip or _best_client_ip(),
        )
        self.db.record_agreement(agreement)
        return agreement

    def has_accepted_current_agreement(self, operator_id: str) -> bool:
        latest = self.db.latest_agreement(operator_id)
        if latest is None:
            return False
        if latest.version != CURRENT_AGREEMENT_VERSION:
            return False
        # Also verify the hash matches — defense-in-depth against a
        # mutated agreement text somewhere in the code.
        if latest.agreement_sha256 != agreement_sha256(CURRENT_AGREEMENT_VERSION):
            logger.warning(
                "operator %s has acceptance with mismatched sha256; "
                "forcing re-acceptance",
                operator_id,
            )
            return False
        return True

    # ── Authorization ─────────────────────────────────────────────

    def authorize(
        self,
        operator_id: str,
        required_role: OperatorRole,
        action: str = "",
    ) -> Operator:
        """Verify operator is registered, active, agreement-accepted,
        and has at least `required_role`. Returns the Operator on success.

        `action` is optional — used for the audit log entry on failure.
        """
        op = self._require_operator(operator_id)
        if not op.is_active:
            self._audit_denial(op, action, "operator_disabled")
            raise PermissionError(f"operator {op.email!r} is disabled")
        if not self.has_accepted_current_agreement(op.operator_id):
            self._audit_denial(op, action, "agreement_not_current")
            raise AgreementNotAcceptedError(
                f"operator {op.email!r} has not accepted the current "
                f"agreement ({CURRENT_AGREEMENT_VERSION}). "
                f"Run: argos operator accept --operator {op.email}"
            )
        if _ROLE_RANK[op.role] < _ROLE_RANK[required_role]:
            self._audit_denial(op, action, f"role_insufficient:has={op.role.value} needs={required_role.value}")
            raise InsufficientRoleError(
                f"operator {op.email!r} role={op.role.value!r} cannot run "
                f"action requiring role={required_role.value!r}"
            )

        # Success path — touch last_active and return.
        self.db.touch_operator_active(op.operator_id)
        return op

    # ── Resolution ────────────────────────────────────────────────

    def resolve(self, ref: str) -> Optional[Operator]:
        """Given an operator_id OR email, return the Operator or None."""
        # Try by ID first (UUID-ish); then by email.
        if ref and "@" in ref:
            return self.db.get_operator_by_email(ref)
        return self.db.get_operator(ref)

    def whoami(self, ref: str) -> WhoamiResult:
        op = self._require_operator_by_ref(ref)
        latest = self.db.latest_agreement(op.operator_id)
        return WhoamiResult(
            operator=op,
            agreement_current=self.has_accepted_current_agreement(op.operator_id),
            agreement_version_seen=(latest.version if latest else None),
        )

    # ── Listing ───────────────────────────────────────────────────

    def list(self, include_disabled: bool = False):
        return self.db.list_operators(include_disabled=include_disabled)

    # ── Internals ─────────────────────────────────────────────────

    def _require_operator(self, operator_id: str) -> Operator:
        op = self.db.get_operator(operator_id)
        if op is None:
            raise OperatorNotFoundError(f"no operator with id {operator_id!r}")
        return op

    def _require_operator_by_ref(self, ref: str) -> Operator:
        op = self.resolve(ref)
        if op is None:
            raise OperatorNotFoundError(f"no operator matches {ref!r}")
        return op

    def _audit_denial(self, op: Operator, action: str, reason: str) -> None:
        self.db.audit(
            AuditEntry(
                log_id=None,
                customer_id=None,
                run_id=None,
                operator_id=op.operator_id,
                timestamp_ns=int(time.time() * 1e9),
                actor="operator_service.authorize",
                action="authorization_denied",
                target=action or None,
                result=reason,
                details={"role": op.role.value},
            )
        )


# ── CLI helpers ────────────────────────────────────────────────────


def current_operator_ref(
    explicit: Optional[str] = None,
    env_var: str = "ARGOS_OPERATOR",
) -> Optional[str]:
    """Return the operator identifier the caller wants to run under.

    Precedence: explicit flag → env var → None.
    The caller resolves the returned string to an Operator via
    OperatorService.resolve().
    """
    if explicit:
        return explicit.strip() or None
    val = os.environ.get(env_var)
    if val:
        return val.strip() or None
    return None


def _best_client_ip() -> Optional[str]:
    """Best-effort source IP for the agreement-acceptance record.

    We just grab the host's first non-loopback IP. This is informational
    in the audit log — an attacker could fake it, and we don't care for
    internal audit purposes.
    """
    try:
        hostname = socket.gethostname()
        # Use getaddrinfo to avoid gethostbyname deprecation on some systems
        infos = socket.getaddrinfo(hostname, None)
        for fam, _t, _p, _c, sockaddr in infos:
            ip = sockaddr[0]
            if not ip.startswith("127.") and ip not in ("::1", "0.0.0.0"):
                return ip
    except (socket.gaierror, OSError):
        pass
    return None
