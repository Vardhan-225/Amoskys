"""CustomerEngagement — the end-to-end customer-facing flow.

This is what `argos customer ...` commands invoke. It ties together
everything else:

    enroll(name, seed, consent_method)
        Creates the customer row. For dns_txt consent, generates
        the TXT token and returns the value the customer must add
        to DNS before any recon runs.

    verify_consent(customer_id)
        For dns_txt: resolves _amoskys-verify.<seed> and checks for
        our token. For lab_self: marks verified immediately.

    recon(customer_id)
        Runs AttackSurfaceMap against the customer's seed. Requires
        verified consent. Returns the AttackSurfaceResult.

    list_scan_targets(customer_id)
        Returns the surface assets that should be scanned by the hunt
        phase: domains + subdomains + URLs. IPs and netblocks are
        metadata, not primary scan targets.

    schedule_scan(customer_id, asset_id) [future]
        Queues an Engagement (the existing authorized-pentest flow)
        against one discovered asset. v2 work — not implemented here,
        but the data model supports it.
"""

from __future__ import annotations

import logging
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

from amoskys.agents.Web.argos.consent import ArtifactRef
from amoskys.agents.Web.argos.recon.orchestrator import (
    AttackSurfaceMap,
    AttackSurfaceResult,
)
from amoskys.agents.Web.argos.storage import (
    AssetKind,
    AssetsDB,
    AuditEntry,
    ConsentMethod,
    Customer,
    SurfaceAsset,
)

logger = logging.getLogger("amoskys.argos.customer")


# ── Errors ─────────────────────────────────────────────────────────


class ConsentNotVerifiedError(PermissionError):
    """Raised when an operation requires verified consent and we don't have it."""


class CustomerNotFoundError(LookupError):
    pass


# ── Result types ───────────────────────────────────────────────────


@dataclass
class EnrollmentResult:
    """What a caller gets back from `enroll()` — includes instructions."""
    customer: Customer
    instructions: str


# ── Service ────────────────────────────────────────────────────────


class CustomerService:
    """Facade for customer lifecycle operations.

    Stateless; can be constructed anywhere AssetsDB is accessible.
    """

    def __init__(self, db: AssetsDB, surface_map: Optional[AttackSurfaceMap] = None) -> None:
        self.db = db
        self.surface_map = surface_map or AttackSurfaceMap(db=db)

    # ── Enrollment ────────────────────────────────────────────────

    def enroll(
        self,
        name: str,
        seed: str,
        consent_method: ConsentMethod = ConsentMethod.DNS_TXT,
        artifact_ref: Optional[ArtifactRef] = None,
    ) -> EnrollmentResult:
        """Enroll a new customer.

        For dns_txt: generates a fresh token and returns instructions.
        For lab_self: marks verified immediately (dev use).
        For email/signed_contract: stores the customer with artifact
          reference in consent_token; operator still runs `verify`
          to mark consent active.

        Bug-bounty is NOT a customer consent method — it's internal
        AMOSKYS tooling gated by operator identity. See argos.hunt.
        """
        if consent_method == ConsentMethod.DNS_TXT:
            token = secrets.token_urlsafe(24)
        elif consent_method in (ConsentMethod.EMAIL, ConsentMethod.SIGNED_CONTRACT):
            if artifact_ref is None:
                raise ValueError(
                    f"{consent_method.value} consent requires an artifact_ref "
                    "(contract number, DocuSign ID, email Message-ID, etc.) "
                    "so the audit log can point back at the authorizing paperwork."
                )
            token = artifact_ref.to_json()
        else:  # LAB_SELF
            token = None

        customer = Customer.new(
            name=name,
            seed=_normalize_seed(seed),
            consent_method=consent_method,
            consent_token=token,
        )
        self.db.create_customer(customer)

        if consent_method == ConsentMethod.LAB_SELF:
            self.db.mark_consent_verified(customer.customer_id)
            instructions = (
                f"Customer {customer.name!r} enrolled with lab_self consent. "
                f"Verified immediately. Do not use this method for customer engagements."
            )
        elif consent_method == ConsentMethod.DNS_TXT:
            instructions = (
                f"Enrolled customer {customer.name!r} (id={customer.customer_id}).\n\n"
                f"Before recon can run, the customer must authorize by adding a DNS TXT "
                f"record:\n\n"
                f"  Name:  _amoskys-verify.{customer.seed}\n"
                f"  Type:  TXT\n"
                f"  Value: amoskys-verify={token}\n\n"
                f"Once the record is live (usually <60 seconds propagation), run:\n"
                f"  argos customer verify {customer.customer_id}\n"
            )
        elif consent_method == ConsentMethod.EMAIL:
            instructions = (
                f"Enrolled customer {customer.name!r} (id={customer.customer_id}).\n"
                f"Artifact on file: {artifact_ref.ref_type}={artifact_ref.ref_value!r}\n"
                f"Run `argos customer verify {customer.customer_id}` to activate consent.\n"
            )
        else:  # SIGNED_CONTRACT
            instructions = (
                f"Enrolled customer {customer.name!r} (id={customer.customer_id}).\n"
                f"Artifact on file: {artifact_ref.ref_type}={artifact_ref.ref_value!r}\n"
                f"Run `argos customer verify {customer.customer_id}` to activate consent.\n"
            )

        return EnrollmentResult(customer=customer, instructions=instructions)

    def get_artifact_ref(self, customer_id: str) -> Optional[ArtifactRef]:
        """Return the ArtifactRef for EMAIL / SIGNED_CONTRACT customers, else None."""
        c = self._require_customer(customer_id)
        if c.consent_method not in (ConsentMethod.EMAIL, ConsentMethod.SIGNED_CONTRACT):
            return None
        return ArtifactRef.from_json(c.consent_token)

    # ── Consent verification ──────────────────────────────────────

    def verify_consent(
        self,
        customer_id: str,
        resolver_fn=None,
    ) -> Tuple[bool, str]:
        """Verify the customer's consent is in place.

        For dns_txt: resolves _amoskys-verify.<seed> TXT and looks for
        the token. For email/signed_contract: assumes the operator has
        already filed the artifact out-of-band — marks verified.

        Returns (verified, human_message).
        """
        customer = self._require_customer(customer_id)

        if customer.consent_method == ConsentMethod.LAB_SELF:
            self._log_consent(customer_id, "lab_self", "ok")
            self.db.mark_consent_verified(customer_id)
            return True, "lab_self consent: verified."

        if customer.consent_method in (ConsentMethod.EMAIL, ConsentMethod.SIGNED_CONTRACT):
            # Operator attests possession of an out-of-band artifact.
            # We already recorded the artifact reference at enroll time;
            # verify just activates consent.
            artifact = ArtifactRef.from_json(customer.consent_token)
            artifact_desc = (
                f"{artifact.ref_type}={artifact.ref_value!r}"
                if artifact else "(no artifact on file)"
            )
            self._log_consent(
                customer_id,
                customer.consent_method.value,
                f"operator_attest; artifact={artifact_desc}",
            )
            self.db.mark_consent_verified(customer_id)
            return True, (
                f"{customer.consent_method.value}: operator attestation recorded. "
                f"Artifact: {artifact_desc}"
            )

        # dns_txt path
        if not customer.consent_token:
            return False, "customer has no consent_token; cannot verify dns_txt."
        record_name = f"_amoskys-verify.{customer.seed}"
        expected = f"amoskys-verify={customer.consent_token}"

        try:
            txt_values = _resolve_txt(record_name, resolver_fn)
        except Exception as e:  # noqa: BLE001
            self._log_consent(customer_id, "dns_txt", f"lookup_error: {e}")
            return False, f"DNS lookup failed for {record_name}: {e}"

        if not any(expected in v for v in txt_values):
            self._log_consent(customer_id, "dns_txt", "token_mismatch")
            return False, (
                f"TXT record at {record_name} does not contain expected token.\n"
                f"  Expected: {expected}\n"
                f"  Found:    {txt_values or '<no records>'}"
            )

        self.db.mark_consent_verified(customer_id)
        self._log_consent(customer_id, "dns_txt", "ok")
        return True, f"dns_txt consent verified at {record_name}."

    # ── Recon ─────────────────────────────────────────────────────

    def run_recon(self, customer_id: str) -> AttackSurfaceResult:
        """Execute attack-surface mapping. Requires verified consent."""
        customer = self._require_customer(customer_id)
        if customer.consent_verified_at_ns is None:
            raise ConsentNotVerifiedError(
                f"customer {customer.name!r} has unverified consent. "
                f"Run `argos customer verify {customer_id}` first."
            )
        return self.surface_map.run(customer)

    # ── Queries ───────────────────────────────────────────────────

    def list_scan_targets(self, customer_id: str) -> List[SurfaceAsset]:
        """Return assets that should be scanned by the hunt phase.

        Domains + subdomains + URLs are scannable. IPs and netblocks are
        inventory; they inform the scan but aren't direct HTTP targets.
        """
        assets = []
        for kind in (AssetKind.DOMAIN, AssetKind.SUBDOMAIN, AssetKind.URL):
            assets.extend(self.db.list_assets(customer_id, kind=kind))
        return assets

    def list_customers(self) -> List[Customer]:
        return self.db.list_customers()

    # ── Internal ──────────────────────────────────────────────────

    def _require_customer(self, customer_id: str) -> Customer:
        c = self.db.get_customer(customer_id)
        if c is None:
            raise CustomerNotFoundError(f"no customer with id {customer_id!r}")
        return c

    def _log_consent(self, customer_id: str, method: str, result: str) -> None:
        self.db.audit(
            AuditEntry(
                log_id=None,
                customer_id=customer_id,
                run_id=None,
                timestamp_ns=int(time.time() * 1e9),
                actor="customer_service.verify_consent",
                action="consent_verify",
                target=method,
                result=result,
                details={},
            )
        )


# ── Helpers ────────────────────────────────────────────────────────


def _normalize_seed(seed: str) -> str:
    t = seed.strip().lower()
    if "://" in t:
        t = t.split("://", 1)[1]
    t = t.split("/", 1)[0]
    t = t.split(":", 1)[0]
    if t.startswith("*."):
        t = t[2:]
    return t


def _resolve_txt(record_name: str, resolver_fn=None) -> List[str]:
    """Resolve a TXT record. Injection point for tests via resolver_fn."""
    if resolver_fn is not None:
        return resolver_fn(record_name)

    try:
        import dns.resolver  # type: ignore
    except ImportError:
        # Fallback to OS resolver via subprocess-less stdlib: not available
        # for TXT without a real DNS library. Tell the operator.
        raise RuntimeError(
            "TXT verification requires dnspython. Install: pip install dnspython"
        )

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5.0
    resolver.lifetime = 15.0
    answer = resolver.resolve(record_name, "TXT")
    out: List[str] = []
    for rdata in answer:
        txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
        out.append(txt)
    return out
