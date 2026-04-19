"""Tests for the customer consent model — DNS-TXT, email, signed contract.

Bug-bounty is NOT a customer consent method (it's internal tooling; see
test_argos_operators.py). This file covers only customer-facing consent.
"""

from __future__ import annotations

import pytest

from amoskys.agents.Web.argos.consent import ArtifactRef
from amoskys.agents.Web.argos.customer import CustomerService
from amoskys.agents.Web.argos.storage import AssetsDB, ConsentMethod


# ── ArtifactRef round-trip ─────────────────────────────────────────


def test_artifact_ref_json_roundtrip():
    a = ArtifactRef(
        ref_type="docusign_envelope",
        ref_value="abc-123",
        notes="signed 2026-04-10",
    )
    restored = ArtifactRef.from_json(a.to_json())
    assert restored.ref_type == "docusign_envelope"
    assert restored.ref_value == "abc-123"
    assert restored.notes == "signed 2026-04-10"


def test_artifact_ref_from_json_tolerates_garbage():
    assert ArtifactRef.from_json(None) is None
    assert ArtifactRef.from_json("") is None
    assert ArtifactRef.from_json("not json {{{") is None


# ── CustomerService: artifact-ref requirements ─────────────────────


@pytest.fixture
def db(tmp_path):
    d = AssetsDB(tmp_path / "customer.db")
    d.initialize()
    return d


def test_enroll_with_signed_contract_requires_artifact_ref(db):
    service = CustomerService(db=db)
    with pytest.raises(ValueError, match="artifact_ref"):
        service.enroll(
            name="ACME",
            seed="acme.com",
            consent_method=ConsentMethod.SIGNED_CONTRACT,
        )


def test_enroll_with_email_requires_artifact_ref(db):
    service = CustomerService(db=db)
    with pytest.raises(ValueError, match="artifact_ref"):
        service.enroll(
            name="ACME",
            seed="acme.com",
            consent_method=ConsentMethod.EMAIL,
        )


def test_enroll_with_signed_contract_stores_artifact(db):
    service = CustomerService(db=db)
    ref = ArtifactRef(ref_type="docusign_envelope", ref_value="env-42")
    result = service.enroll(
        name="ACME",
        seed="acme.com",
        consent_method=ConsentMethod.SIGNED_CONTRACT,
        artifact_ref=ref,
    )
    got = service.get_artifact_ref(result.customer.customer_id)
    assert got.ref_type == "docusign_envelope"
    assert got.ref_value == "env-42"


def test_enroll_dns_txt_generates_token(db):
    service = CustomerService(db=db)
    result = service.enroll(
        name="ACME",
        seed="acme.com",
        consent_method=ConsentMethod.DNS_TXT,
    )
    c = service._require_customer(result.customer.customer_id)
    assert c.consent_token is not None
    assert len(c.consent_token) >= 16  # token_urlsafe(24) ≈ 32 chars


def test_enroll_lab_self_auto_verifies(db):
    service = CustomerService(db=db)
    result = service.enroll(
        name="Lab",
        seed="lab.amoskys.com",
        consent_method=ConsentMethod.LAB_SELF,
    )
    c = service._require_customer(result.customer.customer_id)
    assert c.consent_verified_at_ns is not None


def test_consent_method_enum_does_not_include_bug_bounty():
    """BUG_BOUNTY was removed — bug-bounty is internal operator tooling."""
    assert not hasattr(ConsentMethod, "BUG_BOUNTY")
    values = [m.value for m in ConsentMethod]
    assert "bug_bounty" not in values
    assert set(values) == {"dns_txt", "email", "signed_contract", "lab_self"}
