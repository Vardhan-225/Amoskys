"""Operator identity + agreement tests.

Bug-bounty hunt mode is internal tooling gated on operator authorization.
These tests cover:
  - Operator registration
  - Agreement acceptance flow + version bumps force re-acceptance
  - Role-based authorization (viewer < analyst < admin)
  - Hunt requires an authorized operator; audit log captures operator_id
  - env-var / flag resolution of current operator
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from amoskys.agents.Web.argos import operators as operators_mod
from amoskys.agents.Web.argos.operators import (
    AGREEMENT_V1,
    CURRENT_AGREEMENT_VERSION,
    AgreementNotAcceptedError,
    InsufficientRoleError,
    OperatorNotFoundError,
    OperatorService,
    agreement_sha256,
    current_operator_ref,
)
from amoskys.agents.Web.argos.hunt import Hunt
from amoskys.agents.Web.argos.ast import RestAuthzScanner
from amoskys.agents.Web.argos.corpus import PluginSource
from amoskys.agents.Web.argos.storage import AssetsDB, OperatorRole


# ── Fixtures ───────────────────────────────────────────────────────


@pytest.fixture
def db(tmp_path):
    d = AssetsDB(tmp_path / "customer.db")
    d.initialize()
    return d


@pytest.fixture
def service(db):
    return OperatorService(db)


# ── Registration ───────────────────────────────────────────────────


def test_register_creates_operator_without_accepting(service, db):
    op = service.register(
        email="akash@amoskys.com",
        name="Akash T",
        role=OperatorRole.ADMIN,
    )
    assert op.email == "akash@amoskys.com"
    assert op.role == OperatorRole.ADMIN
    assert op.is_active is True

    # Not yet accepted
    assert not service.has_accepted_current_agreement(op.operator_id)


def test_register_normalizes_email_lowercase(service):
    op = service.register(email="AKash@AMOSKYS.com", name="A", role=OperatorRole.ANALYST)
    assert op.email == "akash@amoskys.com"


def test_register_rejects_duplicate_email(service):
    service.register(email="a@x.com", name="A", role=OperatorRole.ADMIN)
    with pytest.raises(ValueError, match="already exists"):
        service.register(email="a@x.com", name="B", role=OperatorRole.ADMIN)


def test_register_with_auto_accept(service):
    op = service.register(
        email="a@x.com",
        name="A",
        role=OperatorRole.ANALYST,
        accept_agreement=True,
    )
    assert service.has_accepted_current_agreement(op.operator_id) is True


# ── Agreement acceptance ───────────────────────────────────────────


def test_accept_agreement_records_sha256(service):
    op = service.register(email="a@x.com", name="A", role=OperatorRole.ANALYST)
    agreement = service.accept_agreement(op.operator_id)
    assert agreement.version == CURRENT_AGREEMENT_VERSION
    assert agreement.agreement_sha256 == agreement_sha256(CURRENT_AGREEMENT_VERSION)
    assert len(agreement.agreement_sha256) == 64


def test_has_accepted_current_false_when_no_agreement(service):
    op = service.register(email="a@x.com", name="A", role=OperatorRole.ANALYST)
    assert service.has_accepted_current_agreement(op.operator_id) is False


def test_version_bump_forces_reacceptance(service, db):
    """If the current version changes, prior acceptance no longer counts."""
    op = service.register(
        email="a@x.com", name="A",
        role=OperatorRole.ANALYST, accept_agreement=True,
    )
    assert service.has_accepted_current_agreement(op.operator_id) is True

    # Simulate a version bump: monkey-patch CURRENT_AGREEMENT_VERSION to "v2.0"
    # and inject a v2 text so sha256 of v2 differs.
    with patch.object(operators_mod, "CURRENT_AGREEMENT_VERSION", "v2.0"):
        with patch.object(operators_mod, "AGREEMENT_V1", "--- v2 text ---"):
            # agreement_text() now raises for v1 lookups, but has_accepted uses
            # agreement_sha256(CURRENT_AGREEMENT_VERSION=v2.0) vs stored v1.0 hash
            assert service.has_accepted_current_agreement(op.operator_id) is False


def test_agreement_sha256_mismatch_invalidates(service, db):
    """If the stored agreement sha256 doesn't match current text, force re-accept."""
    op = service.register(
        email="a@x.com", name="A",
        role=OperatorRole.ANALYST, accept_agreement=True,
    )
    # Tamper with the stored agreement_sha256 directly
    conn = db._conn_ctx()
    try:
        conn.execute(
            "UPDATE operator_agreements SET agreement_sha256 = ? "
            "WHERE operator_id = ?",
            ("deadbeef" * 8, op.operator_id),
        )
        conn.commit()
    finally:
        conn.close()
    assert service.has_accepted_current_agreement(op.operator_id) is False


# ── Authorization ──────────────────────────────────────────────────


def test_authorize_success_for_admin_admin(service):
    op = service.register(
        email="a@x.com", name="A",
        role=OperatorRole.ADMIN, accept_agreement=True,
    )
    # Admin can do admin things
    got = service.authorize(op.operator_id, OperatorRole.ADMIN, "test")
    assert got.operator_id == op.operator_id


def test_authorize_success_analyst_for_analyst_requirement(service):
    op = service.register(
        email="a@x.com", name="A",
        role=OperatorRole.ANALYST, accept_agreement=True,
    )
    got = service.authorize(op.operator_id, OperatorRole.ANALYST, "test")
    assert got.operator_id == op.operator_id


def test_authorize_fails_when_agreement_not_accepted(service):
    op = service.register(email="a@x.com", name="A", role=OperatorRole.ADMIN)
    # No accept_agreement=True
    with pytest.raises(AgreementNotAcceptedError, match="has not accepted"):
        service.authorize(op.operator_id, OperatorRole.ANALYST, "test")


def test_authorize_fails_when_role_insufficient(service):
    op = service.register(
        email="v@x.com", name="V",
        role=OperatorRole.VIEWER, accept_agreement=True,
    )
    with pytest.raises(InsufficientRoleError, match="cannot run"):
        service.authorize(op.operator_id, OperatorRole.ANALYST, "hunt")


def test_authorize_fails_for_disabled_operator(service, db):
    op = service.register(
        email="a@x.com", name="A",
        role=OperatorRole.ADMIN, accept_agreement=True,
    )
    db.disable_operator(op.operator_id)
    with pytest.raises(PermissionError, match="disabled"):
        service.authorize(op.operator_id, OperatorRole.VIEWER, "test")


def test_authorize_denial_is_audit_logged(service, db):
    op = service.register(email="v@x.com", name="V", role=OperatorRole.VIEWER)
    # No agreement → first denial is "agreement_not_current"
    with pytest.raises(AgreementNotAcceptedError):
        service.authorize(op.operator_id, OperatorRole.ANALYST, "hunt_test")

    entries = db.list_audit(limit=100)
    denials = [e for e in entries if e.action == "authorization_denied"]
    assert len(denials) == 1
    assert denials[0].operator_id == op.operator_id
    assert denials[0].target == "hunt_test"


def test_authorize_touches_last_active(service, db):
    op = service.register(
        email="a@x.com", name="A",
        role=OperatorRole.ADMIN, accept_agreement=True,
    )
    assert db.get_operator(op.operator_id).last_active_at_ns is None
    service.authorize(op.operator_id, OperatorRole.ANALYST, "hunt")
    assert db.get_operator(op.operator_id).last_active_at_ns is not None


# ── Resolution / whoami ────────────────────────────────────────────


def test_resolve_by_email(service):
    op = service.register(email="a@x.com", name="A", role=OperatorRole.ANALYST)
    got = service.resolve("a@x.com")
    assert got.operator_id == op.operator_id


def test_resolve_by_id(service):
    op = service.register(email="a@x.com", name="A", role=OperatorRole.ANALYST)
    got = service.resolve(op.operator_id)
    assert got.email == "a@x.com"


def test_resolve_returns_none_for_unknown(service):
    assert service.resolve("nobody@nowhere.com") is None
    assert service.resolve("not-a-real-uuid") is None


def test_whoami_reports_agreement_status(service):
    op = service.register(email="a@x.com", name="A", role=OperatorRole.ADMIN)
    who = service.whoami("a@x.com")
    assert who.operator.email == "a@x.com"
    assert who.agreement_current is False
    assert who.agreement_version_seen is None

    service.accept_agreement(op.operator_id)
    who = service.whoami("a@x.com")
    assert who.agreement_current is True
    assert who.agreement_version_seen == CURRENT_AGREEMENT_VERSION


# ── current_operator_ref (CLI glue) ────────────────────────────────


def test_current_operator_ref_explicit_beats_env(monkeypatch):
    monkeypatch.setenv("ARGOS_OPERATOR", "env@x.com")
    assert current_operator_ref("flag@x.com") == "flag@x.com"


def test_current_operator_ref_env_var(monkeypatch):
    monkeypatch.setenv("ARGOS_OPERATOR", "env@x.com")
    assert current_operator_ref() == "env@x.com"


def test_current_operator_ref_empty_returns_none(monkeypatch):
    monkeypatch.delenv("ARGOS_OPERATOR", raising=False)
    assert current_operator_ref() is None
    assert current_operator_ref("   ") is None


# ── Hunt integration ──────────────────────────────────────────────


def test_hunt_records_operator_in_result_and_json(tmp_path, service):
    """Hunt carries operator identity through to the JSON report."""
    op = service.register(
        email="analyst@amoskys.com", name="Analyst",
        role=OperatorRole.ANALYST, accept_agreement=True,
    )

    # Make a fake fixture plugin + fake corpus
    php = """<?php
    register_rest_route('d/v1', '/x', array(
        'callback' => 'h',
        'permission_callback' => '__return_true',
    ));
    """
    root = tmp_path / "fixture" / "1.0.0"
    root.mkdir(parents=True)
    (root / "m.php").write_text(php)
    fixture = PluginSource(
        slug="fixture", version="1.0.0",
        extracted_root=root.parent, plugin_root=root,
    )

    class FakeCorpus:
        def fetch(self, slug, version=None):
            return fixture

    hunt = Hunt(
        slugs=["fixture"],
        corpus=FakeCorpus(),
        report_dir=tmp_path / "hunts",
        operator_id=op.operator_id,
        operator_email=op.email,
    )
    result = hunt.run()
    assert result.operator_id == op.operator_id
    assert result.operator_email == "analyst@amoskys.com"

    # Report JSON contains the operator
    report = tmp_path / "hunts" / f"hunt-{result.hunt_id}.json"
    data = json.loads(report.read_text())
    assert data["operator_email"] == "analyst@amoskys.com"
    assert data["operator_id"] == op.operator_id


def test_hunt_writes_audit_entries_when_db_provided(tmp_path, service, db):
    op = service.register(
        email="a@x.com", name="A",
        role=OperatorRole.ANALYST, accept_agreement=True,
    )

    php = """<?php
    register_rest_route('d/v1', '/x', array('callback' => 'h'));
    """
    root = tmp_path / "fixture" / "1.0.0"
    root.mkdir(parents=True)
    (root / "m.php").write_text(php)
    fixture = PluginSource(
        slug="fixture", version="1.0.0",
        extracted_root=root.parent, plugin_root=root,
    )

    class FakeCorpus:
        def fetch(self, slug, version=None):
            return fixture

    hunt = Hunt(
        slugs=["fixture"],
        corpus=FakeCorpus(),
        report_dir=tmp_path / "hunts",
        operator_id=op.operator_id,
        operator_email=op.email,
        db=db,
    )
    hunt.run()

    entries = db.list_audit(limit=100)
    hunt_events = [e for e in entries if e.actor == "argos.hunt"]
    assert len(hunt_events) == 2  # hunt_start + hunt_complete
    for e in hunt_events:
        assert e.operator_id == op.operator_id
        assert e.run_id == hunt.hunt_id


# ── Role enum semantics ────────────────────────────────────────────


def test_role_ranks_order_correctly():
    from amoskys.agents.Web.argos.operators import _ROLE_RANK
    assert _ROLE_RANK[OperatorRole.VIEWER] < _ROLE_RANK[OperatorRole.ANALYST]
    assert _ROLE_RANK[OperatorRole.ANALYST] < _ROLE_RANK[OperatorRole.ADMIN]
