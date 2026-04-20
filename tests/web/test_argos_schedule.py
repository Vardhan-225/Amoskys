"""Scan scheduler tests — recon→scan bridge + apex scope guard.

Covers:
  - Queue creation from a populated surface
  - Apex-scope guard (subdomains allowed; foreign hosts skipped)
  - Job status transitions (pending → running → complete/failed)
  - Consent floor enforcement (unverified customer refused)
  - Operator attribution on every audit row
  - Findings aggregation across multiple engagements
"""

from __future__ import annotations

from typing import Any, Dict, List
from pathlib import Path

import pytest

from amoskys.agents.Web.argos.customer import CustomerService
from amoskys.agents.Web.argos.operators import OperatorService
from amoskys.agents.Web.argos.schedule import (
    CustomerConsentRequiredError,
    EngagementRunner,
    QueueProgress,
    ScanScheduler,
    _is_in_apex_scope,
)
from amoskys.agents.Web.argos.storage import (
    AssetKind,
    AssetsDB,
    ConsentMethod,
    Customer,
    OperatorRole,
    ScanJob,
    ScanQueue,
    SurfaceAsset,
)


# ── Fixtures ───────────────────────────────────────────────────────


@pytest.fixture
def db(tmp_path):
    d = AssetsDB(tmp_path / "customer.db")
    d.initialize()
    return d


@pytest.fixture
def operator(db):
    svc = OperatorService(db)
    return svc.register(
        email="analyst@amoskys.com",
        name="Analyst",
        role=OperatorRole.ANALYST,
        accept_agreement=True,
    )


@pytest.fixture
def customer_with_surface(db):
    """An enrolled + verified customer with a populated surface."""
    cust_svc = CustomerService(db)
    enrollment = cust_svc.enroll(
        name="Acme",
        seed="acme.com",
        consent_method=ConsentMethod.LAB_SELF,
    )
    cid = enrollment.customer.customer_id

    # Populate surface: seed + 3 in-scope subdomains + 1 out-of-scope + 2 IPs
    def _upsert(kind, value, source="test", confidence=0.9):
        db.upsert_asset(SurfaceAsset.new(
            customer_id=cid, kind=kind, value=value,
            source=source, confidence=confidence,
        ))

    _upsert(AssetKind.DOMAIN, "acme.com")
    _upsert(AssetKind.SUBDOMAIN, "www.acme.com")
    _upsert(AssetKind.SUBDOMAIN, "api.acme.com")
    _upsert(AssetKind.SUBDOMAIN, "staging.acme.com")
    # CT logs can occasionally return cross-cert SANs for unrelated hosts.
    # These must be skipped, not probed.
    _upsert(AssetKind.SUBDOMAIN, "foo.example.org")
    # Inventory assets (not scan targets at all)
    _upsert(AssetKind.IPV4, "203.0.113.5")
    _upsert(AssetKind.ASN, "AS64496")
    return db.get_customer(cid)


# ── Apex-scope guard unit tests ────────────────────────────────────


def test_apex_scope_allows_exact_match():
    assert _is_in_apex_scope("acme.com", "acme.com") is True


def test_apex_scope_allows_subdomains():
    assert _is_in_apex_scope("www.acme.com", "acme.com") is True
    assert _is_in_apex_scope("a.b.c.acme.com", "acme.com") is True


def test_apex_scope_rejects_foreign_hosts():
    assert _is_in_apex_scope("example.com", "acme.com") is False
    assert _is_in_apex_scope("acme.com.evil.com", "acme.com") is False
    # prefix attack: "xacme.com" must NOT match "acme.com"
    assert _is_in_apex_scope("xacme.com", "acme.com") is False


def test_apex_scope_strips_url_prefix():
    assert _is_in_apex_scope("https://api.acme.com/path", "acme.com") is True


def test_apex_scope_case_insensitive():
    assert _is_in_apex_scope("API.ACME.COM", "acme.com") is True


# ── Queue creation ─────────────────────────────────────────────────


def test_queue_surface_creates_one_job_per_scan_target(
    db, operator, customer_with_surface
):
    scheduler = ScanScheduler(db=db, operator=operator)
    queue = scheduler.queue_surface(customer_with_surface.customer_id)

    jobs = db.list_scan_jobs(queue.queue_id)
    # Expect 5 jobs for the 5 scannable assets (domain + 4 subdomains).
    # IPv4 + ASN are NOT scan targets.
    assert len(jobs) == 5

    values = {j.asset_value for j in jobs}
    assert "acme.com" in values
    assert "www.acme.com" in values
    assert "api.acme.com" in values
    assert "staging.acme.com" in values
    assert "foo.example.org" in values  # queued, but we expect it skipped

    # IPs/ASNs never become jobs
    assert "203.0.113.5" not in values
    assert "AS64496" not in values


def test_out_of_apex_assets_are_marked_skipped_not_pending(
    db, operator, customer_with_surface
):
    scheduler = ScanScheduler(db=db, operator=operator)
    queue = scheduler.queue_surface(customer_with_surface.customer_id)

    jobs = db.list_scan_jobs(queue.queue_id)
    foreign = [j for j in jobs if j.asset_value == "foo.example.org"]
    assert len(foreign) == 1
    assert foreign[0].status == "skipped"
    assert "outside customer apex" in (foreign[0].skip_reason or "")

    # In-scope jobs start as pending (not yet run)
    in_scope = [j for j in jobs if j.asset_value == "api.acme.com"]
    assert in_scope[0].status == "pending"


def test_queue_refuses_unverified_customer(db, operator):
    """Customer whose consent hasn't been verified cannot be queued."""
    svc = CustomerService(db)
    enrollment = svc.enroll(
        name="Pending",
        seed="pending.com",
        consent_method=ConsentMethod.DNS_TXT,  # NOT auto-verified
    )
    scheduler = ScanScheduler(db=db, operator=operator)
    with pytest.raises(CustomerConsentRequiredError, match="unverified consent"):
        scheduler.queue_surface(enrollment.customer.customer_id)


def test_queue_creation_writes_audit_row(db, operator, customer_with_surface):
    scheduler = ScanScheduler(db=db, operator=operator)
    queue = scheduler.queue_surface(customer_with_surface.customer_id)

    entries = db.list_audit(customer_id=customer_with_surface.customer_id, limit=20)
    queue_creates = [e for e in entries if e.action == "scan_queue_create"]
    assert len(queue_creates) == 1
    assert queue_creates[0].operator_id == operator.operator_id
    assert queue_creates[0].target == "acme.com"


# ── Execution ──────────────────────────────────────────────────────


class _StubRunner(EngagementRunner):
    """Runner that returns scripted results without touching the network."""

    def __init__(self, plan: Dict[str, Dict[str, Any]]):
        self.plan = plan
        self.calls: List[str] = []

    def run(self, asset_value, customer, report_dir, tool_bundle):
        self.calls.append(asset_value)
        if asset_value in self.plan:
            return self.plan[asset_value]
        # Default: clean scan, no findings, no errors
        return {"engagement_id": f"eng-{asset_value}", "findings_count": 0, "errors": []}


def test_run_next_transitions_job_to_complete(
    db, operator, customer_with_surface
):
    runner = _StubRunner(plan={
        "api.acme.com": {"engagement_id": "eng-api", "findings_count": 3, "errors": []},
    })
    scheduler = ScanScheduler(db=db, operator=operator, runner=runner)
    queue = scheduler.queue_surface(customer_with_surface.customer_id)

    job = scheduler.run_next(queue.queue_id)
    assert job is not None
    assert job.status == "complete"
    assert job.completed_at_ns is not None
    assert job.engagement_id is not None
    assert len(runner.calls) == 1


def test_run_all_processes_every_pending_job(
    db, operator, customer_with_surface
):
    runner = _StubRunner(plan={
        "api.acme.com":     {"engagement_id": "e1", "findings_count": 2, "errors": []},
        "staging.acme.com": {"engagement_id": "e2", "findings_count": 5, "errors": []},
        "www.acme.com":     {"engagement_id": "e3", "findings_count": 0, "errors": []},
        "acme.com":         {"engagement_id": "e4", "findings_count": 1, "errors": []},
    })
    scheduler = ScanScheduler(db=db, operator=operator, runner=runner)
    queue = scheduler.queue_surface(customer_with_surface.customer_id)

    progress = scheduler.run_all(queue.queue_id)

    # 4 in-scope completed, 1 out-of-scope skipped, total findings = 2+5+0+1=8
    assert progress.complete == 4
    assert progress.skipped == 1
    assert progress.failed == 0
    assert progress.total_findings == 8

    # Out-of-scope runner never got called
    assert "foo.example.org" not in runner.calls


def test_run_all_handles_runner_exception_as_failed(
    db, operator, customer_with_surface
):
    class CrashyRunner(EngagementRunner):
        def run(self, asset_value, customer, report_dir, tool_bundle):
            if asset_value == "api.acme.com":
                raise RuntimeError("tool crashed")
            return {"engagement_id": "ok", "findings_count": 0, "errors": []}

    scheduler = ScanScheduler(db=db, operator=operator, runner=CrashyRunner())
    queue = scheduler.queue_surface(customer_with_surface.customer_id)
    progress = scheduler.run_all(queue.queue_id)

    assert progress.failed == 1
    jobs = db.list_scan_jobs(queue.queue_id)
    crashed = [j for j in jobs if j.asset_value == "api.acme.com"]
    assert crashed[0].status == "failed"
    assert "tool crashed" in (crashed[0].error or "")


def test_runner_errors_with_zero_findings_marked_failed(
    db, operator, customer_with_surface
):
    """If runner reports errors + 0 findings → failed (partial-success
    with findings stays 'complete')."""
    runner = _StubRunner(plan={
        "api.acme.com": {"engagement_id": None, "findings_count": 0,
                         "errors": ["nuclei timed out"]},
        "www.acme.com": {"engagement_id": "e2", "findings_count": 3,
                         "errors": ["wpscan partial"]},  # partial
    })
    scheduler = ScanScheduler(db=db, operator=operator, runner=runner)
    queue = scheduler.queue_surface(customer_with_surface.customer_id)
    scheduler.run_all(queue.queue_id)

    jobs = db.list_scan_jobs(queue.queue_id)
    api = [j for j in jobs if j.asset_value == "api.acme.com"][0]
    www = [j for j in jobs if j.asset_value == "www.acme.com"][0]
    assert api.status == "failed"
    assert www.status == "complete"   # partial success with findings


# ── Progress + reporting ───────────────────────────────────────────


def test_progress_reflects_live_queue_state(
    db, operator, customer_with_surface
):
    scheduler = ScanScheduler(db=db, operator=operator, runner=_StubRunner({}))
    queue = scheduler.queue_surface(customer_with_surface.customer_id)

    before = scheduler.progress(queue.queue_id)
    assert before.total == 5
    assert before.pending == 4   # 4 in-scope
    assert before.skipped == 1   # 1 out-of-scope

    scheduler.run_all(queue.queue_id)
    after = scheduler.progress(queue.queue_id)
    assert after.complete == 4
    assert after.pending == 0


def test_queue_complete_records_final_audit(
    db, operator, customer_with_surface
):
    runner = _StubRunner(plan={
        "acme.com":     {"engagement_id": "e1", "findings_count": 1, "errors": []},
        "api.acme.com": {"engagement_id": "e2", "findings_count": 2, "errors": []},
    })
    scheduler = ScanScheduler(db=db, operator=operator, runner=runner)
    queue = scheduler.queue_surface(customer_with_surface.customer_id)
    scheduler.run_all(queue.queue_id)

    entries = db.list_audit(customer_id=customer_with_surface.customer_id, limit=50)
    actions = [e.action for e in entries]
    assert "scan_queue_create" in actions
    assert "scan_queue_complete" in actions
    assert actions.count("scan_job_start") == 4   # 4 in-scope jobs
    assert actions.count("scan_job_complete") == 4

    # Every schedule audit entry tagged with our operator
    for e in entries:
        if e.actor == "argos.schedule":
            assert e.operator_id == operator.operator_id


# ── Queue listing ──────────────────────────────────────────────────


def test_list_scan_queues_returns_by_customer(db, operator, customer_with_surface):
    scheduler = ScanScheduler(db=db, operator=operator)
    queue1 = scheduler.queue_surface(customer_with_surface.customer_id)
    queue2 = scheduler.queue_surface(customer_with_surface.customer_id)

    queues = db.list_scan_queues(customer_with_surface.customer_id)
    assert len(queues) == 2
    assert {q.queue_id for q in queues} == {queue1.queue_id, queue2.queue_id}


# ── Integration: the full flow end-to-end ─────────────────────────


def test_full_flow_enroll_recon_queue_scan_report(tmp_path):
    """Minimal smoke test of the complete customer loop with fakes."""
    db = AssetsDB(tmp_path / "customer.db")
    db.initialize()

    # 1. Register + authorize an operator
    op_svc = OperatorService(db)
    op = op_svc.register(
        email="ops@amoskys.com", name="Ops",
        role=OperatorRole.ANALYST, accept_agreement=True,
    )

    # 2. Enroll a lab customer (consent auto-verified)
    cust_svc = CustomerService(db)
    enrollment = cust_svc.enroll(
        name="LabCorp", seed="lab.example.com",
        consent_method=ConsentMethod.LAB_SELF,
    )
    cid = enrollment.customer.customer_id

    # 3. Seed a surface directly (simulating what recon would produce)
    for value in ("lab.example.com", "api.lab.example.com", "www.lab.example.com"):
        kind = AssetKind.DOMAIN if value == "lab.example.com" else AssetKind.SUBDOMAIN
        db.upsert_asset(SurfaceAsset.new(
            customer_id=cid, kind=kind, value=value,
            source="fake", confidence=0.9,
        ))

    # 4. Queue + run scans via a mock runner
    runner = _StubRunner(plan={
        "lab.example.com":       {"engagement_id": "e1", "findings_count": 1, "errors": []},
        "api.lab.example.com":   {"engagement_id": "e2", "findings_count": 4, "errors": []},
        "www.lab.example.com":   {"engagement_id": "e3", "findings_count": 0, "errors": []},
    })
    scheduler = ScanScheduler(db=db, operator=op, runner=runner)
    queue = scheduler.queue_surface(cid)
    progress = scheduler.run_all(queue.queue_id)

    # 5. Expected consolidated state
    assert progress.total == 3
    assert progress.complete == 3
    assert progress.total_findings == 5
    assert progress.failed == 0
    assert progress.skipped == 0

    # 6. Queue is marked complete
    reloaded = db.get_scan_queue(queue.queue_id)
    assert reloaded.completed_at_ns is not None
