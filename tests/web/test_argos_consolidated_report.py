"""Consolidated report tests — finding persistence + renderer + CLI shape.

Covers:
  - Findings persist through the scheduler → DB round-trip
  - Severity ordering (critical > high > medium > low > info)
  - build_report assembles queue + jobs + findings correctly
  - render() produces HTML always; PDF graceful on missing weasyprint
  - HTML escapes injection attempts in customer names / findings
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import patch

import pytest

from amoskys.agents.Web.argos.consolidated_report import (
    ConsolidatedReport,
    RenderResult,
    build_report,
    render,
    _h,
)
from amoskys.agents.Web.argos.customer import CustomerService
from amoskys.agents.Web.argos.operators import OperatorService
from amoskys.agents.Web.argos.schedule import EngagementRunner, ScanScheduler
from amoskys.agents.Web.argos.storage import (
    AssetKind,
    AssetsDB,
    ConsentMethod,
    OperatorRole,
    StoredFinding,
    SurfaceAsset,
)


@pytest.fixture
def db(tmp_path):
    d = AssetsDB(tmp_path / "customer.db")
    d.initialize()
    return d


@pytest.fixture
def operator(db):
    return OperatorService(db).register(
        email="ops@amoskys.com", name="Ops",
        role=OperatorRole.ANALYST, accept_agreement=True,
    )


@pytest.fixture
def customer_with_surface(db):
    cust_svc = CustomerService(db)
    enrollment = cust_svc.enroll(
        name="Acme Corp",
        seed="acme.com",
        consent_method=ConsentMethod.LAB_SELF,
    )
    cid = enrollment.customer.customer_id
    for value, kind in (
        ("acme.com", AssetKind.DOMAIN),
        ("api.acme.com", AssetKind.SUBDOMAIN),
        ("www.acme.com", AssetKind.SUBDOMAIN),
    ):
        db.upsert_asset(SurfaceAsset.new(
            customer_id=cid, kind=kind, value=value,
            source="fake", confidence=0.9,
        ))
    return db.get_customer(cid)


# ── Fixture runner that produces scripted findings ────────────────


class _FindingRunner(EngagementRunner):
    """Runner returning pre-scripted findings per asset."""

    def __init__(self, per_asset: Dict[str, List[Dict[str, Any]]]):
        self.per_asset = per_asset

    def run(self, asset_value, customer, report_dir, tool_bundle):
        findings = self.per_asset.get(asset_value, [])
        return {
            "engagement_id": f"eng-{asset_value}",
            "findings_count": len(findings),
            "errors": [],
            "findings": findings,
        }


# ── Finding persistence (scheduler integration) ───────────────────


def test_scheduler_persists_findings_to_db(db, operator, customer_with_surface):
    runner = _FindingRunner({
        "api.acme.com": [
            {"template_id": "authz-bypass", "severity": "critical",
             "title": "Unauth REST endpoint", "description": "Leaks admin data.",
             "tool": "nuclei", "cwe": "CWE-862", "cvss": 9.1,
             "references": ["https://cwe.mitre.org/data/definitions/862.html"],
             "mitre_techniques": ["T1190"],
             "evidence": {"url": "https://api.acme.com/admin"},
             "detected_at_ns": 1_700_000_000_000_000_000},
            {"template_id": "xss-reflected", "severity": "medium",
             "title": "Reflected XSS on search", "description": "Unescaped query param.",
             "tool": "nuclei", "evidence": {"param": "q"}},
        ],
        "www.acme.com": [
            {"template_id": "exposure", "severity": "low", "title": "Server header leak",
             "description": "nginx/1.18 banner visible.", "tool": "wpscan"},
        ],
    })
    scheduler = ScanScheduler(db=db, operator=operator, runner=runner)
    queue = scheduler.queue_surface(customer_with_surface.customer_id)
    scheduler.run_all(queue.queue_id)

    stored = db.list_findings(queue_id=queue.queue_id)
    # 3 findings across 2 assets
    assert len(stored) == 3
    # Ordered by severity: critical first, then medium, then low
    assert stored[0].severity == "critical"
    assert stored[0].title == "Unauth REST endpoint"
    assert stored[1].severity == "medium"
    assert stored[2].severity == "low"

    # Linkage back to job + customer is populated
    assert stored[0].customer_id == customer_with_surface.customer_id
    assert stored[0].queue_id == queue.queue_id
    # References + evidence round-trip through JSON
    assert "cwe.mitre.org" in stored[0].references[0]
    assert stored[0].evidence.get("url") == "https://api.acme.com/admin"


def test_finding_severity_counts(db, operator, customer_with_surface):
    runner = _FindingRunner({
        "api.acme.com": [
            {"severity": "critical", "title": "a", "description": ""},
            {"severity": "critical", "title": "b", "description": ""},
            {"severity": "high", "title": "c", "description": ""},
        ],
        "acme.com": [
            {"severity": "low", "title": "d", "description": ""},
        ],
    })
    scheduler = ScanScheduler(db=db, operator=operator, runner=runner)
    queue = scheduler.queue_surface(customer_with_surface.customer_id)
    scheduler.run_all(queue.queue_id)

    counts = db.finding_severity_counts(queue.queue_id)
    assert counts.get("critical") == 2
    assert counts.get("high") == 1
    assert counts.get("low") == 1


def test_list_findings_filter_by_severity(db, operator, customer_with_surface):
    runner = _FindingRunner({
        "api.acme.com": [
            {"severity": "critical", "title": "a", "description": ""},
            {"severity": "medium", "title": "b", "description": ""},
        ],
    })
    scheduler = ScanScheduler(db=db, operator=operator, runner=runner)
    queue = scheduler.queue_surface(customer_with_surface.customer_id)
    scheduler.run_all(queue.queue_id)

    crits = db.list_findings(queue_id=queue.queue_id, severity="critical")
    assert len(crits) == 1
    assert crits[0].severity == "critical"


# ── build_report ──────────────────────────────────────────────────


def test_build_report_assembles_from_db(db, operator, customer_with_surface):
    runner = _FindingRunner({
        "api.acme.com": [
            {"severity": "critical", "title": "SQL injection", "description": "UNION-based"},
            {"severity": "high", "title": "Nonce missing", "description": ""},
        ],
        "www.acme.com": [
            {"severity": "low", "title": "Banner leak", "description": ""},
        ],
    })
    scheduler = ScanScheduler(db=db, operator=operator, runner=runner)
    queue = scheduler.queue_surface(customer_with_surface.customer_id)
    scheduler.run_all(queue.queue_id)

    report = build_report(db, queue.queue_id)
    assert report.customer.name == "Acme Corp"
    assert report.operator_email == "ops@amoskys.com"
    assert report.total_findings == 3
    assert report.severity_totals["critical"] == 1
    assert report.severity_totals["high"] == 1
    assert report.severity_totals["low"] == 1
    assert report.critical_plus_high == 2

    # Each asset has its own section
    assert len(report.assets) == 3
    by_asset = {s.asset_value: s for s in report.assets}
    assert len(by_asset["api.acme.com"].findings) == 2
    assert len(by_asset["www.acme.com"].findings) == 1
    assert len(by_asset["acme.com"].findings) == 0


def test_build_report_raises_on_unknown_queue(db):
    with pytest.raises(LookupError, match="no scan_queue"):
        build_report(db, "nope-not-a-real-queue-id")


# ── render() ──────────────────────────────────────────────────────


def test_render_produces_html_always(tmp_path, db, operator, customer_with_surface):
    runner = _FindingRunner({
        "acme.com": [{"severity": "critical", "title": "Unauth RCE",
                      "description": "Code execution via plugin X"}],
    })
    scheduler = ScanScheduler(db=db, operator=operator, runner=runner)
    queue = scheduler.queue_surface(customer_with_surface.customer_id)
    scheduler.run_all(queue.queue_id)

    report = build_report(db, queue.queue_id)
    out_dir = tmp_path / "out"
    result = render(report, out_dir=out_dir, html_only=True)

    assert result.html_path.exists()
    html = result.html_path.read_text()
    assert "Acme Corp" in html
    assert "Unauth RCE" in html
    assert "critical" in html.lower()
    # HTML-only mode — no PDF attempted, no error
    assert result.pdf_path is None


def test_render_handles_missing_weasyprint_gracefully(tmp_path, db, operator, customer_with_surface):
    """When weasyprint isn't installed, PDF gets a clear error but HTML still lands."""
    runner = _FindingRunner({"acme.com": [
        {"severity": "medium", "title": "Something", "description": ""},
    ]})
    scheduler = ScanScheduler(db=db, operator=operator, runner=runner)
    queue = scheduler.queue_surface(customer_with_surface.customer_id)
    scheduler.run_all(queue.queue_id)

    report = build_report(db, queue.queue_id)

    # Simulate weasyprint import failing
    import builtins as _builtins
    real_import = _builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "weasyprint":
            raise ImportError("weasyprint not installed")
        return real_import(name, *args, **kwargs)

    with patch.object(_builtins, "__import__", side_effect=fake_import):
        result = render(report, out_dir=tmp_path / "out", html_only=False)

    assert result.html_path.exists()
    assert result.pdf_path is None
    assert "weasyprint" in (result.pdf_error or "").lower()


def test_render_escapes_injection_in_customer_name(tmp_path, db, operator):
    """Customer name with HTML should be safely escaped."""
    cust_svc = CustomerService(db)
    enrollment = cust_svc.enroll(
        name='<script>alert("xss")</script> Corp',
        seed="evil.com",
        consent_method=ConsentMethod.LAB_SELF,
    )
    db.upsert_asset(SurfaceAsset.new(
        customer_id=enrollment.customer.customer_id,
        kind=AssetKind.DOMAIN, value="evil.com",
        source="fake", confidence=0.9,
    ))
    runner = _FindingRunner({"evil.com": [
        {"severity": "high", "title": "<img src=x onerror=alert(1)>",
         "description": "Evil content"},
    ]})
    scheduler = ScanScheduler(db=db, operator=operator, runner=runner)
    queue = scheduler.queue_surface(enrollment.customer.customer_id)
    scheduler.run_all(queue.queue_id)

    report = build_report(db, queue.queue_id)
    result = render(report, out_dir=tmp_path / "out", html_only=True)
    html = result.html_path.read_text()

    # Raw script tags must not appear as-is
    assert "<script>" not in html
    assert "<img src=x onerror" not in html
    # But the escaped versions should
    assert "&lt;script&gt;" in html
    assert "&lt;img src=x onerror" in html


def test_render_sections_for_skipped_and_failed_assets(
    tmp_path, db, operator, customer_with_surface
):
    """Skipped + failed jobs render with explanatory notes."""
    class _MixedRunner(EngagementRunner):
        def run(self, asset_value, customer, report_dir, tool_bundle):
            if asset_value == "api.acme.com":
                raise RuntimeError("nuclei died")
            return {"engagement_id": f"e-{asset_value}", "findings_count": 0,
                    "errors": [], "findings": []}

    # Inject an out-of-scope asset so one job gets skipped
    db.upsert_asset(SurfaceAsset.new(
        customer_id=customer_with_surface.customer_id,
        kind=AssetKind.SUBDOMAIN, value="foo.example.org",
        source="fake", confidence=0.9,
    ))

    scheduler = ScanScheduler(db=db, operator=operator, runner=_MixedRunner())
    queue = scheduler.queue_surface(customer_with_surface.customer_id)
    scheduler.run_all(queue.queue_id)

    report = build_report(db, queue.queue_id)
    result = render(report, out_dir=tmp_path / "out", html_only=True)
    html = result.html_path.read_text()

    # Skipped section should mention it
    assert "foo.example.org" in html
    assert "skipped" in html.lower() or "Skipped" in html
    # Failed section explains the error
    assert "nuclei died" in html or "Scan failed" in html


# ── Escape helper ─────────────────────────────────────────────────


def test_h_escapes_core_chars():
    assert _h("<script>") == "&lt;script&gt;"
    assert _h('"hi"') == "&quot;hi&quot;"
    assert _h("a & b") == "a &amp; b"
    assert _h(None) == ""
    assert _h(42) == "42"


# ── Summary dict ──────────────────────────────────────────────────


def test_report_to_summary_dict(db, operator, customer_with_surface):
    runner = _FindingRunner({
        "api.acme.com": [{"severity": "critical", "title": "a", "description": ""}],
    })
    scheduler = ScanScheduler(db=db, operator=operator, runner=runner)
    queue = scheduler.queue_surface(customer_with_surface.customer_id)
    scheduler.run_all(queue.queue_id)

    report = build_report(db, queue.queue_id)
    summary = report.to_summary_dict()
    assert summary["customer"] == "Acme Corp"
    assert summary["customer_seed"] == "acme.com"
    assert summary["operator"] == "ops@amoskys.com"
    assert summary["total_findings"] == 1
    assert summary["severity_totals"]["critical"] == 1
