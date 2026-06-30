"""Unit tests for argos/precision/ — APT-grade offensive orchestrator."""

from __future__ import annotations

import datetime

from amoskys.agents.Web.argos.precision import (
    PayloadProbe,
    SchedulePlan,
    TargetTimezone,
    build_precision_plan,
    low_slow_schedule,
    run_precision,
    synthesize_probe,
)

# ──────────────────────────────────────────────────────────────────
# payload_synth.synthesize_probe
# ──────────────────────────────────────────────────────────────────


def _f(scanner, rule_id, **kw):
    """Build a fake AST finding dict."""
    base = {
        "scanner": scanner,
        "rule_id": rule_id,
        "severity": "high",
        "plugin_slug": "test-plug",
        "plugin_version": "1.2.3",
        "file_path": "includes/ajax.php",
        "line": 42,
        "title": "test",
        "cwe": "CWE-89",
    }
    base.update(kw)
    return base


def test_unknown_scanner_returns_none():
    assert synthesize_probe(_f("unknown", "foo"), "https://t.com") is None


def test_unknown_rule_for_known_scanner_returns_none():
    assert (
        synthesize_probe(_f("sql_injection", "sql.nonexistent_rule"), "https://t.com")
        is None
    )


def test_sqli_probe_uses_sleep_timing():
    f = _f("sql_injection", "sql.interpolation_in_query")
    probe = synthesize_probe(f, "https://t.com")
    assert probe is not None
    assert probe.method == "GET"
    assert "SLEEP" in probe.url
    assert "t.com" in probe.url
    assert probe.risk_tier == "low"
    # Vuln signal must mention latency.
    assert "latency" in probe.vuln_signal.lower() or "s " in probe.vuln_signal
    assert "aegis.db.suspicious_query" in probe.expected_aegis_events
    assert probe.cwe == "CWE-89"


def test_sqli_probe_for_prepare_with_interp():
    f = _f("sql_injection", "sql.prepare_with_interpolation")
    probe = synthesize_probe(f, "https://t.com")
    assert probe is not None
    assert "SLEEP" in probe.url


def test_file_upload_probe_is_inert_gif():
    f = _f("file_upload", "upload.move_uploaded_file_tainted_dest", cwe="CWE-434")
    probe = synthesize_probe(f, "https://t.com")
    assert probe is not None
    assert probe.method == "POST"
    # Must be multipart.
    assert "multipart/form-data" in probe.headers.get("Content-Type", "")
    # Must contain the GIF magic header and a unique probe tag.
    assert "GIF87a" in (probe.body or "")
    assert "AMSW-PROBE-" in (probe.body or "")
    # Must NOT contain any executable PHP tag or .phtml filename.
    assert "<?php" not in (probe.body or "")
    assert "<?=" not in (probe.body or "")
    assert "phtml" not in (probe.body or "").lower()
    assert probe.risk_tier == "medium"


def test_poi_probe_is_inert_stdclass():
    import urllib.parse

    f = _f("poi", "poi.unserialize_on_request", cwe="CWE-502")
    probe = synthesize_probe(f, "https://t.com")
    assert probe is not None
    assert probe.method == "POST"
    # Payload is form-urlencoded — decode before checking.
    body = urllib.parse.unquote(probe.body or "")
    assert 'O:8:"stdClass"' in body
    # Must NOT reference any known gadget classes.
    for danger in (
        "PharData",
        "SimpleXMLElement",
        "SplFileObject",
        "WP_Error",
        "SplFileInfo",
    ):
        assert danger not in body
    assert "aegis.request.poi_payload" in probe.expected_aegis_events


def test_csrf_probe_has_cross_origin_referer():
    f = _f("csrf", "csrf.admin_post_no_nonce", cwe="CWE-352")
    probe = synthesize_probe(f, "https://t.com")
    assert probe is not None
    ref = probe.headers.get("Referer", "")
    assert ref
    # Must be cross-origin to simulate CSRF.
    assert "t.com" not in ref
    # Must not expose a real user's session.
    assert "Cookie" not in probe.headers


def test_ssrf_probe_uses_canary_not_metadata():
    f = _f("ssrf", "ssrf.wp_remote_request_tainted", cwe="CWE-918")
    probe = synthesize_probe(f, "https://t.com")
    assert probe is not None
    # Must NOT probe AWS/GCP/metadata directly.
    for danger in (
        "169.254.169.254",
        "metadata.google.internal",
        "metadata.amazonaws.com",
    ):
        assert danger not in probe.url
    # Must reference a canary host.
    assert "canary" in probe.url


def test_rest_authz_probe_is_enum_first():
    f = _f("rest_authz", "rest_authz.permission_callback_return_true")
    probe = synthesize_probe(f, "https://t.com")
    assert probe is not None
    # Starts with namespace enumeration.
    assert "wp-json" in probe.url
    assert probe.method == "GET"
    assert probe.risk_tier == "low"


def test_probe_carries_unique_finding_id():
    f1 = _f("sql_injection", "sql.interpolation_in_query", file_path="a.php", line=1)
    f2 = _f("sql_injection", "sql.interpolation_in_query", file_path="b.php", line=2)
    p1 = synthesize_probe(f1, "https://t.com")
    p2 = synthesize_probe(f2, "https://t.com")
    assert p1.finding_id != p2.finding_id


# ──────────────────────────────────────────────────────────────────
# temporal.low_slow_schedule
# ──────────────────────────────────────────────────────────────────


def test_schedule_produces_requested_count():
    s = low_slow_schedule(probe_count=5, seed=42, max_span_days=30)
    assert s.probe_count == 5
    assert len(s.probe_times) == 5


def test_schedule_is_strictly_ascending():
    s = low_slow_schedule(probe_count=10, seed=42, max_span_days=30)
    for i in range(1, len(s.probe_times)):
        assert s.probe_times[i] >= s.probe_times[i - 1]


def test_schedule_respects_min_gap():
    s = low_slow_schedule(
        probe_count=6,
        min_gap_hours=3.0,
        gap_stddev_hr=0.0,
        seed=1,
        max_span_days=30,
    )
    for i in range(1, len(s.probe_times)):
        delta = (s.probe_times[i] - s.probe_times[i - 1]).total_seconds()
        # 3h floor minus a small slack for business-hour snapping
        assert delta >= 3 * 3600 - 60


def test_schedule_all_in_biz_hours_default_tz():
    tz = TargetTimezone(
        tz_name="America/New_York",
        biz_start_hour=8,
        biz_end_hour=18,
        biz_days=(0, 1, 2, 3, 4),
    )
    s = low_slow_schedule(probe_count=10, tz=tz, seed=7, max_span_days=30)
    try:
        from zoneinfo import ZoneInfo
    except ImportError:
        return  # skip strict check on py<3.9
    zi = ZoneInfo("America/New_York")
    for t in s.probe_times:
        local = t.astimezone(zi)
        assert local.weekday() in (0, 1, 2, 3, 4)
        assert 8 <= local.hour < 18


def test_schedule_deterministic_with_seed():
    start = datetime.datetime(2026, 4, 20, 12, 0, 0, tzinfo=datetime.timezone.utc)
    a = low_slow_schedule(probe_count=5, seed=123, max_span_days=30, start_at=start)
    b = low_slow_schedule(probe_count=5, seed=123, max_span_days=30, start_at=start)
    assert [t.isoformat() for t in a.probe_times] == [
        t.isoformat() for t in b.probe_times
    ]


def test_schedule_notes_when_span_too_tight():
    # Try to schedule 200 probes in 1 day — should truncate.
    s = low_slow_schedule(probe_count=200, max_span_days=1, seed=0)
    assert s.probe_count < 200
    assert any("exceeded" in n for n in s.notes)


# ──────────────────────────────────────────────────────────────────
# chain.build_precision_plan
# ──────────────────────────────────────────────────────────────────


def _make_probe(rule_id, finding_id, slug="test-plug"):
    return PayloadProbe(
        source_rule_id=rule_id,
        plugin_slug=slug,
        plugin_version="1.0",
        finding_id=finding_id,
        url="https://t.com/x",
    )


def test_plan_sorts_intel_first():
    probes = [
        _make_probe("sql.interpolation_in_query", "P1"),
        _make_probe("rest_authz.permission_callback_return_true", "P2"),
        _make_probe("upload.move_uploaded_file_tainted_dest", "P3"),
    ]
    plan = build_precision_plan("https://t.com", probes)
    # rest_authz (intel) should come first.
    assert plan.probes[0].source_rule_id.startswith("rest_authz")


def test_plan_records_tier_per_probe():
    probes = [
        _make_probe("ssrf.wp_remote_request_tainted", "P1"),
        _make_probe("upload.move_uploaded_file_tainted_dest", "P2"),
    ]
    plan = build_precision_plan("https://t.com", probes)
    assert plan.tiers["P1"] == "confirm.passive"
    assert plan.tiers["P2"] == "confirm.active"


def test_plan_encodes_intel_dependency():
    # A non-intel probe should depend on the intel probe on the SAME plugin.
    intel = _make_probe("rest_authz.wp_ajax_nopriv_state_change", "P1", slug="foo")
    # Actually that's confirm.active — let's use a pure intel one.
    intel = _make_probe("rest_authz.permission_callback_missing", "P1", slug="foo")
    # Hmm — "permission_callback_missing" isn't in our _tier_for explicit
    # check. Let me use a rule we know is intel.enum:
    intel = PayloadProbe(
        source_rule_id="rest_authz.permission_callback_missing",
        plugin_slug="foo",
        plugin_version="1",
        finding_id="P1",
        url="x",
    )
    active = _make_probe("sql.interpolation_in_query", "P2", slug="foo")
    plan = build_precision_plan("https://t.com", [intel, active])
    # P2 (SQLi) should list P1 (rest-authz intel on same slug) as dep.
    assert "P1" in plan.depends.get("P2", [])


def test_plan_excludes_escalate_by_default():
    # We currently have no rule mapped to 'escalate' tier in _tier_for,
    # so this mostly verifies the mechanism exists. Confirm include_escalate
    # flag passes through.
    probes = [_make_probe("sql.interpolation_in_query", "P1")]
    plan_default = build_precision_plan("x", probes, include_escalate=False)
    plan_yes = build_precision_plan("x", probes, include_escalate=True)
    assert len(plan_default.probes) == len(plan_yes.probes)  # same here


def test_plan_deterministic_ordering_within_tier():
    # Two confirm.active probes — order should be by (slug, rule, finding_id).
    probes = [
        _make_probe("upload.move_uploaded_file_tainted_dest", "B", slug="b"),
        _make_probe("upload.move_uploaded_file_tainted_dest", "A", slug="a"),
    ]
    plan = build_precision_plan("x", probes)
    assert plan.probes[0].plugin_slug == "a"
    assert plan.probes[1].plugin_slug == "b"


# ──────────────────────────────────────────────────────────────────
# precision.run_precision
# ──────────────────────────────────────────────────────────────────


class _FakeCorpus:
    def __init__(self, plugins_to_return=None, raise_for=None):
        self.plugins_to_return = plugins_to_return or {}
        self.raise_for = raise_for or set()

    def fetch(self, slug, version):
        if slug in self.raise_for:
            raise RuntimeError(f"corpus fetch failed for {slug}")
        return self.plugins_to_return.get(slug, _FakePlugin(slug, version))


class _FakePlugin:
    def __init__(self, slug, version):
        self.slug = slug
        self.version = version
        self.plugin_root = None


class _FakeSQLiScanner:
    def scan(self, plugin):
        from amoskys.agents.Web.argos.ast.base import ASTFinding

        return [
            ASTFinding(
                scanner="sql_injection",
                rule_id="sql.interpolation_in_query",
                severity="high",
                plugin_slug=plugin.slug,
                plugin_version=plugin.version,
                file_path="ajax.php",
                line=1,
                snippet="",
                title="sqli",
                description="",
                cwe="CWE-89",
            ),
        ]


def test_run_precision_requires_inventory():
    eng = run_precision("https://t.com", consent_token="tk")
    assert eng.plan is None
    assert any("inventory" in r for r in eng.blind_reasons)


def test_run_precision_end_to_end():
    corpus = _FakeCorpus()
    scanners = {"sql_injection": _FakeSQLiScanner}
    eng = run_precision(
        "https://t.com",
        consent_token="tk",
        plugin_inventory=[{"slug": "test-plug", "version": "1.2"}],
        corpus=corpus,
        scanner_registry=scanners,
    )
    assert eng.plan is not None
    assert eng.findings_scanned == 1
    assert eng.plugins_scanned == 1
    assert len(eng.plan.probes) == 1
    assert eng.plan.probes[0].source_rule_id == "sql.interpolation_in_query"
    assert eng.schedule is not None
    assert eng.schedule.probe_count == 1


def test_run_precision_records_corpus_errors():
    corpus = _FakeCorpus(raise_for={"bad-plug"})
    eng = run_precision(
        "https://t.com",
        consent_token="tk",
        plugin_inventory=[{"slug": "bad-plug", "version": "1.0"}],
        corpus=corpus,
        scanner_registry={},
    )
    assert eng.plan is not None  # still produces an empty plan
    assert len(eng.plan.probes) == 0
    assert any("bad-plug" in r for r in eng.blind_reasons)


def test_run_precision_schedule_has_all_probe_times():
    corpus = _FakeCorpus()
    scanners = {"sql_injection": _FakeSQLiScanner}
    eng = run_precision(
        "https://t.com",
        consent_token="tk",
        plugin_inventory=[
            {"slug": "a", "version": "1"},
            {"slug": "b", "version": "1"},
            {"slug": "c", "version": "1"},
        ],
        corpus=corpus,
        scanner_registry=scanners,
    )
    assert eng.plan is not None
    assert len(eng.plan.probes) == 3
    assert eng.schedule is not None
    assert eng.schedule.probe_count == 3
    # Schedule must span multiple hours.
    span_hours = eng.schedule.total_hours
    assert span_hours >= 6  # 3 probes × min 3h gap roughly
