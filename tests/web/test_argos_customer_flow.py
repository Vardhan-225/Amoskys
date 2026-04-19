"""End-to-end customer flow tests — storage, stealth, recon, orchestrator.

Proves the foundation works without touching the network.
"""

from __future__ import annotations

import os
import stat
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from amoskys.agents.Web.argos.customer import (
    ConsentNotVerifiedError,
    CustomerNotFoundError,
    CustomerService,
)
from amoskys.agents.Web.argos.recon import (
    ASNEnrichmentSource,
    AttackSurfaceMap,
    CertTransparencyLogs,
    DNSResolveSource,
    ReconContext,
    ReconEvent,
    ReconSource,
    StealthClass,
)
from amoskys.agents.Web.argos.stealth import (
    AdaptiveRateLimiter,
    BlockedTargetError,
    IdentityPool,
    RateLimiterConfig,
)
from amoskys.agents.Web.argos.storage import (
    AssetKind,
    AssetsDB,
    AuditEntry,
    ConsentMethod,
    Customer,
    ReconRun,
    SurfaceAsset,
)


# ── Storage layer ──────────────────────────────────────────────────


@pytest.fixture
def db(tmp_path):
    d = AssetsDB(tmp_path / "customer.db")
    d.initialize()
    return d


def test_db_initialize_sets_0600_perms(tmp_path):
    path = tmp_path / "customer.db"
    d = AssetsDB(path)
    d.initialize()
    mode = path.stat().st_mode & 0o777
    # Must not be world/group readable
    assert mode & (stat.S_IRGRP | stat.S_IROTH) == 0, f"perms too permissive: {oct(mode)}"


def test_db_refuses_world_readable_file(tmp_path):
    path = tmp_path / "customer.db"
    path.touch(mode=0o644)
    d = AssetsDB(path)
    with pytest.raises(PermissionError, match="refusing to open"):
        d.initialize()


def test_customer_crud_roundtrip(db):
    c = Customer.new("Acme Corp", "acme.com", ConsentMethod.DNS_TXT, consent_token="t-123")
    db.create_customer(c)

    got = db.get_customer(c.customer_id)
    assert got is not None
    assert got.name == "Acme Corp"
    assert got.seed == "acme.com"
    assert got.consent_verified_at_ns is None
    assert got.consent_token == "t-123"

    db.mark_consent_verified(c.customer_id)
    got2 = db.get_customer(c.customer_id)
    assert got2.consent_verified_at_ns is not None


def test_upsert_asset_deduplicates_and_merges_confidence(db):
    c = Customer.new("Acme", "acme.com", ConsentMethod.DNS_TXT, "t")
    db.create_customer(c)

    a1 = SurfaceAsset.new(c.customer_id, AssetKind.SUBDOMAIN, "api.acme.com",
                          source="ct_logs.crtsh", confidence=0.7)
    a2 = SurfaceAsset.new(c.customer_id, AssetKind.SUBDOMAIN, "api.acme.com",
                          source="dns_resolve", confidence=0.95)
    id1 = db.upsert_asset(a1)
    id2 = db.upsert_asset(a2)

    assert id1 == id2, "same (kind, value) should collapse to one row"
    rows = db.list_assets(c.customer_id, kind=AssetKind.SUBDOMAIN)
    assert len(rows) == 1
    # Confidence should have been maxed up, not averaged
    assert rows[0].confidence == pytest.approx(0.95)


def test_audit_log_records_every_state_change(db):
    c = Customer.new("Acme", "acme.com", ConsentMethod.DNS_TXT, "t")
    db.create_customer(c)
    db.mark_consent_verified(c.customer_id)
    db.audit(
        AuditEntry(
            log_id=None,
            customer_id=c.customer_id,
            run_id=None,
            timestamp_ns=int(time.time() * 1e9),
            actor="test",
            action="probe_blocked",
            target="acme.com",
            result="403",
            details={"by": "cloudflare"},
        )
    )
    entries = db.list_audit(customer_id=c.customer_id)
    actions = {e.action for e in entries}
    assert "create_customer" in actions
    assert "consent_verify" in actions
    assert "probe_blocked" in actions


# ── Stealth: rate limiter ──────────────────────────────────────────


def test_rate_limiter_halves_rps_on_block():
    rl = AdaptiveRateLimiter("target", RateLimiterConfig(initial_rps=4.0, min_rps=0.5))
    assert rl.current_rps == 4.0
    rl.observe(429)
    assert rl.current_rps == 2.0
    rl.observe(429)
    assert rl.current_rps == 1.0


def test_rate_limiter_blocks_after_threshold():
    fake_now = [0.0]

    def now(): return fake_now[0]

    def sleep(s):  # fast-forward virtual time instead of actually sleeping
        fake_now[0] += s

    rl = AdaptiveRateLimiter(
        "target",
        RateLimiterConfig(block_threshold=2, initial_rps=1.0, backoff_base_s=1.0),
        now_fn=now, sleep_fn=sleep,
    )
    rl.wait()
    rl.observe(429)
    rl.wait()
    rl.observe(429)
    with pytest.raises(BlockedTargetError):
        rl.wait()


def test_rate_limiter_recovers_on_success():
    rl = AdaptiveRateLimiter("target", RateLimiterConfig(initial_rps=2.0))
    rl.observe(429)
    assert rl.current_rps == 1.0
    for _ in range(15):
        rl.observe(200)
    # Should recover back up to initial_rps
    assert rl.current_rps == pytest.approx(2.0)


def test_rate_limiter_respects_retry_after():
    fake_now = [100.0]
    sleeps = []

    def now(): return fake_now[0]

    def sleep(s):
        sleeps.append(s)
        fake_now[0] += s

    rl = AdaptiveRateLimiter(
        "target",
        RateLimiterConfig(block_threshold=5, initial_rps=1.0, backoff_base_s=30.0),
        now_fn=now, sleep_fn=sleep,
    )
    rl.wait()  # first token free
    rl.observe(429, retry_after_s=7.0)
    rl.wait()  # should sleep ~7s
    # sleeps has jitter so accept a band
    assert any(5.0 <= s <= 9.5 for s in sleeps), f"expected retry-after-driven sleep; got {sleeps}"


# ── Stealth: identity pool ─────────────────────────────────────────


def test_identity_pool_is_deterministic_per_seed():
    p = IdentityPool()
    s1 = p.session_for("cust-A", "api.acme.com")
    s2 = p.session_for("cust-A", "api.acme.com")
    assert s1.session_id == s2.session_id
    assert s1.persona["user_agent"] == s2.persona["user_agent"]


def test_identity_pool_splits_across_targets():
    p = IdentityPool()
    s1 = p.session_for("cust-A", "api.acme.com")
    s2 = p.session_for("cust-A", "www.acme.com")
    # Same customer, different targets → different session IDs
    assert s1.session_id != s2.session_id


def test_session_headers_include_sec_ch_ua_when_appropriate():
    p = IdentityPool()
    # Chrome persona exists in default pool; search for one
    any_chrome = False
    for _ in range(20):
        s = p.random_session()
        h = s.headers()
        if "Chrome" in h["User-Agent"]:
            any_chrome = True
            assert "sec-ch-ua" in h
            break
    assert any_chrome, "default pool should contain at least one Chrome persona"


# ── Recon: CT logs (mocked) ────────────────────────────────────────


def test_ct_logs_emits_subdomains_from_mock_response():
    mock_json = b'''[
        {"id": 1, "name_value": "www.acme.com", "issuer_ca_id": 1},
        {"id": 2, "name_value": "api.acme.com\\nadmin.acme.com", "issuer_ca_id": 2},
        {"id": 3, "name_value": "*.acme.com", "issuer_ca_id": 3},
        {"id": 4, "name_value": "unrelated.example.org", "issuer_ca_id": 4}
    ]'''

    def fake_get(url, timeout):
        assert "acme.com" in url
        return mock_json

    source = CertTransparencyLogs(http_get=fake_get)
    context = ReconContext(customer_id="c", run_id="r", seed="acme.com")
    events = list(source.run(context))

    values = {e.value for e in events}
    assert "acme.com" in values  # apex
    assert "www.acme.com" in values
    assert "api.acme.com" in values
    assert "admin.acme.com" in values
    assert "unrelated.example.org" not in values, "out-of-scope domain must be rejected"
    # *.acme.com should dedupe to apex which is already emitted
    assert len([v for v in values if v == "acme.com"]) == 1


def test_ct_logs_handles_crtsh_503():
    import urllib.error

    def flaky_get(url, timeout):
        raise urllib.error.HTTPError(url, 503, "Service Unavailable", hdrs=None, fp=None)

    source = CertTransparencyLogs(http_get=flaky_get, max_retries=1)
    events = list(source.run(
        ReconContext(customer_id="c", run_id="r", seed="acme.com")
    ))
    assert events == []  # soft-fails, no crash


# ── Recon: DNS + ASN (mocked) ──────────────────────────────────────


def test_dns_resolve_emits_ipv4_per_host():
    def fake_resolve(hostname, resolver, timeout):
        return {"acme.com": ["203.0.113.1"],
                "api.acme.com": ["198.51.100.10", "198.51.100.11"]}.get(hostname, [])

    ctx = ReconContext(
        customer_id="c", run_id="r", seed="acme.com",
        known_subdomains=["api.acme.com"],
    )
    source = DNSResolveSource(resolver_fn=fake_resolve)
    events = list(source.run(ctx))
    values = {e.value for e in events}
    assert "203.0.113.1" in values
    assert "198.51.100.10" in values
    assert "198.51.100.11" in values


def test_asn_enrichment_emits_from_bulk_rows():
    def fake_cymru(ips, timeout):
        return [
            {"asn": "15169", "ip": "8.8.8.8", "prefix": "8.8.8.0/24",
             "cc": "US", "registry": "arin", "allocated": "",
             "as_name": "GOOGLE"},
            {"asn": "13335", "ip": "1.1.1.1", "prefix": "1.1.1.0/24",
             "cc": "US", "registry": "apnic", "allocated": "",
             "as_name": "CLOUDFLARENET"},
        ]

    source = ASNEnrichmentSource(connect_fn=fake_cymru)
    ctx = ReconContext(
        customer_id="c", run_id="r", seed="acme.com",
        known_ips=["8.8.8.8", "1.1.1.1"],
    )
    events = list(source.run(ctx))
    asns = {e.value for e in events if e.kind == AssetKind.ASN}
    cidrs = {e.value for e in events if e.kind == AssetKind.NETBLOCK}
    assert "AS15169" in asns
    assert "AS13335" in asns
    assert "8.8.8.0/24" in cidrs
    assert "1.1.1.0/24" in cidrs


# ── Orchestrator ───────────────────────────────────────────────────


class _StubSource(ReconSource):
    """A recon source that emits a fixed list of events."""

    def __init__(self, name, stealth_class, events):
        self.name = name
        self.stealth_class = stealth_class
        self._events = events

    def run(self, context):
        for e in self._events:
            yield e


def test_orchestrator_runs_sources_in_stealth_order(db):
    c = Customer.new("Acme", "acme.com", ConsentMethod.LAB_SELF, None)
    db.create_customer(c)
    db.mark_consent_verified(c.customer_id)

    order_seen = []

    class TraceSource(_StubSource):
        def run(self, context):
            order_seen.append(self.stealth_class.value)
            return super().run(context)

    passive = TraceSource("p", StealthClass.PASSIVE, [
        ReconEvent(kind=AssetKind.SUBDOMAIN, value="www.acme.com", source="p", confidence=0.9)
    ])
    active = TraceSource("a", StealthClass.ACTIVE, [
        ReconEvent(kind=AssetKind.SERVICE, value="www.acme.com:443", source="a", confidence=0.8)
    ])
    resolver = TraceSource("r", StealthClass.RESOLVER, [
        ReconEvent(kind=AssetKind.IPV4, value="203.0.113.5", source="r", confidence=0.9,
                   parent_value="www.acme.com")
    ])

    # Pass in reverse order; orchestrator must reorder to passive→resolver→active
    orch = AttackSurfaceMap(db=db, sources=[active, resolver, passive])
    orch.run(c)
    assert order_seen == ["passive", "resolver", "active"]


def test_orchestrator_persists_events_and_propagates_context(db):
    """Passive source emits a subdomain; resolver source should see it in context."""
    c = Customer.new("Acme", "acme.com", ConsentMethod.LAB_SELF, None)
    db.create_customer(c)
    db.mark_consent_verified(c.customer_id)

    captured_known = []

    class CheckingResolver(_StubSource):
        def run(self, context):
            captured_known.append(list(context.known_subdomains))
            return super().run(context)

    passive = _StubSource("p", StealthClass.PASSIVE, [
        ReconEvent(kind=AssetKind.SUBDOMAIN, value="api.acme.com", source="p", confidence=0.9)
    ])
    resolver = CheckingResolver("r", StealthClass.RESOLVER, [
        ReconEvent(kind=AssetKind.IPV4, value="203.0.113.1", source="r", confidence=0.9,
                   parent_value="api.acme.com"),
    ])

    orch = AttackSurfaceMap(db=db, sources=[passive, resolver])
    result = orch.run(c)

    assert result.total_assets == 2
    assert "api.acme.com" in captured_known[0], \
        "resolver must see the subdomain the passive source emitted"

    # DB counts reflect one subdomain + one ipv4
    counts = db.asset_counts(c.customer_id)
    assert counts.get("subdomain") == 1
    assert counts.get("ipv4") == 1


def test_orchestrator_continues_after_source_failure(db):
    c = Customer.new("Acme", "acme.com", ConsentMethod.LAB_SELF, None)
    db.create_customer(c)
    db.mark_consent_verified(c.customer_id)

    class CrashingSource(ReconSource):
        name = "crasher"
        stealth_class = StealthClass.PASSIVE

        def run(self, context):
            raise RuntimeError("boom")

    ok_source = _StubSource("ok", StealthClass.RESOLVER, [
        ReconEvent(kind=AssetKind.IPV4, value="1.2.3.4", source="ok", confidence=0.9)
    ])

    orch = AttackSurfaceMap(db=db, sources=[CrashingSource(), ok_source])
    result = orch.run(c)

    assert result.total_assets == 1
    # Crash recorded in run errors
    runs = db.list_recon_runs(c.customer_id)
    assert runs
    assert any("boom" in e for e in runs[0].errors)


# ── End-to-end customer flow ───────────────────────────────────────


def test_full_customer_flow_enroll_verify_recon(tmp_path):
    db_path = tmp_path / "customer.db"
    db = AssetsDB(db_path)
    db.initialize()

    # Use a fake orchestrator that returns predetermined events
    class FakeOrchestrator:
        def __init__(self, _db): self._db = _db

        def run(self, customer):
            from amoskys.agents.Web.argos.recon.orchestrator import AttackSurfaceResult

            # Write assets directly via the db
            from amoskys.agents.Web.argos.storage import SurfaceAsset, AssetKind as K
            for val, kind in [
                ("acme.com", K.DOMAIN),
                ("www.acme.com", K.SUBDOMAIN),
                ("api.acme.com", K.SUBDOMAIN),
                ("203.0.113.1", K.IPV4),
                ("AS15169", K.ASN),
            ]:
                self._db.upsert_asset(SurfaceAsset.new(
                    customer.customer_id, kind, val, source="fake", confidence=0.9,
                ))

            result = AttackSurfaceResult(
                run_id="fake-run",
                customer_id=customer.customer_id,
                seed=customer.seed,
                seed_type="domain",
                total_assets=5,
                duration_s=0.01,
            )
            result._by_kind = self._db.asset_counts(customer.customer_id)
            return result

    service = CustomerService(db=db, surface_map=FakeOrchestrator(db))

    enrollment = service.enroll("Acme Corp", "acme.com", ConsentMethod.LAB_SELF)
    assert enrollment.customer.customer_id
    assert "lab_self" in enrollment.instructions

    # lab_self consent auto-verifies
    customer = service._require_customer(enrollment.customer.customer_id)
    assert customer.consent_verified_at_ns is not None

    result = service.run_recon(enrollment.customer.customer_id)
    assert result.total_assets == 5

    targets = service.list_scan_targets(enrollment.customer.customer_id)
    # Domains + subdomains are scan targets; IPv4 and ASN are metadata
    assert len(targets) == 3
    target_values = {t.value for t in targets}
    assert target_values == {"acme.com", "www.acme.com", "api.acme.com"}


def test_recon_refuses_unverified_customer(tmp_path):
    db = AssetsDB(tmp_path / "customer.db")
    db.initialize()
    service = CustomerService(db=db)
    enrollment = service.enroll("Acme", "acme.com", ConsentMethod.DNS_TXT)
    # DNS_TXT is NOT auto-verified
    with pytest.raises(ConsentNotVerifiedError):
        service.run_recon(enrollment.customer.customer_id)


def test_verify_consent_dns_txt_success(tmp_path):
    db = AssetsDB(tmp_path / "customer.db")
    db.initialize()
    service = CustomerService(db=db)
    enrollment = service.enroll("Acme", "acme.com", ConsentMethod.DNS_TXT)
    token = enrollment.customer.consent_token

    def fake_resolver(name):
        assert name == "_amoskys-verify.acme.com"
        return [f"amoskys-verify={token}"]

    ok, msg = service.verify_consent(enrollment.customer.customer_id, resolver_fn=fake_resolver)
    assert ok
    assert "verified" in msg.lower()


def test_verify_consent_dns_txt_missing_token(tmp_path):
    db = AssetsDB(tmp_path / "customer.db")
    db.initialize()
    service = CustomerService(db=db)
    enrollment = service.enroll("Acme", "acme.com", ConsentMethod.DNS_TXT)

    def fake_resolver(name):
        return ["amoskys-verify=some-other-token"]

    ok, msg = service.verify_consent(enrollment.customer.customer_id, resolver_fn=fake_resolver)
    assert not ok
    assert "does not contain" in msg
