"""Tactical recon tests — IP-first pivot flow + stealth classification.

Covers the four new sources (cloud_detector, reverse_dns, tls_cert,
ip_whois) plus the IP-first orchestrator behavior and completeness
report. Zero real network I/O — all sources injected with fakes.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from amoskys.agents.Web.argos.recon import (
    ASNEnrichmentSource,
    AttackSurfaceMap,
    CDNBehavior,
    CertInfo,
    CertTransparencyLogs,
    CloudDetector,
    CompletenessReport,
    DNSResolveSource,
    IPWHOISSource,
    Provider,
    ReconContext,
    ReconEvent,
    ReverseDNSSource,
    StealthClass,
    TLSCertSource,
    is_generic_cloud_hostname,
)
from amoskys.agents.Web.argos.recon.tls_cert import _clean_san, _parse_cert
from amoskys.agents.Web.argos.recon.ip_whois import _host_from_url, _parse_whois
from amoskys.agents.Web.argos.recon.reverse_dns import _best_apex_guess
from amoskys.agents.Web.argos.storage import (
    AssetKind,
    AssetsDB,
    ConsentMethod,
    Customer,
)


# ── Cloud detector ─────────────────────────────────────────────────


def test_cloud_detector_identifies_cloudflare():
    d = CloudDetector()
    c = d.classify("104.16.1.1")
    assert c.provider == Provider.CLOUDFLARE
    assert c.behavior == CDNBehavior.CDN_PROXY
    assert c.is_cdn_proxy is True
    assert c.should_attempt_tls_pivot is False


def test_cloud_detector_identifies_aws_cloud_hosting():
    d = CloudDetector()
    c = d.classify("52.84.1.1")
    assert c.provider == Provider.AWS
    assert c.behavior == CDNBehavior.CLOUD_HOSTING
    assert c.should_attempt_tls_pivot is True  # AWS is customer-bearing, probe is useful


def test_cloud_detector_marks_unknown_ips_as_probable_customer():
    d = CloudDetector()
    # 198.51.100.0/24 is TEST-NET-2 — definitely not any cloud in our table
    c = d.classify("198.51.100.5")
    assert c.provider == Provider.UNKNOWN
    assert c.behavior == CDNBehavior.UNKNOWN
    assert c.should_attempt_tls_pivot is True  # unknown = probably customer, probe


def test_cloud_detector_skips_private_ips():
    d = CloudDetector()
    c = d.classify("10.0.0.1")
    assert c.provider == Provider.UNKNOWN
    assert "private" in " ".join(c.notes).lower()


def test_cloud_detector_rejects_garbage_input():
    d = CloudDetector()
    c = d.classify("not-an-ip")
    assert c.provider == Provider.UNKNOWN
    assert c.should_attempt_tls_pivot is True  # safe fallback


def test_is_generic_cloud_hostname_catches_aws_ec2_ptrs():
    assert is_generic_cloud_hostname("ec2-203-0-113-5.compute-1.amazonaws.com")
    assert is_generic_cloud_hostname("ip-192-168-0-1.us-east-2.compute.amazonaws.com")
    # Real customer names pass through
    assert not is_generic_cloud_hostname("api.acme.com")
    assert not is_generic_cloud_hostname("mail.customer.io")


def test_is_generic_cloud_hostname_catches_azure_gcp():
    assert is_generic_cloud_hostname("vm1.cloudapp.net")
    assert is_generic_cloud_hostname("203.0.113.5.bc.googleusercontent.com")
    assert is_generic_cloud_hostname("app.azurewebsites.net")


# ── Reverse DNS ────────────────────────────────────────────────────


def test_reverse_dns_emits_subdomain_for_real_ptr():
    def fake_ptr(ip, resolver, timeout):
        return {"203.0.113.5": "mail.acme.com"}.get(ip)

    src = ReverseDNSSource(ptr_fn=fake_ptr)
    ctx = ReconContext(customer_id="c", run_id="r", seed="203.0.113.5")
    events = list(src.run(ctx))
    # Should emit a subdomain event for mail.acme.com
    subs = [e for e in events if e.kind == AssetKind.SUBDOMAIN]
    assert len(subs) == 1
    assert subs[0].value == "mail.acme.com"
    assert subs[0].metadata["apex_guess"] == "acme.com"
    assert subs[0].parent_value == "203.0.113.5"


def test_reverse_dns_skips_generic_cloud_ptrs():
    def fake_ptr(ip, resolver, timeout):
        return "ec2-203-0-113-5.compute-1.amazonaws.com"

    src = ReverseDNSSource(ptr_fn=fake_ptr)
    ctx = ReconContext(customer_id="c", run_id="r", seed="203.0.113.5")
    events = list(src.run(ctx))
    # Should NOT emit a domain — instead emits IP metadata marking generic
    assert not any(e.kind in (AssetKind.DOMAIN, AssetKind.SUBDOMAIN) for e in events)
    ip_events = [e for e in events if e.kind == AssetKind.IPV4]
    assert len(ip_events) == 1
    assert ip_events[0].metadata.get("ptr_classification") == "generic_cloud"


def test_reverse_dns_handles_no_record_gracefully():
    def fake_ptr(ip, resolver, timeout):
        return None  # NXDOMAIN equivalent

    src = ReverseDNSSource(ptr_fn=fake_ptr)
    ctx = ReconContext(customer_id="c", run_id="r", seed="203.0.113.5")
    events = list(src.run(ctx))
    assert events == []


def test_reverse_dns_skips_domain_seed_if_no_ips_discovered():
    """If seed is a domain and no prior source supplied known_ips, there's
    nothing to PTR — source should noop cleanly."""
    def fake_ptr(ip, resolver, timeout):
        pytest.fail("PTR should not be queried for domain-only context")

    src = ReverseDNSSource(ptr_fn=fake_ptr)
    ctx = ReconContext(customer_id="c", run_id="r", seed="acme.com")
    events = list(src.run(ctx))
    assert events == []


def test_best_apex_guess_handles_multi_label_tlds():
    assert _best_apex_guess("api.acme.com") == "acme.com"
    assert _best_apex_guess("api.blog.acme.co.uk") == "acme.co.uk"
    assert _best_apex_guess("mail.site.com.au") == "site.com.au"
    assert _best_apex_guess("example.com") == "example.com"


# ── TLS cert parsing + SAN cleaning ───────────────────────────────


def test_tls_cert_clean_san_strips_wildcards():
    assert _clean_san("*.acme.com") == "acme.com"
    assert _clean_san("api.acme.com") == "api.acme.com"
    assert _clean_san("  API.Acme.com  ") == "api.acme.com"


def test_tls_cert_clean_san_rejects_garbage():
    assert _clean_san("") is None
    assert _clean_san("not a domain") is None
    assert _clean_san("1.2.3.4") is None  # bare IP — not scope-useful
    assert _clean_san("ab") is None         # no dot


def test_tls_cert_parse_extracts_sans_and_fingerprint():
    peer_dict = {
        "subject": ((('commonName', 'api.acme.com'),),),
        "issuer": ((('commonName', "Let's Encrypt R3"),),),
        "subjectAltName": (("DNS", "api.acme.com"), ("DNS", "*.acme.com"), ("DNS", "acme.com")),
        "notBefore": "Jan  1 00:00:00 2026 GMT",
        "notAfter": "Apr  1 00:00:00 2026 GMT",
        "version": 3,
        "serialNumber": "DEADBEEF",
    }
    der = b"fake der bytes for fingerprint hashing"
    cert = _parse_cert(ip="203.0.113.5", sni="acme.com", der=der, peer_dict=peer_dict)
    assert cert.subject_cn == "api.acme.com"
    assert cert.issuer_cn == "Let's Encrypt R3"
    assert set(cert.sans) == {"api.acme.com", "*.acme.com", "acme.com"}
    assert cert.fingerprint_sha256 is not None
    assert len(cert.fingerprint_sha256) == 64  # SHA-256 hex


# ── TLS cert source (injected probe_fn) ────────────────────────────


def _fake_cert(ip, sans):
    """Helper: build a CertInfo for a given IP + SAN list."""
    return CertInfo(
        ip=ip,
        sni=None,
        subject_cn=sans[0] if sans else None,
        issuer_cn="Test CA",
        sans=list(sans),
        fingerprint_sha256=f"sha256-{ip}".ljust(64, "0"),
    )


def test_tls_cert_source_emits_sans_as_domain_events():
    def fake_probe(ip, sni, session_tls_id, connect_timeout_s, handshake_timeout_s):
        return _fake_cert(ip, ["acme.com", "*.acme.com", "api.acme.com"])

    src = TLSCertSource(probe_fn=fake_probe)
    ctx = ReconContext(customer_id="c", run_id="r", seed="198.51.100.5")
    events = list(src.run(ctx))

    # Expect: 1 CERT asset + 3 unique SANs emitted as DOMAIN/SUBDOMAIN
    kinds = [e.kind for e in events]
    assert kinds.count(AssetKind.CERT) == 1
    domains = {e.value for e in events if e.kind == AssetKind.DOMAIN}
    subs = {e.value for e in events if e.kind == AssetKind.SUBDOMAIN}
    assert "acme.com" in domains
    assert "api.acme.com" in subs


def test_tls_cert_source_skips_cloudflare_ips():
    calls = []

    def fake_probe(ip, **kwargs):
        calls.append(ip)
        return _fake_cert(ip, ["cloudflare.example"])

    src = TLSCertSource(probe_fn=fake_probe)
    ctx = ReconContext(customer_id="c", run_id="r", seed="104.16.1.1")
    events = list(src.run(ctx))

    # Probe should never have been called for the Cloudflare IP
    assert calls == []
    # Should emit an IP asset with tls_probe_skipped=True for completeness-report harvest
    skipped = [e for e in events if e.metadata.get("tls_probe_skipped")]
    assert len(skipped) == 1
    assert "cloudflare" in skipped[0].metadata["reason"].lower()


def test_tls_cert_source_handles_probe_failure_gracefully():
    def flaky_probe(ip, **kwargs):
        raise TimeoutError("handshake hung")

    src = TLSCertSource(probe_fn=flaky_probe)
    ctx = ReconContext(customer_id="c", run_id="r", seed="198.51.100.5")
    events = list(src.run(ctx))
    # No events — failures are quiet; orchestrator will note in completeness
    assert events == []


# ── IP WHOIS ───────────────────────────────────────────────────────


def test_ip_whois_parse_extracts_org_and_comment_urls():
    whois_text = """
    # ARIN WHOIS data and services are subject to the Terms of Use.
    NetRange:       203.0.113.0 - 203.0.113.255
    CIDR:           203.0.113.0/24
    OrgName:        Acme Widgets Inc.
    OrgId:          ACME-123
    Country:        US
    OrgAbuseEmail:  abuse@acme.com
    OrgTechEmail:   tech@acme.com
    Comment:        https://www.acme.com — primary site
    Comment:        Also see https://status.acme.com for status
    """
    parsed = _parse_whois(whois_text)
    assert parsed["org_name"] == "Acme Widgets Inc."
    assert parsed["country"] == "US"
    assert parsed["abuse_email"] == "abuse@acme.com"
    assert "acme.com" in parsed["comment"]


def test_ip_whois_source_emits_urls_from_comment():
    whois_text = """
    OrgName: Acme Corp
    Comment: Main site https://www.acme.com for info
    Comment: Status https://status.acme.com
    """

    def fake_query(ip, host, timeout):
        assert ip == "203.0.113.5"
        return whois_text

    src = IPWHOISSource(query_fn=fake_query)
    ctx = ReconContext(customer_id="c", run_id="r", seed="203.0.113.5")
    events = list(src.run(ctx))

    # Expect: IP asset with whois metadata + domain/subdomain events for URLs
    ip_events = [e for e in events if e.kind == AssetKind.IPV4]
    assert len(ip_events) == 1
    assert ip_events[0].metadata["whois"]["org_name"] == "Acme Corp"

    hosts = {e.value for e in events if e.kind in (AssetKind.DOMAIN, AssetKind.SUBDOMAIN)}
    assert "www.acme.com" in hosts
    assert "status.acme.com" in hosts


def test_ip_whois_source_skips_domain_seed():
    """whois on an IP is useful; on a domain seed, skip (wrong tool)."""
    def fake_query(*a, **kw):
        pytest.fail("whois should not be queried for domain seed")

    src = IPWHOISSource(query_fn=fake_query)
    ctx = ReconContext(customer_id="c", run_id="r", seed="acme.com")
    events = list(src.run(ctx))
    assert events == []


def test_host_from_url_rejects_garbage():
    assert _host_from_url("https://api.acme.com/path") == "api.acme.com"
    assert _host_from_url("http://example.org") == "example.org"
    assert _host_from_url("not a url") is None
    assert _host_from_url("ftp://") is None


# ── IP-first orchestrator flow ─────────────────────────────────────


@pytest.fixture
def db(tmp_path):
    d = AssetsDB(tmp_path / "customer.db")
    d.initialize()
    return d


def test_orchestrator_picks_ip_lineup_for_ip_seed(db):
    """When seed is an IP, orchestrator MUST include pivot sources."""
    c = Customer.new("Acme", "203.0.113.5", ConsentMethod.LAB_SELF, None)
    db.create_customer(c)
    db.mark_consent_verified(c.customer_id)

    # Inject neutered sources so we can observe lineup without real network
    orch = AttackSurfaceMap(db=db, sources=None)  # auto-pick
    lineup = orch._lineup_for("ip")
    names = [s.name for s in lineup]
    assert "ip_whois" in names
    assert "reverse_dns" in names
    assert "tls_cert" in names
    assert "ct_logs.crtsh" in names
    assert "dns_resolve" in names
    assert "asn.cymru" in names


def test_orchestrator_picks_domain_lineup_for_domain_seed(db):
    orch = AttackSurfaceMap(db=db, sources=None)
    lineup = orch._lineup_for("domain")
    names = [s.name for s in lineup]
    # Pivot-only sources should NOT appear for domain seeds
    assert "ip_whois" not in names
    assert "reverse_dns" not in names
    # Forward sources should
    assert "ct_logs.crtsh" in names
    assert "dns_resolve" in names


def test_orchestrator_ip_first_pivot_chain_to_forward(db, tmp_path):
    """Full IP-first pipeline with all sources mocked — proves the chain:
    IP whois → reverse_dns → tls_cert → ct_logs → dns_resolve."""
    c = Customer.new("Acme", "203.0.113.5", ConsentMethod.LAB_SELF, None)
    db.create_customer(c)
    db.mark_consent_verified(c.customer_id)

    # ── Fake source implementations ────────────────────────────────

    def fake_whois_query(ip, host, timeout):
        assert ip == "203.0.113.5"
        return "OrgName: Acme Corp\nComment: https://www.acme.com"

    def fake_ptr(ip, resolver, timeout):
        return {"203.0.113.5": "mail.acme.com"}.get(ip)

    def fake_tls_probe(ip, **kwargs):
        return _fake_cert(ip, ["acme.com", "api.acme.com", "*.acme.com"])

    def fake_crtsh_get(url, timeout):
        assert "acme.com" in url
        return b'[{"id": 1, "name_value": "api.acme.com\\nstaging.acme.com"}]'

    def fake_dns_resolve(hostname, resolver, timeout):
        return {
            "acme.com":         ["203.0.113.5"],
            "api.acme.com":     ["203.0.113.10"],
            "mail.acme.com":    ["203.0.113.5"],
            "staging.acme.com": ["203.0.113.20"],
            "www.acme.com":     ["203.0.113.5"],
        }.get(hostname, [])

    def fake_cymru(ips, timeout):
        return [{"asn": "64496", "ip": ip, "prefix": "203.0.113.0/24",
                 "cc": "US", "registry": "arin", "allocated": "2020",
                 "as_name": "ACME-CORP"} for ip in ips]

    sources = [
        IPWHOISSource(query_fn=fake_whois_query),
        ReverseDNSSource(ptr_fn=fake_ptr),
        TLSCertSource(probe_fn=fake_tls_probe),
        CertTransparencyLogs(http_get=fake_crtsh_get),
        DNSResolveSource(resolver_fn=fake_dns_resolve),
        ASNEnrichmentSource(connect_fn=fake_cymru),
    ]
    orch = AttackSurfaceMap(db=db, sources=sources)
    result = orch.run(c)

    # Verify seed type detected correctly
    assert result.seed_type == "ip"

    # Verify chain worked: TLS cert SANs + CT logs + reverse DNS all landed
    counts = result.by_kind()
    assert counts.get("domain", 0) >= 1     # acme.com
    assert counts.get("subdomain", 0) >= 3  # api, staging, mail, www
    assert counts.get("ipv4", 0) >= 1
    assert counts.get("asn", 0) >= 1
    assert counts.get("netblock", 0) >= 1
    assert counts.get("cert", 0) == 1       # one TLS cert harvested

    # Completeness report exists and contains pivot notes
    assert result.completeness is not None
    assert result.completeness.seed_type == "ip"
    rendered = result.completeness.render()
    assert "Pivot" in rendered
    # Pivot succeeded → should include an "ok" note about hostnames discovered
    assert any("hostnames" in n.message.lower() or "cert" in n.message.lower()
               for n in result.completeness.pivot_notes)


def test_orchestrator_completeness_report_flags_cdn_skip(db):
    """CDN IP → completeness report notes the cert pivot was skipped."""
    c = Customer.new("Acme", "104.16.1.1", ConsentMethod.LAB_SELF, None)  # cloudflare
    db.create_customer(c)
    db.mark_consent_verified(c.customer_id)

    def fake_whois(ip, host, timeout):
        return "OrgName: Cloudflare Inc"

    def fake_ptr(ip, resolver, timeout):
        return None

    def probe_must_not_run(*a, **kw):
        pytest.fail("TLS probe must not fire on Cloudflare IP")

    sources = [
        IPWHOISSource(query_fn=fake_whois),
        ReverseDNSSource(ptr_fn=fake_ptr),
        TLSCertSource(probe_fn=probe_must_not_run),
    ]
    orch = AttackSurfaceMap(db=db, sources=sources)
    result = orch.run(c)

    # Completeness should note the CDN skip
    rendered = result.completeness.render()
    assert "cdn" in rendered.lower() or "cloudflare" in rendered.lower() or \
           "skipped" in rendered.lower()


def test_orchestrator_continues_despite_whois_failure(db):
    """A failing whois query shouldn't stop later sources from running."""
    c = Customer.new("Acme", "203.0.113.5", ConsentMethod.LAB_SELF, None)
    db.create_customer(c)
    db.mark_consent_verified(c.customer_id)

    def broken_whois(*a, **kw):
        raise ConnectionError("whois.arin.net unreachable")

    def good_ptr(ip, resolver, timeout):
        return "api.acme.com"

    sources = [
        IPWHOISSource(query_fn=broken_whois),
        ReverseDNSSource(ptr_fn=good_ptr),
    ]
    orch = AttackSurfaceMap(db=db, sources=sources)
    result = orch.run(c)

    # reverse_dns still ran and produced the subdomain
    assert result.by_kind().get("subdomain", 0) >= 1
