"""Tests for argos/chain — exploit chain reasoner."""

from __future__ import annotations

import pytest

from amoskys.agents.Web.argos.adapt import ArchitectureProfile
from amoskys.agents.Web.argos.chain import (
    ChainFinding, ChainReport, ExploitChain,
    ChainReasoner, reason_chains,
)


# helpers --------------------------------------------------------------


def _prof(**kw):
    base = dict(target_url="https://t/", target_host="t")
    base.update(kw)
    return ArchitectureProfile(**base)


def _f(kind, loc="/", sev="medium", ev="", **meta):
    return ChainFinding(kind=kind, location=loc, severity=sev, evidence=ev, metadata=meta)


# data model -----------------------------------------------------------


def test_chain_finding_to_dict():
    f = _f("sqli", "/?id=", "high", "SLEEP(5)=5.1s")
    d = f.to_dict()
    assert d["kind"] == "sqli" and d["severity"] == "high"
    assert "SLEEP(5)" in d["evidence"]


def test_empty_findings_returns_empty_report():
    rep = reason_chains([], profile=_prof())
    assert rep.chains == []
    assert rep.unchained == []
    assert rep.max_severity == "low"


# individual rules -----------------------------------------------------


def test_ssrf_to_imds_rule_fires_with_aws_evidence():
    prof = _prof(waf_names=[], database="mysql")
    rep = reason_chains([
        _f("ssrf", "/fetch", "medium", "169.254.169.254 returned IAM creds"),
    ], profile=prof)
    names = [c.name for c in rep.chains]
    assert any("IMDS" in n for n in names)


def test_ssrf_alone_without_cloud_hint_does_not_fire_imds():
    prof = _prof()
    rep = reason_chains([
        _f("ssrf", "/fetch", "medium", "internal host 10.0.0.5 reachable"),
    ], profile=prof)
    # No IMDS chain, but ssrf remains unchained
    assert all("IMDS" not in c.name for c in rep.chains)


def test_lfi_to_wpconfig_requires_wordpress_framework():
    wp = _prof(framework="wordpress")
    non_wp = _prof(framework="drupal")
    lfi = [_f("lfi", "/?page=", "high", "wp-config.php base64 leaked")]
    rep_wp = reason_chains(lfi, profile=wp)
    rep_nonwp = reason_chains(lfi, profile=non_wp)
    assert any("wp-config" in c.name for c in rep_wp.chains)
    assert all("wp-config" not in c.name for c in rep_nonwp.chains)


def test_rest_authz_to_admin_fires_unconditionally():
    rep = reason_chains([_f("rest_authz", "/wp-json/x/y", "high", "perm_cb missing")])
    assert any("Unauth REST" in c.name for c in rep.chains)


def test_upload_plus_lfi_chains_to_rce():
    rep = reason_chains([
        _f("file_upload", "/upload", "high", "jpg polyglot accepted"),
        _f("lfi", "/read", "high", "include arbitrary path"),
    ])
    rce = [c for c in rep.chains if "upload" in c.name.lower() and "LFI" in c.name]
    assert rce
    assert rce[0].severity == "critical"
    assert len(rce[0].links) == 2


def test_csrf_on_admin_endpoint_escalates():
    rep = reason_chains([_f("csrf", "/wp-admin/options.php", "medium", "no nonce")])
    assert any("CSRF" in c.name for c in rep.chains)


def test_csrf_on_nonprivileged_endpoint_does_not_fire():
    rep = reason_chains([_f("csrf", "/comment", "low", "no nonce")])
    assert all("CSRF" not in c.name for c in rep.chains)


def test_info_leak_plus_injection_escalates_severity():
    rep = reason_chains([
        _f("verbose_errors", "/?d=1", "low", "mysql stack trace"),
        _f("sqli", "/?id=", "high", "union-based confirmed"),
    ])
    combo = [c for c in rep.chains if "Info leak" in c.name]
    assert combo
    # Base sqli is 'high'; combo should be 'critical'
    assert combo[0].severity == "critical"


def test_smuggling_plus_waf_fires_when_waf_present():
    prof = _prof(waf_names=["Cloudflare"])
    rep = reason_chains([_f("smuggling", "/", "high", "CL.TE timing anomaly 3s")],
                        profile=prof)
    assert any("smuggling" in c.name.lower() or "Smuggl" in c.name for c in rep.chains)


def test_smuggling_without_waf_does_not_fire_that_rule():
    prof = _prof(waf_names=[])
    rep = reason_chains([_f("smuggling", "/", "high", "anomaly")], profile=prof)
    assert all("smuggling" not in c.name.lower() and "WAF" not in c.name for c in rep.chains)


def test_cdn_bypass_plus_verbose_origin_fires():
    prof = _prof(waf_names=["Cloudflare"], cdn_name="cloudflare", verbose_errors=True)
    rep = reason_chains([_f("cdn_bypass", "203.0.113.1", "high", "direct IP reached")],
                        profile=prof)
    assert any("CDN bypass" in c.name for c in rep.chains)


def test_poi_plus_rce_creates_gadget_chain_link():
    rep = reason_chains([
        _f("poi", "/?data=", "high", "unserialize() reachable"),
        _f("rce", "/exec", "critical", "system() gadget found"),
    ])
    poi_chain = [c for c in rep.chains if "PHP object" in c.name]
    assert poi_chain
    assert len(poi_chain[0].links) == 2


# ranking + narrative + report shape -----------------------------------


def test_chains_ranked_by_severity_then_cvss():
    prof = _prof(framework="wordpress")
    rep = reason_chains([
        _f("rest_authz", "/wp-json/x/y", "high", "perm_cb missing"),
        _f("sqli", "/?id=", "high", "union confirmed"),
    ], profile=prof)
    # rest_authz (9.1 critical) should rank ahead of sqli blind (8.5 high)
    assert rep.chains[0].cvss_estimate >= rep.chains[-1].cvss_estimate


def test_narrative_contains_concrete_steps():
    rep = reason_chains([_f("rest_authz", "/wp-json/plug/update", "high", "perm_cb missing")])
    ch = rep.chains[0]
    assert "1." in ch.narrative
    assert "2." in ch.narrative
    assert ch.business_impact   # non-empty string


def test_unchained_findings_tracked():
    # info_leak alone — no injection to pair with → unchained
    rep = reason_chains([_f("verbose_errors", "/?d=1", "low", "stack trace")])
    assert any(f.kind == "verbose_errors" for f in rep.unchained)


def test_report_to_dict_json_safe():
    import json
    rep = reason_chains([
        _f("rest_authz", "/wp-json/x/y", "high"),
        _f("sqli", "/?id=", "high", "union"),
    ])
    json.dumps(rep.to_dict())


def test_max_severity_derivation_from_chains():
    rep = reason_chains([
        _f("rest_authz", "/wp-json/x/y", "high"),
    ])
    assert rep.max_severity == "critical"


def test_three_plus_chains_attaches_synergy_note():
    prof = _prof(waf_names=["Cloudflare"], cdn_name="cloudflare",
                 framework="wordpress", verbose_errors=True)
    rep = reason_chains([
        _f("lfi", "/?page=", "high", "wp-config leaked"),
        _f("file_upload", "/upload", "high", "jpg polyglot"),
        _f("rest_authz", "/wp-json/x/y", "high", "perm_cb missing"),
        _f("smuggling", "/", "high", "CL.TE"),
    ], profile=prof)
    assert any("independent chains" in n for n in rep.notes)


def test_reason_does_not_crash_on_broken_rule(monkeypatch):
    """Synthetic broken rule; other rules still produce output."""
    from amoskys.agents.Web.argos.chain import reasoner

    def _broken(_findings, _profile):
        raise RuntimeError("kaboom")

    monkeypatch.setitem(reasoner.__dict__, "CHAIN_RULES",
                        [("broken_rule", _broken, 50),
                         ("rest_authz_to_admin", reasoner._rule_rest_authz_to_admin, 85)])
    rep = ChainReasoner().reason([_f("rest_authz", "/wp-json/x/y", "high")])
    assert any("broken_rule" in n and "kaboom" in n for n in rep.notes)
    assert any("Unauth REST" in c.name for c in rep.chains)
