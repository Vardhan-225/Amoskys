"""Unit tests for the prospecting suite (CT discovery, WP indicator,
scoring, orchestrator)."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from amoskys.agents.Web.argos.prospecting import (
    Prospect,
    WPIndicatorResult,
    check_wp_indicator,
    discover_domains_via_ct,
    find_wp_prospects,
    score_prospect,
)
from amoskys.agents.Web.argos.prospecting.ct_discovery import (
    _registered_domain,
)


# ── CT discovery ──────────────────────────────────────────────────


def test_registered_domain_simple():
    assert _registered_domain("www.example.com") == "example.com"
    assert _registered_domain("blog.shop.example.com") == "example.com"
    assert _registered_domain("example.com") == "example.com"


def test_registered_domain_multi_suffix():
    assert _registered_domain("shop.example.co.uk") == "example.co.uk"
    assert _registered_domain("api.example.com.au") == "example.com.au"


def test_registered_domain_strips_wildcards():
    assert _registered_domain("*.example.com") == "example.com"


def test_ct_discovery_parses_crtsh_json():
    body = json.dumps([
        {"common_name": "www.acme.com", "name_value": "www.acme.com\nacme.com"},
        {"common_name": "blog.widget.io", "name_value": "blog.widget.io"},
        {"common_name": "",   "name_value": "other.example.net"},
    ])
    res = discover_domains_via_ct("acme", http_get=lambda url: body)
    assert res.raw_count == 3
    assert "acme.com" in res.unique_domains
    assert "widget.io" in res.unique_domains
    assert "example.net" in res.unique_domains
    # No email CNs or whitespace entries leaked in.
    assert all(" " not in d for d in res.unique_domains)


def test_ct_discovery_handles_empty_body():
    res = discover_domains_via_ct("xxx", http_get=lambda url: None)
    assert res.raw_count == 0
    assert res.unique_domains == []
    assert len(res.errors) == 1


def test_ct_discovery_handles_malformed_json():
    res = discover_domains_via_ct("xxx", http_get=lambda url: "not json")
    assert res.raw_count == 0
    assert res.errors


# ── WP indicator ──────────────────────────────────────────────────


def _fake_http(route_map):
    """Build a fake http_fetch function from a {path: (status, headers, body)} map."""
    def _fn(url, headers):
        from urllib.parse import urlparse
        path = urlparse(url).path or "/"
        return route_map.get(path, (404, {}, ""))
    return _fn


def test_wp_indicator_detects_wordpress_via_rest_link():
    body = ('<html><head>'
            '<link rel="https://api.w.org/" href="https://x.com/wp-json/" />'
            '</head><body></body></html>')
    http = _fake_http({"/": (200, {"server": "nginx"}, body)})
    r = check_wp_indicator("x.com", http_fetch=http)
    assert r.is_wordpress is True
    assert r.wp_confidence >= 40


def test_wp_indicator_detects_wordpress_via_generator_meta():
    body = ('<html><head><meta name="generator" content="WordPress 6.4.1"/>'
            '</head><body></body></html>')
    http = _fake_http({"/": (200, {}, body)})
    r = check_wp_indicator("x.com", http_fetch=http)
    assert r.is_wordpress is True
    assert r.wp_version_hint == "6.4.1"
    assert r.wp_generator_exposed is True


def test_wp_indicator_extracts_plugin_slugs():
    body = """<html>
<link href='/wp-content/plugins/contact-form-7/foo.css?ver=5.7.5' rel='stylesheet'/>
<script src='/wp-content/plugins/woocommerce/bar.js?ver=8.0.2'></script>
</html>"""
    http = _fake_http({"/": (200, {}, body)})
    r = check_wp_indicator("x.com", http_fetch=http)
    assert r.is_wordpress is True
    assert "contact-form-7@5.7.5" in r.plugin_slugs_in_html
    assert "woocommerce@8.0.2" in r.plugin_slugs_in_html
    assert r.plugin_inventory_leaks == 2


def test_wp_indicator_not_wordpress():
    body = '<html><body>some static site</body></html>'
    http = _fake_http({"/": (200, {}, body)})
    r = check_wp_indicator("x.com", http_fetch=http)
    assert r.is_wordpress is False
    assert r.wp_confidence == 0


def test_wp_indicator_flags_bug_bounty():
    body = ('<html><body>See our bug bounty program on '
            '<a href="https://hackerone.com/acme">HackerOne</a></body></html>')
    http = _fake_http({"/": (200, {}, body)})
    r = check_wp_indicator("acme.com", http_fetch=http)
    assert r.on_bug_bounty is True
    assert r.bounty_evidence


def test_wp_indicator_reads_security_txt():
    http = _fake_http({
        "/": (200, {}, '<html><meta name="generator" content="WordPress 6.4"></html>'),
        "/.well-known/security.txt": (200, {},
            "Contact: mailto:security@acme.com\n"
            "Policy: https://acme.com/security\n"),
    })
    r = check_wp_indicator("acme.com", http_fetch=http)
    assert r.has_security_txt is True
    assert any("security@acme.com" in c for c in r.contact_hints)


def test_wp_indicator_extracts_mailto_from_homepage():
    body = ('<html><body>Contact us at '
            '<a href="mailto:hello@acme.com">hello@acme.com</a></body></html>')
    http = _fake_http({"/": (200, {}, body)})
    r = check_wp_indicator("acme.com", http_fetch=http)
    assert "hello@acme.com" in r.contact_hints


def test_wp_indicator_detects_cdn():
    http = _fake_http({
        "/": (200, {"cf-ray": "abc-DFW", "server": "cloudflare"},
              '<html><meta name="generator" content="WordPress 6.4"/></html>'),
    })
    r = check_wp_indicator("x.com", http_fetch=http)
    assert r.uses_cdn is True
    assert r.cdn_name == "Cloudflare"


def test_wp_indicator_always_uses_at_most_two_http_requests():
    # The stealth contract: at most 2 GETs per candidate.
    http = _fake_http({"/": (200, {}, "<html></html>")})
    r = check_wp_indicator("x.com", http_fetch=http)
    assert r.http_requests_used <= 2


# ── Scoring ──────────────────────────────────────────────────────


def test_score_not_wordpress_drops_to_zero():
    ind = WPIndicatorResult(host="x.com", is_wordpress=False)
    p = score_prospect(ind)
    assert p.score == 0
    assert "Not WordPress" in p.why_this_score


def test_score_high_quality_prospect():
    ind = WPIndicatorResult(
        host="acme.com",
        is_wordpress=True, wp_confidence=100,
        wp_version_hint="5.8.0",  # older than 6.9 → old-signal bonus
        wp_generator_exposed=True,
        plugin_slugs_in_html=["a@1", "b@2", "c@3"],
        plugin_inventory_leaks=3,
        has_security_txt=True,
        contact_hints=["mailto:sec@acme.com"],
        on_bug_bounty=False,
        uses_cdn=False,
    )
    p = score_prospect(ind)
    # wp_confirmed(30) + contact(20) + sectxt(15) + plugin_leak(15) +
    # generator(5) + old_version(10) + no_cdn_bonus(5) = 100
    assert p.score == 100
    assert "wp_confirmed" in p.breakdown
    assert "security_txt_present" in p.breakdown
    assert "plugin_inventory_leak" in p.breakdown


def test_score_bug_bounty_kills_score():
    ind = WPIndicatorResult(
        host="acme.com", is_wordpress=True, wp_confidence=100,
        contact_hints=["mailto:sec@acme.com"],
        on_bug_bounty=True, bounty_evidence="via security.txt Policy",
    )
    p = score_prospect(ind)
    # wp_confirmed(30) + contact(20) + bug_bounty(-60) = -10 → clamped to 0
    assert p.score == 0
    assert p.on_bug_bounty is True
    assert "bug_bounty_PENALTY" in p.breakdown


def test_score_enterprise_cdn_penalty():
    ind = WPIndicatorResult(
        host="acme.com", is_wordpress=True, wp_confidence=100,
        contact_hints=["hi@acme.com"],
        uses_cdn=True, cdn_name="Akamai",
    )
    p = score_prospect(ind)
    # Should apply the enterprise-CDN penalty.
    assert p.breakdown.get("enterprise_cdn_PENALTY") == -15


def test_score_why_this_score_populated():
    ind = WPIndicatorResult(
        host="acme.com", is_wordpress=True, wp_confidence=100,
        contact_hints=["hi@acme.com"],
    )
    p = score_prospect(ind)
    assert p.why_this_score  # narrative text is populated


# ── Orchestrator ──────────────────────────────────────────────────


def test_find_wp_prospects_skips_excluded_domains():
    """wordpress.org, automattic.com, .gov etc. MUST be filtered out."""
    # crt.sh returns a mix of excluded + not-excluded.
    body = json.dumps([
        {"common_name": "example.com", "name_value": "example.com"},
        {"common_name": "wordpress.org", "name_value": "wordpress.org"},
        {"common_name": "nsa.gov", "name_value": "nsa.gov"},
        {"common_name": "hackerone.com", "name_value": "hackerone.com"},
        {"common_name": "widget.com", "name_value": "widget.com"},
    ])
    http_indicator = _fake_http({
        "/": (200, {}, '<html><meta name="generator" content="WordPress 6.9"/></html>'),
        "/.well-known/security.txt": (200, {}, "Contact: mailto:s@x.com\n"),
    })
    run = find_wp_prospects(
        "seed",
        want=5,
        min_score=0,
        http_get_crtsh=lambda url: body,
        http_fetch_indicator=http_indicator,
        pacing_s=0.001,
    )
    hosts = {p.host for p in run.prospects}
    assert "wordpress.org" not in hosts
    assert "nsa.gov" not in hosts
    assert "hackerone.com" not in hosts
    # Clean domains passed through.
    assert "example.com" in hosts or "widget.com" in hosts


def test_find_wp_prospects_drops_non_wordpress():
    body = json.dumps([{"common_name": "static.com", "name_value": "static.com"}])
    http_indicator = _fake_http({"/": (200, {}, '<html><body>static</body></html>')})
    run = find_wp_prospects(
        "seed", want=5, min_score=0,
        http_get_crtsh=lambda url: body,
        http_fetch_indicator=http_indicator,
        pacing_s=0.001,
    )
    assert run.prospects == []
    assert any("not WordPress" in s for s in run.skipped)


def test_find_wp_prospects_ranks_by_score():
    # Two candidates; one with more signals should score higher.
    body = json.dumps([
        {"common_name": "plain.com",   "name_value": "plain.com"},
        {"common_name": "leaky.com",   "name_value": "leaky.com"},
    ])
    # Different HTTP behavior per host — we use url path; host is in URL.
    def http_fetch(url, headers):
        host = url.split("://", 1)[1].split("/", 1)[0]
        from urllib.parse import urlparse
        path = urlparse(url).path or "/"
        if host == "plain.com":
            routes = {
                "/": (200, {}, '<html><meta name="generator" content="WordPress 6.9"></html>'),
                "/.well-known/security.txt": (404, {}, ""),
            }
        else:  # leaky.com
            routes = {
                "/": (200, {}, """<html><meta name="generator" content="WordPress 5.1"/>
<link href='/wp-content/plugins/a/x.css?ver=1.0' rel='stylesheet'/>
<link href='/wp-content/plugins/b/x.css?ver=1.0' rel='stylesheet'/>
<link href='/wp-content/plugins/c/x.css?ver=1.0' rel='stylesheet'/>
<a href='mailto:hi@leaky.com'>contact</a></html>"""),
                "/.well-known/security.txt": (200, {}, "Contact: mailto:s@leaky.com\n"),
            }
        return routes.get(path, (404, {}, ""))

    run = find_wp_prospects(
        "seed", want=5, min_score=10,
        http_get_crtsh=lambda url: body,
        http_fetch_indicator=http_fetch,
        pacing_s=0.001,
    )
    # Both should qualify; leaky.com should rank HIGHER.
    hosts = [p.host for p in run.prospects]
    assert "leaky.com" in hosts
    leaky_p = next(p for p in run.prospects if p.host == "leaky.com")
    if "plain.com" in hosts:
        plain_p = next(p for p in run.prospects if p.host == "plain.com")
        assert leaky_p.score > plain_p.score


def test_find_wp_prospects_filters_by_min_score():
    body = json.dumps([{"common_name": "weak.com", "name_value": "weak.com"}])
    http_indicator = _fake_http({
        # Just enough to qualify as WP, but nothing else — no contact, no sectxt.
        "/": (200, {}, '<html><meta name="generator" content="WordPress"/></html>'),
        "/.well-known/security.txt": (404, {}, ""),
    })
    run = find_wp_prospects(
        "seed", want=5, min_score=80,  # high bar
        http_get_crtsh=lambda url: body,
        http_fetch_indicator=http_indicator,
        pacing_s=0.001,
    )
    assert run.prospects == []


def test_find_wp_prospects_run_to_dict_shape():
    run = find_wp_prospects(
        "seed", want=5,
        http_get_crtsh=lambda url: "[]",  # empty
        pacing_s=0.001,
    )
    d = run.to_dict()
    assert d["seed"] == "seed"
    assert "ct_domains_seen" in d
    assert "prospects" in d
    assert "skipped_count" in d
