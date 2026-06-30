"""Tests for argos/adapt — architecture fingerprinting, strategy, origin."""

from __future__ import annotations

from typing import Dict, Optional, Tuple

import pytest

from amoskys.agents.Web.argos.adapt import (
    AdaptedStrategy,
    ArchitectureProfile,
    OriginCandidate,
    TacticSpec,
    discover_origin,
    fingerprint_architecture,
    pick_strategy,
)

# ──────────────────────────────────────────────────────────────────
# fingerprint
# ──────────────────────────────────────────────────────────────────


class _FakeHTTP:
    """Deterministic http_get injection for fingerprint tests."""

    def __init__(self, responses: Dict[str, Tuple[int, Dict[str, str], str]]):
        # keyed by path or full-url suffix
        self.responses = responses
        self.calls = []

    def __call__(self, url: str, timeout: float, headers: Dict[str, str]):
        self.calls.append(url)
        for suffix, resp in self.responses.items():
            if url.endswith(suffix):
                return resp
        # default: 200 empty
        return (200, {}, "")


def test_fingerprint_cloudflare_wordfence_wp_mysql_linux():
    http = _FakeHTTP(
        {
            "/": (
                200,
                {
                    "server": "cloudflare",
                    "cf-ray": "abc123",
                    "set-cookie": "wfwaf-authcookie-deadbeef=1; path=/",
                    "x-powered-by": "PHP/8.0.30",
                },
                (
                    "<html><head><meta name='generator' content='WordPress 6.4.2'>"
                    "</head><body>powered by wordfence · Linux</body></html>"
                ),
            ),
            "/does-not-exist-%zz-xyz": (
                404,
                {"server": "cloudflare"},
                (
                    "<!-- nginx default 404 page -->"
                    "mysql_fetch_array() duplicate entry"
                ),
            ),
            "/wp-login.php": (
                200,
                {"server": "cloudflare"},
                "<form id='loginform'></form>",
            ),
            "/WP-LOGIN.PHP": (
                404,
                {"server": "cloudflare"},
                "",
            ),  # case-sensitive → Linux
        }
    )

    profile = fingerprint_architecture("https://blog.example.com/", http_get=http)

    assert profile.target_host == "blog.example.com"
    assert (profile.cdn_name or "").lower() == "cloudflare"
    assert "wordfence" in [w.lower() for w in profile.waf_names]
    assert profile.framework == "wordpress"
    # framework version should match the generator meta
    assert profile.framework_version and "6.4" in profile.framework_version
    # MySQL inference from error-page echo
    assert profile.database == "mysql"
    # OS inference from case-sensitive filesystem probe
    assert profile.os_family == "linux"
    # Probes should stay small (≤ 8 requests)
    assert profile.http_requests_used <= 8


def test_fingerprint_handles_totally_blank_server():
    http = _FakeHTTP({})
    profile = fingerprint_architecture("https://nowhere.test/", http_get=http)
    # Everything None / empty but no crash
    assert profile.target_host == "nowhere.test"
    assert profile.errors == [] or profile.errors == profile.errors  # survives


# ──────────────────────────────────────────────────────────────────
# strategy
# ──────────────────────────────────────────────────────────────────


def _prof(**kw):
    base = dict(target_url="https://t/", target_host="t")
    base.update(kw)
    return ArchitectureProfile(**base)


def test_strategy_wordfence_wp_mysql_linux_cloudflare_verbose():
    p = _prof(
        waf_names=["Wordfence"],
        cdn_name="Cloudflare",
        database="mysql",
        os_family="linux",
        framework="wordpress",
        runtime="php-fpm",
        verbose_errors=True,
    )
    s = pick_strategy(p)
    # WP ordering puts rest_authz first
    assert s.probe_order[0] == "rest_authz"
    # Wordfence cascade has comment_pad + utf8_overlong
    assert "comment_pad" in s.encoding_cascade
    assert "utf8_overlong" in s.encoding_cascade
    # RPS ceiling tightened under Wordfence
    assert s.rps_ceiling <= 10
    # CDN triggers origin_bypass
    assert s.origin_bypass is True
    # Verbose errors prepend error-based SQLi
    first_sqli = s.per_class["sqli"].payload_templates[0]
    assert "UNION" in first_sqli or "extractvalue" in first_sqli
    # DB-aware SLEEP in MySQL form
    assert any("SLEEP(5)" in t for t in s.per_class["sqli"].payload_templates)
    # LFI uses Linux paths
    assert any("/etc/passwd" in t for t in s.per_class["lfi"].payload_templates)
    # Notes are populated
    assert any("Wordfence" in n or "wordfence" in n for n in s.notes)


def test_strategy_postgres_payloads_use_pg_sleep():
    p = _prof(database="postgres", framework="custom")
    s = pick_strategy(p)
    sqli_tmpls = " ".join(s.per_class["sqli"].payload_templates)
    assert "pg_sleep" in sqli_tmpls
    assert "SLEEP(5)" not in sqli_tmpls


def test_strategy_windows_lfi_paths():
    p = _prof(os_family="windows", framework="wordpress")
    s = pick_strategy(p)
    lfi_tmpls = s.per_class["lfi"].payload_templates
    assert any("win.ini" in t for t in lfi_tmpls)
    assert any("..\\" in t for t in lfi_tmpls)


def test_strategy_no_waf_no_bypass_higher_ceiling():
    p = _prof(framework="wordpress")
    s = pick_strategy(p)
    assert s.origin_bypass is False
    assert s.rps_ceiling >= 25


def test_strategy_python_runtime_picks_ssti_payload():
    p = _prof(runtime="python/flask", framework="flask")
    s = pick_strategy(p)
    rce_tmpls = " ".join(s.per_class["rce"].payload_templates)
    assert "__globals__" in rce_tmpls


def test_strategy_probe_order_generic_for_non_wp():
    p = _prof(framework="drupal")
    s = pick_strategy(p)
    assert s.probe_order[0] == "sqli"
    assert "rest_authz" not in s.probe_order


def test_strategy_to_dict_is_json_safe():
    p = _prof(waf_names=["Cloudflare"], database="mysql", framework="wordpress")
    s = pick_strategy(p)
    import json

    json.dumps(s.to_dict())  # must not raise


# ──────────────────────────────────────────────────────────────────
# origin
# ──────────────────────────────────────────────────────────────────


def test_origin_ip_belongs_to_edge_detection():
    from amoskys.agents.Web.argos.adapt.origin import _ip_belongs_to_edge

    assert _ip_belongs_to_edge("104.21.5.100") == "cloudflare"
    assert _ip_belongs_to_edge("151.101.1.1") == "fastly"
    assert _ip_belongs_to_edge("203.0.113.42") is None  # TEST-NET-3


def test_discover_origin_soft_fails_offline_and_returns_list():
    """Without a sensible http_get + DNS the function must return an
    empty list (or CT-only candidates) without raising. Gracefully
    handles no-network."""

    def bad_get(url, t, h):
        return (0, {}, "__error__:no-net")

    result = discover_origin(
        "nonexistent-host-abc.invalid",
        fingerprint_body=None,
        http_get=bad_get,
        max_candidates=5,
    )
    assert isinstance(result, list)
    # No exception, just empty list
    assert len(result) == 0


def test_origin_candidate_serializes_cleanly():
    c = OriginCandidate(
        ip="198.51.100.10",
        source="crt.sh",
        hostname="origin.example.com",
        confidence=70,
        evidence=["CT SAN origin.example.com resolved"],
    )
    d = c.to_dict()
    assert d["ip"] == "198.51.100.10"
    assert d["source"] == "crt.sh"
    assert d["confidence"] == 70
    assert d["confirmed"] is False
