"""Tests for argos/evasion — encoding, mutation, WAF FP, statistics, session."""

from __future__ import annotations

import math
import random
import re
import urllib.parse
from unittest.mock import MagicMock, patch

import pytest

from amoskys.agents.Web.argos.evasion import (
    StatSample, StealthSession, TimingExperiment,
    available_encoders, b64, case_mutate, comment_pad, compose,
    fingerprint_waf, hex_escape, html_entity, lfi_variants, null_byte_after,
    recommend_bypass_layers, rce_variants,
    sql_keyword_obfuscate, sqli_variants, url, url2, url_unicode,
    utf8_overlong, welch_t_test, whitespace_mutate, xss_variants,
)


# ──────────────────────────────────────────────────────────────────
# encode
# ──────────────────────────────────────────────────────────────────


def test_url_basic():
    assert url("a b") == "a%20b"


def test_url2_is_double_encoded():
    raw = "'"
    once = url(raw)                  # %27
    twice = url2(raw)                # %2527
    assert once == "%27"
    assert twice == "%2527"
    # Decoding once should give %27, not the literal '.
    assert urllib.parse.unquote(twice) == once


def test_utf8_overlong_encodes_quote():
    r = utf8_overlong("'")
    # ' = 0x27; overlong 2-byte = %C0%A7
    assert r == "%C0%A7"


def test_url_unicode_format():
    r = url_unicode("A")
    assert r == "%u0041"


def test_html_entity_decimal_hex():
    assert html_entity("<>") == "&#60;&#62;"


def test_hex_escape_basic():
    assert hex_escape("A") == r"\x41"


def test_b64_round_trip():
    import base64
    original = "SELECT * FROM users"
    assert base64.b64decode(b64(original)).decode() == original


def test_case_mutate_changes_case():
    rng = random.Random(0)
    out = case_mutate("SELECT", rng=rng)
    # Should be mixed-case for this seed.
    assert out != "SELECT" and out != "select"
    # Must still have same letters.
    assert out.lower() == "select"


def test_comment_pad_inserts_comment():
    assert comment_pad("UNION SELECT") == "UNION/**/SELECT"


def test_sql_keyword_obfuscate_wraps_keywords():
    r = sql_keyword_obfuscate("UNION SELECT * FROM users")
    assert "/*!50000UNION*/" in r
    assert "/*!50000SELECT*/" in r


def test_whitespace_mutate_preserves_meaning():
    rng = random.Random(0)
    out = whitespace_mutate("SELECT 1 FROM users", rng=rng)
    # At least one whitespace char replaced.
    assert out != "SELECT 1 FROM users"
    # But alpha tokens preserved.
    assert "SELECT" in out
    assert "users" in out


def test_null_byte_after_with_marker():
    r = null_byte_after("/etc/passwd.txt", marker=".")
    assert r == "/etc/passwd%00.txt"


def test_compose_applies_in_order():
    f = compose(["case", "url"])
    out = f("AB")
    # After case: 2-char mixed case; after url: encodes nothing really since
    # letters are safe. Assert the output is either "aB", "Ab", "ab", "AB".
    assert out.lower() == "ab"


def test_compose_unknown_layer_raises():
    with pytest.raises(KeyError):
        compose(["nonexistent"])


def test_available_encoders_is_non_empty():
    assert "url" in available_encoders()
    assert "url2" in available_encoders()
    assert "sql_keyword" in available_encoders()


# ──────────────────────────────────────────────────────────────────
# mutate
# ──────────────────────────────────────────────────────────────────


def test_sqli_variants_timing_mode_contains_sleep():
    variants = sqli_variants(mode="timing", max_variants=20, seed=1)
    assert variants
    assert any("SLEEP" in v.upper() or "pg_sleep" in v.lower() or "WAITFOR" in v.upper()
               for v in variants)


def test_sqli_variants_tautology_mode_contains_tautology():
    variants = sqli_variants(mode="tautology", max_variants=10, seed=1)
    # Some original tautologies plus encoded versions.
    assert any("1=1" in v or "1%3D1" in v or "'1'%3D'1'" in v or "OR" in v.upper()
               for v in variants)


def test_sqli_variants_max_count_respected():
    v = sqli_variants(mode="all", max_variants=5, seed=0)
    assert len(v) <= 5


def test_sqli_variants_no_destructive_keywords():
    # Rule of engagement: never produce a payload that drops/deletes data.
    variants = sqli_variants(mode="all", max_variants=100, seed=0)
    joined = " ".join(variants).upper()
    for danger in ("DROP TABLE", "DROP DATABASE", "DELETE FROM",
                   "TRUNCATE TABLE"):
        assert danger not in joined, f"forbidden keyword: {danger}"


def test_xss_variants_contains_script_or_svg():
    v = xss_variants(max_variants=20, seed=1)
    joined = " ".join(v).lower()
    assert any(needle in joined for needle in ("script", "svg", "iframe",
                                                "onerror", "alert"))


def test_lfi_variants_includes_traversal():
    v = lfi_variants(max_variants=30)
    joined = "\n".join(v)
    assert ".." in joined or "%2e%2e" in joined


def test_lfi_variants_includes_php_filter():
    v = lfi_variants(max_variants=30)
    assert any("php://filter" in x or "filter/" in x for x in v)


def test_rce_variants_no_destructive():
    v = rce_variants(max_variants=30)
    joined = " ".join(v).lower()
    # We only probe with 'id' or 'sleep'.
    for danger in ("rm -rf", "mkfs", "dd if=", ":() { :|:& };:"):
        assert danger not in joined, f"forbidden shell: {danger}"


# ──────────────────────────────────────────────────────────────────
# statistical
# ──────────────────────────────────────────────────────────────────


def test_welch_t_test_identical_samples_p_high():
    a = StatSample("a", [1.0, 1.0, 1.0, 1.0, 1.0])
    b = StatSample("b", [1.0, 1.0, 1.0, 1.0, 1.0])
    t, p = welch_t_test(a, b)
    assert p == 1.0
    assert t == 0.0


def test_welch_t_test_clear_difference_p_low():
    a = StatSample("a", [1.0, 1.1, 0.9, 1.05, 0.95, 1.02, 0.98, 1.01])
    b = StatSample("b", [5.0, 5.1, 4.9, 5.05, 4.95, 5.02, 4.98, 5.01])
    t, p = welch_t_test(a, b)
    assert p < 0.001
    assert t > 0


def test_welch_t_test_noisy_overlap_p_high():
    random.seed(42)
    a = StatSample("a", [random.gauss(1, 0.5) for _ in range(10)])
    b = StatSample("b", [random.gauss(1.05, 0.5) for _ in range(10)])
    t, p = welch_t_test(a, b)
    # 0.05 effect vs 0.5 stddev — no power, should be non-significant.
    assert p > 0.1


def test_welch_t_test_tiny_samples_safe():
    a = StatSample("a", [1.0])
    b = StatSample("b", [5.0])
    t, p = welch_t_test(a, b)
    assert p == 1.0  # insufficient data


def test_timing_experiment_detects_vuln_when_probe_slower():
    # Simulate: baseline ~1s, probe ~5s (SLEEP(4) would look like this).
    call_count = {"n": 0}
    def fire(is_probe: bool) -> float:
        call_count["n"] += 1
        random.seed(call_count["n"])
        if is_probe:
            return 5.0 + random.gauss(0, 0.1)
        return 1.0 + random.gauss(0, 0.1)
    expt = TimingExperiment(
        label="sleep4", n_samples=8, alpha=0.01, fire=fire,
    )
    r = expt.run()
    assert r["significant"]
    assert r["delta"] > 3.5
    assert r["p_value"] < 0.01


def test_timing_experiment_no_vuln_when_similar_timing():
    def fire(is_probe: bool) -> float:
        random.seed(random.random())
        return 1.0 + random.gauss(0, 0.1)
    expt = TimingExperiment(n_samples=8, alpha=0.01, fire=fire)
    r = expt.run()
    assert not r["significant"]


# ──────────────────────────────────────────────────────────────────
# waf_fingerprint
# ──────────────────────────────────────────────────────────────────


def test_fingerprint_cloudflare():
    hdr = {"Server": "cloudflare", "CF-RAY": "abc123-DFW"}
    fps = fingerprint_waf(hdr, "")
    assert fps
    assert fps[0].name == "Cloudflare"
    assert fps[0].confidence >= 50


def test_fingerprint_wordfence():
    hdr = {"Set-Cookie": "wfwaf-authcookie-abc=xyz; path=/"}
    body = "Wordfence firewall blocked your request"
    fps = fingerprint_waf(hdr, body)
    names = [f.name for f in fps]
    assert "Wordfence" in names


def test_fingerprint_sucuri():
    hdr = {"X-Sucuri-ID": "17002"}
    fps = fingerprint_waf(hdr, "")
    assert any(f.name == "Sucuri" for f in fps)


def test_fingerprint_stacked_detection():
    hdr = {"CF-RAY": "abc", "X-Sucuri-ID": "1"}
    fps = fingerprint_waf(hdr, "")
    names = {f.name for f in fps}
    assert "Cloudflare" in names
    assert "Sucuri" in names


def test_fingerprint_unknown_returns_empty():
    fps = fingerprint_waf({"Server": "nginx/1.24"}, "")
    assert fps == []


def test_recommend_bypass_layers_wordfence():
    layers = recommend_bypass_layers(["Wordfence"])
    assert "sql_keyword" in layers
    assert "utf8_overlong" in layers


def test_recommend_bypass_layers_unknown_falls_back():
    layers = recommend_bypass_layers([])
    assert layers                    # non-empty default stack
    assert "case" in layers


# ──────────────────────────────────────────────────────────────────
# session
# ──────────────────────────────────────────────────────────────────


def test_session_absorbs_cookies():
    # Build a session and call the internal cookie-absorb method.
    s = StealthSession("example.com")
    s._absorb_cookies({"set-cookie":
        "PHPSESSID=abc123; path=/; HttpOnly, wordpress_test_cookie=1; path=/"})
    assert s._cookies.get("PHPSESSID") == "abc123"
    assert s._cookies.get("wordpress_test_cookie") == "1"


def test_session_cookie_jar_survives_multi_calls():
    s = StealthSession("example.com")
    s._absorb_cookies({"set-cookie": "a=1; path=/"})
    s._absorb_cookies({"set-cookie": "b=2; path=/"})
    assert s._cookies == {"a": "1", "b": "2"}


def test_session_set_cookie_parser_handles_date_comma():
    # Set-Cookie can contain `; Expires=Wed, 20 Apr 2026 ...` — the comma
    # is NOT a cookie separator there.
    s = StealthSession("example.com")
    raw = "sess=xyz; Expires=Wed, 20 Apr 2026 10:00:00 GMT, other=val; path=/"
    s._absorb_cookies({"set-cookie": raw})
    assert "sess" in s._cookies
    assert "other" in s._cookies
    assert s._cookies["sess"] == "xyz"


def test_session_headers_keep_alive_and_referer_chain():
    s = StealthSession("example.com")
    # Before any request: first_nav=True, no last_url.
    h1 = s._base_headers("https://example.com/page1")
    assert h1.get("Connection") == "keep-alive"
    # Set the last_url (simulating one prior successful request).
    s._last_url = "https://example.com/home"
    s._first_nav = False
    h2 = s._base_headers("https://example.com/page2")
    assert h2.get("Referer") == "https://example.com/home"
    assert h2.get("Sec-Fetch-Site") == "same-origin"
