"""Unit tests for argos/legitimacy.py — traffic-legitimacy primitives."""

from __future__ import annotations

import random
import time
from unittest.mock import MagicMock, patch

from amoskys.agents.Web.argos.legitimacy import (
    BackoffController,
    Pacer,
    PacingProfile,
    RobotsPolicy,
    UserAgentPool,
    _parse_security_txt,
    load_robots,
    load_security_txt,
)

# ── UserAgentPool ──────────────────────────────────────────────────


def test_ua_pool_sticky_identity():
    pool = UserAgentPool(rng=random.Random(42))
    first = pool.identity()
    # Second call must return the SAME object — sticky within engagement.
    assert pool.identity() is first
    assert pool.identity().ua == first.ua


def test_ua_headers_contain_expected_fields():
    pool = UserAgentPool(rng=random.Random(1))
    h = pool.headers()
    assert "User-Agent" in h
    assert "Accept" in h
    assert "Accept-Language" in h
    assert "Accept-Encoding" in h
    # None of our pool UAs are stale / known-bad.
    assert "curl" not in h["User-Agent"].lower()
    assert "python" not in h["User-Agent"].lower()
    assert "wpscan" not in h["User-Agent"].lower()


def test_ua_sec_ch_ua_platform_hint_consistent():
    pool = UserAgentPool(rng=random.Random(2))
    ident = pool.identity()
    h = pool.headers()
    if ident.sec_ch_ua:
        assert "Sec-CH-UA-Platform" in h
        # Hint must match UA family.
        ua_lower = ident.ua.lower()
        plat = h["Sec-CH-UA-Platform"]
        if "windows" in ua_lower:
            assert plat == '"Windows"'
        elif "mac os x" in ua_lower:
            assert plat == '"macOS"'


# ── Pacer ──────────────────────────────────────────────────────────


def test_pacer_first_call_does_not_sleep():
    p = Pacer(profile=PacingProfile(), rng=random.Random(1))
    t0 = time.monotonic()
    slept = p.wait(1)
    assert slept == 0.0
    assert time.monotonic() - t0 < 0.1


def test_pacer_subsequent_calls_respect_floor():
    # Override the profile to make the test fast but still testable.
    prof = PacingProfile(
        median_s=0.05,
        stddev_s=0.01,
        min_s=0.03,
        max_s=0.1,
        long_tail_prob=0.0,  # disable long-tail so test is deterministic
    )
    p = Pacer(profile=prof, rng=random.Random(1))
    p.wait(1)  # sets initial timestamp
    # Clear the timestamp so next call hits the sleep path.
    t0 = time.monotonic()
    p.wait(2)
    elapsed = time.monotonic() - t0
    assert elapsed >= 0.02  # respects floor (minus some slack)


def test_pacer_long_tail_excursion():
    # With prob=1.0, every wait is a long-tail. The Pacer CAPS the
    # drawn value at profile.max_s, so long-tail draws get capped too
    # — we use max_s high enough here that the long-tail value passes
    # through, and assert the sleep is in the long-tail range.
    prof = PacingProfile(
        median_s=0.05,
        stddev_s=0.01,
        min_s=0.0,
        max_s=1.0,
        min_long_s=0.1,
        max_long_s=0.15,
        long_tail_prob=1.0,
    )
    p = Pacer(profile=prof, rng=random.Random(1))
    p.wait(1)
    t0 = time.monotonic()
    p.wait(2)
    elapsed = time.monotonic() - t0
    # Long-tail sleeps land in [min_long_s, max_long_s] minus a small
    # timing slack for the function overhead.
    assert 0.08 <= elapsed <= 0.25


# ── BackoffController ─────────────────────────────────────────────


def test_backoff_passes_through_success():
    b = BackoffController(rng=random.Random(1))
    should_abort, delay = b.note_status(200)
    assert not should_abort
    assert delay == 0.0
    assert b.state.consecutive_errors == 0


def test_backoff_accumulates_on_429():
    b = BackoffController(base_delay_s=1.0, max_delay_s=30.0, rng=random.Random(1))
    _, d1 = b.note_status(429)
    _, d2 = b.note_status(429)
    _, d3 = b.note_status(429)
    # Exponential: d2 > d1, d3 > d2, all under max.
    assert d1 > 0
    assert d2 > d1
    assert d3 > d2
    assert d3 <= 30.0 * 1.25  # max * jitter cap


def test_backoff_aborts_at_budget():
    b = BackoffController(consecutive_error_budget=3, rng=random.Random(1))
    b.note_status(403)
    b.note_status(403)
    should_abort, _ = b.note_status(403)  # 3rd consecutive
    assert should_abort


def test_backoff_resets_on_success():
    b = BackoffController(consecutive_error_budget=3, rng=random.Random(1))
    b.note_status(403)
    b.note_status(403)
    # Success resets.
    b.note_status(200)
    assert b.state.consecutive_errors == 0
    should_abort, _ = b.note_status(403)
    assert not should_abort  # now only 1 error


def test_backoff_honors_retry_after():
    b = BackoffController(rng=random.Random(1))
    _, delay = b.note_status(429, retry_after=12.0)
    # Retry-After + jitter (1-5s).
    assert 12.0 <= delay <= 12.0 + 5.0


# ── robots.txt parser ─────────────────────────────────────────────


def test_robots_parses_disallow_and_crawl_delay():
    text = """User-agent: *
Disallow: /wp-admin/
Disallow: /private/
Crawl-delay: 5
Sitemap: https://example.com/sitemap.xml
"""
    with patch("urllib.request.urlopen") as m:
        resp = MagicMock()
        resp.status = 200
        resp.read = MagicMock(return_value=text.encode())
        resp.__enter__ = MagicMock(return_value=resp)
        resp.__exit__ = MagicMock(return_value=None)
        m.return_value = resp
        policy = load_robots("https://example.com/", {"User-Agent": "X"})
    assert policy.raw is not None
    assert "/wp-admin/" in policy.disallows_for_us
    assert "/private/" in policy.disallows_for_us
    assert policy.crawl_delay_s == 5.0
    assert "https://example.com/sitemap.xml" in policy.sitemaps


def test_robots_policy_path_allowed_check():
    p = RobotsPolicy(raw="x", disallows_for_us=["/admin/", "/private/"])
    assert not p.is_allowed("/admin/users")
    assert not p.is_allowed("/private/")
    assert p.is_allowed("/public/page")
    assert p.is_allowed("/")


def test_robots_blanket_disallow_blocks_everything():
    p = RobotsPolicy(raw="x", disallows_for_us=["/"])
    assert not p.is_allowed("/anything")
    assert not p.is_allowed("/")


def test_robots_missing_treats_all_allowed():
    p = RobotsPolicy(raw=None)
    assert p.is_allowed("/anything")


# ── security.txt parser ──────────────────────────────────────────


def test_security_txt_parses_all_fields():
    text = """Contact: mailto:security@example.com
Contact: https://example.com/security
Canonical: https://example.com/.well-known/security.txt
Preferred-Languages: en, de
Expires: 2026-12-31T23:59:59Z
Policy: https://example.com/security-policy
"""
    st = _parse_security_txt(text)
    assert "mailto:security@example.com" in st.contact
    assert "https://example.com/security" in st.contact
    assert st.preferred_languages == "en, de"
    assert st.expires == "2026-12-31T23:59:59Z"


def test_security_txt_handles_missing_fields():
    text = "Contact: mailto:sec@x.com\n"
    st = _parse_security_txt(text)
    assert st.contact == ["mailto:sec@x.com"]
    assert st.canonical == []
    assert st.preferred_languages is None
