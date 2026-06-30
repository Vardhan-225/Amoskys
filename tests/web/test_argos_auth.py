"""Tests for argos/auth — JWT, session, ratelimit."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

import pytest

from amoskys.agents.Web.argos.auth import (  # jwt; session; ratelimit
    JWTReport,
    RateLimitReport,
    SessionReport,
    analyze_reset_tokens,
    analyze_session_entropy,
    attack_alg_none,
    attack_jku_spoofing,
    attack_key_confusion,
    attack_kid_injection,
    attack_weak_secret,
    bypass_case_variation,
    bypass_header_rotation,
    bypass_param_pollution,
    decode_jwt_unsafe,
    forge_wp_auth_cookie,
    probe_ratelimit,
    scan_jwt,
    scan_sessions,
)

# ── JWT helpers ──────────────────────────────────────────────────


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _make_hs256(payload: dict, secret: str = "secret") -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    h = _b64url(json.dumps(header, sort_keys=True, separators=(",", ":")).encode())
    p = _b64url(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
    sig = hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url(sig)}"


# ── JWT decode ───────────────────────────────────────────────────


def test_decode_jwt_unsafe_splits_correctly():
    tok = _make_hs256({"sub": "admin", "exp": 9999999999})
    h, p, sig = decode_jwt_unsafe(tok)
    assert h["alg"] == "HS256"
    assert p["sub"] == "admin"
    assert len(sig) == 32


def test_decode_jwt_unsafe_rejects_malformed():
    with pytest.raises(ValueError):
        decode_jwt_unsafe("not-a-jwt")


# ── alg=none ─────────────────────────────────────────────────────


def test_attack_alg_none_produces_empty_signature():
    tok = _make_hs256({"sub": "user"})
    f = attack_alg_none(tok)
    assert f.severity == "critical"
    assert f.forged_token.endswith(".")  # empty b64 sig segment
    h, _p, sig = decode_jwt_unsafe(f.forged_token)
    assert h["alg"] == "none"
    assert sig == b""


def test_attack_alg_none_gracefully_handles_garbage():
    f = attack_alg_none("garbage.token")
    assert f.severity == "none"
    assert "decode failed" in f.evidence


# ── RS↔HS confusion ──────────────────────────────────────────────


def test_attack_key_confusion_signs_with_public_key():
    tok = _make_hs256({"sub": "admin"})
    fake_pub_pem = "-----BEGIN PUBLIC KEY-----\nABCDEF\n-----END PUBLIC KEY-----"
    f = attack_key_confusion(tok, fake_pub_pem)
    assert f.severity == "critical"
    h, _p, _s = decode_jwt_unsafe(f.forged_token)
    assert h["alg"] == "HS256"
    # Signature is HMAC of signing_input with the PEM as key
    parts = f.forged_token.split(".")
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    expected = hmac.new(fake_pub_pem.encode(), signing_input, hashlib.sha256).digest()
    from amoskys.agents.Web.argos.auth.jwt import _b64url_decode

    assert _b64url_decode(parts[2]) == expected


# ── Weak HMAC secret ─────────────────────────────────────────────


def test_attack_weak_secret_finds_common_word():
    tok = _make_hs256({"sub": "x"}, secret="secret")
    f = attack_weak_secret(tok)
    assert f.severity == "critical"
    assert f.metadata["secret"] == "secret"


def test_attack_weak_secret_skips_non_hmac_alg():
    # RS256 token — HMAC brute not applicable
    header = {"alg": "RS256", "typ": "JWT"}
    h = _b64url(json.dumps(header, sort_keys=True, separators=(",", ":")).encode())
    p = _b64url(b'{"sub":"x"}')
    sig = _b64url(b"faked-rsa-sig")
    f = attack_weak_secret(f"{h}.{p}.{sig}")
    assert f.severity == "info"
    assert "not HMAC" in f.evidence


def test_attack_weak_secret_respects_custom_wordlist():
    tok = _make_hs256({"sub": "x"}, secret="uncommon-secret-789")
    # Default wordlist fails
    f1 = attack_weak_secret(tok)
    assert f1.severity == "info"
    # Custom wordlist succeeds
    f2 = attack_weak_secret(tok, wordlist=["uncommon-secret-789"])
    assert f2.severity == "critical"


# ── kid injection ────────────────────────────────────────────────


def test_attack_kid_injection_sets_kid_and_signs_with_empty_key():
    tok = _make_hs256({"sub": "x"})
    f = attack_kid_injection(tok, injection="/dev/null", hmac_secret="")
    h, _p, sig = decode_jwt_unsafe(f.forged_token)
    assert h["kid"] == "/dev/null"
    # Signature is HMAC with empty-string key
    parts = f.forged_token.split(".")
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    expected = hmac.new(b"", signing_input, hashlib.sha256).digest()
    assert sig == expected


# ── jku spoofing ─────────────────────────────────────────────────


def test_attack_jku_spoofing_overrides_jku_and_kid():
    tok = _make_hs256({"sub": "x"})
    f = attack_jku_spoofing(tok, "https://attacker.example/jwks.json", "k1")
    assert f.forged_token.endswith(".")  # unsigned placeholder
    h, _p, _s = decode_jwt_unsafe(f.forged_token + "aa")  # append pad for decode
    assert h["jku"].startswith("https://attacker.example")
    assert h["kid"] == "k1"


# ── scan_jwt orchestrator ────────────────────────────────────────


def test_scan_jwt_runs_applicable_techniques():
    tok = _make_hs256({"sub": "admin"}, secret="secret")
    rep = scan_jwt(tok)
    techniques = [f.technique for f in rep.findings]
    assert "alg_none" in techniques
    assert "weak_secret_brute" in techniques
    assert "kid_injection" in techniques


def test_scan_jwt_includes_rs_confusion_when_pubkey_supplied():
    tok = _make_hs256({"sub": "admin"})
    rep = scan_jwt(
        tok,
        rsa_public_key_pem="-----BEGIN PUBLIC KEY-----\nX\n-----END PUBLIC KEY-----",
    )
    assert any(f.technique == "rs_hs_confusion" for f in rep.findings)


# ── Session: WP cookie forgery ───────────────────────────────────


def test_forge_wp_auth_cookie_matches_wp_hash_logic():
    f = forge_wp_auth_cookie(
        username="admin",
        password_hash="$P$BxQG9S3aDeadBeef1234567890",
        auth_key="aaa",
        auth_salt="bbb",
        scheme="logged_in",
        expiration=1_000_000_000,
        token="a" * 64,
    )
    assert f.severity == "critical"
    cookie = f.metadata["cookie_value"]
    # Shape: username|expiration|token|hash
    parts = cookie.split("|")
    assert len(parts) == 4
    assert parts[0] == "admin"
    assert parts[1] == "1000000000"
    assert len(parts[3]) == 64  # sha256 hex


def test_forge_wp_auth_cookie_uses_password_fragment():
    # The pass_frag is substr(password_hash, 8, 4) — bytes 8..12
    # chars 0-3: "$P$B", 4-7: "XXXX", 8-11: "UNIQ" → frag = "UNIQ"
    pwd = "$P$B" + "X" * 4 + "UNIQUEFRAG" + "YYY"
    f = forge_wp_auth_cookie(
        username="u",
        password_hash=pwd,
        auth_key="k",
        auth_salt="s",
        expiration=1,
        token="t" * 64,
    )
    assert "UNIQ" in f.evidence


# ── Session: entropy ─────────────────────────────────────────────


def test_analyze_session_entropy_flags_weak_tokens():
    weak = ["aaaaaa", "aaaaab", "aaaaac", "aaaaad"]  # ~0 bit entropy
    f = analyze_session_entropy(weak)
    assert f.severity == "critical"
    assert "BELOW" in f.evidence


def test_analyze_session_entropy_ok_for_random_tokens():
    import secrets

    strong = [secrets.token_hex(32) for _ in range(10)]
    f = analyze_session_entropy(strong)
    # mean entropy of hex tokens ~3.9-4.0 bits/char → info (above 3.5)
    assert f.severity == "info"


def test_analyze_session_entropy_handles_empty():
    f = analyze_session_entropy([])
    assert f.severity == "info"


# ── Session: reset tokens ────────────────────────────────────────


def test_analyze_reset_tokens_detects_timestamp_bleed():
    ts = 1_700_000_000
    bad = hashlib.md5(str(ts).encode()).hexdigest()
    f = analyze_reset_tokens([(bad, ts)])
    assert f.severity == "critical"
    assert "md5" in " ".join(f.metadata["leaks"])


def test_analyze_reset_tokens_ok_on_random():
    import secrets

    tokens = [(secrets.token_hex(16), 1_700_000_000 + i) for i in range(5)]
    f = analyze_reset_tokens(tokens)
    # token_hex is random hex strings; ordering is unpredictable so likely non-monotonic
    # and no timestamp-hash shows up → info
    assert f.severity == "info"


# ── Session orchestrator ─────────────────────────────────────────


def test_scan_sessions_runs_all_three_checks_when_inputs_provided():
    rep = scan_sessions(
        observed_session_tokens=["abcd1234", "abcd5678"],
        observed_reset_tokens=[("random1", 1_700_000_000)],
        wp_forge={
            "username": "admin",
            "password_hash": "$P$BDEADBEEFfoo",
            "auth_key": "k",
            "auth_salt": "s",
        },
    )
    techniques = [f.technique for f in rep.findings]
    assert "session_entropy" in techniques
    assert "reset_token_entropy" in techniques
    assert any("wp_cookie_forge" in t for t in techniques)


def test_scan_sessions_logs_error_on_missing_wp_key():
    rep = scan_sessions(wp_forge={"username": "admin"})  # missing password_hash
    assert rep.errors
    assert "missing key" in rep.errors[0]


# ── RateLimit: bypass builders (pure) ────────────────────────────


def test_bypass_case_variation_generates_variants():
    f = bypass_case_variation("/login")
    variants = f.metadata["variants"]
    assert any(v.endswith("/") for v in variants)
    assert any("%2e" in v for v in variants)
    assert any(v.upper() == v and "LOGIN" in v for v in variants)


def test_bypass_param_pollution_builds_query_suffix():
    f = bypass_param_pollution("/login", "user", ["a", "b", "c"])
    assert f.metadata["query_suffix"] == "user=a&user=b&user=c"
    assert f.metadata["count"] == 3


def test_bypass_param_pollution_handles_empty_values():
    f = bypass_param_pollution("/login", "user", [])
    assert f.severity == "info"


# ── RateLimit: probe + rotation with fake sender ─────────────────


class _FakeSender:
    """sender(url, method, headers, body, timeout) -> (status, headers, body, elapsed_ms)"""

    def __init__(self, scripted):
        self.scripted = list(scripted)
        self.calls = 0

    def __call__(self, url, method, headers, body, timeout):
        if self.calls >= len(self.scripted):
            return (200, {}, "", 10)
        r = self.scripted[self.calls]
        self.calls += 1
        return r


def test_probe_ratelimit_detects_429(monkeypatch):
    # Patch time.sleep so the test is fast
    import amoskys.agents.Web.argos.auth.ratelimit as rl

    monkeypatch.setattr(rl.time, "sleep", lambda _s: None)
    scripted = [
        *[(200, {}, "", 10) for _ in range(4)],
        (429, {"Retry-After": "60"}, "", 10),
    ]
    sender = _FakeSender(scripted)
    rep = probe_ratelimit(
        "https://t/",
        "/api/login",
        sender=sender,
        max_requests=20,
        request_interval_s=0.0,
    )
    assert rep.limit_requests == 5
    threshold = [f for f in rep.findings if f.technique == "ratelimit_threshold"]
    assert threshold
    assert "429 after 5" in threshold[0].evidence


def test_probe_ratelimit_returns_no_limit_when_never_throttled(monkeypatch):
    import amoskys.agents.Web.argos.auth.ratelimit as rl

    monkeypatch.setattr(rl.time, "sleep", lambda _s: None)
    scripted = [(200, {}, "", 10) for _ in range(10)]
    sender = _FakeSender(scripted)
    rep = probe_ratelimit(
        "https://t/", "/api", sender=sender, max_requests=10, request_interval_s=0.0
    )
    assert rep.limit_requests is None
    assert any("no 429 observed" in f.evidence for f in rep.findings)


def test_bypass_header_rotation_counts_non_429_successes(monkeypatch):
    import amoskys.agents.Web.argos.auth.ratelimit as rl

    monkeypatch.setattr(rl.time, "sleep", lambda _s: None)
    # All succeed → bypass!
    scripted = [(200, {}, "", 10) for _ in range(30)]
    sender = _FakeSender(scripted)
    f = bypass_header_rotation(
        "https://t/",
        "/api/login",
        confirmed_limit_requests=5,
        attempt_count=30,
        sender=sender,
    )
    assert f.severity == "high"
    assert f.metadata["bypassed"] is True


def test_bypass_header_rotation_reports_info_when_no_bypass(monkeypatch):
    import amoskys.agents.Web.argos.auth.ratelimit as rl

    monkeypatch.setattr(rl.time, "sleep", lambda _s: None)
    scripted = [(429, {}, "", 10) for _ in range(30)]
    sender = _FakeSender(scripted)
    f = bypass_header_rotation(
        "https://t/",
        "/api/login",
        confirmed_limit_requests=5,
        attempt_count=30,
        sender=sender,
    )
    assert f.severity == "info"
    assert f.metadata["bypassed"] is False
