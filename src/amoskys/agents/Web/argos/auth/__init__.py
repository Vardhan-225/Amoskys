"""Argos Auth Breach Kit — authentication-layer attack primitives.

Three sub-modules each targeting a class of auth-layer weakness
that commodity scanners miss:

  jwt.py        JWT algorithm confusion (alg=none, RS↔HS, weak HMAC
                secret brute, kid path traversal, jku spoofing).
  session.py    WordPress cookie forgery once wp-config salts leak;
                session-token entropy analysis; password-reset
                token distribution checks.
  ratelimit.py  Rate-limit detection and bypass via header rotation
                (X-Forwarded-For, X-Real-IP), case variation,
                parameter pollution, and multi-IP proxy fan-out.

Legal ceiling
-------------
All primitives take inputs the operator has been given (tokens from
a test account, salts from a disclosed leak, the operator's own
proxies). They do not scrape victim tokens.
"""

from amoskys.agents.Web.argos.auth.jwt import (
    JWTFinding,
    JWTReport,
    attack_alg_none,
    attack_jku_spoofing,
    attack_key_confusion,
    attack_kid_injection,
    attack_weak_secret,
    decode_jwt_unsafe,
    scan_jwt,
)
from amoskys.agents.Web.argos.auth.ratelimit import (
    RateLimitFinding,
    RateLimitReport,
    bypass_case_variation,
    bypass_header_rotation,
    bypass_param_pollution,
    probe_ratelimit,
)
from amoskys.agents.Web.argos.auth.session import (
    SessionFinding,
    SessionReport,
    analyze_reset_tokens,
    analyze_session_entropy,
    forge_wp_auth_cookie,
    scan_sessions,
)

__all__ = [
    # jwt
    "JWTFinding",
    "JWTReport",
    "attack_alg_none",
    "attack_jku_spoofing",
    "attack_kid_injection",
    "attack_key_confusion",
    "attack_weak_secret",
    "decode_jwt_unsafe",
    "scan_jwt",
    # session
    "SessionFinding",
    "SessionReport",
    "analyze_reset_tokens",
    "analyze_session_entropy",
    "forge_wp_auth_cookie",
    "scan_sessions",
    # ratelimit
    "RateLimitFinding",
    "RateLimitReport",
    "bypass_case_variation",
    "bypass_header_rotation",
    "bypass_param_pollution",
    "probe_ratelimit",
]
