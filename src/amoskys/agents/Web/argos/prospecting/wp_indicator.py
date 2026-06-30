"""Is-this-WordPress + has-reachable-contact indicator checks.

The lightest-possible qualification pass. Given a domain, one or
two HTTP GETs tell us:
  1. Does it serve a WordPress site at all?
  2. Is there a reachable contact path we can pitch to?
  3. Is there a bug bounty program that would take first-refusal?

We use the legitimacy layer (UA pool + gaussian pacing) so our
discovery traffic looks like a single curious visitor — not a
scanner.

Stealth discipline
──────────────────
At most 2 HTTP GETs per candidate:
  1. GET / — extract generator meta, plugin inventory hints, Sec-*
     headers, security.txt Canonical hint, obvious bug-bounty text
  2. GET /.well-known/security.txt — the RFC 9116 path; single check

We do NOT probe:
  - /wp-admin, /wp-login, /wp-json at this stage (Stage-1 sweep does
    those; here we only decide whether the target is worth Stage 1)
  - /.env, /.git, wp-config.bak, etc. — those are Stage-1 signals,
    not discovery signals
  - Sitemaps, xmlrpc — post-qualification only
"""

from __future__ import annotations

import json
import logging
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from amoskys.agents.Web.argos.legitimacy import LegitimacyProfile, UserAgentPool

logger = logging.getLogger("amoskys.argos.prospecting.wp_indicator")

_DEFAULT_TIMEOUT = 10.0

# Known bug-bounty program hosts/keywords — if we see these in the
# security.txt or homepage, we SKIP this target. We don't step on
# a paying program's toes.
_BUG_BOUNTY_TELLS = [
    "hackerone.com/",
    "bugcrowd.com/",
    "intigriti.com/",
    "yeswehack.com/",
    "hackerone.com",  # in plain text
    "bug bounty program",
    "responsible disclosure program",
]


@dataclass
class WPIndicatorResult:
    host: str
    is_wordpress: bool = False
    wp_confidence: int = 0  # 0-100
    wp_version_hint: Optional[str] = None
    plugin_slugs_in_html: List[str] = field(default_factory=list)
    # Contact
    has_security_txt: bool = False
    contact_hints: List[str] = field(default_factory=list)
    # Bounty
    on_bug_bounty: bool = False
    bounty_evidence: Optional[str] = None
    # Infra signals
    server_header: Optional[str] = None
    uses_cdn: bool = False
    cdn_name: Optional[str] = None
    # Exposure signals (visible on homepage alone)
    wp_generator_exposed: bool = False
    plugin_inventory_leaks: int = 0
    # Meta
    http_requests_used: int = 0
    errors: List[str] = field(default_factory=list)
    checked_at: float = 0.0


def _decompress(body_bytes: bytes, encoding: Optional[str]) -> str:
    """Decompress a response body according to the Content-Encoding header.

    A real browser that advertises `Accept-Encoding: gzip, deflate, br`
    MUST handle gzip/deflate; br (Brotli) is optional if the brotli
    library is unavailable. Returning garbage silently would both break
    our detection AND produce a traffic-shape anomaly a WAF could flag
    ('UA claims Chrome but never ACKs compressed bytes').
    """
    if not body_bytes:
        return ""
    enc = (encoding or "").lower().strip()
    try:
        if enc == "gzip":
            import gzip

            body_bytes = gzip.decompress(body_bytes)
        elif enc == "deflate":
            import zlib

            try:
                body_bytes = zlib.decompress(body_bytes)
            except zlib.error:
                body_bytes = zlib.decompress(body_bytes, -zlib.MAX_WBITS)
        elif enc == "br":
            try:
                import brotli  # type: ignore

                body_bytes = brotli.decompress(body_bytes)
            except ImportError:
                # Brotli not installed — return as-is; caller may still
                # get useful bytes if the body is plain text. In steady
                # state we'd install brotli; for now this is graceful.
                pass
    except Exception:
        # Decompression error — fall through to raw bytes so at least
        # we don't hard-crash on a single malformed response.
        pass
    return body_bytes.decode("utf-8", errors="replace")


def _get(
    url: str,
    headers: Dict[str, str],
    timeout: float = _DEFAULT_TIMEOUT,
    max_bytes: int = 512 * 1024,
    http_fetch=None,
):
    """Single HTTP GET. Returns (status, headers_lower, body_text, final_url).

    `http_fetch` override for tests: fn(url, headers) -> (status, headers_dict, body).
    """
    if http_fetch is not None:
        status, h, body = http_fetch(url, headers)
        return status, {k.lower(): v for k, v in h.items()}, body, url

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body_bytes = resp.read(max_bytes)
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            body = _decompress(body_bytes, resp_headers.get("content-encoding"))
            return resp.status, resp_headers, body, resp.url
    except urllib.error.HTTPError as e:
        body = ""
        err_headers = {k.lower(): v for k, v in (e.headers or {}).items()}
        if e.fp:
            try:
                body = _decompress(
                    e.fp.read(max_bytes), err_headers.get("content-encoding")
                )
            except Exception:
                pass
        return e.code, err_headers, body, url
    except Exception as e:  # noqa: BLE001
        return 0, {}, "", url


def _detect_cdn(headers: Dict[str, str]) -> Optional[str]:
    """Cheap CDN fingerprint from HTTP headers."""
    if "cf-ray" in headers or "cf-cache-status" in headers:
        return "Cloudflare"
    if "x-amz-cf-id" in headers or "x-amz-cf-pop" in headers:
        return "CloudFront"
    if (
        "x-fastly-request-id" in headers
        or "fastly" in (headers.get("via") or "").lower()
    ):
        return "Fastly"
    if (
        "x-akamai-transformed" in headers
        or "akamai" in (headers.get("server") or "").lower()
    ):
        return "Akamai"
    if "x-cache" in headers and "varnish" in (headers.get("x-cache") or "").lower():
        return "Varnish"
    return None


def _extract_wp_signals(html_body: str) -> Dict:
    """Parse homepage HTML for WordPress fingerprints and contact hints."""
    out = {
        "meta_generator": None,
        "rest_api_link": False,
        "plugin_slugs": [],
        "is_wordpress": False,
        "contact_mailto": [],
        "contact_form_ref": False,
    }
    # WP meta generator — exactly the value, when present.
    m = re.search(
        r"""<meta\s+name=['"]generator['"]\s+content=['"]([^'"]+)['"]""",
        html_body,
        re.IGNORECASE,
    )
    if m:
        out["meta_generator"] = m.group(1)
        if "wordpress" in m.group(1).lower():
            out["is_wordpress"] = True
    # REST API link hint.
    if re.search(
        r"""<link\s+rel=['"]https://api\.w\.org/['"]""",
        html_body,
        re.IGNORECASE,
    ):
        out["rest_api_link"] = True
        out["is_wordpress"] = True
    # /wp-content/ anywhere in the HTML.
    if "/wp-content/" in html_body or "/wp-includes/" in html_body:
        out["is_wordpress"] = True
    # Extract plugin slugs from asset URLs.
    plugin_refs = re.findall(
        r"""/wp-content/plugins/([a-z0-9][-a-z0-9._]*)/[^'"]+\?ver=([0-9][0-9a-z.+-]*)""",
        html_body,
        re.IGNORECASE,
    )
    seen = {}
    for slug, ver in plugin_refs:
        seen[(slug.lower(), ver)] = True
    out["plugin_slugs"] = [f"{s}@{v}" for (s, v) in sorted(seen.keys())][:30]
    # Contact hints — mailto: + /contact paths referenced.
    mailtos = re.findall(r"""mailto:([^"'?\s]+)""", html_body)
    out["contact_mailto"] = sorted(set(mailtos))[:10]
    if re.search(
        r"""href=['"][^'"]*/(contact|contact-us|get-in-touch)""",
        html_body,
        re.IGNORECASE,
    ):
        out["contact_form_ref"] = True
    return out


def _parse_security_txt_snippet(text: str) -> Dict:
    """Minimal parser — we just want Contact + Policy lines."""
    out = {"contact": [], "policy": None, "canonical": None, "expires": None}
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        k = k.strip().lower()
        v = v.strip()
        if k == "contact":
            out["contact"].append(v)
        elif k == "policy" and not out["policy"]:
            out["policy"] = v
        elif k == "canonical" and not out["canonical"]:
            out["canonical"] = v
        elif k == "expires" and not out["expires"]:
            out["expires"] = v
    return out


def check_wp_indicator(
    domain: str,
    legitimacy: Optional[LegitimacyProfile] = None,
    scheme: str = "https",
    http_fetch=None,
) -> WPIndicatorResult:
    """One lightweight qualification check. At most 2 HTTP GETs.

    Returns a WPIndicatorResult that downstream scoring uses.
    """
    lp = legitimacy or LegitimacyProfile()
    hdr = lp.ua_pool.headers()
    result = WPIndicatorResult(host=domain, checked_at=time.time())

    base = f"{scheme}://{domain}"
    # 1. Homepage GET.
    status, headers, body, final_url = _get(base + "/", hdr, http_fetch=http_fetch)
    result.http_requests_used += 1
    if status == 0:
        result.errors.append("homepage fetch failed (network)")
        return result
    if status >= 500:
        result.errors.append(f"homepage 5xx ({status}) — target unhealthy")
        return result
    if status in (403, 429):
        result.errors.append(f"homepage {status} — target may be hostile to discovery")
        return result

    result.server_header = headers.get("server")
    result.cdn_name = _detect_cdn(headers)
    result.uses_cdn = bool(result.cdn_name)

    signals = _extract_wp_signals(body or "")
    if signals["is_wordpress"]:
        result.is_wordpress = True
    # Scored confidence: 40 for REST link, 30 for generator meta, 30 for asset
    # path. Capped at 100.
    conf = 0
    if signals["rest_api_link"]:
        conf += 40
    if signals["meta_generator"]:
        conf += 30
    if "/wp-content/" in body:
        conf += 30
    result.wp_confidence = min(100, conf)
    if signals["meta_generator"]:
        mg = signals["meta_generator"]
        result.wp_generator_exposed = "wordpress" in mg.lower()
        m = re.search(r"WordPress\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)", mg)
        if m:
            result.wp_version_hint = m.group(1)
    result.plugin_slugs_in_html = signals["plugin_slugs"]
    result.plugin_inventory_leaks = len(signals["plugin_slugs"])

    # Contact hints — merge mailtos + /contact refs.
    result.contact_hints.extend(signals["contact_mailto"])
    if signals["contact_form_ref"]:
        result.contact_hints.append("/contact form present on homepage")

    # Bounty check — scan homepage body for explicit bounty program tells.
    body_lower = (body or "").lower()
    for tell in _BUG_BOUNTY_TELLS:
        if tell in body_lower:
            result.on_bug_bounty = True
            result.bounty_evidence = f"homepage contains: {tell}"
            break

    # 2. security.txt GET.
    status, headers, body, _ = _get(
        base + "/.well-known/security.txt",
        hdr,
        http_fetch=http_fetch,
    )
    result.http_requests_used += 1
    if status == 200 and body and ("contact:" in body.lower() or "Contact:" in body):
        result.has_security_txt = True
        sec = _parse_security_txt_snippet(body)
        for c in sec["contact"]:
            if c not in result.contact_hints:
                result.contact_hints.append(c)
        # security.txt sometimes explicitly references bounty.
        if sec["policy"]:
            pol = sec["policy"].lower()
            for tell in _BUG_BOUNTY_TELLS:
                if tell in pol:
                    result.on_bug_bounty = True
                    result.bounty_evidence = f"security.txt Policy: {sec['policy']}"
                    break

    return result
