"""Deep architecture fingerprinting.

Given a target URL, probe the stack end-to-end and produce an
ArchitectureProfile: what's at every layer (edge, origin, runtime,
database, cache, OS). Subsequent offensive tactics adapt to this
profile.

Fingerprint layers
------------------
  1. EDGE/CDN         : Cloudflare, Akamai, Fastly, CloudFront, Sucuri,
                        direct-to-origin
  2. WAF              : Cloudflare Managed, Wordfence, Sucuri,
                        ModSecurity, Imperva, AWS WAF
  3. ORIGIN WEB       : Apache, Nginx, IIS, Caddy, LiteSpeed, OpenLiteSpeed
  4. RUNTIME          : PHP-FPM / mod_php / php-cgi; Python WSGI;
                        Node.js; etc. (+ version)
  5. DATABASE         : MySQL / MariaDB / Postgres / SQLite — inferred
                        from error messages
  6. CACHE            : Varnish, Redis, Memcached presence via header
                        probing
  7. OS               : Linux (case-sensitive FS) vs Windows (case-
                        insensitive FS, `\\` path separator tolerant,
                        ::$DATA ADS)
  8. FRAMEWORK        : WordPress, Drupal, Joomla (via /readme.*,
                        fingerprint HTML, generator meta)
  9. MISC             : Debug mode, Xdebug, verbose error reporting

Probing technique
-----------------
Single polite pass (5-8 GETs) against:
    /                  — homepage, headers, generator meta, hostname
    /nonexistent-xyz   — 404 page patterns (reveals origin + framework)
    /wp-login.php       — WP confirmation
    /robots.txt         — crawler policy + hint paths
    /.env              — dev-artifact leak test
    /phpinfo.php       — PHP info leak (rare but gold)
    /%25                — malformed URL, reveals normalizer behavior
    / w/ OPTIONS       — exposed methods

Timing probes (optional, 2x extra requests):
    Response-time distribution on a cached vs uncached endpoint.
    Large divergence = caching layer present (Varnish/CDN).

Output
------
ArchitectureProfile with confidence scores per-layer. Downstream
strategy.py uses this to select tactics.
"""

from __future__ import annotations

import logging
import re
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("amoskys.argos.adapt.fingerprint")


# ── Data model ────────────────────────────────────────────────────


@dataclass
class ArchitectureProfile:
    target_url: str
    target_host: str
    # Edge / CDN
    cdn_name: Optional[str] = None
    cdn_confidence: int = 0
    # WAF
    waf_names: List[str] = field(default_factory=list)
    waf_confidence: int = 0
    # Origin web server
    origin_server: Optional[str] = (
        None  # "nginx" / "apache" / "iis" / "caddy" / "litespeed"
    )
    origin_version: Optional[str] = None
    origin_confidence: int = 0
    # Runtime
    runtime: Optional[str] = None  # "php-fpm" / "mod_php" / "php-cgi"
    runtime_version: Optional[str] = None
    runtime_confidence: int = 0
    # Database (inferred from error messages)
    database: Optional[str] = None  # "mysql" / "mariadb" / "postgres" / "sqlite"
    database_confidence: int = 0
    # Cache
    cache_layers: List[str] = field(
        default_factory=list
    )  # ["varnish","cloudflare-cache"]
    # OS
    os_family: Optional[str] = None  # "linux" / "windows"
    os_confidence: int = 0
    # Framework
    framework: Optional[str] = None  # "wordpress" / "drupal" / "joomla" / None
    framework_version: Optional[str] = None
    framework_confidence: int = 0
    # Security posture signals
    debug_mode: bool = False
    xdebug_present: bool = False
    php_expose: bool = False
    verbose_errors: bool = False
    # Ops
    http_requests_used: int = 0
    fingerprint_time_ms: int = 0
    errors: List[str] = field(default_factory=list)
    # Raw evidence trail (for auditing)
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_url": self.target_url,
            "target_host": self.target_host,
            "cdn": {"name": self.cdn_name, "confidence": self.cdn_confidence},
            "waf": {"names": self.waf_names, "confidence": self.waf_confidence},
            "origin": {
                "server": self.origin_server,
                "version": self.origin_version,
                "confidence": self.origin_confidence,
            },
            "runtime": {
                "name": self.runtime,
                "version": self.runtime_version,
                "confidence": self.runtime_confidence,
            },
            "database": {"name": self.database, "confidence": self.database_confidence},
            "cache_layers": self.cache_layers,
            "os": {"family": self.os_family, "confidence": self.os_confidence},
            "framework": {
                "name": self.framework,
                "version": self.framework_version,
                "confidence": self.framework_confidence,
            },
            "debug_mode": self.debug_mode,
            "xdebug_present": self.xdebug_present,
            "php_expose": self.php_expose,
            "verbose_errors": self.verbose_errors,
            "http_requests_used": self.http_requests_used,
            "fingerprint_time_ms": self.fingerprint_time_ms,
            "evidence": self.evidence,
            "errors": self.errors,
        }


# ── HTTP primitives ──────────────────────────────────────────────


@dataclass
class _Response:
    status: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    url: str = ""
    latency_ms: int = 0
    error: Optional[str] = None


def _get(
    url: str,
    timeout: float = 10.0,
    headers: Optional[Dict[str, str]] = None,
    http_get=None,
) -> _Response:
    """Low-level HTTP GET. http_get injectable for tests.

    `http_get(url, timeout, headers) -> (status, headers_dict, body)`
    """
    if http_get is not None:
        t0 = time.time()
        s, h, b = http_get(url, timeout, headers or {})
        return _Response(
            status=s,
            headers={k.lower(): v for k, v in (h or {}).items()},
            body=b or "",
            url=url,
            latency_ms=int((time.time() - t0) * 1000),
        )
    h = dict(headers or {})
    h.setdefault(
        "User-Agent",
        "Mozilla/5.0 (Macintosh) AppleWebKit/605.1 Version/17.0 Safari/605.1",
    )
    req = urllib.request.Request(url, headers=h)
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body_bytes = resp.read(256 * 1024)
            body = body_bytes.decode("utf-8", errors="replace")
            return _Response(
                status=resp.status,
                headers={k.lower(): v for k, v in resp.headers.items()},
                body=body,
                url=resp.url,
                latency_ms=int((time.time() - t0) * 1000),
            )
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = (e.read(256 * 1024) or b"").decode("utf-8", errors="replace")
        except Exception:
            pass
        return _Response(
            status=e.code,
            headers={k.lower(): v for k, v in (e.headers or {}).items()},
            body=body,
            url=url,
            latency_ms=int((time.time() - t0) * 1000),
        )
    except Exception as e:  # noqa: BLE001
        return _Response(
            url=url, error=str(e), latency_ms=int((time.time() - t0) * 1000)
        )


# ── Layer detectors ──────────────────────────────────────────────


def _detect_cdn(r: _Response) -> Tuple[Optional[str], int, List[str]]:
    h = r.headers
    server = (h.get("server") or "").lower()
    evidence: List[str] = []
    if "cf-ray" in h or "cf-cache-status" in h or server.startswith("cloudflare"):
        evidence.append(f"cloudflare: cf-ray/server={server}")
        return ("Cloudflare", 95, evidence)
    if "x-amz-cf-id" in h or "x-amz-cf-pop" in h or server.startswith("cloudfront"):
        evidence.append("cloudfront: x-amz-cf-*")
        return ("CloudFront", 90, evidence)
    if "x-fastly-request-id" in h or "fastly" in (h.get("via") or "").lower():
        evidence.append("fastly: x-fastly / via")
        return ("Fastly", 90, evidence)
    if "x-akamai-transformed" in h or "akamai" in server:
        evidence.append(f"akamai: x-akamai / server={server}")
        return ("Akamai", 90, evidence)
    if "x-sucuri-id" in h or "x-sucuri-cache" in h:
        evidence.append("sucuri: x-sucuri")
        return ("Sucuri", 90, evidence)
    return (None, 0, evidence)


def _detect_waf(
    r: _Response, blocked: Optional[_Response]
) -> Tuple[List[str], int, List[str]]:
    """Walks header + body of baseline and (optionally) a blocked
    response looking for WAF fingerprints."""
    names: List[str] = []
    conf = 0
    evidence: List[str] = []
    for res in (r, blocked):
        if not res:
            continue
        h = res.headers
        body = (res.body or "").lower()
        # Wordfence
        if (
            "wfwaf-authcookie" in (h.get("set-cookie") or "").lower()
            or "wordfence" in body
        ):
            if "Wordfence" not in names:
                names.append("Wordfence")
                conf = max(conf, 85)
                evidence.append("Wordfence: cookie/body")
        # Sucuri
        if "x-sucuri-block" in h or "sucuri website firewall" in body:
            if "Sucuri" not in names:
                names.append("Sucuri")
                conf = max(conf, 80)
                evidence.append("Sucuri: header/body")
        # ModSecurity
        if "mod_security" in (h.get("server") or "").lower() or "mod_security" in body:
            if "ModSecurity" not in names:
                names.append("ModSecurity")
                conf = max(conf, 75)
                evidence.append("ModSecurity: server/body")
        # Cloudflare WAF challenge page signatures
        if "attention required! | cloudflare" in body or "ray id:" in body:
            if "Cloudflare" not in names:
                names.append("Cloudflare")
                conf = max(conf, 80)
                evidence.append("Cloudflare WAF: body challenge")
        # Imperva/Incapsula
        if "x-iinfo" in h or "incapsula" in body:
            if "Imperva/Incapsula" not in names:
                names.append("Imperva/Incapsula")
                conf = max(conf, 80)
                evidence.append("Imperva: x-iinfo/body")
        # AWS WAF
        if res.status == 403 and "aws" in body and "request blocked" in body:
            if "AWS WAF" not in names:
                names.append("AWS WAF")
                conf = max(conf, 70)
                evidence.append("AWS WAF: 403 + body")
    return (names, conf, evidence)


def _detect_origin_server(
    r: _Response,
) -> Tuple[Optional[str], Optional[str], int, List[str]]:
    server = r.headers.get("server") or ""
    evidence: List[str] = []
    if not server:
        return (None, None, 0, evidence)
    evidence.append(f"server-header: {server[:80]}")
    s = server.lower()
    version_match = re.search(r"([a-z-]+)[/\s]([0-9][0-9a-z.+-]*)", s)
    version = version_match.group(2) if version_match else None
    if "nginx" in s:
        return ("nginx", version, 90, evidence)
    if "apache" in s:
        return ("apache", version, 90, evidence)
    if "litespeed" in s or "lsws" in s:
        return ("litespeed", version, 85, evidence)
    if "microsoft-iis" in s or "iis" in s:
        return ("iis", version, 85, evidence)
    if "caddy" in s:
        return ("caddy", version, 85, evidence)
    if "cloudflare" in s or "cloudfront" in s or "akamai" in s:
        # CDN intermediaries — origin hidden. Record as "cdn-proxied".
        return ("cdn-proxied", None, 50, evidence)
    return (server.split("/")[0].strip(), version, 60, evidence)


def _detect_runtime(
    r: _Response,
) -> Tuple[Optional[str], Optional[str], int, List[str]]:
    """Detect PHP via X-Powered-By, Set-Cookie names, response behavior."""
    h = r.headers
    evidence: List[str] = []
    xpb = h.get("x-powered-by") or ""
    if xpb:
        evidence.append(f"x-powered-by: {xpb[:80]}")
        m = re.search(r"php/([0-9][0-9.a-z-]+)", xpb, re.IGNORECASE)
        if m:
            return ("php", m.group(1), 95, evidence)
        if "php" in xpb.lower():
            return ("php", None, 85, evidence)
    # PHP session cookie.
    sc = (h.get("set-cookie") or "").lower()
    if "phpsessid" in sc:
        evidence.append("cookie:PHPSESSID")
        return ("php", None, 70, evidence)
    # WordPress sets these with PHP runtime.
    if "wp-settings" in sc or "wordpress_" in sc:
        evidence.append("cookie:wp-*")
        return ("php", None, 70, evidence)
    return (None, None, 0, evidence)


def _detect_framework(
    r: _Response, login_r: Optional[_Response]
) -> Tuple[Optional[str], Optional[str], int, List[str]]:
    body = r.body or ""
    evidence: List[str] = []
    # WordPress via meta-generator.
    m = re.search(
        r"""<meta\s+name=['"]generator['"]\s+content=['"]([^'"]+)['"]""",
        body,
        re.IGNORECASE,
    )
    if m:
        gen = m.group(1)
        evidence.append(f"meta-generator: {gen}")
        if "wordpress" in gen.lower():
            v = re.search(r"WordPress\s+([0-9.]+)", gen)
            return ("wordpress", v.group(1) if v else None, 95, evidence)
        if "drupal" in gen.lower():
            v = re.search(r"Drupal\s+([0-9.]+)", gen)
            return ("drupal", v.group(1) if v else None, 95, evidence)
        if "joomla" in gen.lower():
            return ("joomla", None, 90, evidence)
    # WordPress REST API hint via Link header (hardened themes hide the
    # generator meta tag but wp-json is almost always advertised via
    # `Link: <https://host/wp-json/>; rel="https://api.w.org/"`)
    link_hdr = (r.headers.get("link") or "").lower()
    if "wp-json" in link_hdr or "api.w.org" in link_hdr:
        evidence.append(f"Link header: {link_hdr[:120]}")
        return ("wordpress", None, 90, evidence)
    # Inline hints.
    if "/wp-content/" in body or "/wp-includes/" in body or "wp-json" in body:
        evidence.append("body: wp-content / wp-includes / wp-json")
        return ("wordpress", None, 85, evidence)
    if (
        login_r
        and login_r.status == 200
        and "wordpress" in (login_r.body or "").lower()
    ):
        evidence.append("wp-login.php present")
        return ("wordpress", None, 85, evidence)
    if "sites/default/files" in body or "drupal.js" in body:
        return ("drupal", None, 80, evidence)
    if "option=com_" in body:
        return ("joomla", None, 75, evidence)
    return (None, None, 0, evidence)


def _detect_os(
    origin_server: Optional[str], r_root: _Response, r_case_upper: Optional[_Response]
) -> Tuple[Optional[str], int, List[str]]:
    """Linux vs Windows via:
    - IIS in server header = Windows (high confidence)
    - Case-sensitivity test: /WP-login.php should 404 on Linux
      but serve WP login page on Windows
    - X-Powered-By 'ASP.NET' = Windows
    """
    evidence: List[str] = []
    if origin_server == "iis":
        evidence.append("IIS → Windows")
        return ("windows", 95, evidence)
    # Case sensitivity.
    if r_case_upper and r_root:
        # If /WP-LOGIN.PHP returns WP login page on both (case-insensitive FS),
        # we're likely Windows.
        if r_case_upper.status == 200 and r_root.status == 200:
            if "wordpress" in (r_case_upper.body or "").lower():
                # But Linux can also have this if the exact file exists.
                # Weak signal; use low confidence.
                evidence.append("case-insensitive FS")
                return ("windows", 55, evidence)
    # Default: Linux (majority of WP hosting).
    evidence.append("default → linux (no windows indicators)")
    return ("linux", 60, evidence)


def _detect_cache(r: _Response) -> Tuple[List[str], List[str]]:
    layers: List[str] = []
    evidence: List[str] = []
    h = r.headers
    if "x-varnish" in h or "varnish" in (h.get("via") or "").lower():
        layers.append("varnish")
        evidence.append("x-varnish/via")
    if "cf-cache-status" in h:
        layers.append("cloudflare-cache")
        evidence.append("cf-cache-status")
    if "x-cache" in h:
        layers.append(f"x-cache: {h['x-cache'][:40]}")
        evidence.append(f"x-cache: {h['x-cache'][:40]}")
    if "x-amz-cf-id" in h:
        layers.append("cloudfront-cache")
        evidence.append("x-amz-cf-id")
    return (layers, evidence)


def _detect_database(
    r_error: Optional[_Response],
) -> Tuple[Optional[str], int, List[str]]:
    """Try to catch a DB error message from a malformed query.

    We don't fire SQLi here — we check the baseline/404 body for
    leaked error messages like 'You have an error in your SQL syntax'
    (MySQL) vs 'syntax error at or near' (Postgres).
    """
    if not r_error:
        return (None, 0, [])
    body = (r_error.body or "").lower()
    ev: List[str] = []
    if "you have an error in your sql syntax" in body or "mysql_fetch" in body:
        ev.append("MySQL error string")
        return ("mysql", 85, ev)
    if "syntax error at or near" in body or "postgresql" in body:
        ev.append("Postgres error string")
        return ("postgres", 85, ev)
    if "sqlite error" in body or "sqlite_query" in body:
        ev.append("SQLite error string")
        return ("sqlite", 80, ev)
    if "microsoft ole db provider" in body or "sql server" in body:
        ev.append("MSSQL error string")
        return ("mssql", 80, ev)
    return (None, 0, [])


# ── Top-level fingerprinter ──────────────────────────────────────


def fingerprint_architecture(
    target_url: str,
    http_get=None,
    probe_timing: bool = False,
) -> ArchitectureProfile:
    """Probe the target (5-7 polite GETs) and return the profile."""
    if "://" not in target_url:
        target_url = "https://" + target_url.lstrip("/")
    parsed = urllib.parse.urlparse(target_url)
    host = parsed.netloc
    prof = ArchitectureProfile(target_url=target_url.rstrip("/"), target_host=host)

    t0 = time.time()
    base = f"{parsed.scheme}://{host}"

    # Probe 1: homepage.
    r_root = _get(base + "/", http_get=http_get)
    prof.http_requests_used += 1
    if r_root.error:
        prof.errors.append(f"root fetch: {r_root.error}")
    # Probe 2: nonexistent URL to provoke error/404 page.
    r_err = _get(base + "/does-not-exist-%zz-xyz", http_get=http_get)
    prof.http_requests_used += 1
    # Probe 3: wp-login presence.
    r_login = _get(base + "/wp-login.php", http_get=http_get)
    prof.http_requests_used += 1
    # Probe 4: case-sensitivity test — only if root succeeded.
    r_case: Optional[_Response] = None
    if r_root.status == 200:
        r_case = _get(base + "/WP-LOGIN.PHP", http_get=http_get)
        prof.http_requests_used += 1

    # Layer detection.
    cdn_name, cdn_conf, cdn_ev = _detect_cdn(r_root)
    prof.cdn_name = cdn_name
    prof.cdn_confidence = cdn_conf
    prof.evidence.extend(cdn_ev)

    waf_names, waf_conf, waf_ev = _detect_waf(r_root, r_err)
    prof.waf_names = waf_names
    prof.waf_confidence = waf_conf
    prof.evidence.extend(waf_ev)

    origin, origin_ver, origin_conf, origin_ev = _detect_origin_server(r_root)
    prof.origin_server = origin
    prof.origin_version = origin_ver
    prof.origin_confidence = origin_conf
    prof.evidence.extend(origin_ev)

    rt, rt_ver, rt_conf, rt_ev = _detect_runtime(r_root)
    prof.runtime = rt
    prof.runtime_version = rt_ver
    prof.runtime_confidence = rt_conf
    prof.evidence.extend(rt_ev)

    db, db_conf, db_ev = _detect_database(r_err)
    prof.database = db
    prof.database_confidence = db_conf
    prof.evidence.extend(db_ev)

    cache, cache_ev = _detect_cache(r_root)
    prof.cache_layers = cache
    prof.evidence.extend(cache_ev)

    os_fam, os_conf, os_ev = _detect_os(prof.origin_server, r_root, r_case)
    prof.os_family = os_fam
    prof.os_confidence = os_conf
    prof.evidence.extend(os_ev)

    fw, fw_ver, fw_conf, fw_ev = _detect_framework(r_root, r_login)
    prof.framework = fw
    prof.framework_version = fw_ver
    prof.framework_confidence = fw_conf
    prof.evidence.extend(fw_ev)

    # Debug / posture indicators.
    body_lc = (r_err.body or "").lower()
    if "fatal error" in body_lc or "parse error" in body_lc:
        prof.verbose_errors = True
        prof.evidence.append("error page reveals php errors verbose_errors=True")
    if "xdebug" in body_lc:
        prof.xdebug_present = True
        prof.evidence.append("xdebug present")
    if (r_root.headers.get("x-powered-by") or "").lower().startswith("php"):
        prof.php_expose = True
        prof.evidence.append("PHP expose_php=On")

    prof.fingerprint_time_ms = int((time.time() - t0) * 1000)
    return prof
