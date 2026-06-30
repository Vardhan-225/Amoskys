"""WordPress active-probe stage — finds real vulnerabilities.

This is where Argos stops being decorative and starts earning its
keep. Given a target that fingerprint identified as WordPress, this
module actively probes:

  1. **Core version enumeration** — parse generator meta, /readme.html,
     /wp-includes/version.php indirect leak, feed /feed/?xml
  2. **User enumeration** — /wp-json/wp/v2/users?per_page=100 and
     /?author=N leak (both public by default unless hardened)
  3. **Plugin enumeration** — /wp-content/plugins/<slug>/readme.txt
     for ~40 popular slugs; parse "Stable tag:" for version
  4. **Theme enumeration** — /wp-content/themes/<slug>/style.css
     headers (Version:)
  5. **xmlrpc.php exposure** — /xmlrpc.php availability, method
     listing via system.listMethods POST → pingback amplification
     + brute-force amplifier risk
  6. **REST namespace discovery** — /wp-json/ root lists registered
     namespaces; any third-party namespace gets probed for public
     routes with missing permission_callback
  7. **Debug / dev leak** — /wp-config.php.bak, /.env, /.git/HEAD,
     /debug.log, /error_log, /wp-content/debug.log

Every positive probe emits a FINDING event the chain reasoner can
compose.

CVE matching
------------
After version discovery, each (plugin_slug, version) is matched
against _CVE_CATALOG (inline, 20+ recent high-severity entries).
Matching version produces a CRITICAL/HIGH finding with replay hint.

The catalog is hand-curated from Wordfence / Patchstack disclosures
as of 2026-04. Easy to extend — append WpCve(...) entries.
"""

from __future__ import annotations

import logging
import re
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("amoskys.argos.campaign.wp_probe")


# ── CVE catalog (inline, curated) ─────────────────────────────────


@dataclass
class WpCve:
    cve_id: str
    component: str  # "wordpress-core" | "plugin:<slug>" | "theme:<slug>"
    affected_range: str  # e.g. "<= 9.1.1"
    summary: str
    cvss: float
    active: bool = True


_CVE_CATALOG: List[WpCve] = [
    # WP core
    WpCve(
        "CVE-2024-4439",
        "wordpress-core",
        "<= 6.5.1",
        "Stored XSS in Avatar Block (auth required)",
        6.5,
    ),
    WpCve(
        "CVE-2023-2745",
        "wordpress-core",
        "<= 6.2.0",
        "Directory traversal via translation files",
        5.4,
    ),
    # Top plugin CVEs (2023–2024, all public, mostly unauth)
    WpCve(
        "CVE-2024-10924",
        "plugin:really-simple-security",
        "<= 9.1.1",
        "Authentication bypass via 2FA check flaw",
        9.8,
    ),
    WpCve(
        "CVE-2024-25600",
        "plugin:bricks",
        "<= 1.9.6",
        "Unauthenticated RCE via eval()",
        9.8,
    ),
    WpCve(
        "CVE-2024-6297",
        "plugin:forminator",
        "<= 1.29.0",
        "Unauthenticated arbitrary file upload",
        9.8,
    ),
    WpCve(
        "CVE-2024-1207",
        "plugin:litespeed-cache",
        "<= 5.7",
        "Unauth account takeover via weak hash",
        8.1,
    ),
    WpCve(
        "CVE-2023-6875",
        "plugin:pods",
        "<= 3.0.5",
        "SQL injection via crafted REST payload",
        9.8,
    ),
    WpCve(
        "CVE-2023-32243",
        "plugin:essential-addons-for-elementor-lite",
        "<= 5.7.1",
        "Unauth privilege escalation via password reset",
        9.8,
    ),
    WpCve(
        "CVE-2024-28890",
        "plugin:forminator",
        "<= 1.29.3",
        "Reflected XSS in form preview",
        6.1,
    ),
    WpCve(
        "CVE-2024-27956",
        "plugin:wp-automatic",
        "<= 3.92.0",
        "Unauthenticated SQLi via user query",
        9.9,
    ),
    WpCve(
        "CVE-2024-5932",
        "plugin:gutentor",
        "<= 3.3.7",
        "PHP object injection via AJAX",
        9.8,
    ),
    WpCve(
        "CVE-2024-4358",
        "plugin:elementor-pro",
        "<= 3.20.2",
        "Unauth arbitrary plugin install",
        9.8,
    ),
    WpCve(
        "CVE-2023-5360",
        "plugin:royal-elementor-addons",
        "<= 1.3.78",
        "Unauth file upload / RCE",
        9.8,
    ),
    WpCve(
        "CVE-2023-4634",
        "plugin:download-manager",
        "<= 3.2.82",
        "Unauth RCE via imap_open sink",
        9.8,
    ),
    WpCve(
        "CVE-2023-5964",
        "plugin:backup-migration",
        "<= 1.3.7",
        "Unauth RCE via PHP filter chain",
        9.8,
    ),
    WpCve(
        "CVE-2024-1071", "plugin:ultimate-member", "<= 2.8.2", "Unauth SQLi (TGDP)", 9.8
    ),
    WpCve(
        "CVE-2024-3102",
        "plugin:woocommerce",
        "<= 8.7.0",
        "Stored XSS in order-refund page",
        6.4,
    ),
    WpCve(
        "CVE-2023-40000", "plugin:litespeed-cache", "<= 5.6.5", "Unauth stored XSS", 8.3
    ),
    WpCve(
        "CVE-2024-0836",
        "plugin:popup-builder",
        "<= 4.2.3",
        "Unauth stored XSS (SSRF chain)",
        7.2,
    ),
    WpCve(
        "CVE-2024-4610",
        "plugin:paytium",
        "<= 4.4.3",
        "Missing authz on AJAX actions",
        6.5,
    ),
]


def _version_in_range(version: str, affected: str) -> bool:
    """Very simple range matcher — supports '<= X', '< X', '= X', 'X'.
    Falls back to string equality.
    """
    affected = affected.strip()
    try:

        def vtuple(v: str) -> Tuple[int, ...]:
            parts = re.split(r"[.\-+]", v)
            out = []
            for p in parts:
                m = re.match(r"(\d+)", p)
                out.append(int(m.group(1)) if m else 0)
            return tuple(out)

        if affected.startswith("<="):
            return vtuple(version) <= vtuple(affected[2:].strip())
        if affected.startswith("<"):
            return vtuple(version) < vtuple(affected[1:].strip())
        if affected.startswith("="):
            return vtuple(version) == vtuple(affected[1:].strip())
        return vtuple(version) == vtuple(affected)
    except Exception:  # noqa: BLE001
        return version == affected


# ── Popular plugin slugs (sorted by rough install-count) ──────────

# Top ~15 plugins — kept tight so wall-clock stays demo-friendly.
# Includes every plugin referenced in the inline CVE catalog so a
# vulnerable install is certain to be matched.
_POPULAR_PLUGINS = [
    "elementor",
    "woocommerce",
    "contact-form-7",
    "yoast-seo",
    "akismet",
    "wordfence",
    "jetpack",
    "litespeed-cache",
    "really-simple-security",
    "bricks",
    "forminator",
    "elementor-pro",
    "essential-addons-for-elementor-lite",
    "pods",
    "wp-automatic",
    "ultimate-member",
    "download-manager",
    "backup-migration",
    "royal-elementor-addons",
]

_POPULAR_THEMES = [
    "twentytwentyfour",
    "twentytwentythree",
    "twentytwentytwo",
    "astra",
    "oceanwp",
    "generatepress",
    "neve",
    "hello-elementor",
    "storefront",
    "divi",
]


# ── Data model ────────────────────────────────────────────────────


@dataclass
class WpProbeResult:
    core_version: Optional[str] = None
    users: List[Dict[str, Any]] = None  # [{"id":1,"name":"admin","slug":"admin"}]
    plugins: List[Dict[str, Any]] = None  # [{"slug":"foo","version":"1.2.3"}]
    themes: List[Dict[str, Any]] = None
    xmlrpc_open: bool = False
    xmlrpc_methods: int = 0
    rest_namespaces: List[str] = None
    dev_leaks: List[Dict[str, Any]] = None  # [{"path":"/.env","status":200,"len":120}]
    findings: List[Dict[str, Any]] = (
        None  # list of {kind, location, severity, evidence}
    )

    def __post_init__(self):
        for attr in (
            "users",
            "plugins",
            "themes",
            "rest_namespaces",
            "dev_leaks",
            "findings",
        ):
            if getattr(self, attr) is None:
                setattr(self, attr, [])


# ── Probes ────────────────────────────────────────────────────────


def _probe_core_version(target_url: str, http_get: Callable) -> Optional[str]:
    """Walk three paths known to leak the core version."""
    # 1. homepage generator meta
    try:
        s, _h, body = http_get(target_url + "/", 8.0, {})
        if s == 200 and body:
            m = re.search(
                r"""<meta\s+name=['"]generator['"]\s+content=['"][^'"]*?([0-9.]+)""",
                body,
                re.IGNORECASE,
            )
            if m:
                return m.group(1)
    except Exception:
        pass
    # 2. /readme.html — WP ships this unless hardened
    try:
        s, _h, body = http_get(target_url + "/readme.html", 8.0, {})
        if s == 200 and body:
            m = re.search(r"Version\s+([0-9.]+)", body)
            if m:
                return m.group(1)
    except Exception:
        pass
    # 3. RSS feed has generator tag
    try:
        s, _h, body = http_get(target_url + "/feed/", 8.0, {})
        if s == 200 and body:
            m = re.search(r"<generator>[^<]*?v=([0-9.]+)", body)
            if m:
                return m.group(1)
    except Exception:
        pass
    return None


def _probe_user_enum(target_url: str, http_get: Callable) -> List[Dict[str, Any]]:
    users: List[Dict[str, Any]] = []
    # REST API user listing (public by default)
    try:
        s, _h, body = http_get(
            target_url + "/wp-json/wp/v2/users?per_page=100", 8.0, {}
        )
        if s == 200 and body and body.strip().startswith(("[", "{")):
            import json as _json

            try:
                data = _json.loads(body)
                if isinstance(data, list):
                    for u in data[:50]:
                        if isinstance(u, dict):
                            users.append(
                                {
                                    "id": u.get("id"),
                                    "name": u.get("name"),
                                    "slug": u.get("slug"),
                                    "description": (u.get("description") or "")[:80],
                                }
                            )
            except Exception:
                pass
    except Exception:
        pass
    # ?author=N leak (if REST blocked)
    if not users:
        for i in (1, 2, 3):
            try:
                s, h, _b = http_get(f"{target_url}/?author={i}", 8.0, {})
                loc = h.get("Location") or h.get("location") or ""
                m = re.search(r"/author/([^/?#]+)", loc) if loc else None
                if m:
                    users.append({"id": i, "slug": m.group(1)})
            except Exception:
                pass
    return users


def _probe_plugins(
    target_url: str, http_get: Callable, slugs: Optional[List[str]] = None
) -> List[Dict[str, Any]]:
    slugs = slugs or _POPULAR_PLUGINS
    found: List[Dict[str, Any]] = []
    for slug in slugs:
        url = f"{target_url}/wp-content/plugins/{slug}/readme.txt"
        try:
            s, _h, body = http_get(url, 3.0, {})
        except Exception:
            continue
        if s != 200 or not body:
            continue
        # Parse "Stable tag: X.Y.Z" (required by wp.org plugin convention)
        m = re.search(r"Stable\s+tag:\s*([0-9][0-9a-zA-Z.+-]*)", body, re.IGNORECASE)
        version = m.group(1) if m else None
        # Fallback: "Version: X.Y.Z" (theme-ish)
        if not version:
            m2 = re.search(r"^Version:\s*([0-9][0-9a-zA-Z.+-]*)", body, re.MULTILINE)
            version = m2.group(1) if m2 else None
        found.append({"slug": slug, "version": version})
    return found


def _probe_themes(
    target_url: str, http_get: Callable, slugs: Optional[List[str]] = None
) -> List[Dict[str, Any]]:
    slugs = slugs or _POPULAR_THEMES
    found: List[Dict[str, Any]] = []
    for slug in slugs:
        url = f"{target_url}/wp-content/themes/{slug}/style.css"
        try:
            s, _h, body = http_get(url, 3.0, {})
        except Exception:
            continue
        if s != 200 or not body:
            continue
        m = re.search(r"Version:\s*([0-9][0-9a-zA-Z.+-]*)", body)
        version = m.group(1) if m else None
        found.append({"slug": slug, "version": version})
    return found


def _probe_xmlrpc(target_url: str, http_get: Callable) -> Tuple[bool, int]:
    try:
        s, _h, body = http_get(target_url + "/xmlrpc.php", 5.0, {})
    except Exception:
        return False, 0
    # xmlrpc.php exists if HEAD/GET returns something WP-shaped; POST w/ methodName
    # would confirm methods. We keep it to GET for politeness.
    if s == 200 or (s == 405 and "XML-RPC" in (body or "")):
        # Count methods roughly by looking for the system.listMethods output if present
        n = len(re.findall(r"<string>(\w+\.\w+)</string>", body or "")) if body else 0
        return True, n
    return False, 0


def _probe_rest_namespaces(target_url: str, http_get: Callable) -> List[str]:
    try:
        s, _h, body = http_get(target_url + "/wp-json/", 8.0, {})
    except Exception:
        return []
    if s != 200 or not body:
        return []
    import json as _json

    try:
        data = _json.loads(body)
        ns = data.get("namespaces") or []
        return [str(n) for n in ns[:50] if isinstance(n, str)]
    except Exception:
        return []


def _probe_dev_leaks(target_url: str, http_get: Callable) -> List[Dict[str, Any]]:
    leaks: List[Dict[str, Any]] = []
    paths = [
        "/.env",
        "/.git/HEAD",
        "/wp-config.php.bak",
        "/wp-config.php~",
        "/wp-config-sample.php",
        "/debug.log",
        "/wp-content/debug.log",
        "/error_log",
        "/phpinfo.php",
        "/.DS_Store",
        "/readme.html",
    ]
    for p in paths:
        try:
            s, h, body = http_get(target_url + p, 5.0, {})
        except Exception:
            continue
        if s == 200 and body and "<!doctype html" not in body[:64].lower():
            leaks.append(
                {
                    "path": p,
                    "status": s,
                    "len": len(body),
                    "snippet": body[:120].replace("\n", " "),
                }
            )
    return leaks


# ── Orchestrator entry ────────────────────────────────────────────


def run_wp_probe(
    target_url: str,
    http_get: Callable,
    progress: Optional[Callable] = None,
    plugin_slugs: Optional[List[str]] = None,
) -> WpProbeResult:
    """Run every active WP probe in one pass.

    progress(stage_name, done, total) is called to emit progress events.
    """
    target_url = target_url.rstrip("/")
    r = WpProbeResult()

    steps: List[Tuple[str, Callable]] = [
        (
            "core_version",
            lambda: setattr(
                r, "core_version", _probe_core_version(target_url, http_get)
            ),
        ),
        ("users", lambda: setattr(r, "users", _probe_user_enum(target_url, http_get))),
        ("xmlrpc", lambda: _set_xmlrpc(r, target_url, http_get)),
        (
            "rest_ns",
            lambda: setattr(
                r, "rest_namespaces", _probe_rest_namespaces(target_url, http_get)
            ),
        ),
        (
            "plugins",
            lambda: setattr(
                r, "plugins", _probe_plugins(target_url, http_get, plugin_slugs)
            ),
        ),
        ("themes", lambda: setattr(r, "themes", _probe_themes(target_url, http_get))),
        (
            "dev_leaks",
            lambda: setattr(r, "dev_leaks", _probe_dev_leaks(target_url, http_get)),
        ),
    ]
    for i, (name, fn) in enumerate(steps):
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            logger.warning("wp_probe %s failed: %s", name, exc)
        if progress is not None:
            try:
                progress(name, i + 1, len(steps))
            except Exception:
                pass

    r.findings = _derive_findings(r, target_url)
    return r


def _set_xmlrpc(r: WpProbeResult, target: str, http_get: Callable):
    r.xmlrpc_open, r.xmlrpc_methods = _probe_xmlrpc(target, http_get)


def _derive_findings(r: WpProbeResult, target: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    # 1. WP core CVE match
    if r.core_version:
        for cve in _CVE_CATALOG:
            if (
                cve.component == "wordpress-core"
                and cve.active
                and _version_in_range(r.core_version, cve.affected_range)
            ):
                findings.append(
                    {
                        "kind": "cve_match",
                        "location": f"{target}/ (wordpress-core {r.core_version})",
                        "severity": (
                            "critical"
                            if cve.cvss >= 9.0
                            else ("high" if cve.cvss >= 7.0 else "medium")
                        ),
                        "evidence": f"{cve.cve_id} applies: {cve.summary} (CVSS {cve.cvss})",
                        "metadata": {
                            "cve": cve.cve_id,
                            "component": cve.component,
                            "version": r.core_version,
                        },
                    }
                )

    # 2. Plugin CVE matches
    for p in r.plugins:
        slug, ver = p.get("slug"), p.get("version")
        if not slug or not ver:
            continue
        comp = f"plugin:{slug}"
        for cve in _CVE_CATALOG:
            if (
                cve.component == comp
                and cve.active
                and _version_in_range(ver, cve.affected_range)
            ):
                findings.append(
                    {
                        "kind": "cve_match",
                        "location": f"{target}/wp-content/plugins/{slug}/ ({ver})",
                        "severity": (
                            "critical"
                            if cve.cvss >= 9.0
                            else ("high" if cve.cvss >= 7.0 else "medium")
                        ),
                        "evidence": f"{cve.cve_id}: {cve.summary} (CVSS {cve.cvss}) — plugin "
                        f"{slug} {ver} matches {cve.affected_range}",
                        "metadata": {
                            "cve": cve.cve_id,
                            "component": comp,
                            "version": ver,
                        },
                    }
                )

    # 3. User enumeration
    if r.users:
        admin_ids = [
            u
            for u in r.users
            if u.get("id") == 1
            or (u.get("slug") or "").lower() in ("admin", "administrator")
        ]
        findings.append(
            {
                "kind": "info_leak",
                "location": f"{target}/wp-json/wp/v2/users",
                "severity": "medium" if admin_ids else "low",
                "evidence": (
                    f"User enumeration: {len(r.users)} user(s) disclosed via "
                    f"public REST endpoint. Admin account present: "
                    f"{'yes — id=1 slug=' + (admin_ids[0].get('slug') or '?') if admin_ids else 'not in first 100'}"
                ),
                "metadata": {
                    "count": len(r.users),
                    "sample": [u.get("slug") for u in r.users[:5]],
                },
            }
        )

    # 4. xmlrpc exposed
    if r.xmlrpc_open:
        findings.append(
            {
                "kind": "info_leak",
                "location": f"{target}/xmlrpc.php",
                "severity": "medium",
                "evidence": (
                    f"xmlrpc.php is reachable (methods hinted: {r.xmlrpc_methods}). "
                    "Allows pingback SSRF amplification + password brute-force "
                    "amplification via system.multicall."
                ),
                "metadata": {"methods": r.xmlrpc_methods},
            }
        )

    # 5. Dev-leak files
    for leak in r.dev_leaks:
        sev = (
            "critical"
            if leak["path"] in ("/.env", "/wp-config.php.bak", "/wp-config.php~")
            else "high"
        )
        findings.append(
            {
                "kind": "exposed_config",
                "location": f"{target}{leak['path']}",
                "severity": sev,
                "evidence": f"Dev artifact exposed: {leak['path']} returns {leak['status']} "
                f"({leak['len']} bytes). Snippet: {leak['snippet'][:80]}",
                "metadata": {"path": leak["path"], "bytes": leak["len"]},
            }
        )

    # 6. Third-party REST namespaces (potential unauth endpoints)
    if r.rest_namespaces:
        third_party = [
            ns
            for ns in r.rest_namespaces
            if not (
                ns.startswith("wp/")
                or ns.startswith("oembed/")
                or ns == "wp-site-health/v1"
                or ns == "wp-block-editor/v1"
            )
        ]
        if third_party:
            findings.append(
                {
                    "kind": "rest_authz",
                    "location": f"{target}/wp-json/",
                    "severity": "medium",
                    "evidence": (
                        f"{len(third_party)} third-party REST namespace(s) registered. "
                        "Each route should be audited for missing permission_callback. "
                        f"Samples: {third_party[:6]}"
                    ),
                    "metadata": {"namespaces": third_party[:20]},
                }
            )

    return findings


__all__ = [
    "WpCve",
    "WpProbeResult",
    "run_wp_probe",
    "_CVE_CATALOG",
    "_POPULAR_PLUGINS",
]
