"""AMOSKYS Web — passive 10-second preview of any WordPress site.

This is the ease-of-use front door. One domain input → single HTTPS
GET → public-surface summary. No DNS TXT required, no email required,
no account required. The full pentest still requires ownership proof
(handled by /redemption).

What's legally in bounds:
  * GET / — fetch the public HTML, parse for WordPress fingerprints
  * Check headers (Server, X-Powered-By)
  * Look for wp-admin, wp-content references
  * Check if xmlrpc.php responds (single GET, not a probe)
  * Check TLS version + basic cert info

What we DO NOT do (would require DNS-TXT gate):
  * User enumeration via wp-json
  * Multiple requests / fuzzing / scanning
  * Any CVE check against named plugin versions
  * Any authenticated or exploit-shaped payload

Deployed as:
    /opt/amoskys-web/src/app/web_product/preview_view.py
"""

from __future__ import annotations

import re
import socket
import ssl
import time
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional


SEVERITY_CLASS = {
    "high": "bad",
    "medium": "warn",
    "low": "good",
    "info": "good",
}

SEVERITY_ICON = {
    "high": "❌",
    "medium": "⚠️",
    "low": "✓",
    "info": "ℹ️",
}


def _normalize_target(raw: str) -> Optional[str]:
    """Normalize user input into a scheme-prefixed URL we can GET."""
    raw = (raw or "").strip()
    if not raw:
        return None
    # Drop scheme if present, then add https://
    cleaned = re.sub(r"^https?://", "", raw, flags=re.IGNORECASE)
    cleaned = cleaned.split("/")[0].split("?")[0].strip()
    if not cleaned or " " in cleaned:
        return None
    if not re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", cleaned):
        return None
    return f"https://{cleaned}"


def _tls_info(host: str) -> Dict[str, Any]:
    """Quick TLS probe — just open a socket and grab the cert."""
    out: Dict[str, Any] = {"ok": False, "version": None, "issuer": None, "expires": None}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                out["ok"] = True
                out["version"] = ssock.version()
                cert = ssock.getpeercert()
                if cert:
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    out["issuer"] = issuer.get("organizationName") or issuer.get("commonName")
                    out["expires"] = cert.get("notAfter")
    except Exception:
        pass
    return out


def _fetch(url: str, timeout: float = 8.0):
    """GET the URL once, return (status, headers, body, response_ms)."""
    t0 = time.time()
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 AMOSKYS-Preview/0.2"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body_bytes = resp.read(200_000)  # cap
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return (
                resp.status,
                headers,
                body_bytes.decode("utf-8", errors="replace"),
                int((time.time() - t0) * 1000),
            )
    except Exception as e:
        return (None, None, None, int((time.time() - t0) * 1000), str(e))


def run_preview(target_raw: str) -> Dict[str, Any]:
    """Single-GET passive preview of a domain. Returns view-model dict."""

    url = _normalize_target(target_raw)
    if not url:
        return {
            "error": "That doesn't look like a valid domain. Try `example.com` without the https://.",
        }

    host = urllib.parse.urlparse(url).hostname or ""

    # 1. Reach + basic headers + body
    try:
        fetch = _fetch(url, timeout=8.0)
    except Exception as e:
        return {"error": f"Fetch failed: {type(e).__name__}: {e}"}

    if len(fetch) == 5:
        return {
            "error": f"Couldn't connect to {host}: {fetch[4]}",
            "response_ms": fetch[3],
        }

    status, headers, body, response_ms = fetch
    if not body:
        return {"error": f"{host} responded with status {status} but no body."}

    # 2. TLS
    tls = _tls_info(host)

    # 3. WordPress fingerprint
    is_wp = bool(
        re.search(r"wp-content/|wp-includes/|wp-json/|wp-admin/", body)
        or re.search(r'meta name="generator" content="WordPress', body, re.IGNORECASE)
    )

    wp_version = None
    m = re.search(r'meta name="generator" content="WordPress ([\d.]+)"', body, re.IGNORECASE)
    if m:
        wp_version = m.group(1)

    # 4. Readme exposure (version disclosure)
    readme_exposed = False
    try:
        r = _fetch(f"https://{host}/readme.html", timeout=4.0)
        if len(r) == 4 and r[0] == 200 and r[2] and "WordPress" in r[2]:
            readme_exposed = True
    except Exception:
        pass

    # 5. xmlrpc.php
    xmlrpc_enabled = False
    try:
        r = _fetch(f"https://{host}/xmlrpc.php", timeout=4.0)
        if len(r) == 4 and r[0] == 200 and r[2] and "XML-RPC server accepts POST requests only" in r[2]:
            xmlrpc_enabled = True
    except Exception:
        pass

    # 6. /wp-json root (public API surface)
    rest_api_exposed = False
    try:
        r = _fetch(f"https://{host}/wp-json/", timeout=4.0)
        if len(r) == 4 and r[0] == 200 and r[2] and '"name"' in r[2]:
            rest_api_exposed = True
    except Exception:
        pass

    # 7. Build findings list
    findings = []

    # WordPress detection itself
    if is_wp:
        findings.append({
            "severity_class": "good", "ico": "✓",
            "title": f"WordPress {'v' + wp_version if wp_version else ''} detected",
            "desc": "Your site runs WordPress. AMOSKYS Aegis can protect this site; AMOSKYS Argos can pentest it.",
        })
    else:
        findings.append({
            "severity_class": "warn", "ico": "⚠️",
            "title": "This doesn't look like a WordPress site",
            "desc": "We couldn't find WordPress fingerprints in the public HTML. AMOSKYS Web is WordPress-first today; support for other CMSes is on our roadmap.",
        })

    # Server header disclosure
    server_header = (headers.get("server") or "").strip()
    if server_header and any(c.isdigit() for c in server_header):
        findings.append({
            "severity_class": "warn", "ico": "⚠️",
            "title": f"Server version disclosed: {server_header}",
            "desc": "Attackers use the version in your Server header to match public CVEs to your deployed software.",
        })

    # X-Powered-By disclosure
    xpb = (headers.get("x-powered-by") or "").strip()
    if xpb:
        findings.append({
            "severity_class": "warn", "ico": "⚠️",
            "title": f"X-Powered-By: {xpb}",
            "desc": "The X-Powered-By header is telling the world what runtime you use. Strip this header — it gives attackers free targeting data.",
        })

    # Readme version disclosure
    if readme_exposed:
        findings.append({
            "severity_class": "warn", "ico": "⚠️",
            "title": "WordPress readme.html is publicly accessible",
            "desc": "readme.html exposes your WordPress version to anyone. Block this file in your webserver or delete it.",
        })

    # xmlrpc
    if xmlrpc_enabled:
        findings.append({
            "severity_class": "warn", "ico": "⚠️",
            "title": "/xmlrpc.php is reachable",
            "desc": "XML-RPC is a common brute-force + amplification target. Unless you have a specific need for it, disable or block it.",
        })

    # REST API exposure
    if rest_api_exposed:
        findings.append({
            "severity_class": "low", "ico": "ℹ️",
            "title": "WordPress REST API is public",
            "desc": "/wp-json/ is reachable. This is WordPress default behavior — the full pentest checks if the API leaks user enumeration or exposes unauthenticated routes (EssentialPlugin-class risk).",
        })

    # TLS
    if not tls["ok"]:
        findings.append({
            "severity_class": "bad", "ico": "❌",
            "title": "No TLS or broken TLS",
            "desc": "We couldn't negotiate TLS to your site. This is a critical-severity issue — visitors are transmitting credentials in the clear.",
        })
    elif tls["version"] and tls["version"] in ("TLSv1", "TLSv1.1"):
        findings.append({
            "severity_class": "bad", "ico": "❌",
            "title": f"Deprecated TLS: {tls['version']}",
            "desc": "TLS 1.0/1.1 is deprecated and must be disabled. Attackers can downgrade + break the session.",
        })

    # Count issues by severity
    issues_high = sum(1 for f in findings if f["severity_class"] == "bad")
    issues_med  = sum(1 for f in findings if f["severity_class"] == "warn")
    issues_low  = sum(1 for f in findings if f["severity_class"] == "low")

    return {
        "host": host,
        "response_ms": response_ms,
        "is_wordpress": is_wp,
        "wp_version": wp_version,
        "tls_ok": tls["ok"],
        "tls_version": tls["version"],
        "readme_exposed": readme_exposed,
        "xmlrpc_enabled": xmlrpc_enabled,
        "rest_api_exposed": rest_api_exposed,
        "server_header": server_header,
        "findings": findings,
        "issues_high": issues_high,
        "issues_med": issues_med,
        "issues_low": issues_low,
    }
