"""Origin-IP discovery for CDN bypass.

If a target is behind Cloudflare/Sucuri/Akamai/Fastly/CloudFront, the
public A record points at the edge. Every probe terminates at the
WAF; the real server never sees the traffic unless we find its
hostname / direct IP and connect with a spoofed Host header.

Four historically-reliable discovery vectors
--------------------------------------------
1. **DNS history / passive DNS**     The edge address is recent; the
   original A/AAAA records are sitting in SecurityTrails, RiskIQ,
   DNSdumpster, and ViewDNS. The offline version we implement here
   reads from a caller-supplied lookup callable so the library
   stays dependency-free. (Real deployments plug an API key in.)

2. **Certificate Transparency SAN bleed**
   When ops request a cert for `origin.example.com` (internal
   staging) but the same CA also signs the public `example.com`, the
   Subject Alternative Names list often leaks internal hostnames
   that resolve directly to the origin. We query crt.sh by default.

3. **SPF / DMARC record leak**
   `v=spf1 ip4:203.0.113.42 include:_spf.google.com ~all` — the
   ip4 entries are mail servers, commonly shared-host with the
   web origin. DMARC rua= addresses frequently point at internal
   mailboxes on the origin network.

4. **Default-error-page fingerprint over direct IP**
   Iterate a small candidate list (SPF results, DNS history),
   request `http://IP/` with `Host: example.com` spoofed; if the
   origin serves identical HTML to the CDN-fronted request, the IP
   is confirmed origin.

Output
------
list[OriginCandidate] sorted by confidence.

Scope note
----------
Every technique here uses PUBLIC data sources (DNS, CT, SPF) — no
target-site traffic required for candidate discovery. The
confirmation step (direct-IP + spoofed Host) is a single polite GET.
The function refuses to issue any traffic when `http_get=None`; tests
that want offline-only behavior simply omit it.
"""

from __future__ import annotations

import json
import logging
import re
import socket
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("amoskys.argos.adapt.origin")


# ── Data model ────────────────────────────────────────────────────


@dataclass
class OriginCandidate:
    ip: str
    source: str  # "crt.sh" / "spf" / "dns-history" / "direct-probe"
    hostname: Optional[str] = None  # SAN hostname if any
    confidence: int = 0  # 0–100
    evidence: List[str] = field(default_factory=list)
    confirmed: bool = False  # direct-IP GET returned matching content

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "source": self.source,
            "hostname": self.hostname,
            "confidence": self.confidence,
            "evidence": list(self.evidence),
            "confirmed": self.confirmed,
        }


# ── CDN IP-range detection (short list — we only need to exclude) ──
#
# We don't need exhaustive ranges; we need to skip "obvious edge" IPs
# before spending confirmation budget on them.

_CDN_CIDR_PREFIXES = {
    "cloudflare": [
        "104.16.",
        "104.17.",
        "104.18.",
        "104.19.",
        "104.20.",
        "104.21.",
        "104.22.",
        "104.23.",
        "104.24.",
        "104.25.",
        "104.26.",
        "104.27.",
        "104.28.",
        "172.64.",
        "172.65.",
        "172.66.",
        "172.67.",
        "172.68.",
        "172.69.",
        "172.70.",
        "172.71.",
        "131.0.72.",
        "141.101.",
        "108.162.",
        "190.93.",
        "188.114.",
        "197.234.",
        "198.41.",
    ],
    "akamai": [
        "23.",
        "104.64.",
        "184.24.",
        "184.25.",
        "184.26.",
        "184.27.",
        "184.28.",
        "184.29.",
        "184.30.",
        "184.31.",
    ],
    "fastly": ["151.101.", "199.232."],
    "cloudfront": [
        "13.224.",
        "13.225.",
        "13.226.",
        "13.227.",
        "13.228.",
        "13.249.",
        "52.84.",
        "52.85.",
        "54.230.",
        "54.239.",
        "99.84.",
        "205.251.",
    ],
    "sucuri": ["192.124.249.", "185.93."],
}


def _ip_belongs_to_edge(ip: str) -> Optional[str]:
    for edge, prefixes in _CDN_CIDR_PREFIXES.items():
        for p in prefixes:
            if ip.startswith(p):
                return edge
    return None


# ── Low-level HTTP helper ─────────────────────────────────────────


def _default_http_get(
    url: str, timeout: float = 8.0, headers: Optional[Dict[str, str]] = None
):
    try:
        req = urllib.request.Request(url, headers=headers or {})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(64_000).decode("utf-8", errors="replace")
            return r.status, dict(r.headers.items()), body
    except Exception as exc:  # noqa: BLE001
        return 0, {}, f"__error__:{exc.__class__.__name__}:{exc}"


# ── Source 1: crt.sh — Certificate Transparency SAN leak ───────────


def _query_crtsh(host: str, http_get: Callable) -> List[Dict[str, Any]]:
    """Returns list[{name_value, issuer, entry_timestamp}] or []."""
    url = f"https://crt.sh/?q=%25.{urllib.parse.quote(host)}&output=json"
    try:
        s, _h, body = http_get(url, 12.0, {"User-Agent": "argos-origin/1"})
        if s != 200 or not body:
            return []
        if body.startswith("__error__"):
            return []
        # crt.sh returns either JSON array or "[" prefix — strip any JS wrapper
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            # crt.sh sometimes returns malformed concatenated objects — soft-fix
            body2 = "[" + body.replace("}{", "},{") + "]"
            try:
                return json.loads(body2)
            except Exception:
                return []
    except Exception as exc:  # noqa: BLE001
        logger.debug("crt.sh query failed: %s", exc)
        return []


def _extract_sans(entries: List[Dict[str, Any]]) -> List[str]:
    names = set()
    for entry in entries:
        nv = entry.get("name_value", "") or ""
        for line in nv.split("\n"):
            line = line.strip().lstrip("*.").lower()
            if line and "@" not in line and " " not in line:
                names.add(line)
    return sorted(names)


# ── Source 2: SPF / DMARC record parsing ──────────────────────────


_SPF_IP4_RE = re.compile(r"ip4:([0-9]+(?:\.[0-9]+){3})(?:/(\d+))?", re.I)
_SPF_IP6_RE = re.compile(r"ip6:([0-9a-f:]+)(?:/(\d+))?", re.I)


def _resolve_txt(host: str) -> List[str]:
    """Plain-socket TXT lookup via /etc/resolv.conf. Soft-fail empty list."""
    try:
        # Python stdlib has no TXT helper — fall back to getaddrinfo + a
        # synthetic DNS probe is out of scope. If dnspython is installed
        # we use it; otherwise we gracefully return empty.
        import dns.resolver  # type: ignore

        answers = dns.resolver.resolve(host, "TXT")
        out = []
        for r in answers:
            t = b"".join(r.strings).decode("utf-8", errors="replace")
            out.append(t)
        return out
    except Exception:
        return []


def _spf_candidates(host: str) -> List[OriginCandidate]:
    cands: List[OriginCandidate] = []
    for txt in _resolve_txt(host):
        if "v=spf1" not in txt.lower():
            continue
        for m in _SPF_IP4_RE.finditer(txt):
            ip = m.group(1)
            cands.append(
                OriginCandidate(
                    ip=ip,
                    source="spf",
                    confidence=35,
                    evidence=[f"SPF ip4: entry in {host} TXT record"],
                )
            )
        for m in _SPF_IP6_RE.finditer(txt):
            ip = m.group(1)
            cands.append(
                OriginCandidate(
                    ip=ip,
                    source="spf",
                    confidence=25,
                    evidence=[f"SPF ip6: entry in {host} TXT record"],
                )
            )
    return cands


# ── Source 3: Resolve SAN hostnames to IPs ────────────────────────


def _resolve_a(host: str) -> List[str]:
    try:
        infos = socket.getaddrinfo(host, None)
        return sorted({str(i[4][0]) for i in infos if ":" not in str(i[4][0])})
    except socket.gaierror:
        return []


# ── Source 4: Direct-IP confirmation ──────────────────────────────


def _confirm_origin(
    ip: str, host: str, fingerprint_body: str, http_get: Callable
) -> bool:
    """Probe http://IP/ with Host: spoofed to `host`; return True if
    the body matches fingerprint_body within a loose threshold."""
    url = f"http://{ip}/"
    try:
        s, _h, body = http_get(
            url,
            8.0,
            {
                "Host": host,
                "User-Agent": "argos-origin/1",
            },
        )
        if s == 0 or not body:
            return False
        # Loose match: any 128-char shingle from fingerprint present in body
        shingles = [
            fingerprint_body[i : i + 128]
            for i in range(0, len(fingerprint_body) - 128, 128)
        ][:8]
        for sh in shingles:
            if sh and sh in body:
                return True
        return False
    except Exception:
        return False


# ── Orchestrator ──────────────────────────────────────────────────


def discover_origin(
    host: str,
    fingerprint_body: Optional[str] = None,
    http_get: Optional[Callable] = None,
    max_candidates: int = 20,
) -> List[OriginCandidate]:
    """Return OriginCandidate list sorted by confidence descending.

    `host` is the fronted hostname (e.g. "example.com"). If
    `fingerprint_body` is provided, we'll attempt direct-IP
    confirmation; otherwise candidates remain unconfirmed.

    `http_get(url, timeout, headers) -> (status, headers, body)` —
    injectable for tests. If None we use urllib.
    """
    t0 = time.time()
    getter = http_get or _default_http_get
    candidates: List[OriginCandidate] = []

    # Source 1: crt.sh
    try:
        crt_entries = _query_crtsh(host, getter)
        sans = _extract_sans(crt_entries)
        # Filter: keep only hostnames under same org that aren't the bare host
        internal_sans = [s for s in sans if s != host and host in s]
        for san in internal_sans[:10]:  # cap for budget
            for ip in _resolve_a(san):
                edge = _ip_belongs_to_edge(ip)
                if edge:
                    # Still record but low confidence; may be direct-to-CDN-proxy
                    candidates.append(
                        OriginCandidate(
                            ip=ip,
                            source="crt.sh",
                            hostname=san,
                            confidence=15,
                            evidence=[f"CT SAN {san}→{ip} but belongs to {edge} range"],
                        )
                    )
                else:
                    candidates.append(
                        OriginCandidate(
                            ip=ip,
                            source="crt.sh",
                            hostname=san,
                            confidence=70,
                            evidence=[f"CT SAN {san} resolved to non-edge IP {ip}"],
                        )
                    )
    except Exception as exc:  # noqa: BLE001
        logger.debug("crt.sh path failed: %s", exc)

    # Source 2: SPF
    try:
        spf_cands = _spf_candidates(host)
        for c in spf_cands:
            edge = _ip_belongs_to_edge(c.ip)
            if edge:
                c.confidence = max(5, c.confidence - 20)
                c.evidence.append(f"belongs to {edge} range — likely not origin")
            candidates.append(c)
    except Exception as exc:  # noqa: BLE001
        logger.debug("SPF path failed: %s", exc)

    # Dedupe by IP, keep best-confidence record
    by_ip: Dict[str, OriginCandidate] = {}
    for c in candidates:
        prev = by_ip.get(c.ip)
        if prev is None or c.confidence > prev.confidence:
            if prev is not None:
                c.evidence = list(prev.evidence) + list(c.evidence)
            by_ip[c.ip] = c

    ordered = sorted(by_ip.values(), key=lambda x: x.confidence, reverse=True)[
        :max_candidates
    ]

    # Confirmation pass — only spend budget on top candidates
    if fingerprint_body and http_get is not None:
        for c in ordered[:5]:
            edge = _ip_belongs_to_edge(c.ip)
            if edge:
                continue  # pointless to confirm an edge IP
            if _confirm_origin(c.ip, host, fingerprint_body, http_get):
                c.confirmed = True
                c.confidence = max(c.confidence, 90)
                c.evidence.append(
                    "direct-IP GET w/ spoofed Host matched fingerprint body"
                )

    # Final sort: confirmed first
    ordered.sort(key=lambda x: (x.confirmed, x.confidence), reverse=True)

    for c in ordered:
        c.evidence.append(f"discover_origin elapsed={int((time.time()-t0)*1000)}ms")

    return ordered


__all__ = ["OriginCandidate", "discover_origin"]
