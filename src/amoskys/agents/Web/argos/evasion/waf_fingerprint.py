"""WAF fingerprinting and bypass-strategy selection.

Given an HTTP response (or a pair: clean baseline + 403-from-attack-
probe), identify WHICH commercial WAF is in front of the target and
recommend the bypass-corpus to use next.

Commercial WAF fingerprints
---------------------------
  Cloudflare   — `Server: cloudflare`, `CF-RAY` header, `__cfduid`
                 cookie, 403 body mentions "Cloudflare" or "Ray ID"
  Sucuri       — `X-Sucuri-ID`, `X-Sucuri-Cache`, body "Sucuri Website
                 Firewall"
  Wordfence    — Cookie `wfwaf-authcookie-*`, body mentions
                 "Wordfence firewall", server-side 403 response
                 renders the Wordfence block page
  Akamai       — `X-Akamai-*` headers, 403 body mentions "Access
                 Denied" with Akamai reference number
  AWS WAF      — 403 with body "Request blocked", CloudFront Server
                 header, `x-amz-cf-id`
  Imperva      — `X-Iinfo` header, body contains "Incapsula Incident
                 ID"
  F5 BIG-IP ASM — `Server: BigIP`, body "The requested URL was
                 rejected"
  ModSecurity  — Response contains "Mod_Security" or log line
                 `[client 1.2.3.4] ModSecurity: ...`

Known bypasses per WAF
----------------------
Each WAF has a dynamic bypass landscape documented in public research
(Patchstack, PortSwigger, HackTricks, etc.). We encode the
CURRENT best-known bypass vectors as tags the mutate module can
use to prefer specific variants for the identified WAF.

This module doesn't claim universal coverage — each WAF has thousands
of bypass techniques and patches them daily. We document the stable
categories, not the rotating specifics.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class WAFFingerprint:
    """One WAF identification."""

    name: str
    confidence: int  # 0-100
    evidence: List[str] = field(default_factory=list)
    bypass_tags: List[str] = field(default_factory=list)


# ── Per-WAF detector rules ────────────────────────────────────────


def _detect_cloudflare(headers: Dict[str, str], body: str) -> Optional[WAFFingerprint]:
    evidence: List[str] = []
    conf = 0
    for h in ("cf-ray", "cf-cache-status", "cf-connecting-ip"):
        if h in headers:
            evidence.append(f"header:{h}")
            conf += 30
    server = (headers.get("server") or "").lower()
    if "cloudflare" in server:
        evidence.append(f"server:{headers.get('server')}")
        conf += 25
    # Cookie set-cookie-line contains __cfduid / __cf_bm.
    sc = headers.get("set-cookie", "")
    if "__cfduid" in sc or "__cf_bm" in sc:
        evidence.append("cookie:__cf_bm")
        conf += 20
    if body and re.search(r"cloudflare|cf-ray|ray id", body, re.IGNORECASE):
        evidence.append("body:cloudflare-text")
        conf += 15
    if conf == 0:
        return None
    return WAFFingerprint(
        name="Cloudflare",
        confidence=min(100, conf),
        evidence=evidence,
        bypass_tags=[
            # Categories known to bypass or reduce CF score:
            "user-agent-rotation",  # CF tracks UA+IP rep
            "keep-alive-reuse",  # many CF rules gate on new TCP
            "path-case-mutate",  # CF matches URI case-sensitively
            "http2-goaway-evasion",  # CF aggressively enforces HTTP/2
            "managed-challenge-pause",  # pause on 403 + retry after 5m
        ],
    )


def _detect_wordfence(headers: Dict[str, str], body: str) -> Optional[WAFFingerprint]:
    evidence = []
    conf = 0
    sc = headers.get("set-cookie", "")
    if "wfwaf-authcookie" in sc:
        evidence.append("cookie:wfwaf-authcookie")
        conf += 60
    if body and re.search(r"wordfence", body, re.IGNORECASE):
        evidence.append("body:wordfence-text")
        conf += 35
    if body and re.search(r"Wordfence firewall", body, re.IGNORECASE):
        evidence.append("body:wordfence-firewall")
        conf += 30
    if conf == 0:
        return None
    return WAFFingerprint(
        name="Wordfence",
        confidence=min(100, conf),
        evidence=evidence,
        bypass_tags=[
            "sql-keyword-comment",  # Wordfence historically weak on
            # /*!50000SELECT*/ MySQL conditionals
            "utf8-overlong-quote",  # Wordfence normalizes URL-decode
            # once but not overlong UTF-8
            "rest-endpoint-direct",  # Some vulns bypass WF by going
            # directly to /wp-json/... instead
            # of /wp-admin/admin-ajax.php
            "param-pollution",  # WF checks first occurrence of a
            # duplicated param in many contexts
        ],
    )


def _detect_sucuri(headers: Dict[str, str], body: str) -> Optional[WAFFingerprint]:
    evidence = []
    conf = 0
    for h in ("x-sucuri-id", "x-sucuri-cache", "x-sucuri-block"):
        if h in headers:
            evidence.append(f"header:{h}")
            conf += 40
    if body and "sucuri" in body.lower():
        evidence.append("body:sucuri-text")
        conf += 25
    if conf == 0:
        return None
    return WAFFingerprint(
        name="Sucuri",
        confidence=min(100, conf),
        evidence=evidence,
        bypass_tags=[
            "path-encoding-cascade",  # Sucuri aggressive on paths
            "header-case-mutate",
        ],
    )


def _detect_akamai(headers: Dict[str, str], body: str) -> Optional[WAFFingerprint]:
    evidence = []
    conf = 0
    for h in ("x-akamai-transformed", "x-akamai-request-id", "akamai-grn"):
        if h in headers:
            evidence.append(f"header:{h}")
            conf += 35
    if body and re.search(r"akamai|access denied.*reference", body, re.IGNORECASE):
        evidence.append("body:akamai-text")
        conf += 30
    server = (headers.get("server") or "").lower()
    if "akamai" in server:
        evidence.append(f"server:{server}")
        conf += 25
    if conf == 0:
        return None
    return WAFFingerprint(
        name="Akamai",
        confidence=min(100, conf),
        evidence=evidence,
        bypass_tags=[
            "path-case-mutate",
            "http2-large-header",  # Akamai's HTTP/1.1→2 transform
            # sometimes mangles large headers
        ],
    )


def _detect_aws_waf(headers: Dict[str, str], body: str) -> Optional[WAFFingerprint]:
    evidence = []
    conf = 0
    for h in ("x-amz-cf-id", "x-amz-cf-pop"):
        if h in headers:
            evidence.append(f"header:{h}")
            conf += 30
    server = (headers.get("server") or "").lower()
    if "cloudfront" in server:
        evidence.append(f"server:{server}")
        conf += 20
    if body and "request blocked" in body.lower() and "amazon" in body.lower():
        evidence.append("body:aws-waf-blocked")
        conf += 35
    if conf == 0:
        return None
    return WAFFingerprint(
        name="AWS WAF",
        confidence=min(100, conf),
        evidence=evidence,
        bypass_tags=[
            "path-case-mutate",
            "header-fragmentation",
        ],
    )


def _detect_imperva(headers: Dict[str, str], body: str) -> Optional[WAFFingerprint]:
    evidence = []
    conf = 0
    for h in ("x-iinfo", "x-cdn"):
        if h in headers:
            val = headers[h].lower()
            if "imperva" in val or "incapsula" in val or h == "x-iinfo":
                evidence.append(f"header:{h}")
                conf += 40
    if body and re.search(r"incapsula|imperva", body, re.IGNORECASE):
        evidence.append("body:incapsula")
        conf += 35
    if conf == 0:
        return None
    return WAFFingerprint(
        name="Imperva/Incapsula",
        confidence=min(100, conf),
        evidence=evidence,
        bypass_tags=[
            "body-chunked-encoding",
            "method-override",
        ],
    )


def _detect_modsecurity(headers: Dict[str, str], body: str) -> Optional[WAFFingerprint]:
    evidence = []
    conf = 0
    if body and re.search(r"mod_security", body, re.IGNORECASE):
        evidence.append("body:modsecurity-text")
        conf += 50
    server = (headers.get("server") or "").lower()
    if "mod_security" in server:
        evidence.append(f"server:{server}")
        conf += 30
    if conf == 0:
        return None
    return WAFFingerprint(
        name="ModSecurity",
        confidence=min(100, conf),
        evidence=evidence,
        bypass_tags=[
            "sql-keyword-comment",
            "overlong-utf8",
            "param-pollution",
        ],
    )


_DETECTORS = (
    _detect_cloudflare,
    _detect_wordfence,
    _detect_sucuri,
    _detect_akamai,
    _detect_aws_waf,
    _detect_imperva,
    _detect_modsecurity,
)


# ── Public API ────────────────────────────────────────────────────


def fingerprint(headers: Dict[str, str], body: str = "") -> List[WAFFingerprint]:
    """Given one HTTP response (headers + body), return identified WAFs.

    Multiple WAFs can be stacked; each gets its own WAFFingerprint.
    Headers dict keys should be lowercased by the caller.
    """
    out: List[WAFFingerprint] = []
    for det in _DETECTORS:
        f = det({k.lower(): v for k, v in (headers or {}).items()}, body or "")
        if f:
            out.append(f)
    return sorted(out, key=lambda w: -w.confidence)


def recommend_bypass_layers(waf_names: List[str]) -> List[str]:
    """Given identified WAFs, produce a ranked list of mutation/encoding
    layers (matching encode._ENCODER_REGISTRY keys) to prefer.

    This drives the mutate.py layer-ordering when a specific WAF is
    detected. Unknown WAF → use the general-purpose ranking.
    """
    name_set = {n.lower() for n in waf_names}
    layers: List[str] = []
    if "wordfence" in name_set:
        layers += ["sql_keyword", "utf8_overlong", "case", "comment"]
    if "cloudflare" in name_set:
        layers += ["case", "url2", "whitespace"]
    if "modsecurity" in name_set:
        layers += ["sql_keyword", "utf8_overlong", "comment"]
    if "imperva/incapsula" in name_set:
        layers += ["url2", "comment"]
    if "sucuri" in name_set:
        layers += ["url2", "case"]
    if "akamai" in name_set:
        layers += ["case", "url"]
    if "aws waf" in name_set:
        layers += ["case", "url"]
    if not layers:
        # Default stack for unknown WAF.
        layers = ["case", "comment", "url"]
    # Dedup preserving order.
    seen = set()
    out: List[str] = []
    for layer in layers:
        if layer not in seen:
            out.append(layer)
            seen.add(layer)
    return out
