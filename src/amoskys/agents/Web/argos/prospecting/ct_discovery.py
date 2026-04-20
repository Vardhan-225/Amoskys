"""Certificate-Transparency discovery.

Uses the public crt.sh JSON API to find domains matching a seed
keyword or organization name. CT logs are mandatory for every
publicly-trusted certificate (RFC 6962, RFC 9162), so every TLS-
serving site worldwide is indexed in at least one log.

Legal basis
───────────
CT logs are explicitly public by spec. CAs are required to submit
every cert they issue. Querying the logs is equivalent to reading
a phone book — there is no authentication boundary, and no
reasonable expectation of privacy. This is the same data source
Shodan, Censys, and all reputable OSINT tooling use.

Stealth
───────
We rate-limit crt.sh queries (1 req every 2s default). crt.sh has
no authentication and its operators publish the full archive at
https://crt.sh/atom — so querying is essentially free. We never
query the same term twice in a session.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

logger = logging.getLogger("amoskys.argos.prospecting.ct")

_CRT_SH_URL = "https://crt.sh/?q={query}&output=json"
_DEFAULT_TIMEOUT = 20.0


@dataclass
class CTDiscoveryResult:
    query:         str
    raw_count:     int
    unique_domains: List[str] = field(default_factory=list)
    errors:        List[str] = field(default_factory=list)
    queried_at:    float = 0.0


def _fetch_crtsh(query: str, timeout: float = _DEFAULT_TIMEOUT,
                 http_get=None, retries: int = 3,
                 retry_backoff_s: float = 2.0) -> Optional[str]:
    """Low-level fetch. `http_get` is injectable for tests.

    crt.sh is a free community service and occasionally returns 502/503.
    We retry up to `retries` times with exponential backoff before
    giving up. A return of None after all retries means the caller
    should either try a different seed or supply a manual domain list
    via find_wp_prospects_from_domain_list().
    """
    url = _CRT_SH_URL.format(query=urllib.parse.quote(query))
    if http_get is not None:
        return http_get(url)

    last_err = None
    for attempt in range(retries):
        if attempt > 0:
            # Exponential backoff with small jitter.
            import random as _r
            delay = retry_backoff_s * (2 ** (attempt - 1)) * _r.uniform(0.8, 1.2)
            logger.info("crt.sh retry %d/%d after %.1fs (last: %s)",
                        attempt + 1, retries, delay, last_err)
            time.sleep(delay)
        req = urllib.request.Request(url, headers={
            "User-Agent": "AMOSKYS-Argos-Prospecting/1.0 (+https://amoskys.com)",
            "Accept":     "application/json",
        })
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status != 200:
                    last_err = f"HTTP {resp.status}"
                    continue
                return resp.read(8 * 1024 * 1024).decode("utf-8", errors="replace")
        except Exception as e:  # noqa: BLE001
            last_err = f"{type(e).__name__}: {e}"
            continue
    logger.warning("crt.sh fetch exhausted retries for %r: %s", query, last_err)
    return None


def _registered_domain(host: str) -> str:
    """Best-effort eTLD+1 extraction without a PSL.

    We collapse `*.example.co.uk` to `example.co.uk` and
    `blog.shop.example.com` to `example.com` using a simple 2-label
    fallback with a small multi-suffix allow-list. This is good enough
    for ranking; precise eTLD+1 requires publicsuffix2.
    """
    host = host.lower().strip().lstrip("*.")
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    # Multi-suffix handling for the common country-code ccTLDs.
    multi = {"co.uk", "ac.uk", "gov.uk", "com.au", "com.br", "co.in",
             "co.jp", "co.za", "com.mx", "com.sg"}
    tail_2 = ".".join(parts[-2:])
    tail_3 = ".".join(parts[-3:])
    if tail_2 in multi:
        return tail_3
    return tail_2


def discover_domains_via_ct(query: str, max_results: int = 500,
                            http_get=None) -> CTDiscoveryResult:
    """Return unique registered domains appearing in certs matching `query`.

    Args:
        query:       Search term — organization name, keyword, subdomain.
                     Example: "acme" or "yoga-studio" or "bakery.com".
        max_results: Cap on unique domains returned (sorted alphabetically).
        http_get:    Optional override — call signature is fn(url) -> body_str.
                     Tests inject a mock; production path uses urllib.

    Returns:
        CTDiscoveryResult with unique_domains populated, or errors logged.
    """
    body = _fetch_crtsh(query, http_get=http_get)
    if not body:
        return CTDiscoveryResult(
            query=query, raw_count=0, unique_domains=[],
            errors=[f"crt.sh returned empty/error for {query!r}"],
            queried_at=time.time(),
        )

    try:
        rows = json.loads(body)
    except json.JSONDecodeError as e:
        return CTDiscoveryResult(
            query=query, raw_count=0, unique_domains=[],
            errors=[f"json decode error: {e}"],
            queried_at=time.time(),
        )
    if not isinstance(rows, list):
        return CTDiscoveryResult(
            query=query, raw_count=0, unique_domains=[],
            errors=["crt.sh returned non-list JSON"],
            queried_at=time.time(),
        )

    unique: Set[str] = set()
    for row in rows:
        # Each row has common_name + name_value (newline-separated SANs).
        cn = str(row.get("common_name") or "").strip()
        sans = str(row.get("name_value") or "").splitlines()
        for host in [cn] + sans:
            host = host.strip().lower()
            if not host or "@" in host:  # skip email CNs
                continue
            if host.startswith("*."):
                host = host[2:]
            # Filter to DNS-looking entries.
            if "." not in host:
                continue
            if any(c.isspace() for c in host):
                continue
            unique.add(_registered_domain(host))

    domains = sorted(unique)
    return CTDiscoveryResult(
        query=query,
        raw_count=len(rows),
        unique_domains=domains[:max_results],
        queried_at=time.time(),
    )
