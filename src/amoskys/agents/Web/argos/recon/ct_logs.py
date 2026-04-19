"""Certificate Transparency log recon — crt.sh query.

Every TLS cert a customer has ever issued through a public CA ends up
in a CT log. Querying crt.sh yields every subdomain that ever appeared
on a cert — historical + current.

This is the best stealth source we have:

    - Zero traffic to the customer's infrastructure
    - Discovers subdomains the customer may have forgotten about
      (old staging, decommissioned services with lingering DNS)
    - Those "forgotten" assets are exactly where the bugs live

crt.sh offers a JSON API; we paginate, dedupe, and emit one event per
unique (sub)domain.

If crt.sh is down or rate-limits us, we fall through to alternative
CT sources (api.certspotter.com) as future extension — not in v1.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Iterator, List, Optional, Set

from amoskys.agents.Web.argos.recon.base import (
    ReconContext,
    ReconEvent,
    ReconSource,
    StealthClass,
)
from amoskys.agents.Web.argos.storage import AssetKind

logger = logging.getLogger("amoskys.argos.recon.ct_logs")

CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
DEFAULT_TIMEOUT = 30.0
# crt.sh is slow at times; single-retry posture.
MAX_RETRIES = 2


class CertTransparencyLogs(ReconSource):
    """crt.sh certificate transparency log enumerator."""

    name = "ct_logs.crtsh"
    stealth_class = StealthClass.PASSIVE
    description = (
        "Queries crt.sh (public Certificate Transparency log mirror) for "
        "every subdomain ever issued a cert for the seed domain. "
        "Zero traffic to the target."
    )

    def __init__(
        self,
        timeout_s: float = DEFAULT_TIMEOUT,
        max_retries: int = MAX_RETRIES,
        http_get=None,   # injection point for tests
    ) -> None:
        self.timeout_s = timeout_s
        self.max_retries = max_retries
        self._http_get = http_get or self._default_http_get

    def run(self, context: ReconContext) -> Iterator[ReconEvent]:
        seed = _normalize_domain(context.seed)
        if not seed or not _looks_like_domain(seed):
            logger.info(
                "ct_logs.crtsh: seed %r is not a domain (skipping)", context.seed
            )
            return

        url = CRTSH_URL.format(domain=urllib.parse.quote(seed))
        data = self._fetch_with_retries(url)
        if not data:
            return

        seen: Set[str] = set()
        seen.add(seed)  # seed itself is always an asset, emitted once

        yield ReconEvent(
            kind=AssetKind.DOMAIN,
            value=seed,
            source=self.name,
            confidence=1.0,
            metadata={"discovered_via": "seed"},
        )

        for entry in data:
            if not isinstance(entry, dict):
                continue
            name_value = entry.get("name_value", "")
            if not isinstance(name_value, str):
                continue
            # crt.sh often packs multiple SANs into one name_value with \n
            for raw in name_value.splitlines():
                candidate = _clean_candidate(raw, seed)
                if not candidate:
                    continue
                if candidate in seen:
                    continue
                seen.add(candidate)

                yield ReconEvent(
                    kind=AssetKind.SUBDOMAIN,
                    value=candidate,
                    source=self.name,
                    confidence=0.95,  # CT is highly authoritative
                    parent_value=seed,
                    metadata={
                        "ct_entry_id": entry.get("id"),
                        "issuer_ca_id": entry.get("issuer_ca_id"),
                    },
                )

    # ── HTTP plumbing ──────────────────────────────────────────────

    def _fetch_with_retries(self, url: str) -> Optional[list]:
        last_err: Optional[str] = None
        for attempt in range(self.max_retries + 1):
            try:
                raw = self._http_get(url, self.timeout_s)
            except urllib.error.HTTPError as e:
                last_err = f"HTTP {e.code} from crt.sh"
                if e.code in (429, 503):
                    # crt.sh is hammered; back off more aggressively.
                    time.sleep(5.0 * (attempt + 1))
                    continue
                logger.warning("%s: %s", self.name, last_err)
                return None
            except urllib.error.URLError as e:
                last_err = f"URLError: {e.reason}"
                time.sleep(2.0 * (attempt + 1))
                continue

            try:
                return json.loads(raw)
            except json.JSONDecodeError as e:
                last_err = f"JSONDecodeError: {e}"
                logger.warning("%s: %s", self.name, last_err)
                return None

        logger.warning("%s: failed after %d retries: %s",
                       self.name, self.max_retries, last_err)
        return None

    @staticmethod
    def _default_http_get(url: str, timeout_s: float) -> bytes:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Argos-Recon/0.1 (+https://amoskys.com/argos)"},
        )
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return resp.read()


# ── Helpers ────────────────────────────────────────────────────────


def _normalize_domain(seed: str) -> str:
    t = seed.strip().lower()
    # Strip scheme/port/path if someone passed a URL.
    if "://" in t:
        t = t.split("://", 1)[1]
    t = t.split("/", 1)[0]
    t = t.split(":", 1)[0]
    # Strip leading wildcard markers (e.g. "*.example.com" → "example.com")
    if t.startswith("*."):
        t = t[2:]
    return t


def _looks_like_domain(value: str) -> bool:
    if not value or "." not in value:
        return False
    # Crude but effective: all dot-separated labels are valid chars
    for label in value.split("."):
        if not label:
            return False
        if not all(c.isalnum() or c == "-" for c in label):
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
    return True


def _clean_candidate(raw: str, seed: str) -> Optional[str]:
    """Normalize one crt.sh name-value entry to a usable (sub)domain.

    Returns None if:
      - It's a wildcard (*.example.com) — we record the apex elsewhere
      - It's not actually under the seed domain (CT entries for other
        SANs on the same cert — rare but possible)
      - It contains characters suggesting it's not a DNS name
    """
    t = raw.strip().lower()
    if not t:
        return None
    # Drop wildcard markers — the apex is already emitted
    if t.startswith("*."):
        t = t[2:]
    if not _looks_like_domain(t):
        return None
    # Scope to the seed domain: must equal it OR be a subdomain of it.
    if t == seed:
        return None  # already emitted as apex
    if not t.endswith("." + seed):
        return None
    return t
