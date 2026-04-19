"""IP WHOIS — passive org attribution for a seed IP.

Team Cymru gives us ASN + netblock (existing source). This module adds
richer attribution: OrgName, abuse contacts, and often a customer URL
in the Comment field. Useful for:

    - Confirming the IP is actually the customer's (OrgName match)
    - Discovering additional customer domains (URLs in comments)
    - Picking the right abuse-contact email if we need to hand-off

We use ARIN's port-43 whois service. ARIN redirects to RIPE/APNIC/LACNIC
/AFRINIC for non-ARIN IPs transparently. One query per seed IP is enough
— we don't iterate over discovered IPs (Cymru already enriched those).

Fully passive: the customer's infra never sees this query.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
from typing import Dict, Iterator, List, Optional

from amoskys.agents.Web.argos.recon.base import (
    ReconContext,
    ReconEvent,
    ReconSource,
    StealthClass,
)
from amoskys.agents.Web.argos.storage import AssetKind

logger = logging.getLogger("amoskys.argos.recon.ip_whois")

WHOIS_HOST = "whois.arin.net"
WHOIS_PORT = 43

# Fields we care about across RIR responses. Keys vary by RIR — we parse
# the common ones. ARIN uses `OrgName:`, RIPE uses `descr:` + `org:`,
# APNIC uses `netname:` + `descr:`.
_FIELD_ALIASES = {
    "org_name": ("OrgName:", "org-name:", "owner:", "netname:", "organisation:"),
    "org_id": ("OrgId:", "org:", "owner-id:"),
    "country": ("Country:", "country:"),
    "abuse_email": ("OrgAbuseEmail:", "abuse-mailbox:", "abuse-c:", "e-mail:"),
    "tech_email": ("OrgTechEmail:",),
    "comment": ("Comment:", "remarks:", "descr:"),
    "ref_url": ("Ref:",),
    "cidr": ("CIDR:", "inetnum:", "NetRange:", "route:"),
}

_URL_RE = re.compile(r"https?://[^\s<>'\"()]+", re.IGNORECASE)


class IPWHOISSource(ReconSource):
    """WHOIS lookup on the seed IP — parses OrgName + comments + URLs."""

    name = "ip_whois"
    stealth_class = StealthClass.PASSIVE
    description = (
        "One WHOIS query (port 43, ARIN) for the seed IP to attribute "
        "ownership and extract any customer URLs from the Comment "
        "field. Passive — customer infra sees nothing."
    )

    def __init__(
        self,
        whois_host: str = WHOIS_HOST,
        timeout_s: float = 10.0,
        query_fn=None,  # injection point for tests
    ) -> None:
        self.whois_host = whois_host
        self.timeout_s = timeout_s
        self._query = query_fn or _arin_query

    def run(self, context: ReconContext) -> Iterator[ReconEvent]:
        # Only run if the seed is an IP; domain seeds skip this source.
        if not _is_ip(context.seed):
            return

        try:
            raw = self._query(context.seed, self.whois_host, self.timeout_s)
        except Exception as e:  # noqa: BLE001
            logger.warning("ip_whois: %s query failed: %s", context.seed, e)
            return

        if not raw:
            return

        parsed = _parse_whois(raw)

        # Emit the org as metadata on the seed IP
        ip_kind = AssetKind.IPV4 if _is_ipv4(context.seed) else AssetKind.IPV6
        yield ReconEvent(
            kind=ip_kind,
            value=context.seed,
            source=self.name,
            confidence=0.9,
            metadata={
                "whois": {
                    "org_name": parsed.get("org_name"),
                    "org_id": parsed.get("org_id"),
                    "country": parsed.get("country"),
                    "abuse_email": parsed.get("abuse_email"),
                    "tech_email": parsed.get("tech_email"),
                    "cidr": parsed.get("cidr"),
                },
            },
        )

        # Extract any URLs from Comment / Description → domain candidates
        url_text = " ".join([
            parsed.get("comment", "") or "",
            parsed.get("ref_url", "") or "",
        ])
        for url in _URL_RE.findall(url_text):
            host = _host_from_url(url)
            if not host:
                continue
            # Apex or subdomain depending on label count
            kind = AssetKind.DOMAIN if host.count(".") == 1 else AssetKind.SUBDOMAIN
            yield ReconEvent(
                kind=kind,
                value=host,
                source=self.name,
                confidence=0.7,  # URLs in whois comments are often outdated but still useful hints
                parent_value=context.seed,
                metadata={
                    "discovered_via": "whois_comment_url",
                    "source_url": url,
                },
            )


# ── WHOIS query implementation ────────────────────────────────────


def _arin_query(ip: str, host: str, timeout_s: float) -> str:
    """One-shot WHOIS query via port 43.

    ARIN supports the `+` prefix to request detailed output and will
    redirect to the right RIR for non-ARIN IPs. We use `n + <ip>` to
    query network records.
    """
    query = f"n + {ip}\r\n"
    with socket.create_connection((host, WHOIS_PORT), timeout=timeout_s) as sock:
        sock.settimeout(timeout_s)
        sock.sendall(query.encode("ascii"))

        chunks: List[bytes] = []
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks).decode("utf-8", errors="replace")


# ── Parsing ────────────────────────────────────────────────────────


def _parse_whois(raw: str) -> Dict[str, str]:
    """Extract known fields. Accumulates Comment / Description lines."""
    out: Dict[str, str] = {}
    multi_accum: Dict[str, List[str]] = {}

    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("%"):
            continue

        for canonical, aliases in _FIELD_ALIASES.items():
            for alias in aliases:
                if stripped.lower().startswith(alias.lower()):
                    value = stripped[len(alias):].strip()
                    if not value:
                        continue
                    if canonical in ("comment", "ref_url"):
                        multi_accum.setdefault(canonical, []).append(value)
                    else:
                        # First-wins for single-valued fields (top record)
                        out.setdefault(canonical, value)
                    break

    for key, lines in multi_accum.items():
        out[key] = " ".join(lines)

    return out


# ── Helpers ────────────────────────────────────────────────────────


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def _host_from_url(url: str) -> Optional[str]:
    # Lightweight — avoid urllib.parse quirks on malformed WHOIS text
    if "://" in url:
        rest = url.split("://", 1)[1]
    else:
        rest = url
    rest = rest.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    rest = rest.split(":", 1)[0].strip().lower().rstrip(".")
    if not rest or "." not in rest:
        return None
    # Filter: no spaces, all labels are DNS-legal
    for label in rest.split("."):
        if not label:
            return None
        if not all(c.isalnum() or c == "-" for c in label):
            return None
    return rest
