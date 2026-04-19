"""ASN / netblock enrichment — map discovered IPs to their owning ASN.

Once we know a customer's external IPs, an ASN lookup tells us:

    - Which AS owns each IP (AS15169=Google, AS13335=Cloudflare, etc.)
    - Whether the IP is behind a CDN (hint: origin may be hiding)
    - The CIDR netblock the IP sits in (useful for later scope expansion)

We use Team Cymru's free whois service — it's passive (just a whois
query, nothing target-facing) and returns ASN+netblock+org for any IP
in one round-trip.

Alternative: `ipinfo.io` JSON API (requires token for volume). Not used
in v1 because we want to ship zero-dependency recon.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from typing import Iterator, List, Optional

from amoskys.agents.Web.argos.recon.base import (
    ReconContext,
    ReconEvent,
    ReconSource,
    StealthClass,
)
from amoskys.agents.Web.argos.storage import AssetKind

logger = logging.getLogger("amoskys.argos.recon.asn")

CYMRU_HOST = "whois.cymru.com"
CYMRU_PORT = 43


class ASNEnrichmentSource(ReconSource):
    """Team Cymru bulk-whois enrichment for discovered IPs."""

    name = "asn.cymru"
    stealth_class = StealthClass.PASSIVE
    description = (
        "Queries Team Cymru's whois service to attach ASN, netblock, "
        "and org info to every discovered IP. Purely passive — does "
        "not touch the target."
    )

    def __init__(
        self,
        timeout_s: float = 10.0,
        connect_fn=None,   # injection point for tests
    ) -> None:
        self.timeout_s = timeout_s
        self._connect = connect_fn or _cymru_bulk_query

    def run(self, context: ReconContext) -> Iterator[ReconEvent]:
        ips = _dedupe_ips(context.known_ips)
        if not ips:
            return

        try:
            rows = self._connect(ips, self.timeout_s)
        except Exception as e:  # noqa: BLE001
            logger.warning("asn.cymru: bulk query failed: %s", e)
            return

        emitted_asns = set()
        emitted_blocks = set()
        for row in rows:
            asn = row.get("asn")
            cidr = row.get("prefix")
            org = row.get("as_name", "")
            ip = row.get("ip")

            if asn and asn not in emitted_asns:
                emitted_asns.add(asn)
                yield ReconEvent(
                    kind=AssetKind.ASN,
                    value=f"AS{asn}",
                    source=self.name,
                    confidence=0.98,
                    parent_value=ip,
                    metadata={"organization": org, "anchor_ip": ip},
                )
            if cidr and cidr not in emitted_blocks:
                emitted_blocks.add(cidr)
                yield ReconEvent(
                    kind=AssetKind.NETBLOCK,
                    value=cidr,
                    source=self.name,
                    confidence=0.98,
                    parent_value=f"AS{asn}" if asn else ip,
                    metadata={"as_name": org, "anchor_ip": ip},
                )


# ── Cymru bulk query ──────────────────────────────────────────────


def _cymru_bulk_query(ips: List[str], timeout_s: float) -> List[dict]:
    """Run one bulk whois query against whois.cymru.com.

    Protocol:
        begin
        verbose
        <ip1>
        <ip2>
        ...
        end

    Response is a table:
        AS      | IP               | BGP Prefix  | CC | Registry | Allocated  | AS Name
        15169   | 8.8.8.8          | 8.8.8.0/24  | US | arin     | 1992-12-01 | GOOGLE
    """
    rows: List[dict] = []

    with socket.create_connection((CYMRU_HOST, CYMRU_PORT), timeout=timeout_s) as sock:
        sock.settimeout(timeout_s)
        payload = "begin\nverbose\n" + "\n".join(ips) + "\nend\n"
        sock.sendall(payload.encode("ascii"))

        chunks: List[bytes] = []
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
        raw = b"".join(chunks).decode("utf-8", errors="replace")

    for line in raw.splitlines():
        if line.startswith("Bulk mode;") or line.startswith("AS ") or not line.strip():
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 7:
            continue
        asn_raw, ip, prefix, cc, registry, allocated, as_name = parts[:7]
        if asn_raw.upper() == "NA" or not asn_raw:
            continue
        rows.append({
            "asn": asn_raw,
            "ip": ip,
            "prefix": prefix,
            "cc": cc,
            "registry": registry,
            "allocated": allocated,
            "as_name": as_name,
        })

    return rows


def _dedupe_ips(ips: List[str]) -> List[str]:
    out: List[str] = []
    seen = set()
    for ip in ips:
        try:
            parsed = ipaddress.ip_address(ip)
        except ValueError:
            continue
        s = str(parsed)
        if s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out
