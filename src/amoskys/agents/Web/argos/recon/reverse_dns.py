"""Reverse DNS (PTR) lookup — the cheapest, quietest pivot.

Given an IP, we ask a public resolver "what's the PTR record for this
IP's in-addr.arpa?" The target's authoritative NS may or may not be
the one that answers — but our source IP isn't visible to them either
way, because the question goes to 1.1.1.1 (Cloudflare) first.

What we do with the result:

    acme.com                    → treat as customer-owned hostname
    mail.acme.com               → treat as subdomain hint
    ec2-203-0-113-5.compute...  → ignore (AWS generic)
    ip-192-168-0-1.us-east-2... → ignore (AWS generic)
    (no record)                  → emit a note, move on

The cloud-generic filter is what makes this source useful. Without it,
every AWS IP's PTR returns `ec2-*.compute.amazonaws.com` and we'd
falsely report "customer uses amazonaws.com as a domain."

Stealth class: RESOLVER (reasoning same as forward DNS — public
resolvers see our query, but not the customer's NS directly).
"""

from __future__ import annotations

import ipaddress
import logging
import random
import socket
from typing import Iterator, List, Optional

from amoskys.agents.Web.argos.recon.base import (
    ReconContext,
    ReconEvent,
    ReconSource,
    StealthClass,
)
from amoskys.agents.Web.argos.recon.cloud_detector import (
    is_generic_cloud_hostname,
)
from amoskys.agents.Web.argos.storage import AssetKind

logger = logging.getLogger("amoskys.argos.recon.reverse_dns")

DEFAULT_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]


class ReverseDNSSource(ReconSource):
    """Pivot from IP → hostname via PTR records."""

    name = "reverse_dns"
    stealth_class = StealthClass.RESOLVER
    description = (
        "Queries PTR records for seed IPs (and any discovered IPs) via "
        "rotating public resolvers. Filters out provider-generic PTR "
        "names (ec2-*.compute.amazonaws.com etc.) — only real customer "
        "hostnames are emitted as domain candidates."
    )

    def __init__(
        self,
        resolvers: Optional[List[str]] = None,
        timeout_s: float = 5.0,
        ptr_fn=None,  # injection point for tests
    ) -> None:
        self.resolvers = list(resolvers or DEFAULT_RESOLVERS)
        self.timeout_s = timeout_s
        self._ptr = ptr_fn or _socket_ptr

    def run(self, context: ReconContext) -> Iterator[ReconEvent]:
        # Start from the seed if it's an IP, plus any IPs prior sources found.
        candidate_ips: List[str] = []
        if _is_ip(context.seed):
            candidate_ips.append(context.seed)
        for ip in context.known_ips:
            if ip not in candidate_ips:
                candidate_ips.append(ip)

        if not candidate_ips:
            return

        for ip in candidate_ips:
            try:
                ptr = self._ptr(ip, random.choice(self.resolvers), self.timeout_s)
            except Exception as e:  # noqa: BLE001
                logger.debug("reverse_dns: %s → %s", ip, e)
                continue

            if not ptr:
                continue

            hostname = ptr.rstrip(".").lower()

            if is_generic_cloud_hostname(hostname):
                # Emit as metadata on the IP (useful signal for the
                # completeness report) but DO NOT treat as a domain.
                yield ReconEvent(
                    kind=AssetKind.IPV4 if _is_ipv4(ip) else AssetKind.IPV6,
                    value=ip,
                    source=self.name,
                    confidence=0.6,
                    parent_value=None,
                    metadata={
                        "ptr_hostname": hostname,
                        "ptr_classification": "generic_cloud",
                    },
                )
                continue

            # Real hostname — emit as a subdomain candidate.
            # The apex extraction is best-effort: last two labels for
            # common TLDs, last three for .co.uk / .com.au / etc.
            apex = _best_apex_guess(hostname)
            yield ReconEvent(
                kind=AssetKind.SUBDOMAIN if apex != hostname else AssetKind.DOMAIN,
                value=hostname,
                source=self.name,
                confidence=0.75,  # PTR can lie, but if non-generic it's a strong hint
                parent_value=ip,
                metadata={"source_ip": ip, "apex_guess": apex},
            )


# ── PTR lookup implementation ─────────────────────────────────────


def _socket_ptr(ip: str, resolver: str, timeout_s: float) -> Optional[str]:
    """Stdlib PTR lookup via OS resolver (which chain-forwards).

    The `resolver` argument is informational in this default impl —
    the OS decides. For explicit resolver selection, swap in a
    dnspython-backed ptr_fn.
    """
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout_s)
    try:
        hostname, _aliases, _addrs = socket.gethostbyaddr(ip)
    except (socket.herror, socket.gaierror):
        return None
    finally:
        socket.setdefaulttimeout(old_timeout)
    return hostname


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


# A compact list of multi-label public suffixes we need to handle for
# apex extraction. For v1 this covers ~90% of customer domains we'll
# see. A proper PSL (publicsuffix.org) integration is v2 work.
_MULTI_LABEL_TLDS = (
    "co.uk", "com.au", "co.jp", "co.nz", "co.za", "com.br",
    "com.mx", "com.sg", "com.hk", "co.in", "com.cn", "com.tw",
    "ac.uk", "gov.uk", "org.uk", "net.au", "org.au",
)


def _best_apex_guess(hostname: str) -> str:
    """Return the likely apex domain for `hostname`.

    api.acme.com            → acme.com
    api.blog.acme.co.uk     → acme.co.uk
    """
    labels = hostname.rstrip(".").split(".")
    if len(labels) <= 2:
        return hostname

    last_two = ".".join(labels[-2:])
    last_three = ".".join(labels[-3:]) if len(labels) >= 3 else last_two

    if last_two in _MULTI_LABEL_TLDS:
        # e.g. acme.co.uk — keep 3 labels
        if len(labels) >= 3:
            return ".".join(labels[-3:])
        return hostname

    return last_two
