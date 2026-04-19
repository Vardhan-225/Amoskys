"""DNS resolution recon — bulk resolve subdomains via rotating public resolvers.

The subdomains CT logs discovered need to be resolved to IPs so the
hunt phase can scan them. We deliberately DO NOT query the customer's
authoritative nameservers — that would leak our reconnaissance pattern
back to their ops team. Public resolvers are the right hop:

    - 1.1.1.1  (Cloudflare)
    - 8.8.8.8  (Google)
    - 9.9.9.9  (Quad9)

Queries spread across all three round-robin. Each resolver sees ~1/3 of
our queries; the target's authoritative NS sees a normal cache-miss
pattern instead of a burst from one source.

Why this is stealth-class RESOLVER not PASSIVE:
    The target's NS operator *does* ultimately see the query (cache
    miss → recursion to authoritative). But (a) it's indistinguishable
    from a user's browser query, and (b) it's spread across providers
    instead of sourced from our IP.
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
from amoskys.agents.Web.argos.storage import AssetKind

logger = logging.getLogger("amoskys.argos.recon.dns_resolve")

DEFAULT_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]


class DNSResolveSource(ReconSource):
    """Resolves known subdomains to A / AAAA records.

    Consumes subdomains from the shared ReconContext (populated by CT
    logs etc.) and emits one ReconEvent per (subdomain, ip) pair.
    """

    name = "dns_resolve"
    stealth_class = StealthClass.RESOLVER
    description = (
        "Resolves each known (sub)domain to its A/AAAA records via "
        "rotating public DNS resolvers. Emits IPv4/IPv6 assets linked "
        "back to their parent hostname."
    )

    def __init__(
        self,
        resolvers: Optional[List[str]] = None,
        timeout_s: float = 5.0,
        resolver_fn=None,   # injection point for tests
    ) -> None:
        self.resolvers = list(resolvers or DEFAULT_RESOLVERS)
        self.timeout_s = timeout_s
        self._resolve = resolver_fn or _socket_resolve

    def run(self, context: ReconContext) -> Iterator[ReconEvent]:
        # Always include the seed, plus everything prior sources found.
        hostnames: List[str] = []
        seen = set()
        for h in [context.seed] + list(context.known_subdomains):
            if h and h not in seen:
                seen.add(h)
                hostnames.append(h)

        if not hostnames:
            return

        for hostname in hostnames:
            try:
                ips = self._resolve(hostname, random.choice(self.resolvers),
                                    self.timeout_s)
            except Exception as e:  # noqa: BLE001
                logger.debug("dns_resolve: %s → %s", hostname, e)
                continue
            for ip in ips:
                try:
                    parsed = ipaddress.ip_address(ip)
                except ValueError:
                    continue
                kind = AssetKind.IPV4 if parsed.version == 4 else AssetKind.IPV6
                yield ReconEvent(
                    kind=kind,
                    value=str(parsed),
                    source=self.name,
                    confidence=0.9,
                    parent_value=hostname,
                    metadata={"hostname": hostname},
                )


# ── Default resolver ──────────────────────────────────────────────


def _socket_resolve(hostname: str, resolver: str, timeout_s: float) -> List[str]:
    """Resolve A + AAAA via the OS resolver.

    The `resolver` argument is informational in this default
    implementation (the OS chooses its own). For real rotation, the
    caller should swap in a dnspython-backed resolver_fn. Stub here
    keeps v1 dependency-free.
    """
    # Use getaddrinfo to return both IPv4 and IPv6.
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout_s)
    try:
        infos = socket.getaddrinfo(
            hostname, None,
            proto=socket.IPPROTO_TCP,
        )
    except socket.gaierror:
        return []
    finally:
        socket.setdefaulttimeout(old_timeout)

    ips: List[str] = []
    for fam, _type, _proto, _canon, sockaddr in infos:
        ip = sockaddr[0]
        if ip not in ips:
            ips.append(ip)
    return ips
