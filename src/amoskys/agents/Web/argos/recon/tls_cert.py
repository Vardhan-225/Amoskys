"""TLS :443 cert harvester — the highest-signal stealth pivot.

This is the source that does the hardest work and needs the most care.
Given an IP, we want the certificate served on port 443 without looking
like a scanner. The cert's Subject + Subject Alternative Names tell us
every hostname that IP answers for — which is exactly the pivot we need
to kick off the forward recon flow (CT logs, DNS, ASN).

## Stealth posture

**One connection, one purpose.**
    A real visitor's browser makes many requests (main page, JS, CSS,
    images). We have no business reason to make more than one. We open
    a TLS socket, complete the handshake, read the certificate, close.
    Total bytes on wire ≈ 3 KB. Total connection lifetime ≈ 200 ms.

**No port scans.**
    We probe :443 only. Not :80, not :8080, not the full range. Defenders
    flag sequences; we never produce one.

**No HTTP requests after handshake.**
    After TLS negotiates, we close. We do NOT issue a GET / or HEAD /.
    That would (a) generate a log line on their web server, and (b)
    require us to pick a Host: header that might not match what a real
    visitor would send.

**Rate limited + identity-consistent.**
    Every connection goes through `AdaptiveRateLimiter`. Each
    (customer, target) pair gets a stable `Session` from `IdentityPool`
    — the same SNI value across retries, not random.

**Skip CDN edges.**
    Before connecting, we check `CloudDetector`. If the IP is Cloudflare
    or Akamai, we SKIP the probe entirely and log "cert pivot skipped
    (cdn_edge)" in the completeness report. Probing gives us nothing.

**Honest TLS fingerprint.**
    Python's stdlib ssl library has a recognizable JA3/JA4 fingerprint
    that isn't a real browser. We set:
      - SNI matches target
      - ALPN advertises h2 + http/1.1
      - Cipher list in modern-server order
    This gets us past basic heuristics. Full JA4-spoofing (matching
    Chrome byte-for-byte) requires curl_cffi or similar — flagged for
    v2. A v1 operator running a real customer engagement should KNOW
    that a sophisticated WAF can fingerprint this traffic as non-
    browser. Use the lab for now; real customer scans benefit from a
    second iteration on this module.

## Output

For each reachable IP:
    - Emit `AssetKind.CERT` with the cert's SHA-256 fingerprint (this
      becomes a pivot key — later we can ask "what other IPs serve
      this exact cert?")
    - Emit `AssetKind.DOMAIN` or `AssetKind.SUBDOMAIN` for each SAN
    - Emit metadata with issuer, not-after, common-name

For unreachable IPs:
    - Emit nothing; log the reason for the completeness report.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import random
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Iterator, List, Optional, Tuple

from amoskys.agents.Web.argos.recon.base import (
    ReconContext,
    ReconEvent,
    ReconSource,
    StealthClass,
)
from amoskys.agents.Web.argos.recon.cloud_detector import (
    CDNBehavior,
    CloudDetector,
)
from amoskys.agents.Web.argos.stealth import (
    AdaptiveRateLimiter,
    BlockedTargetError,
    IdentityPool,
    RateLimiterConfig,
)
from amoskys.agents.Web.argos.storage import AssetKind

logger = logging.getLogger("amoskys.argos.recon.tls_cert")


# Cipher list aligned with modern Chrome/Firefox defaults. This is our
# closest stdlib-achievable approximation of a browser handshake. It
# does NOT fully match JA4 — see module docstring.
_MODERN_CIPHERS = ":".join([
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "ECDHE-RSA-AES128-SHA",
    "ECDHE-RSA-AES256-SHA",
    "AES128-GCM-SHA256",
    "AES256-GCM-SHA384",
])

DEFAULT_CONNECT_TIMEOUT_S = 5.0
DEFAULT_HANDSHAKE_TIMEOUT_S = 5.0


# ── Data ───────────────────────────────────────────────────────────


@dataclass
class CertInfo:
    """Parsed certificate relevant fields."""
    ip: str
    sni: Optional[str]             # the SNI we sent (None if IP-only)
    subject_cn: Optional[str]
    issuer_cn: Optional[str]
    sans: List[str] = field(default_factory=list)
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    fingerprint_sha256: Optional[str] = None
    version: Optional[int] = None
    serial: Optional[str] = None


# ── Source ─────────────────────────────────────────────────────────


class TLSCertSource(ReconSource):
    """One-shot TLS cert harvester for seed + discovered IPs.

    Yields one cert asset per IP, plus domain events for every SAN.
    """

    name = "tls_cert"
    stealth_class = StealthClass.ACTIVE
    description = (
        "Connects to port 443 of each discovered IP, completes TLS "
        "handshake, reads certificate SANs, closes. One handshake per "
        "IP. Skips known CDN edges. Rate-limited + identity-consistent."
    )

    def __init__(
        self,
        detector: Optional[CloudDetector] = None,
        identity_pool: Optional[IdentityPool] = None,
        rate_config: Optional[RateLimiterConfig] = None,
        connect_timeout_s: float = DEFAULT_CONNECT_TIMEOUT_S,
        handshake_timeout_s: float = DEFAULT_HANDSHAKE_TIMEOUT_S,
        probe_fn=None,   # injection point for tests
    ) -> None:
        self.detector = detector or CloudDetector()
        self.identity = identity_pool or IdentityPool()
        self.rate_config = rate_config or RateLimiterConfig(
            initial_rps=0.5,   # cert probes should be QUIET — 1 per 2 seconds
            max_rps=1.0,
            min_rps=0.1,
            block_threshold=2,  # two handshake failures = back off hard
        )
        self.connect_timeout_s = connect_timeout_s
        self.handshake_timeout_s = handshake_timeout_s
        self._probe = probe_fn or self._default_probe
        # Per-target rate limiters — shared across IPs of same /24
        self._limiters: dict = {}

    def run(self, context: ReconContext) -> Iterator[ReconEvent]:
        # Candidate IPs: seed if it's an IP, plus everything discovered.
        candidates: List[str] = []
        if _is_ip(context.seed):
            candidates.append(context.seed)
        for ip in context.known_ips:
            if ip not in candidates:
                candidates.append(ip)

        if not candidates:
            return

        # Randomize order so a defender doesn't see us walk their /24
        # in sequence. (This matters even at 0.5 rps — sequential probes
        # of adjacent IPs are a stronger signal than randomized ones.)
        shuffled = list(candidates)
        random.shuffle(shuffled)

        sni_hint = _seed_sni_hint(context)

        for ip in shuffled:
            classification = self.detector.classify(ip)

            if not classification.should_attempt_tls_pivot:
                # Record the skip so the completeness report can explain it
                yield ReconEvent(
                    kind=AssetKind.IPV4 if _is_ipv4(ip) else AssetKind.IPV6,
                    value=ip,
                    source=self.name,
                    confidence=0.5,
                    metadata={
                        "tls_probe_skipped": True,
                        "reason": f"{classification.provider.value}_{classification.behavior.value}",
                        "matched_cidr": classification.matched_cidr,
                    },
                )
                continue

            limiter = self._limiter_for(ip)

            try:
                limiter.wait()
            except BlockedTargetError:
                logger.warning("tls_cert: %s rate-limited (hard block); skipping", ip)
                continue

            session = self.identity.session_for(context.customer_id, ip)

            try:
                cert = self._probe(
                    ip=ip,
                    sni=sni_hint,
                    session_tls_id=session.session_id,
                    connect_timeout_s=self.connect_timeout_s,
                    handshake_timeout_s=self.handshake_timeout_s,
                )
            except ssl.SSLError as e:
                limiter.observe_error(e)
                logger.debug("tls_cert: %s TLS error: %s", ip, e)
                continue
            except (socket.timeout, TimeoutError, OSError) as e:
                limiter.observe_error(e)
                logger.debug("tls_cert: %s network error: %s", ip, e)
                continue

            if cert is None:
                continue

            # Successful handshake — treat as a "200" for rate-limiter purposes.
            limiter.observe(200)

            # Emit the cert as an asset (pivot key for same-cert lookups)
            if cert.fingerprint_sha256:
                yield ReconEvent(
                    kind=AssetKind.CERT,
                    value=cert.fingerprint_sha256,
                    source=self.name,
                    confidence=1.0,
                    parent_value=ip,
                    metadata={
                        "ip": ip,
                        "subject_cn": cert.subject_cn,
                        "issuer_cn": cert.issuer_cn,
                        "not_before": cert.not_before,
                        "not_after": cert.not_after,
                        "sans": cert.sans,
                        "version": cert.version,
                    },
                )

            # Emit each SAN as a domain / subdomain candidate.
            seen_sans = set()
            for san in cert.sans:
                cleaned = _clean_san(san)
                if not cleaned or cleaned in seen_sans:
                    continue
                seen_sans.add(cleaned)
                kind = AssetKind.DOMAIN if cleaned.count(".") == 1 else AssetKind.SUBDOMAIN
                yield ReconEvent(
                    kind=kind,
                    value=cleaned,
                    source=self.name,
                    confidence=0.9,  # SANs are strong signals — the cert is signed
                    parent_value=ip,
                    metadata={
                        "source_ip": ip,
                        "cert_fingerprint_sha256": cert.fingerprint_sha256,
                        "issuer_cn": cert.issuer_cn,
                    },
                )

    # ── internals ──────────────────────────────────────────────────

    def _limiter_for(self, ip: str) -> AdaptiveRateLimiter:
        """One limiter per /24 — adjacent IPs share fate on WAFs."""
        bucket = _rate_bucket_for(ip)
        if bucket not in self._limiters:
            self._limiters[bucket] = AdaptiveRateLimiter(bucket, self.rate_config)
        return self._limiters[bucket]

    def _default_probe(
        self,
        ip: str,
        sni: Optional[str],
        session_tls_id: str,
        connect_timeout_s: float,
        handshake_timeout_s: float,
    ) -> Optional[CertInfo]:
        """One TLS handshake. Close immediately. Return parsed cert.

        Uses stdlib ssl. See module docstring for v1 limitations re:
        JA4 fingerprinting.
        """
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.set_ciphers(_MODERN_CIPHERS)
        # Advertise modern ALPN so we look like a browser doing h2.
        try:
            ctx.set_alpn_protocols(["h2", "http/1.1"])
        except (AttributeError, NotImplementedError):
            pass
        # We're pivoting off certs, not validating — we WANT self-signed,
        # expired, and CN-mismatched certs to land in the data.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        # Connect raw first (so connect vs handshake timeouts are separable)
        raw = socket.create_connection((ip, 443), timeout=connect_timeout_s)
        try:
            raw.settimeout(handshake_timeout_s)
            # server_hostname = SNI. If no hint, don't set SNI — some
            # servers will reject; that's fine, we log and move on.
            server_hostname = sni if sni else None
            try:
                wrapped = ctx.wrap_socket(raw, server_hostname=server_hostname)
            except ssl.SSLError:
                # Retry without SNI — some servers misbehave on virt-host mismatch
                if server_hostname:
                    raw2 = socket.create_connection((ip, 443), timeout=connect_timeout_s)
                    raw2.settimeout(handshake_timeout_s)
                    wrapped = ctx.wrap_socket(raw2, server_hostname=None)
                    raw = raw2
                    server_hostname = None
                else:
                    raise
            try:
                der = wrapped.getpeercert(binary_form=True)
                peer_cert_dict = wrapped.getpeercert() or {}
                cert = _parse_cert(ip, server_hostname, der, peer_cert_dict)
                return cert
            finally:
                try:
                    wrapped.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                wrapped.close()
        finally:
            try:
                raw.close()
            except OSError:
                pass


# ── Cert parsing ──────────────────────────────────────────────────


def _parse_cert(
    ip: str,
    sni: Optional[str],
    der: Optional[bytes],
    peer_dict: dict,
) -> Optional[CertInfo]:
    """Extract the fields we care about from the peer cert.

    stdlib `getpeercert()` gives us a dict-form; `getpeercert(True)`
    gives DER bytes. We use DER for the fingerprint (stable + portable)
    and the dict for the structured fields.
    """
    if der is None and not peer_dict:
        return None

    subject_cn = _extract_cn(peer_dict.get("subject") or ())
    issuer_cn = _extract_cn(peer_dict.get("issuer") or ())

    sans: List[str] = []
    for kind, value in peer_dict.get("subjectAltName") or ():
        if kind == "DNS":
            sans.append(value.strip().lower())

    fingerprint = None
    if der:
        fingerprint = hashlib.sha256(der).hexdigest()

    return CertInfo(
        ip=ip,
        sni=sni,
        subject_cn=subject_cn,
        issuer_cn=issuer_cn,
        sans=sans,
        not_before=peer_dict.get("notBefore"),
        not_after=peer_dict.get("notAfter"),
        fingerprint_sha256=fingerprint,
        version=peer_dict.get("version"),
        serial=peer_dict.get("serialNumber"),
    )


def _extract_cn(name_tuple: tuple) -> Optional[str]:
    """Extract the commonName from a cert name like:
        ((('commonName', 'example.com'),),)
    """
    for rdn in name_tuple:
        for key, value in rdn:
            if key.lower() in ("commonname", "cn"):
                return value
    return None


def _clean_san(san: str) -> Optional[str]:
    """Normalize a SAN value. Strip wildcards, lower-case, validate.

    Rejects bare IPs (certs occasionally have IP SANs, but for our flow
    a SAN is a pivot to more *domains* — bare-IP SANs are already
    captured as the connection target and would create a duplicate
    IPv4 asset tagged as a domain.)
    """
    t = san.strip().lower().rstrip(".")
    if not t:
        return None
    if t.startswith("*."):
        t = t[2:]
    # Reject bare IPs — all labels numeric
    try:
        ipaddress.ip_address(t)
        return None
    except ValueError:
        pass
    # Reject if it contains characters not valid in DNS
    for label in t.split("."):
        if not label:
            return None
        if not all(c.isalnum() or c == "-" for c in label):
            return None
    if "." not in t:
        return None
    return t


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


def _rate_bucket_for(ip: str) -> str:
    """Group adjacent IPs under one limiter (one /24 per bucket)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if addr.version == 4:
        net = ipaddress.ip_network(f"{ip}/24", strict=False)
        return str(net)
    # IPv6: group by /48 (a "site" in many allocations)
    net6 = ipaddress.ip_network(f"{ip}/48", strict=False)
    return str(net6)


def _seed_sni_hint(context: ReconContext) -> Optional[str]:
    """Pick an SNI value for the handshake.

    - If the seed is a domain, use it (strongest signal).
    - If we already know subdomains from earlier sources, use one
      (deterministically picked for session consistency).
    - Otherwise None — skip SNI, let the server's default vhost answer.
    """
    seed = context.seed.strip().lower()
    if not _is_ip(seed):
        return seed
    if context.known_subdomains:
        # Deterministic choice — not random — so a retry uses the same SNI.
        return sorted(context.known_subdomains)[0]
    return None
