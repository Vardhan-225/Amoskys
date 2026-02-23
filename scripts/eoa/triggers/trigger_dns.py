#!/usr/bin/env python3
"""Trigger Pack: DNSAgent — Exercise 8 silent DNS probes.

Targeted probes:
    1. DGAScoreProbe — high-entropy domain lookups
    2. BeaconingPatternProbe — periodic queries to same domain
    3. SuspiciousTLDProbe — queries to risky TLDs
    4. NXDomainBurstProbe — rapid NXDOMAIN responses
    5. LargeTXTTunnelingProbe — TXT record queries with long labels
    6. FastFluxRebindingProbe — rapid lookups for same domain
    7. NewDomainForProcessProbe — first-time domains
    8. BlockedDomainHitProbe — known-bad domain patterns

All queries target non-existent domains (.invalid, .test) or known-safe
destinations. No real attack traffic is generated.
Run with --dry-run to preview without executing.
"""

from __future__ import annotations

import argparse
import random
import shutil
import socket
import string
import subprocess
import time


def log(msg: str) -> None:
    print(f"  [DNS] {msg}")


def _dig_available() -> bool:
    return shutil.which("dig") is not None


def _dig_query(domain: str, qtype: str = "A") -> None:
    """Run dig query (fire-and-forget)."""
    try:
        subprocess.run(
            ["dig", "+short", "+time=1", "+tries=1", qtype, domain],
            capture_output=True,
            timeout=3,
        )
    except Exception:
        pass


def _resolve(domain: str) -> None:
    """Resolve domain via socket (fallback if dig unavailable)."""
    try:
        socket.getaddrinfo(domain, 80, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror:
        pass


# ── Trigger 1: DGAScoreProbe ──────────────────────────────────────────────


def trigger_dga(dry_run: bool = False) -> None:
    """Generate high-entropy domain lookups (DGA-like patterns)."""
    log("Trigger: DGAScoreProbe")

    # Random consonant-heavy strings (high entropy, low vowel ratio)
    dga_domains = []
    for _ in range(5):
        chars = "".join(
            random.choices("bcdfghjklmnpqrstvwxyz0123456789", k=random.randint(15, 25))
        )
        dga_domains.append(f"{chars}.invalid")

    for domain in dga_domains:
        if dry_run:
            log(f"  [DRY-RUN] Would resolve: {domain}")
        else:
            _resolve(domain)
            log(f"  Resolved DGA-like: {domain}")


# ── Trigger 2: BeaconingPatternProbe ──────────────────────────────────────


def trigger_beaconing(dry_run: bool = False) -> None:
    """Periodic queries to same domain (beacon pattern)."""
    log("Trigger: BeaconingPatternProbe (5 queries at 2s intervals)")

    domain = "eoa-beacon-check.invalid"

    if dry_run:
        log(f"  [DRY-RUN] Would query {domain} 5 times at 2s intervals")
        return

    for i in range(5):
        _resolve(domain)
        log(f"  Beacon query {i+1}/5: {domain}")
        time.sleep(2)


# ── Trigger 3: SuspiciousTLDProbe ─────────────────────────────────────────


def trigger_suspicious_tld(dry_run: bool = False) -> None:
    """Queries to high-risk TLDs (.top, .xyz, .click, .tk, etc.)."""
    log("Trigger: SuspiciousTLDProbe")

    risky_tlds = [
        "eoa-test.top",
        "eoa-test.xyz",
        "eoa-test.click",
        "eoa-test.tk",
        "eoa-test.gq",
        "eoa-test.buzz",
    ]

    for domain in risky_tlds:
        if dry_run:
            log(f"  [DRY-RUN] Would resolve: {domain}")
        else:
            _resolve(domain)
            log(f"  Queried risky TLD: {domain}")


# ── Trigger 4: NXDomainBurstProbe ─────────────────────────────────────────


def trigger_nxdomain_burst(dry_run: bool = False) -> None:
    """Rapid NXDOMAIN burst (12 non-existent domains in quick succession)."""
    log("Trigger: NXDomainBurstProbe (12 rapid NXDOMAIN)")

    if dry_run:
        log("  [DRY-RUN] Would resolve 12 non-existent domains rapidly")
        return

    for i in range(12):
        domain = f"eoa-nx-burst-{i}-{random.randint(1000,9999)}.invalid"
        _resolve(domain)
    log("  Sent 12 NXDOMAIN queries")


# ── Trigger 5: LargeTXTTunnelingProbe ────────────────────────────────────


def trigger_txt_tunneling(dry_run: bool = False) -> None:
    """TXT record queries with long subdomain labels (tunneling pattern)."""
    log("Trigger: LargeTXTTunnelingProbe")

    if not _dig_available():
        log("  dig not available — skipping TXT tunneling trigger")
        return

    # Long base64-like subdomain labels
    for i in range(6):
        label = "".join(random.choices(string.ascii_lowercase + string.digits, k=55))
        domain = f"{label}.eoa-tunnel.invalid"
        if dry_run:
            log(f"  [DRY-RUN] Would dig TXT {domain}")
        else:
            _dig_query(domain, "TXT")
            log(f"  TXT query: {domain[:40]}...")


# ── Trigger 6: FastFluxRebindingProbe ────────────────────────────────────


def trigger_fast_flux(dry_run: bool = False) -> None:
    """Rapid repeated lookups for same domain (fast-flux pattern)."""
    log("Trigger: FastFluxRebindingProbe")

    domain = "eoa-fastflux-test.invalid"

    if dry_run:
        log(f"  [DRY-RUN] Would resolve {domain} 8 times rapidly")
        return

    for i in range(8):
        _resolve(domain)
    log(f"  Resolved {domain} 8 times rapidly")


# ── Trigger 7: NewDomainForProcessProbe ──────────────────────────────────


def trigger_new_domains(dry_run: bool = False) -> None:
    """Resolve many unique domains (first-time domain pattern)."""
    log("Trigger: NewDomainForProcessProbe")

    domains = [f"eoa-new-{i}-{random.randint(10000,99999)}.invalid" for i in range(15)]

    for domain in domains:
        if dry_run:
            log(f"  [DRY-RUN] Would resolve: {domain}")
        else:
            _resolve(domain)
    log(f"  Resolved {len(domains)} unique new domains")


# ── Trigger 8: BlockedDomainHitProbe ─────────────────────────────────────


def trigger_blocked_domain(dry_run: bool = False) -> None:
    """Queries matching blocked domain patterns (.onion, .bit, phishing-*)."""
    log("Trigger: BlockedDomainHitProbe")

    # These are non-routable / invalid — safe to query
    blocked_patterns = [
        "eoa-test.onion",  # Tor pattern
        "eoa-test.bit",  # Namecoin pattern
        "phishing-eoa-bank.test",  # Phishing pattern
    ]

    for domain in blocked_patterns:
        if dry_run:
            log(f"  [DRY-RUN] Would resolve: {domain}")
        else:
            _resolve(domain)
            log(f"  Queried blocked pattern: {domain}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Trigger Pack: DNSAgent probes")
    parser.add_argument(
        "--dry-run", action="store_true", help="Preview without executing"
    )
    args = parser.parse_args()

    print("\n═══ DNSAgent Trigger Pack ═══")

    trigger_dga(args.dry_run)
    trigger_beaconing(args.dry_run)
    trigger_suspicious_tld(args.dry_run)
    trigger_nxdomain_burst(args.dry_run)
    trigger_txt_tunneling(args.dry_run)
    trigger_fast_flux(args.dry_run)
    trigger_new_domains(args.dry_run)
    trigger_blocked_domain(args.dry_run)

    print("═══ DNSAgent triggers complete ═══\n")


if __name__ == "__main__":
    main()
