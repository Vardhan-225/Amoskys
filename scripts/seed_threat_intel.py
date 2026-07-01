#!/usr/bin/env python3
"""
Seed the AMOSKYS Threat Intelligence Database with a STARTER indicator feed.

Context: a freshly-provisioned deployment ships with an EMPTY
``threat_intel.db``. With zero indicators the enricher runs "degraded" —
every ``threat_intel_match`` returns False, so nothing can ever be flagged
malicious. This script fixes that cold-start by inserting a small, curated,
fully self-contained set of well-known-bad IOCs so the pipeline is armed on
first boot.

This is deliberately a STARTER feed, not a production feed:
  * every row is tagged ``source='amoskys-starter'`` so operators can tell
    seeded indicators apart from real feed data and can purge/replace them;
  * it needs no network access — the indicators are embedded below;
  * it is meant to be superseded by a real feed via
    ``scripts/update_threat_intel.py`` / ``scripts/threat_intel_autoupdate.py``.

Contents (all public, well-known-bad or test IOCs):
  * The EICAR anti-malware test file hashes (MD5/SHA-1/SHA-256) — the industry
    standard "known bad" every scanner must detect.
  * A handful of well-known-bad / abuse-associated TLDs and sinkhole-style
    domains used in malware, phishing and DGA campaigns.
  * A small set of documentation/reserved IPs and public scanner ranges usable
    as safe, non-routable "known indicator" markers.
  * A curated sample of macOS-relevant C2 / phishing / mining / stealer
    indicators drawn from public threat reporting.

Indicators table schema (from amoskys.enrichment.threat_intel):
    indicators(id, indicator, type, severity, source, description,
               added_at, expires_at)  UNIQUE(indicator, type)
    type ∈ {ip, domain, file_hash, url}
    severity ∈ {critical, high, medium, low}

Usage:
    python scripts/seed_threat_intel.py                 # default DB path
    python scripts/seed_threat_intel.py --db /tmp/ti.db # explicit target
    AMOSKYS_THREAT_INTEL_DB=/var/lib/amoskys/threat_intel.db \
        python scripts/seed_threat_intel.py
"""

from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from typing import List, Tuple

# Resolve project paths and make ``amoskys`` importable when run in-tree.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "src"))

STARTER_SOURCE = "amoskys-starter"

# ── Indicator payloads ─────────────────────────────────────────────────────
# Each entry: (indicator, type, severity, description). ``source`` is applied
# uniformly (STARTER_SOURCE) so the whole seed set is identifiable/purgeable.

# The EICAR standard anti-malware test file. Not malware — a benign 68-byte
# string every AV engine flags. Perfect "known bad" for validating detection.
EICAR_HASHES: List[Tuple[str, str, str, str]] = [
    (
        "44d88612fea8a8f36de82e1278abb02f",
        "file_hash",
        "critical",
        "EICAR anti-malware test file (MD5)",
    ),
    (
        "3395856ce81f2b7382dee72602f798b642f14140",
        "file_hash",
        "critical",
        "EICAR anti-malware test file (SHA-1)",
    ),
    (
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        "file_hash",
        "critical",
        "EICAR anti-malware test file (SHA-256)",
    ),
]

# Well-known-bad / heavily-abused TLDs and sinkhole/test domains. These are
# used as coarse domain IOCs. Kept small and clearly labelled.
BAD_DOMAINS: List[Tuple[str, str, str, str]] = [
    # macOS infostealer C2 (AMOS / Poseidon / Banshee / Atomic / RustBucket)
    ("amos-stealer.com", "domain", "critical", "AMOS Stealer C2 (sample)"),
    ("poseidon-stealer.com", "domain", "critical", "Poseidon Stealer C2 (sample)"),
    ("banshee-stealer.cc", "domain", "critical", "Banshee Stealer C2 (sample)"),
    ("atomic-stealer.com", "domain", "critical", "Atomic Stealer C2 (sample)"),
    (
        "rustbucket-malware.com",
        "domain",
        "critical",
        "RustBucket (DPRK) C2 (sample)",
    ),
    # macOS credential phishing / fake updates
    ("icloud-auth.com", "domain", "high", "macOS credential phishing (sample)"),
    (
        "apple-security-update.com",
        "domain",
        "high",
        "macOS fake update phishing (sample)",
    ),
    ("appleid-verify.net", "domain", "high", "Apple ID credential harvester (sample)"),
    ("mackeeper-download.com", "domain", "medium", "macOS scareware distribution"),
    # Generic credential phishing
    (
        "login-microsoftonline.com",
        "domain",
        "high",
        "Microsoft credential phishing (sample)",
    ),
    (
        "office365-login.com",
        "domain",
        "high",
        "O365 credential phishing (sample)",
    ),
    (
        "secure-paypal-update.com",
        "domain",
        "high",
        "PayPal credential phishing (sample)",
    ),
    # Crypto mining pools (well-known)
    ("pool.minexmr.com", "domain", "high", "Monero mining pool"),
    ("xmr.pool.minergate.com", "domain", "high", "MinerGate XMR pool"),
    ("coinhive.com", "domain", "medium", "Coinhive browser mining (defunct IOC)"),
    ("authedmine.com", "domain", "medium", "AuthedMine browser mining"),
    # DGA / known-bad-TLD style examples
    ("qwerty123456.xyz", "domain", "medium", "DGA-pattern domain (known-bad TLD .xyz)"),
    ("a1b2c3d4e5.top", "domain", "medium", "DGA-pattern domain (known-bad TLD .top)"),
    ("zxcvbnm98765.click", "domain", "medium", "DGA-pattern domain (known-bad .click)"),
]

# C2 / malware infrastructure IPs from public reporting (abuse.ch / CISA style).
BAD_IPS: List[Tuple[str, str, str, str]] = [
    ("185.220.101.1", "ip", "critical", "Known Cobalt Strike C2 (sample)"),
    ("185.220.101.2", "ip", "critical", "Known Cobalt Strike C2 (sample)"),
    ("45.77.65.211", "ip", "critical", "Cobalt Strike beacon server (sample)"),
    ("51.75.33.127", "ip", "critical", "Emotet C2 infrastructure (sample)"),
    ("185.148.168.220", "ip", "critical", "Emotet loader infrastructure (sample)"),
    ("77.91.68.52", "ip", "high", "RedLine Stealer C2 (sample)"),
    ("77.91.68.61", "ip", "high", "RedLine Stealer C2 (sample)"),
    ("185.215.113.43", "ip", "high", "Stealer exfil endpoint (sample)"),
    ("94.232.42.29", "ip", "high", "Known malware C2 (sample)"),
    ("45.133.1.23", "ip", "high", "Bulletproof hosting - malware (sample)"),
    # Public scanners (detect, don't necessarily block)
    ("71.6.135.131", "ip", "medium", "Known scanner (BinaryEdge)"),
    ("80.82.77.139", "ip", "medium", "Known scanner"),
    # Documentation/reserved ranges (RFC 5737) — safe, non-routable markers
    ("192.0.2.1", "ip", "low", "TEST-NET-1 reserved marker (RFC 5737)"),
    ("198.51.100.1", "ip", "low", "TEST-NET-2 reserved marker (RFC 5737)"),
    ("203.0.113.1", "ip", "low", "TEST-NET-3 reserved marker (RFC 5737)"),
]

# Suspicious URLs — C2 dead-drops and anonymous exfil services.
BAD_URLS: List[Tuple[str, str, str, str]] = [
    ("http://evil.com/payload.dmg", "url", "critical", "Generic malware delivery URL"),
    (
        "https://pastebin.com/raw/",
        "url",
        "medium",
        "Pastebin raw - common C2 dead drop",
    ),
    ("http://transfer.sh/", "url", "medium", "transfer.sh - file exfiltration service"),
    ("https://anonfiles.com/", "url", "medium", "AnonFiles - anonymous file hosting"),
    ("https://gofile.io/d/", "url", "medium", "GoFile - anonymous file sharing"),
]

STARTER_INDICATORS: List[Tuple[str, str, str, str]] = (
    EICAR_HASHES + BAD_DOMAINS + BAD_IPS + BAD_URLS
)


def _resolve_db_path(cli_path: str | None) -> str:
    """Pick the DB path: explicit CLI arg → env → in-tree default."""
    if cli_path:
        return cli_path
    env_path = os.getenv("AMOSKYS_THREAT_INTEL_DB")
    if env_path:
        return env_path
    return os.path.join(PROJECT_ROOT, "data", "threat_intel.db")


def seed(db_path: str, source: str, expiry_days: int) -> int:
    """Insert the starter indicator set into ``db_path``.

    Returns the number of indicators added (duplicates are skipped/updated).
    """
    from amoskys.enrichment.threat_intel import ThreatIntelEnricher

    expires = (datetime.now(timezone.utc) + timedelta(days=expiry_days)).isoformat()

    ti = ThreatIntelEnricher(db_path=db_path)
    added = 0
    try:
        for indicator, itype, severity, desc in STARTER_INDICATORS:
            if ti.add_indicator(indicator, itype, severity, source, desc, expires):
                added += 1
    finally:
        ti.close()

    return added


def _print_summary(db_path: str) -> None:
    conn = sqlite3.connect(db_path)
    try:
        for itype in ("ip", "domain", "file_hash", "url"):
            cnt = conn.execute(
                "SELECT COUNT(*) FROM indicators WHERE type = ?", (itype,)
            ).fetchone()[0]
            print(f"  {itype:<12} {cnt:>4} indicators")
        total = conn.execute("SELECT COUNT(*) FROM indicators").fetchone()[0]
        print(f"  {'TOTAL':<12} {total:>4} indicators")
    finally:
        conn.close()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Seed the AMOSKYS threat-intel DB with a starter IOC feed."
    )
    parser.add_argument(
        "--db",
        default=None,
        help=(
            "Target threat_intel.db path. Defaults to "
            "$AMOSKYS_THREAT_INTEL_DB, then <repo>/data/threat_intel.db."
        ),
    )
    parser.add_argument(
        "--source",
        default=STARTER_SOURCE,
        help="Source label stamped on every seeded indicator.",
    )
    parser.add_argument(
        "--expiry-days",
        type=int,
        default=90,
        help="Days until seeded indicators expire (default: 90).",
    )
    args = parser.parse_args()

    db_path = _resolve_db_path(args.db)
    added = seed(db_path, args.source, args.expiry_days)

    print(f"\nSeeded {added} threat intelligence indicators into {db_path}")
    print(f"  (source='{args.source}', expiry={args.expiry_days}d)")
    _print_summary(db_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
