#!/usr/bin/env python3
"""Update AMOSKYS ThreatIntel database with public threat feeds.

Downloads indicators from:
  - abuse.ch Feodo Tracker (C2 IPs)
  - abuse.ch URLhaus (malicious URLs)
  - Emerging Threats compromised IPs

Run: PYTHONPATH=src python scripts/update_threat_intel.py
Cron: 0 4 * * 0  (weekly, Sunday 4am)
"""

import logging
import os
import sys
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from amoskys.enrichment.threat_intel import ThreatIntelEnricher

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# Default DB path
DB_PATH = os.getenv("AMOSKYS_THREAT_INTEL_DB", "data/threat_intel.db")

# Public feeds (no API key required)
FEEDS = [
    {
        "name": "abuse.ch Feodo C2",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
        "type": "ip",
        "severity": "critical",
        "parser": "feodo",
    },
    {
        "name": "abuse.ch SSLBL C2",
        "url": "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv",
        "type": "ip",
        "severity": "critical",
        "parser": "sslbl",
    },
    {
        "name": "Emerging Threats Compromised IPs",
        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "type": "ip",
        "severity": "high",
        "parser": "plain_ip",
    },
]


def parse_feodo(text: str) -> list[tuple[str, str]]:
    """Parse abuse.ch Feodo CSV (skip comments, extract IPs)."""
    results = []
    for line in text.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(",")
        if len(parts) >= 2:
            ip = parts[1].strip().strip('"')
            if _is_valid_ip(ip):
                results.append((ip, parts[0].strip().strip('"')))
    return results


def parse_sslbl(text: str) -> list[tuple[str, str]]:
    """Parse abuse.ch SSLBL CSV."""
    results = []
    for line in text.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(",")
        if len(parts) >= 2:
            ip = parts[1].strip().strip('"')
            if _is_valid_ip(ip):
                results.append((ip, "SSLBL"))
    return results


def parse_plain_ip(text: str) -> list[tuple[str, str]]:
    """Parse plain text IP list (one per line)."""
    results = []
    for line in text.strip().split("\n"):
        ip = line.strip()
        if ip and not ip.startswith("#") and _is_valid_ip(ip):
            results.append((ip, ""))
    return results


def _is_valid_ip(s: str) -> bool:
    """Basic IPv4 validation."""
    parts = s.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


PARSERS = {
    "feodo": parse_feodo,
    "sslbl": parse_sslbl,
    "plain_ip": parse_plain_ip,
}


def main():
    enricher = ThreatIntelEnricher(db_path=DB_PATH)
    total = 0

    for feed in FEEDS:
        logger.info("Fetching: %s", feed["name"])
        try:
            resp = requests.get(feed["url"], timeout=30)
            if resp.status_code != 200:
                logger.warning("  Failed: HTTP %d", resp.status_code)
                continue

            parser = PARSERS[feed["parser"]]
            indicators = parser(resp.text)
            logger.info("  Parsed: %d indicators", len(indicators))

            count = 0
            for ip, desc in indicators:
                if enricher.add_indicator(
                    indicator=ip,
                    indicator_type=feed["type"],
                    severity=feed["severity"],
                    source=feed["name"],
                    description=desc or feed["name"],
                ):
                    count += 1

            total += count
            logger.info("  Added: %d new indicators", count)

        except Exception as e:
            logger.warning("  Error: %s", e)

    # Summary
    indicator_count = enricher._conn.execute("SELECT COUNT(*) FROM indicators").fetchone()[0]
    logger.info("Total indicators in DB: %d (added %d this run)", indicator_count, total)


if __name__ == "__main__":
    main()
