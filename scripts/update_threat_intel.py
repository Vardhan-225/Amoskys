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
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from amoskys.enrichment.threat_intel import ThreatIntelEnricher

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# Default DB path
DB_PATH = os.getenv("AMOSKYS_THREAT_INTEL_DB", "data/threat_intel.db")

# Feed rows expire after 72h — C2 infrastructure churns fast and recycled IPs
# must not keep matching. The enricher already excludes expired rows
# (expires_at > now); a daily refresh keeps live indicators alive.
_EXPIRY_HOURS = 72

# Sanity floor per feed: fewer rows than this means the feed is broken or
# truncated (outage / format change) — keep the previous rows instead of
# purging good intel on a bad fetch.
_MIN_ROWS = {"feodo": 5, "threatfox": 20, "plain_ip": 20, "hostfile": 50}

_UA = {"User-Agent": "AMOSKYS-intel-refresh/1.0 (+https://amoskys.com)"}

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
        # SSLBL was deprecated 2025-01-03; ThreatFox is abuse.ch's live IOC
        # exchange — recent botnet C2 ip:port IOCs with confidence levels.
        "name": "abuse.ch ThreatFox C2",
        "url": "https://threatfox.abuse.ch/export/csv/ip-port/recent/",
        "type": "ip",
        "severity": "critical",
        "parser": "threatfox",
    },
    {
        "name": "Emerging Threats Compromised IPs",
        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "type": "ip",
        "severity": "high",
        "parser": "plain_ip",
    },
    {
        # DNS telemetry matches DOMAINS — without a domain feed the dns_events
        # enrichment can never hit. URLhaus hostfile = active malware-
        # distribution hosts (abuse.ch, CC0).
        "name": "abuse.ch URLhaus Hosts",
        "url": "https://urlhaus.abuse.ch/downloads/hostfile/",
        "type": "domain",
        "severity": "high",
        "parser": "hostfile",
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


def parse_threatfox(text: str) -> list[tuple[str, str]]:
    """Parse ThreatFox recent ip-port CSV.

    Quoted fields: first_seen, ioc_id, "IP:port", ioc_type, threat_type,
    fk_malware, alias, malware_printable, last_seen, confidence, ...
    Only keeps confidence >= 50 rows.
    """
    import csv as _csv
    import io as _io

    results = []
    data = "\n".join(
        ln for ln in text.split("\n") if ln.strip() and not ln.lstrip().startswith("#")
    )
    for row in _csv.reader(_io.StringIO(data), skipinitialspace=True):
        if len(row) < 10:
            continue
        ioc = row[2].strip()
        ip = ioc.rsplit(":", 1)[0] if ":" in ioc else ioc
        try:
            conf = int(row[9])
        except (ValueError, IndexError):
            conf = 0
        if _is_valid_ip(ip) and conf >= 50:
            malware = (row[7] or "").strip() or "botnet C2"
            results.append((ip, f"ThreatFox {row[4].strip()}: {malware}"))
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


_DOMAIN_RE = __import__("re").compile(
    r"^(?=.{4,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
    r"(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$"
)


def parse_hostfile(text: str) -> list[tuple[str, str]]:
    """Parse hosts(5) format: '127.0.0.1<ws>domain' with '#' comments."""
    results = []
    for line in text.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2:
            dom = parts[1].strip().lower().rstrip(".")
            if _DOMAIN_RE.match(dom):
                results.append((dom, "URLhaus malware host"))
    return results


PARSERS = {
    "feodo": parse_feodo,
    "threatfox": parse_threatfox,
    "plain_ip": parse_plain_ip,
    "hostfile": parse_hostfile,
}


def main():
    enricher = ThreatIntelEnricher(db_path=DB_PATH)
    now = datetime.now(timezone.utc)
    expires = (now + timedelta(hours=_EXPIRY_HOURS)).isoformat()
    total = 0

    for feed in FEEDS:
        logger.info("Fetching: %s", feed["name"])
        try:
            resp = requests.get(feed["url"], timeout=45, headers=_UA)
            if resp.status_code != 200:
                logger.warning("  Failed: HTTP %d — previous rows kept", resp.status_code)
                continue

            parser = PARSERS[feed["parser"]]
            indicators = parser(resp.text)
            logger.info("  Parsed: %d indicators", len(indicators))
            if len(indicators) < _MIN_ROWS.get(feed["parser"], 5):
                logger.warning(
                    "  SUSPICIOUS: %d rows below sanity floor — previous rows kept",
                    len(indicators),
                )
                continue

            count = 0
            seen: set[str] = set()
            for ip, desc in indicators:
                if ip in seen:
                    continue
                seen.add(ip)
                if enricher.add_indicator(
                    indicator=ip,
                    indicator_type=feed["type"],
                    severity=feed["severity"],
                    source=feed["name"],
                    description=desc or feed["name"],
                    expires_at=expires,
                ):
                    count += 1

            # Purge THIS feed's rows that were absent from this refresh (the C2
            # went down / IP recycled). Other sources (seed rows) untouched.
            try:
                placeholders = ",".join("?" * len(seen))
                cur = enricher._conn.execute(
                    f"DELETE FROM indicators WHERE source = ? "
                    f"AND indicator NOT IN ({placeholders})",
                    [feed["name"], *seen],
                )
                if cur.rowcount:
                    logger.info("  Purged %d stale rows from this feed", cur.rowcount)
                enricher._conn.commit()
            except Exception as e:  # noqa: BLE001
                logger.warning("  Purge failed (non-fatal): %s", e)

            total += count
            logger.info("  Upserted: %d indicators (expire %dh)", count, _EXPIRY_HOURS)

        except Exception as e:
            logger.warning("  Error: %s — previous rows kept", e)

    # Drop globally-expired rows (any source that sets expiry)
    try:
        cur = enricher._conn.execute(
            "DELETE FROM indicators WHERE expires_at IS NOT NULL AND expires_at < ?",
            (now.isoformat(),),
        )
        if cur.rowcount:
            logger.info("Dropped %d expired indicators", cur.rowcount)
        enricher._conn.commit()
    except Exception:
        pass

    # Summary
    indicator_count = enricher._conn.execute(
        "SELECT COUNT(*) FROM indicators"
    ).fetchone()[0]
    by_source = enricher._conn.execute(
        "SELECT source, COUNT(*) FROM indicators GROUP BY source ORDER BY 2 DESC LIMIT 6"
    ).fetchall()
    logger.info(
        "Total indicators in DB: %d (upserted %d this run)", indicator_count, total
    )
    for src, n in by_source:
        logger.info("  %s: %d", src, n)


if __name__ == "__main__":
    main()
