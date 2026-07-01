#!/usr/bin/env python3
"""AMOSKYS threat-intel auto-updater — STDLIB ONLY (no third-party deps).

Designed to run from launchd as root on a deployed agent, under whatever
Python the agent already uses. No `requests`, no venv, no external volume.

Pulls public, no-API-key feeds into the indicator store and ages out stale
indicators so the DB self-heals instead of rotting (the original failure mode:
a 73-day-stale DB whose C2 IPs had all rotated).

  DB path:  $AMOSKYS_THREAT_INTEL_DB  or  /var/lib/amoskys/data/threat_intel.db
  Schedule: see deploy/macos/com.amoskys.threat-intel.plist (daily)
  Manual:   python3 scripts/threat_intel_autoupdate.py
"""
from __future__ import annotations

import logging
import os
import sqlite3
import ssl
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger("ti-update")

DB = os.getenv("AMOSKYS_THREAT_INTEL_DB", "/var/lib/amoskys/data/threat_intel.db")
TTL_DAYS = int(os.getenv("AMOSKYS_TI_TTL_DAYS", "14"))
URLHAUS_CAP = int(os.getenv("AMOSKYS_TI_URLHAUS_CAP", "4000"))
UA = "AMOSKYS-ThreatIntel/1.0"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS indicators (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator TEXT NOT NULL,
    type TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'medium',
    source TEXT, description TEXT,
    added_at TEXT NOT NULL, expires_at TEXT,
    UNIQUE(indicator, type)
);
CREATE INDEX IF NOT EXISTS idx_indicator_value ON indicators(indicator);
CREATE INDEX IF NOT EXISTS idx_indicator_type ON indicators(type);
"""

FEEDS = [
    {
        "name": "abuse.ch Feodo C2",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
        "type": "ip",
        "sev": "critical",
        "parser": "feodo",
    },
    {
        "name": "Emerging Threats Compromised",
        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "type": "ip",
        "sev": "high",
        "parser": "plain_ip",
    },
    {
        "name": "abuse.ch URLhaus",
        "url": "https://urlhaus.abuse.ch/downloads/text_online/",
        "type": "domain",
        "sev": "high",
        "parser": "urlhaus_domains",
    },
]


def _valid_ipv4(s: str) -> bool:
    p = s.split(".")
    if len(p) != 4:
        return False
    try:
        return all(0 <= int(x) <= 255 for x in p)
    except ValueError:
        return False


def parse_feodo(text: str):
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(",")
        if len(parts) >= 2 and _valid_ipv4(parts[1].strip().strip('"')):
            out.append((parts[1].strip().strip('"'), "Feodo C2"))
    return out


def parse_plain_ip(text: str):
    out = []
    for line in text.splitlines():
        ip = line.strip()
        if ip and not ip.startswith("#") and _valid_ipv4(ip):
            out.append((ip, "compromised host"))
    return out


# URLhaus flags malware URLs hosted ON these platforms, but the bare domains
# are benign and high-traffic — flagging them would flood the brain with false
# positives. Never ingest a host whose registrable domain is allowlisted.
_ALLOWLIST = {
    "googleusercontent.com",
    "google.com",
    "googleapis.com",
    "gstatic.com",
    "githubusercontent.com",
    "github.com",
    "github.io",
    "gitlab.com",
    "dropbox.com",
    "dropboxusercontent.com",
    "amazonaws.com",
    "cloudfront.net",
    "discord.com",
    "discordapp.com",
    "discordapp.net",
    "cdn.discordapp.com",
    "microsoft.com",
    "live.com",
    "sharepoint.com",
    "onedrive.com",
    "1drv.ms",
    "apple.com",
    "icloud.com",
    "cloudflare.com",
    "cloudflarestorage.com",
    "wordpress.com",
    "blogspot.com",
    "weebly.com",
    "wixsite.com",
    "sites.google.com",
    "firebasestorage.googleapis.com",
    "telegram.org",
    "t.me",
    "bit.ly",
    "ipfs.io",
    "backblazeb2.com",
    "digitaloceanspaces.com",
}


def _allowlisted(host: str) -> bool:
    return any(host == d or host.endswith("." + d) for d in _ALLOWLIST)


def parse_urlhaus_domains(text: str):
    """Extract unique malicious hostnames from URLhaus (bounded, FP-guarded)."""
    seen, out = set(), []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        host = urllib.parse.urlparse(line).hostname
        if not host or _valid_ipv4(host) or host in seen or _allowlisted(host):
            continue
        seen.add(host)
        out.append((host, "URLhaus malware host"))
        if len(out) >= URLHAUS_CAP:
            break
    return out


PARSERS = {
    "feodo": parse_feodo,
    "plain_ip": parse_plain_ip,
    "urlhaus_domains": parse_urlhaus_domains,
}

# High-confidence, macOS-relevant indicators that are NOT in the volatile public
# feeds. Re-applied every run (so they never age out) — the endpoint-specific
# core of the store. (indicator, type, severity, description)
CURATED = [
    ("amos-stealer.com", "domain", "critical", "AMOS Stealer C2"),
    ("poseidon-stealer.com", "domain", "critical", "Poseidon Stealer C2"),
    ("banshee-stealer.cc", "domain", "critical", "Banshee Stealer C2"),
    ("atomic-stealer.com", "domain", "critical", "Atomic Stealer C2"),
    ("rustbucket-malware.com", "domain", "critical", "RustBucket (DPRK) C2"),
    ("icloud-auth.com", "domain", "critical", "macOS credential phishing"),
    ("apple-security-update.com", "domain", "critical", "Fake macOS update phishing"),
    ("appleid-verify.net", "domain", "critical", "Apple ID harvester"),
    ("update-flash-player.com", "domain", "high", "Flash update social engineering"),
    ("mackeeper-download.com", "domain", "high", "macOS scareware"),
    ("pool.minexmr.com", "domain", "high", "Monero mining pool"),
    ("pool.hashvault.pro", "domain", "high", "Crypto mining pool"),
    ("185.220.101.1", "ip", "critical", "Known Cobalt Strike C2"),
    ("45.77.65.211", "ip", "critical", "Cobalt Strike beacon server"),
    ("77.91.68.52", "ip", "high", "RedLine Stealer C2"),
    ("185.215.113.43", "ip", "high", "Stealer exfil endpoint"),
]


def add_curated(con, added, expires):
    con.executemany(
        "INSERT INTO indicators(indicator,type,severity,source,description,added_at,expires_at) "
        "VALUES(?,?,?,?,?,?,?) ON CONFLICT(indicator,type) DO UPDATE SET "
        "severity=excluded.severity, source=excluded.source, "
        "added_at=excluded.added_at, expires_at=excluded.expires_at",
        [
            (ind.lower(), t, sev, "AMOSKYS-curated", desc, added, expires)
            for ind, t, sev, desc in CURATED
        ],
    )
    con.commit()
    return len(CURATED)


def fetch(url: str) -> str:
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=45, context=ctx) as r:
        return r.read().decode("utf-8", "replace")


def main() -> int:
    os.makedirs(os.path.dirname(DB) or ".", exist_ok=True)
    con = sqlite3.connect(DB, timeout=10)
    con.executescript(_SCHEMA)
    now = datetime.now(timezone.utc)
    added = now.isoformat()
    expires = (now + timedelta(days=TTL_DAYS)).isoformat()

    total = 0
    for feed in FEEDS:
        try:
            rows = PARSERS[feed["parser"]](fetch(feed["url"]))
        except Exception as e:
            log.warning("feed FAILED %s: %s", feed["name"], e)
            continue
        con.executemany(
            "INSERT INTO indicators(indicator,type,severity,source,description,added_at,expires_at) "
            "VALUES(?,?,?,?,?,?,?) "
            "ON CONFLICT(indicator,type) DO UPDATE SET "
            "severity=excluded.severity, source=excluded.source, "
            "added_at=excluded.added_at, expires_at=excluded.expires_at",
            [
                (
                    ind.lower(),
                    feed["type"],
                    feed["sev"],
                    feed["name"],
                    desc,
                    added,
                    expires,
                )
                for ind, desc in rows
            ],
        )
        con.commit()
        log.info("%-28s +%d", feed["name"], len(rows))
        total += len(rows)

    total += add_curated(con, added, expires)
    log.info("%-28s +%d", "AMOSKYS-curated (static)", len(CURATED))

    # Self-heal: drop indicators that aged out (and were not refreshed above).
    pruned = con.execute(
        "DELETE FROM indicators WHERE expires_at IS NOT NULL AND expires_at < ?",
        (now.isoformat(),),
    ).rowcount
    con.commit()
    live = con.execute("SELECT COUNT(*) FROM indicators").fetchone()[0]
    by = con.execute("SELECT type,COUNT(*) FROM indicators GROUP BY type").fetchall()
    con.close()
    log.info(
        "refreshed=%d pruned=%d live=%d (%s) db=%s", total, pruned, live, dict(by), DB
    )
    return 0 if live > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
