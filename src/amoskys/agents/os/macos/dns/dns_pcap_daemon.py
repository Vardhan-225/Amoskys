#!/usr/bin/env python3
"""DNS Plaintext Capture Daemon — standalone tcpdump process.

Runs as a separate process managed by the watchdog (NOT inside the
collector thread). Captures outbound DNS queries on port 53 via tcpdump
and writes plaintext domain names to a rotating log file that the DNS
collector reads.

This bypasses macOS 15+ Unified Logging privacy hashing by reading
domains directly from the wire.

Usage (run as root):
    python3 -m amoskys.agents.os.macos.dns.dns_pcap_daemon

Output format (one line per query):
    <unix_timestamp>|<record_type>|<domain>

The file is capped at 10,000 lines and rotated automatically.
"""

from __future__ import annotations

import logging
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path

logger = logging.getLogger("dns_pcap_daemon")

OUTPUT_PATH = Path("/var/lib/amoskys/data/dns_plaintext.log")
MAX_LINES = 10_000
TCPDUMP_BIN = "/usr/sbin/tcpdump"

# Regex to extract domain from tcpdump DNS output
# Matches: "12:34:56.789 IP 192.168.1.1.52311 > 8.8.8.8.53: 12345+ A? example.com. (30)"
_DNS_PATTERN = re.compile(
    r"\d{2}:\d{2}:\d{2}\.\d+\s+"
    r"IP[46]?\s+\S+\s+>\s+\S+:\s+"
    r"\d+\+?\s+"
    r"(A{1,4}\??|AAAA\??|PTR\??|MX\??|TXT\??|CNAME\??|SRV\??|NS\??)\s+"
    r"(\S+?)\.\s"
)


def _rotate_if_needed() -> None:
    """Trim the output file to MAX_LINES if it's grown too large."""
    try:
        if not OUTPUT_PATH.exists():
            return
        with open(OUTPUT_PATH) as f:
            lines = f.readlines()
        if len(lines) > MAX_LINES:
            # Keep the newest half
            with open(OUTPUT_PATH, "w") as f:
                f.writelines(lines[-(MAX_LINES // 2):])
    except Exception:
        pass


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    logger.info("DNS pcap daemon starting — output: %s", OUTPUT_PATH)

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    # Handle graceful shutdown
    running = True

    def _shutdown(signum, frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    seen_recent: dict[str, float] = {}  # domain → last_seen (dedup within 10s)

    while running:
        try:
            proc = subprocess.Popen(
                [
                    TCPDUMP_BIN,
                    "-i", "any",
                    "-nn",
                    "-l",
                    "-c", "1000",
                    "udp port 53 and not src port 53",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )

            for line in proc.stdout:
                if not running:
                    break
                match = _DNS_PATTERN.search(line)
                if not match:
                    continue
                record_type = match.group(1).rstrip("?").upper()
                domain = match.group(2).rstrip(".")

                if not domain or domain.endswith(".local"):
                    continue
                # Skip reverse lookups (in-addr.arpa)
                if domain.endswith(".in-addr.arpa") or domain.endswith(".ip6.arpa"):
                    continue

                # Dedup: skip if seen in last 10 seconds
                now = time.time()
                if domain in seen_recent and now - seen_recent[domain] < 10:
                    continue
                seen_recent[domain] = now

                # Write to output file
                try:
                    with open(OUTPUT_PATH, "a") as f:
                        f.write(f"{now:.3f}|{record_type}|{domain}\n")
                except Exception:
                    pass

            proc.wait()

            # Clean up old dedup entries
            now = time.time()
            seen_recent = {d: t for d, t in seen_recent.items() if now - t < 30}

            # Rotate file if needed
            _rotate_if_needed()

            # Brief pause before restarting tcpdump
            time.sleep(1)

        except Exception as e:
            logger.error("DNS pcap error: %s", e)
            time.sleep(5)

    logger.info("DNS pcap daemon shutting down")


if __name__ == "__main__":
    main()
