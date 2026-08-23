"""Tail the Sentinel's NDJSON stream into the telemetry store.

    python -m amoskys.agents.os.macos.esf [stream_path]

Runs as the normal user. The Sentinel itself needs root, so it writes its
stream to a file and this reads it — which also decouples the two lifecycles:
the collector restarting must never interrupt kernel authorization, and the
Sentinel restarting must not lose the collector's position.
"""

from __future__ import annotations

import logging
import os
import socket
import sys
import time

from amoskys.agents.os.macos.esf.collector import ESFStreamCollector

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
)
logger = logging.getLogger("amoskys.esf")

DEFAULT_STREAM = "logs/sentinel_stream.ndjson"
POSITION_FILE = "data/.esf_stream_pos"
PRUNE_EVERY_S = 3600.0


def _load_position(path: str) -> int:
    try:
        with open(POSITION_FILE) as fh:
            stored_path, offset, inode = fh.read().split("\n")[:3]
        # Inode is checked, not just the path: log rotation replaces the file
        # while keeping the name, and resuming at a stale offset would silently
        # skip the whole new file. A rotated stream must restart at 0.
        if stored_path == path and int(inode) == os.stat(path).st_ino:
            return int(offset)
    except Exception:
        pass
    return 0


def _save_position(path: str, offset: int) -> None:
    try:
        os.makedirs(os.path.dirname(POSITION_FILE) or ".", exist_ok=True)
        with open(POSITION_FILE, "w") as fh:
            fh.write("%s\n%d\n%d\n" % (path, offset, os.stat(path).st_ino))
    except Exception:
        logger.debug("could not persist stream position", exc_info=True)


def main() -> int:
    stream = sys.argv[1] if len(sys.argv) > 1 else os.getenv(
        "AMOSKYS_ESF_STREAM", DEFAULT_STREAM
    )
    from amoskys.storage.telemetry_store import TelemetryStore

    store = TelemetryStore()
    device_id = os.getenv("AMOSKYS_DEVICE_ID") or socket.gethostname()
    collector = ESFStreamCollector(store, device_id=device_id)

    logger.info("ESF collector starting: stream=%s device=%s", stream, device_id)
    if not os.path.exists(stream):
        # Not an error. The Sentinel needs root and is started separately, so
        # "not running yet" is an ordinary state — but it must be VISIBLE,
        # because a collector that quietly waits forever looks identical to one
        # that is working.
        logger.warning(
            "ESF stream %s does not exist yet. The Sentinel writes it and "
            "requires root; until it runs, AMOSKYS has NO kernel-level exec "
            "visibility. Waiting.", stream,
        )

    offset = _load_position(stream)
    last_prune = time.time()
    last_report = time.time()

    while True:
        try:
            if not os.path.exists(stream):
                time.sleep(5)
                continue
            size = os.path.getsize(stream)
            if size < offset:
                logger.warning("stream truncated (rotation?) — restarting at 0")
                offset = 0
            with open(stream, "r", errors="replace") as fh:
                fh.seek(offset)
                # readline() rather than `for line in fh`: iterating a file
                # object enables a read-ahead buffer and Python then refuses
                # tell() with "telling position disabled by next() call". The
                # offset is the whole point here — without it every restart
                # re-ingests the file from the beginning.
                while True:
                    line = fh.readline()
                    if not line:
                        break
                    if not line.endswith("\n"):
                        break  # partial write; pick it up next pass
                    collector.ingest_line(line)
                    offset = fh.tell()
            collector.flush()
            _save_position(stream, offset)

            now = time.time()
            if now - last_prune > PRUNE_EVERY_S:
                removed = collector.prune()
                logger.info("ESF retention pruned %d rows", removed)
                last_prune = now
            if now - last_report > 300:
                logger.info("ESF collector: %s", collector.stats())
                last_report = now
            time.sleep(1.0)
        except KeyboardInterrupt:
            collector.flush()
            logger.info("ESF collector stopping: %s", collector.stats())
            return 0
        except Exception:
            logger.exception("ESF collector loop error; continuing")
            time.sleep(5)


if __name__ == "__main__":
    sys.exit(main())
