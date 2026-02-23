"""Telemetry Bridge — connects the dashboard to the permanent TelemetryStore.

Provides a lazy singleton so the dashboard can query real event data from
telemetry.db without import-time side effects.  Returns None if the database
does not exist yet (fresh install), allowing callers to fall back gracefully.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from amoskys.storage.telemetry_store import TelemetryStore

logger = logging.getLogger(__name__)

_telemetry_store: Optional["TelemetryStore"] = None

# Resolve the project-root data directory (web/ is one level under project root)
_DATA_DIR = Path(__file__).resolve().parents[3] / "data"
_DB_PATH = _DATA_DIR / "telemetry.db"


def get_telemetry_store() -> Optional["TelemetryStore"]:
    """Get or create a TelemetryStore instance pointing to data/telemetry.db.

    Returns None if the database file does not exist (no events ingested yet).
    """
    global _telemetry_store
    if _telemetry_store is not None:
        return _telemetry_store

    if not _DB_PATH.exists():
        logger.debug("telemetry.db not found at %s — using empty fallback", _DB_PATH)
        return None

    try:
        from amoskys.storage.telemetry_store import TelemetryStore

        _telemetry_store = TelemetryStore(db_path=str(_DB_PATH))
        logger.info("Connected to TelemetryStore at %s", _DB_PATH)
        return _telemetry_store
    except Exception:
        logger.exception("Failed to initialize TelemetryStore")
        return None
