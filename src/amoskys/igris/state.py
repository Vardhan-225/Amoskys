"""
IGRIS Persistent State Management

Atomic state persistence to data/igris/state.json.
Survives process restarts. Never blocks observation cycles.

Includes signal cooldown index to prevent noisy repeat emissions.
IGRIS is calm — same condition does not spam every 60 seconds.
"""

import json
import logging
import os
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Resolve project root from this file's location (src/amoskys/igris/state.py)
_PROJECT_ROOT = str(Path(__file__).resolve().parents[3])
_DEFAULT_DATA_DIR = os.path.join(_PROJECT_ROOT, "data", "igris")

IGRIS_VERSION = "1.0.0"

# Default cooldown: 10 minutes between repeat signals for same condition
DEFAULT_COOLDOWN_S = 600


def _severity_rank(s: str) -> int:
    """Map severity string to numeric rank for escalation comparison."""
    return {"low": 1, "medium": 2, "high": 3, "critical": 4}.get((s or "").lower(), 0)


class IgrisState:
    """Manages IGRIS persistent state with atomic writes and signal cooldown."""

    def __init__(self, data_dir: str | None = None):
        self._data_dir = data_dir or _DEFAULT_DATA_DIR
        self._state_path = os.path.join(self._data_dir, "state.json")
        os.makedirs(self._data_dir, exist_ok=True)
        self._state = self._defaults()
        self.load()

    def _defaults(self) -> dict:
        return {
            "igris_version": IGRIS_VERSION,
            "started_at": None,
            "last_cycle_at": None,
            "cycle_count": 0,
            "cycle_duration_ms": 0,
            "status": "stopped",
            "metrics_snapshot": {},
            "active_signal_count": 0,
            "signal_count_since_start": 0,
            "cleared_count_since_start": 0,
            "fleet_summary": {
                "total": 0,
                "healthy": 0,
                "degraded": 0,
                "offline": 0,
            },
            # Cooldown index: dedup_key -> {last_emitted_at_epoch, last_severity}
            "signal_index": {},
        }

    def load(self) -> dict:
        """Load state from disk. Returns defaults if file missing/corrupt."""
        if not os.path.exists(self._state_path):
            return self._state
        try:
            with open(self._state_path) as f:
                loaded = json.load(f)
            if isinstance(loaded, dict):
                self._state.update(loaded)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(
                "Failed to load IGRIS state from %s: %s", self._state_path, e
            )
        return self._state

    def save(self) -> None:
        """Atomic write: temp file + rename to prevent corruption."""
        try:
            fd, tmp_path = tempfile.mkstemp(
                dir=self._data_dir, suffix=".tmp", prefix="state_"
            )
            with os.fdopen(fd, "w") as f:
                json.dump(self._state, f, indent=2, default=str)
            os.replace(tmp_path, self._state_path)
        except OSError as e:
            logger.warning("Failed to save IGRIS state to %s: %s", self._state_path, e)
            try:
                os.unlink(tmp_path)
            except (OSError, UnboundLocalError):
                pass  # cleanup best-effort

    def mark_started(self) -> None:
        """Mark IGRIS as started."""
        self._state["started_at"] = datetime.now(timezone.utc).isoformat()
        self._state["status"] = "warming_up"
        self._state["signal_count_since_start"] = 0
        self.save()

    def mark_stopped(self) -> None:
        """Mark IGRIS as stopped."""
        self._state["status"] = "stopped"
        self.save()

    def update(
        self,
        metrics: dict[str, Any],
        signals_emitted: list,
        duration_ms: float,
        signals_cleared: list | None = None,
    ) -> None:
        """Update state after an observation cycle."""
        self._state["last_cycle_at"] = datetime.now(timezone.utc).isoformat()
        self._state["cycle_count"] = self._state.get("cycle_count", 0) + 1
        self._state["cycle_duration_ms"] = round(duration_ms, 1)

        # Determine status
        cycle_count = self._state["cycle_count"]
        if cycle_count < 10:
            self._state["status"] = "warming_up"
        elif self._state.get("status") != "error":
            self._state["status"] = "observing"

        # Store metrics snapshot (exclude large nested dicts)
        snapshot = {}
        for k, v in metrics.items():
            if k in ("fleet.agents", "amrdr.agents"):
                continue
            snapshot[k] = v
        self._state["metrics_snapshot"] = snapshot

        # Signal summary
        # active_signal_count = persistent conditions in signal_index,
        # NOT just this-cycle emissions (which would show 0 during cooldown)
        self._state["active_signal_count"] = len(self._state.get("signal_index", {}))
        self._state["signals_emitted_this_cycle"] = len(signals_emitted)
        self._state["signal_count_since_start"] = self._state.get(
            "signal_count_since_start", 0
        ) + len(signals_emitted)

        # Recovery narrative tracking
        cleared = signals_cleared or []
        self._state["cleared_this_cycle"] = len(cleared)
        self._state["cleared_count_since_start"] = self._state.get(
            "cleared_count_since_start", 0
        ) + len(cleared)

        # Fleet summary
        self._state["fleet_summary"] = {
            "total": metrics.get("fleet.total") or 0,
            "healthy": metrics.get("fleet.healthy") or 0,
            "degraded": metrics.get("fleet.degraded") or 0,
            "offline": metrics.get("fleet.offline") or 0,
        }

    # ── Cooldown Gate ───────────────────────────────────────────

    def should_emit(
        self, dedup_key: str, severity: str, cooldown_s: int = DEFAULT_COOLDOWN_S
    ) -> bool:
        """Cooldown gate. Emit if: new key, severity escalated, or cooldown elapsed."""
        now = int(time.time())
        index = self._state.get("signal_index", {})
        prev = index.get(dedup_key)

        if not prev:
            return True  # Never seen this condition before

        last_ts = int(prev.get("last_emitted_at_epoch", 0))
        last_sev = str(prev.get("last_severity", "low"))

        # Escalation: always emit if severity increased
        if _severity_rank(severity) > _severity_rank(last_sev):
            return True

        # Cooldown: emit if enough time has passed
        if now - last_ts >= cooldown_s:
            return True

        return False  # Suppressed — same condition, same severity, still in cooldown

    def mark_emitted(
        self,
        dedup_key: str,
        severity: str,
        signal_type: str = "",
        metric_name: str = "",
        subsystem: str = "",
    ) -> None:
        """Record that a signal was emitted for this condition.

        Stores enough context to reconstruct a cleared signal when the
        condition resolves (Phase 1.5 recovery narrative).
        """
        if "signal_index" not in self._state:
            self._state["signal_index"] = {}
        self._state["signal_index"][dedup_key] = {
            "last_emitted_at_epoch": int(time.time()),
            "last_severity": severity,
            "signal_type": signal_type,
            "metric_name": metric_name,
            "subsystem": subsystem,
        }

    def clear_condition(self, dedup_key: str) -> None:
        """Remove a condition from cooldown index (condition resolved)."""
        index = self._state.get("signal_index", {})
        index.pop(dedup_key, None)

    def get_active_conditions(self) -> dict:
        """Return snapshot of all tracked conditions for recovery detection.

        Returns a copy so callers can iterate while the index is modified.
        """
        return dict(self._state.get("signal_index", {}))

    # ── Query API ───────────────────────────────────────────────

    def get_status(self) -> dict:
        """Return current state for API consumers."""
        uptime = None
        if self._state.get("started_at"):
            try:
                started = datetime.fromisoformat(self._state["started_at"])
                uptime = round((datetime.now(timezone.utc) - started).total_seconds())
            except (ValueError, TypeError):
                pass

        signal_index = self._state.get("signal_index", {})
        active_signals = [
            {
                "dedup_key": k,
                "signal_type": v.get("signal_type", ""),
                "metric_name": v.get("metric_name", ""),
                "severity": v.get("last_severity", ""),
                "subsystem": v.get("subsystem", ""),
                "since_epoch": v.get("last_emitted_at_epoch", 0),
            }
            for k, v in signal_index.items()
        ]

        return {
            "igris_version": IGRIS_VERSION,
            "status": self._state.get("status", "stopped"),
            "started_at": self._state.get("started_at"),
            "uptime_seconds": uptime,
            "cycle_count": self._state.get("cycle_count", 0),
            "last_cycle_at": self._state.get("last_cycle_at"),
            "cycle_duration_ms": self._state.get("cycle_duration_ms", 0),
            "active_signal_count": len(signal_index),
            "active_signals": active_signals,
            "signals_emitted_this_cycle": self._state.get(
                "signals_emitted_this_cycle", 0
            ),
            "signal_count_since_start": self._state.get("signal_count_since_start", 0),
            "cleared_this_cycle": self._state.get("cleared_this_cycle", 0),
            "cleared_count_since_start": self._state.get(
                "cleared_count_since_start", 0
            ),
            "cooldown_entries": len(signal_index),
            "fleet_summary": self._state.get("fleet_summary", {}),
        }

    @property
    def cycle_count(self) -> int:
        return self._state.get("cycle_count", 0)

    @property
    def metrics_snapshot(self) -> dict:
        return self._state.get("metrics_snapshot", {})
