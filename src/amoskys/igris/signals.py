"""
IGRIS Signal Definitions and Emitter

Structured signals emitted when IGRIS detects deviations from learned baselines.
Every signal is evidence-backed. No speculation. No hallucination.
"""

import json
import logging
import os
import uuid
from dataclasses import asdict, dataclass, field

logger = logging.getLogger(__name__)
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

# Resolve project root from this file's location (src/amoskys/igris/signals.py)
_PROJECT_ROOT = str(Path(__file__).resolve().parents[3])
_DEFAULT_DATA_DIR = os.path.join(_PROJECT_ROOT, "data", "igris")


class SignalType(str, Enum):
    """Categories of governance signals IGRIS can emit."""

    STABILITY_WARNING = "STABILITY_WARNING"
    DRIFT_WARNING = "DRIFT_WARNING"
    INTEGRITY_WARNING = "INTEGRITY_WARNING"
    SUPERVISION_DEFICIT = "SUPERVISION_DEFICIT"
    MODEL_STALENESS = "MODEL_STALENESS"
    TRANSPORT_BACKPRESSURE = "TRANSPORT_BACKPRESSURE"


@dataclass
class IgrisSignal:
    """A structured governance signal — deterministic, evidence-backed."""

    signal_type: SignalType
    severity: str  # low | medium | high | critical
    metric_name: str
    baseline_value: float
    current_value: float
    deviation_sigma: float
    confidence: float
    subsystem: str  # fleet|transport|ingestion|intelligence|amrdr|soma|enrichment
    message: str
    signal_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    evidence: list = field(default_factory=list)
    agent_id: Optional[str] = None
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    # Cooldown + dedup support
    dedup_key: str = ""  # Set by supervisor before emit: "{type}:{metric}:{agent_id}"
    status: str = "active"  # active | cleared

    def __post_init__(self):
        if not self.dedup_key:
            agent = self.agent_id or "fleet"
            sig_type = (
                self.signal_type.value
                if isinstance(self.signal_type, SignalType)
                else str(self.signal_type)
            )
            self.dedup_key = f"{sig_type}:{self.metric_name}:{agent}"

    def to_dict(self) -> dict:
        d = asdict(self)
        if isinstance(d.get("signal_type"), SignalType):
            d["signal_type"] = d["signal_type"].value
        return d


class SignalEmitter:
    """Append-only signal log. Writes to data/igris/signals.jsonl."""

    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB rotation threshold

    def __init__(self, data_dir: str | None = None):
        self._data_dir = data_dir or _DEFAULT_DATA_DIR
        self._signals_path = os.path.join(self._data_dir, "signals.jsonl")
        os.makedirs(self._data_dir, exist_ok=True)

    def emit(self, signal: IgrisSignal) -> None:
        """Append signal to JSONL log."""
        self._rotate_if_needed()
        with open(self._signals_path, "a") as f:
            f.write(json.dumps(signal.to_dict(), default=str) + "\n")

    def get_recent(self, limit: int = 50) -> list[dict]:
        """Read last N signals from the log."""
        if not os.path.exists(self._signals_path):
            return []
        try:
            with open(self._signals_path) as f:
                lines = f.readlines()
            result = []
            for line in reversed(lines[-limit:]):
                line = line.strip()
                if line:
                    result.append(json.loads(line))
            return result[:limit]
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Failed to read signals from %s: %s", self._signals_path, e)
            return []

    def get_by_id(self, signal_id: str) -> Optional[dict]:
        """Find a specific signal by ID."""
        if not os.path.exists(self._signals_path):
            return None
        try:
            with open(self._signals_path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    sig = json.loads(line)
                    if sig.get("signal_id") == signal_id:
                        return sig
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(
                "Failed to search signal %s in %s: %s", signal_id, self._signals_path, e
            )
        return None

    def _rotate_if_needed(self) -> None:
        """Rotate signals.jsonl when it exceeds MAX_FILE_SIZE."""
        if not os.path.exists(self._signals_path):
            return
        try:
            if os.path.getsize(self._signals_path) > self.MAX_FILE_SIZE:
                rotated = self._signals_path + ".1"
                if os.path.exists(rotated):
                    os.remove(rotated)
                os.rename(self._signals_path, rotated)
        except OSError as e:
            logger.warning(
                "Signal log rotation failed for %s: %s", self._signals_path, e
            )
