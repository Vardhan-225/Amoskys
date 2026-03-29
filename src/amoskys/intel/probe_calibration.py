"""Probe Self-Calibration — Beta-Binomial precision tracking per probe.

Every probe in AMOSKYS carries a precision weight that reflects its
historical accuracy. Probes that cry wolf (fire on familiar baseline
patterns) get downweighted. Probes that fire on genuinely novel or
anomalous events get upweighted.

The ground-truth signal comes from SOMA's frequency memory:
  - SOMA verdict "familiar" + probe fired → FALSE POSITIVE → β += 1
  - SOMA verdict "novel"/"anomalous" + probe fired → TRUE POSITIVE → α += 1
  - SOMA verdict "learning" → no update (insufficient data)

Math: Same Beta-Binomial posterior as AMRDR agent reliability.
  precision_weight = α / (α + β)

Storage: SQLite table in data/intel/probe_calibration.db
  - Lightweight, per-probe α/β parameters
  - Persists across restarts
  - Auto-decays stale calibrations (exponential smoothing)

Usage:
    calibrator = ProbeCalibrator()

    # After scoring, feed SOMA verdict back to calibrator
    calibrator.update("macos_suspicious_script", soma_verdict="familiar")
    # → This probe fired on a familiar pattern → FP → β += 1

    calibrator.update("macos_c2_beacon", soma_verdict="novel")
    # → This probe fired on a novel pattern → TP → α += 1

    # Get precision weight for scoring
    weight = calibrator.get_weight("macos_suspicious_script")
    # → 0.35 (probe has been crying wolf)

    risk_score *= weight  # Downweight noisy probes
"""

from __future__ import annotations

import logging
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger("amoskys.probe_calibration")

DB_PATH = Path("data/intel/probe_calibration.db")

# Minimum observations before calibration kicks in.
# Below this, probes run at full weight (benefit of the doubt).
MIN_OBSERVATIONS = 10

# Exponential decay factor applied every 24h to prevent stale calibrations
# from permanently penalizing probes that have been fixed.
DECAY_FACTOR = 0.95

# Floor weight — even the worst probe keeps 5% weight so it's never
# fully silenced (allows recovery via true positives).
MIN_WEIGHT = 0.05

# Ceiling — probes don't get boosted above 1.0
MAX_WEIGHT = 1.0

# Prior: start with α=2, β=1 (slight optimism — assume probes work)
PRIOR_ALPHA = 2.0
PRIOR_BETA = 1.0

# Critical probes: SOMA suppression is DISABLED for these.
# These detect attacks where repetition IS the attack pattern (credential
# harvesting, persistence, C2 beaconing). Frequent firing = real threat,
# not false positive. SOMA's "familiar" verdict must not suppress them.
CRITICAL_PROBES = frozenset(
    {
        "macos_infostealer_fake_dialog",  # T1056.002 — fake password prompts
        "macos_infostealer_browser_cred_theft",  # T1555.003 — browser credential theft
        "macos_config_backdoor",  # T1543 — persistence mechanism modification
        "macos_c2_beacon",  # T1071 — C2 callback beaconing
        "macos_dns_beaconing",  # T1071.004 — DNS-based C2
        "macos_quarantine_bypass",  # T1553.001 — gatekeeper bypass
        "macos_credential_access",  # T1555 — credential harvesting
    }
)


@dataclass
class ProbeCalibration:
    """Calibration state for a single probe."""

    probe_name: str
    alpha: float  # Beta distribution α (true positives + prior)
    beta: float  # Beta distribution β (false positives + prior)
    total_updates: int
    last_update: float  # epoch seconds
    last_decay: float  # epoch seconds of last decay application

    @property
    def precision_weight(self) -> float:
        """E[precision] = α / (α + β), clamped to [MIN_WEIGHT, MAX_WEIGHT]."""
        denom = self.alpha + self.beta
        if denom <= 0:
            return 1.0
        raw = self.alpha / denom
        return max(MIN_WEIGHT, min(MAX_WEIGHT, raw))

    @property
    def observation_count(self) -> int:
        """Total observations (α + β - prior)."""
        return max(0, int((self.alpha - PRIOR_ALPHA) + (self.beta - PRIOR_BETA)))


class ProbeCalibrator:
    """Tracks per-probe precision using Beta-Binomial posteriors.

    Thread-safe via SQLite serialization. Lightweight enough to call
    on every event in the analyzer pipeline.
    """

    def __init__(self, db_path: Optional[str] = None):
        self._db_path = db_path or str(DB_PATH)
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn: Optional[sqlite3.Connection] = None
        self._cache: Dict[str, ProbeCalibration] = {}
        self._cache_ts: float = 0
        self._pending: int = 0
        self._ensure_schema()

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(self._db_path, timeout=5)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA busy_timeout=3000")
        return self._conn

    def _ensure_schema(self):
        conn = self._get_conn()
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS probe_calibration (
                probe_name  TEXT PRIMARY KEY,
                alpha       REAL NOT NULL DEFAULT 2.0,
                beta        REAL NOT NULL DEFAULT 1.0,
                total_updates INTEGER NOT NULL DEFAULT 0,
                last_update REAL NOT NULL,
                last_decay  REAL NOT NULL
            );
        """
        )
        conn.commit()

    def update(self, probe_name: str, soma_verdict: str) -> float:
        """Update probe calibration based on SOMA's ground-truth verdict.

        Args:
            probe_name: The probe that fired.
            soma_verdict: SOMA's assessment of the event the probe fired on.
                "familiar" → false positive (β += 1)
                "novel" or "anomalous" → true positive (α += 1)
                "learning" → skip (insufficient baseline)

        Returns:
            Updated precision_weight for the probe.
        """
        # Critical probes: SOMA cannot suppress these. Repetition IS the attack.
        # A fake password dialog firing 100 times is 100x more dangerous, not a FP.
        if probe_name in CRITICAL_PROBES and soma_verdict == "familiar":
            soma_verdict = "novel"  # Override: treat as true positive
            logger.debug(
                "Critical probe %s: SOMA suppression overridden → forced TP",
                probe_name,
            )

        if soma_verdict == "learning":
            # Not enough data to judge — don't penalize or reward
            return self.get_weight(probe_name)

        conn = self._get_conn()
        now = time.time()

        row = conn.execute(
            "SELECT alpha, beta, total_updates, last_decay "
            "FROM probe_calibration WHERE probe_name = ?",
            (probe_name,),
        ).fetchone()

        if row:
            alpha, beta = row["alpha"], row["beta"]
            total = row["total_updates"]
            last_decay = row["last_decay"]
        else:
            alpha, beta = PRIOR_ALPHA, PRIOR_BETA
            total = 0
            last_decay = now

        # Apply decay if >24h since last decay
        if now - last_decay > 86400:
            days = (now - last_decay) / 86400
            decay = DECAY_FACTOR**days
            # Decay both α and β toward the prior (shrink toward 50%)
            alpha = PRIOR_ALPHA + (alpha - PRIOR_ALPHA) * decay
            beta = PRIOR_BETA + (beta - PRIOR_BETA) * decay
            last_decay = now

        # Update posterior
        if soma_verdict == "familiar":
            # Probe fired on a familiar pattern → false positive
            beta += 1.0
        elif soma_verdict in ("novel", "anomalous"):
            # Probe fired on novel/anomalous event → true positive
            alpha += 1.0

        total += 1

        conn.execute(
            """INSERT INTO probe_calibration
               (probe_name, alpha, beta, total_updates, last_update, last_decay)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(probe_name) DO UPDATE SET
               alpha=?, beta=?, total_updates=?, last_update=?, last_decay=?""",
            (
                probe_name,
                alpha,
                beta,
                total,
                now,
                last_decay,
                alpha,
                beta,
                total,
                now,
                last_decay,
            ),
        )

        self._pending += 1
        if self._pending >= 5:
            conn.commit()
            self._pending = 0

        # Update cache
        cal = ProbeCalibration(
            probe_name=probe_name,
            alpha=alpha,
            beta=beta,
            total_updates=total,
            last_update=now,
            last_decay=last_decay,
        )
        self._cache[probe_name] = cal

        return cal.precision_weight

    def get_weight(self, probe_name: str) -> float:
        """Get precision weight for a probe. Returns 1.0 if unknown."""
        # Check cache first
        if probe_name in self._cache:
            cal = self._cache[probe_name]
            if cal.observation_count >= MIN_OBSERVATIONS:
                return cal.precision_weight
            return 1.0  # Not enough data yet

        # Check DB
        conn = self._get_conn()
        row = conn.execute(
            "SELECT alpha, beta, total_updates FROM probe_calibration "
            "WHERE probe_name = ?",
            (probe_name,),
        ).fetchone()

        if row and row["total_updates"] >= MIN_OBSERVATIONS:
            denom = row["alpha"] + row["beta"]
            if denom > 0:
                return max(MIN_WEIGHT, min(MAX_WEIGHT, row["alpha"] / denom))
        return 1.0

    def get_all_weights(self) -> Dict[str, float]:
        """Get precision weights for all tracked probes."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT probe_name, alpha, beta, total_updates "
            "FROM probe_calibration ORDER BY (alpha / (alpha + beta)) ASC"
        ).fetchall()

        result = {}
        for r in rows:
            if r["total_updates"] >= MIN_OBSERVATIONS:
                denom = r["alpha"] + r["beta"]
                w = max(MIN_WEIGHT, r["alpha"] / denom) if denom > 0 else 1.0
                result[r["probe_name"]] = round(w, 4)
            else:
                result[r["probe_name"]] = 1.0
        return result

    def get_report(self) -> Dict[str, dict]:
        """Full calibration report for all probes."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM probe_calibration ORDER BY (alpha / (alpha + beta)) ASC"
        ).fetchall()

        report = {}
        for r in rows:
            cal = ProbeCalibration(
                probe_name=r["probe_name"],
                alpha=r["alpha"],
                beta=r["beta"],
                total_updates=r["total_updates"],
                last_update=r["last_update"],
                last_decay=r["last_decay"],
            )
            report[cal.probe_name] = {
                "precision_weight": round(cal.precision_weight, 4),
                "alpha": round(cal.alpha, 2),
                "beta": round(cal.beta, 2),
                "observations": cal.observation_count,
                "total_updates": cal.total_updates,
                "calibrated": cal.observation_count >= MIN_OBSERVATIONS,
            }
        return report

    def flush(self):
        """Force commit pending writes."""
        if self._pending > 0 and self._conn:
            self._conn.commit()
            self._pending = 0

    def close(self):
        """Flush and close."""
        self.flush()
        if self._conn:
            self._conn.close()
            self._conn = None
