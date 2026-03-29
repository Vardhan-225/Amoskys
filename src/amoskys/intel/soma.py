"""SOMA — Unified Self-Organizing Memory & Anomaly Engine.

Two hemispheres, one brain:
  LEFT:  Frequency memory (IGRIS soma_observations → what's normal for THIS machine)
  RIGHT: Statistical anomaly detection (numpy z-score → what deviates from baseline)

When sklearn is available, a third layer activates:
  DEEP:  IsolationForest + GradientBoosting (from soma_brain.py)

The unified SOMA answers one question:
  "Is this event normal for this machine, or is it something new?"

Returns a novelty score (0.0 = deeply familiar, 1.0 = never seen before)
and a familiarity profile that the scoring engine uses to suppress
false positives on known-benign patterns.

Usage:
    soma = UnifiedSOMA()

    # Record what we see (learning)
    soma.observe(category="suspicious_script", process="bash", path="/bin/bash", risk=0.8)

    # Query novelty (detection)
    result = soma.assess("suspicious_script", process="bash", path="/bin/bash")
    # result.novelty = 0.05 (very familiar)
    # result.seen_count = 47
    # result.suppression_factor = 0.85 (suppress 85% of behavioral score)

    # Get baseline stats
    stats = soma.get_baseline_stats()
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np

logger = logging.getLogger("amoskys.soma")

DATA_DIR = Path("data")
MEMORY_DB = DATA_DIR / "igris" / "memory.db"

# ── Dual-use process awareness ───────────────────────────────────────────
# Legitimate system tools that appear in BOTH normal operations and attacks.
# SOMA must not flag these as ANOMALY based on process name alone —
# classification must come from event context (what the process was doing).
DUAL_USE_PROCESSES: frozenset[str] = frozenset(
    {
        "arp",
        "curl",
        "wget",
        "ssh",
        "scp",
        "python3",
        "python",
        "bash",
        "zsh",
        "sh",
        "find",
        "ps",
        "netstat",
        "lsof",
        "osascript",
        "security",
        "openssl",
        "nslookup",
        "dig",
        "host",
        "nc",
        "ncat",
        "socat",
        "perl",
        "ruby",
        "system_profiler",
        "sw_vers",
        "ifconfig",
        "networksetup",
        "dscl",
    }
)

# Event categories that indicate clearly malicious intent — only these
# justify marking a dual-use process as ANOMALY.
MALICIOUS_CATEGORIES: frozenset[str] = frozenset(
    {
        "exfil",
        "beacon",
        "c2_",
        "reverse_shell",
        "credential",
        "keylog",
        "ransomware",
        "cryptominer",
        "backdoor",
        "rootkit",
        "trojan",
    }
)


@dataclass
class SOMAAssessment:
    """Result of SOMA novelty assessment for a single event."""

    category: str
    process_name: str
    path: str
    novelty: float  # 0.0 = deeply familiar, 1.0 = completely novel
    seen_count: int  # How many times SOMA has seen this exact pattern
    suppression_factor: float  # 0.0-1.0: how much to suppress behavioral score
    is_known: bool  # True if seen_count > threshold
    baseline_risk: float  # Average risk score for this pattern historically
    z_score: float  # Statistical deviation from category baseline
    verdict: str  # "familiar", "learning", "novel", "anomalous"


@dataclass
class SOMABaseline:
    """Aggregate baseline statistics for the device."""

    total_observations: int
    unique_patterns: int
    known_patterns: int  # seen_count > threshold
    novel_patterns: int  # seen_count == 1
    learning_patterns: int  # 1 < seen_count < threshold
    categories: Dict[str, int]  # category → count
    top_familiar: List[Dict[str, Any]]  # Most seen patterns
    top_novel: List[Dict[str, Any]]  # Newest patterns
    baseline_age_hours: float  # How long SOMA has been learning
    maturity: str  # "cold_start", "learning", "baseline", "mature"


class UnifiedSOMA:
    """The unified brain. Frequency memory + statistical anomaly.

    LEFT hemisphere (frequency):
        Reads from data/igris/memory.db → soma_observations table.
        Built by IGRIS tactical engine during assessment cycles.
        Answers: "how many times have I seen this exact pattern?"

    RIGHT hemisphere (statistical):
        Computes z-scores against per-category risk distributions.
        Uses numpy for statistical analysis.
        Answers: "does this event's risk score deviate from the norm?"

    SCORING integration:
        Returns suppression_factor that the ScoringEngine uses to
        reduce behavioral_score for known-benign patterns.
        Factor = 0.0 means "no suppression" (novel event).
        Factor = 0.85 means "suppress 85% of behavioral score" (deeply familiar).
    """

    # Thresholds for maturity and suppression
    KNOWN_THRESHOLD = 5  # seen_count >= 5 = "known pattern"
    MATURE_THRESHOLD = 100  # unique_patterns >= 100 = "mature baseline"
    BASELINE_THRESHOLD = 30  # unique_patterns >= 30 = "baseline established"
    MAX_SUPPRESSION = 0.85  # Never suppress more than 85%

    def __init__(self, memory_db: Optional[str] = None):
        self._db_path = memory_db or str(MEMORY_DB)
        self._conn: Optional[sqlite3.Connection] = None
        self._category_stats: Dict[str, Dict[str, float]] = {}
        self._last_stats_refresh: float = 0
        self._pending_writes: int = 0
        self._FLUSH_INTERVAL: int = 50  # commit every N observations
        self._ensure_db()

    def _ensure_db(self):
        """Ensure memory.db exists with soma_observations table."""
        db_path = Path(self._db_path)
        db_path.parent.mkdir(parents=True, exist_ok=True)

        conn = self._get_conn()
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS soma_observations (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                event_category  TEXT NOT NULL,
                process_name    TEXT DEFAULT '',
                path            TEXT DEFAULT '',
                domain          TEXT DEFAULT '',
                risk_score      REAL NOT NULL,
                is_normal       INTEGER DEFAULT -1,
                seen_count      INTEGER DEFAULT 1,
                first_seen      REAL NOT NULL,
                last_seen       REAL NOT NULL,
                UNIQUE(event_category, process_name, path)
            );
            CREATE INDEX IF NOT EXISTS idx_soma_category
                ON soma_observations(event_category);
            CREATE INDEX IF NOT EXISTS idx_soma_seen
                ON soma_observations(seen_count);
        """
        )
        conn.commit()
        self._graduate_existing()

    def _graduate_existing(self):
        """Retroactively classify observations stuck at is_normal = -1."""
        conn = self._get_conn()

        # ── Dual-use fix: rehabilitate common system tools wrongly flagged ──
        # These processes are normal when seen frequently in benign contexts.
        dual_placeholders = ",".join("?" for _ in DUAL_USE_PROCESSES)
        malicious_clauses = " AND ".join(
            f"event_category NOT LIKE '%{tag}%'" for tag in MALICIOUS_CATEGORIES
        )
        dual_cur = conn.execute(
            f"UPDATE soma_observations SET is_normal = 1 "
            f"WHERE process_name IN ({dual_placeholders}) "
            f"AND seen_count >= 10 AND is_normal != 1 "
            f"AND {malicious_clauses}",
            tuple(DUAL_USE_PROCESSES),
        )
        if dual_cur.rowcount > 0:
            logger.info(
                "SOMA retrograde: rehabilitated %d dual-use process observations as normal",
                dual_cur.rowcount,
            )

        # Graduate well-established low-risk patterns as normal
        normal_cur = conn.execute(
            "UPDATE soma_observations SET is_normal = 1 "
            "WHERE is_normal != 1 AND seen_count >= 5 AND risk_score < 0.3"
        )
        if normal_cur.rowcount > 0:
            logger.info(
                "SOMA retrograde: graduated %d observations as normal",
                normal_cur.rowcount,
            )

        # Flag high-risk patterns with enough evidence as anomalies
        # but NOT dual-use processes (those are context-driven above)
        anomaly_cur = conn.execute(
            f"UPDATE soma_observations SET is_normal = 0 "
            f"WHERE is_normal != 0 AND risk_score > 0.7 AND seen_count >= 3 "
            f"AND process_name NOT IN ({dual_placeholders})",
            tuple(DUAL_USE_PROCESSES),
        )
        if anomaly_cur.rowcount > 0:
            logger.info(
                "SOMA retrograde: graduated %d observations as anomaly",
                anomaly_cur.rowcount,
            )

        conn.commit()

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(self._db_path, timeout=5)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
        return self._conn

    def close(self):
        if self._conn:
            self.flush()
            self._conn.close()
            self._conn = None

    # ── LEFT HEMISPHERE: Frequency Memory ────────────────────────────────

    @staticmethod
    def _is_malicious_context(event_category: str) -> bool:
        """Check if the event category signals clearly malicious intent."""
        cat_lower = event_category.lower()
        return any(tag in cat_lower for tag in MALICIOUS_CATEGORIES)

    def observe(
        self,
        category: str,
        process: str = "",
        path: str = "",
        domain: str = "",
        risk: float = 0.0,
    ):
        """Record an observation. Called on every event in the analyzer pipeline.

        Uses INSERT OR REPLACE with deferred commits (every 50 writes) to
        avoid per-event I/O overhead when processing thousands of events/cycle.
        """
        if not category:
            return

        conn = self._get_conn()
        now = time.time()

        existing = conn.execute(
            "SELECT id, seen_count, risk_score FROM soma_observations "
            "WHERE event_category = ? AND process_name = ? AND path = ?",
            (category, process or "", path or ""),
        ).fetchone()

        if existing:
            new_count = existing["seen_count"] + 1
            old_risk = existing["risk_score"]

            # Risk decay: when pattern is well-established and new risk is low,
            # use exponential decay so the average converges faster instead of
            # being poisoned by early high-risk observations.
            if existing["seen_count"] > 5 and risk < 0.2:
                avg_risk = old_risk * 0.3 + risk * 0.7
            else:
                avg_risk = (old_risk * existing["seen_count"] + risk) / new_count

            # Graduation logic: classify is_normal based on accumulated evidence
            old_normal = conn.execute(
                "SELECT is_normal FROM soma_observations WHERE id = ?",
                (existing["id"],),
            ).fetchone()["is_normal"]
            new_normal = old_normal  # default: no change

            proc_base = Path(process).name if process else ""
            is_dual_use = proc_base in DUAL_USE_PROCESSES

            if is_dual_use:
                # Dual-use processes: context decides, not risk score alone
                if self._is_malicious_context(category):
                    new_normal = 0  # ANOMALY — malicious context confirmed
                    logger.info(
                        "SOMA dual-use %s → anomaly (malicious context: %s)",
                        proc_base,
                        category,
                    )
                elif new_count >= 10:
                    new_normal = 1  # NORMAL — common system tool, benign context
                    if old_normal != 1:
                        logger.info(
                            "SOMA dual-use %s → normal (seen=%d, benign context)",
                            proc_base,
                            new_count,
                        )
            elif new_count >= 5 and avg_risk < 0.3:
                if old_normal != 1:
                    new_normal = 1  # NORMAL
                    logger.info(
                        "SOMA graduated %s as normal (seen=%d, risk=%.3f)",
                        process or category,
                        new_count,
                        avg_risk,
                    )
            elif risk > 0.7 and old_normal == 1:
                new_normal = 0  # ANOMALY — something normal went bad
                logger.info(
                    "SOMA graduated %s as anomaly (was normal, new risk=%.3f)",
                    process or category,
                    risk,
                )

            conn.execute(
                "UPDATE soma_observations SET seen_count = ?, last_seen = ?, "
                "risk_score = ?, is_normal = ? WHERE id = ?",
                (new_count, now, round(avg_risk, 4), new_normal, existing["id"]),
            )
        else:
            conn.execute(
                "INSERT OR IGNORE INTO soma_observations "
                "(event_category, process_name, path, domain, risk_score, "
                "first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (category, process or "", path or "", domain or "", risk, now, now),
            )

        self._pending_writes += 1
        if self._pending_writes >= self._FLUSH_INTERVAL:
            conn.commit()
            self._pending_writes = 0

    def flush(self):
        """Force commit any pending writes."""
        if self._pending_writes > 0 and self._conn:
            self._conn.commit()
            self._pending_writes = 0

    def is_known(self, category: str, process: str = "", path: str = "") -> bool:
        """Quick check: has SOMA seen this pattern enough to consider it normal?"""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT seen_count FROM soma_observations "
            "WHERE event_category = ? AND process_name = ? AND path = ?",
            (category, process, path),
        ).fetchone()
        return row is not None and row["seen_count"] >= self.KNOWN_THRESHOLD

    # ── RIGHT HEMISPHERE: Statistical Anomaly ────────────────────────────

    def _refresh_category_stats(self):
        """Compute per-category risk score distributions for z-score."""
        now = time.time()
        if now - self._last_stats_refresh < 60:
            return  # Cache for 60s

        conn = self._get_conn()
        rows = conn.execute(
            "SELECT event_category, risk_score, seen_count FROM soma_observations"
        ).fetchall()

        categories: Dict[str, List[float]] = {}
        for r in rows:
            cat = r["event_category"]
            if cat not in categories:
                categories[cat] = []
            # Weight by seen_count — more observations = more reliable
            categories[cat].extend([r["risk_score"]] * min(r["seen_count"], 10))

        self._category_stats = {}
        for cat, risks in categories.items():
            if len(risks) >= 3:
                arr = np.array(risks)
                self._category_stats[cat] = {
                    "mean": float(np.mean(arr)),
                    "std": float(np.std(arr)) or 0.01,  # Avoid div by zero
                    "median": float(np.median(arr)),
                    "count": len(risks),
                }

        self._last_stats_refresh = now

    def _z_score(self, category: str, risk: float) -> float:
        """How many standard deviations is this risk from the category mean?"""
        self._refresh_category_stats()
        stats = self._category_stats.get(category)
        if not stats:
            return 0.0  # No baseline yet
        return (risk - stats["mean"]) / stats["std"]

    # ── UNIFIED ASSESSMENT ────────────────────────────────────────────────

    def assess(
        self,
        category: str,
        process: str = "",
        path: str = "",
        risk: float = 0.0,
    ) -> SOMAAssessment:
        """Full SOMA assessment: novelty + statistical deviation.

        This is the core method that the scoring engine calls.
        """
        conn = self._get_conn()

        # Frequency lookup
        row = conn.execute(
            "SELECT seen_count, risk_score, first_seen FROM soma_observations "
            "WHERE event_category = ? AND process_name = ? AND path = ?",
            (category, process, path),
        ).fetchone()

        seen_count = row["seen_count"] if row else 0
        baseline_risk = row["risk_score"] if row else risk
        is_known = seen_count >= self.KNOWN_THRESHOLD

        # Statistical deviation
        z = self._z_score(category, risk)

        # Compute novelty (0.0 = familiar, 1.0 = novel)
        if seen_count == 0:
            novelty = 1.0
        elif seen_count < self.KNOWN_THRESHOLD:
            novelty = max(0.3, 1.0 - (seen_count / self.KNOWN_THRESHOLD))
        else:
            # Known pattern — novelty drops with log of seen_count
            novelty = max(0.0, 0.3 - 0.1 * np.log10(seen_count))

        # Z-score can override: even a known pattern with abnormal risk is novel
        if abs(z) > 2.5:
            novelty = max(novelty, 0.6)

        # Compute suppression factor (how much to reduce behavioral score)
        if is_known and abs(z) < 2.0:
            # Known + within normal range = suppress
            suppression = min(
                self.MAX_SUPPRESSION,
                0.3 + 0.1 * np.log10(max(seen_count, 1)),
            )
        else:
            suppression = 0.0

        # Verdict
        if seen_count == 0:
            verdict = "novel"
        elif seen_count < self.KNOWN_THRESHOLD:
            verdict = "learning"
        elif abs(z) > 2.5:
            verdict = "anomalous"  # Known pattern but abnormal risk
        else:
            verdict = "familiar"

        return SOMAAssessment(
            category=category,
            process_name=process,
            path=path,
            novelty=round(novelty, 3),
            seen_count=seen_count,
            suppression_factor=round(suppression, 3),
            is_known=is_known,
            baseline_risk=round(baseline_risk, 4),
            z_score=round(z, 2),
            verdict=verdict,
        )

    # ── BASELINE STATS ────────────────────────────────────────────────────

    def get_baseline_stats(self) -> SOMABaseline:
        """Get aggregate baseline statistics for the device."""
        conn = self._get_conn()

        total = conn.execute("SELECT COUNT(*) FROM soma_observations").fetchone()[0]
        known = conn.execute(
            f"SELECT COUNT(*) FROM soma_observations WHERE seen_count >= {self.KNOWN_THRESHOLD}"
        ).fetchone()[0]
        novel = conn.execute(
            "SELECT COUNT(*) FROM soma_observations WHERE seen_count = 1"
        ).fetchone()[0]
        learning = total - known - novel

        # Categories
        cats = conn.execute(
            "SELECT event_category, SUM(seen_count) as total "
            "FROM soma_observations GROUP BY event_category "
            "ORDER BY total DESC"
        ).fetchall()
        categories = {r["event_category"]: r["total"] for r in cats}

        # Top familiar
        familiar = conn.execute(
            "SELECT event_category, process_name, path, seen_count, risk_score "
            "FROM soma_observations ORDER BY seen_count DESC LIMIT 10"
        ).fetchall()
        top_familiar = [dict(r) for r in familiar]

        # Top novel
        novel_rows = conn.execute(
            "SELECT event_category, process_name, path, risk_score, first_seen "
            "FROM soma_observations WHERE seen_count = 1 "
            "ORDER BY first_seen DESC LIMIT 10"
        ).fetchall()
        top_novel = [dict(r) for r in novel_rows]

        # Age
        oldest = conn.execute(
            "SELECT MIN(first_seen) FROM soma_observations"
        ).fetchone()[0]
        age_hours = (time.time() - oldest) / 3600 if oldest else 0

        # Maturity
        if total == 0:
            maturity = "cold_start"
        elif total < self.BASELINE_THRESHOLD:
            maturity = "learning"
        elif total < self.MATURE_THRESHOLD:
            maturity = "baseline"
        else:
            maturity = "mature"

        return SOMABaseline(
            total_observations=total,
            unique_patterns=total,
            known_patterns=known,
            novel_patterns=novel,
            learning_patterns=learning,
            categories=categories,
            top_familiar=top_familiar,
            top_novel=top_novel,
            baseline_age_hours=round(age_hours, 1),
            maturity=maturity,
        )
