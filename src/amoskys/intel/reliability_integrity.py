"""Has the trust model ever seen a counterexample?

WHY THIS EXISTS
---------------
On 2026-09-02, AMRDR held 26,643 observations with ground_truth_match = 1 on
every single one. No exceptions, `reason` empty on every row. Beta therefore
never left 1.0, and all three agents converged to essentially the same weight:

    process   Beta(a=7931, b=1)  weight=0.999874  sd=0.000126
    network   Beta(a=8625, b=1)  weight=0.999884  sd=0.000116
    SECURITY  Beta(a=1778, b=1)  weight=0.999438  sd=0.000562
    spread across agents: 4.46e-04

Multiplying a score by 0.999874 instead of 0.999884 is not a preference. The
trust framework was running, current, and arithmetically identical to having no
trust framework at all.

THE FAILURE MODE THIS CATCHES, WHICH IS NOT THE USUAL ONE
---------------------------------------------------------
Most integrity checks look for something MISSING — a dead process, an empty
table, a stale timestamp. AMRDR would pass all of them: the store is populated,
the writes are current, the numbers are well-formed.

This is the inverted failure. The model runs, produces authoritative output, and
the output carries no information. sd=0.000126 reads as a tight, confident
posterior. It is the variance of a model that has never recorded a
counterexample — confidence manufactured from the absence of evidence rather
than the weight of it.

That is the same error as treating `kernel_would_deny` as a strong witness when
all 6 of 657,764 occurrences were benign local builds: rarity read as
reliability. Here it has been promoted into the layer whose job is to catch
exactly that, which is why nothing below it can see it.

A confident number that means nothing is worse than a blank one. A blank invites
a question; a confident one invites the trust it has not earned.

THREE STATES, DELIBERATELY
--------------------------
UNMEASURABLE  the store cannot answer — missing, unreadable, no agents.
UNINFORMATIVE it answered, and the answer cannot distinguish any sensor from
              any other. This is NOT healthy and NOT broken; it is a model with
              nothing to say, and it must not be rendered as either.
INFORMATIVE   the model has seen disagreement and its weights carry it.

Collapsing UNINFORMATIVE into healthy is the whole bug. Collapsing it into
broken would be wrong too — nothing has failed, the model has simply never been
given a negative to learn from, and the fix is a ground-truth path, not a
repair.
"""
from __future__ import annotations

import logging
import os
import sqlite3
from typing import Any, Dict

logger = logging.getLogger(__name__)

DEFAULT_DB = "data/intel/reliability.db"

# Below this, weights cannot express a preference. At the measured 4.46e-04 the
# strongest and weakest agent differ by under a twentieth of one percent — no
# downstream decision can turn on that, so reporting it as three distinct
# reliabilities overstates what the model knows.
_UNIFORM_WEIGHT_SPREAD = 1e-3


def measure(db_path: str | None = None) -> Dict[str, Any]:
    """Report what AMRDR can actually distinguish. Never raises."""
    path = db_path or os.getenv("AMOSKYS_RELIABILITY_DB", DEFAULT_DB)
    out: Dict[str, Any] = {
        "state": "unmeasurable",
        "headline": "The trust model cannot be assessed on this tier",
        "detail": "No reliability store is readable here.",
        "observations": None,
        "counterexamples": None,
        "agents": None,
        "beta_max": None,
        "weight_spread": None,
    }
    if not os.path.exists(path):
        return out
    try:
        db = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5.0)
    except sqlite3.Error:
        return out
    try:
        total = db.execute("SELECT COUNT(*) FROM observation_log").fetchone()[0]
        # The single load-bearing number. Everything else is consequence.
        negatives = db.execute(
            "SELECT COUNT(*) FROM observation_log WHERE ground_truth_match = 0"
        ).fetchone()[0]
        rows = db.execute(
            "SELECT agent_id, alpha, beta, fusion_weight FROM agent_reliability"
        ).fetchall()
    except sqlite3.Error:
        logger.warning("reliability integrity read failed", exc_info=True)
        return out
    finally:
        db.close()

    if not rows:
        out["observations"] = total
        out["detail"] = "The reliability store has no agents recorded."
        return out

    weights = [r[3] for r in rows if r[3] is not None]
    spread = (max(weights) - min(weights)) if len(weights) > 1 else 0.0
    beta_max = max((r[2] or 0.0) for r in rows)

    out.update({
        "observations": total,
        "counterexamples": negatives,
        "agents": len(rows),
        "beta_max": beta_max,
        "weight_spread": spread,
    })

    if negatives == 0 or spread < _UNIFORM_WEIGHT_SPREAD:
        out["state"] = "uninformative"
        out["headline"] = "The trust model has never seen a counterexample"
        out["detail"] = (
            f"{total:,} observations recorded and {negatives} of them disagreed "
            f"with the agent. Beta has not moved past {beta_max:.1f}, so every "
            f"agent carries effectively the same weight (spread "
            f"{spread:.2e}). Weighting by these numbers is arithmetically the "
            "same as not weighting at all — the model cannot prefer one sensor "
            "over another, and its confidence comes from never having been "
            "contradicted rather than from evidence. Nothing here has failed; "
            "there is no path recording negatives for it to learn from."
        )
        return out

    out["state"] = "informative"
    out["headline"] = "The trust model has seen disagreement and carries it"
    out["detail"] = (
        f"{negatives:,} of {total:,} observations disagreed with the agent; "
        f"weights span {spread:.3f} across {len(rows)} agents."
    )
    return out
