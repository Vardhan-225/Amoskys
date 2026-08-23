"""The canonical verdict — computed once, read everywhere.

Before this module the app carried FOUR independent answers to "is this machine
OK", in two opposite orientations:

  * ``insight_service.compute_verdict``   risk 0-100, 0 = safe  (corroboration-gated)
  * ``routes_overview._compute_posture``  risk 0-100, 0 = safe  (count-driven)
  * ``devices.html`` line 191 (JavaScript) health 0-100, 100 = safe
  * ``store.compute_nerve_posture``       health 0-100, 100 = safe (tanh/decay)

So one laptop could read "High Risk 35", "All Clear 100" and "CRITICAL 5" at the
same moment. Only the first of those is corroboration-gated and anti-cry-wolf,
so it wins; everything else in the UI must read this module instead of computing
its own.

Two rules this module enforces that no caller may opt out of:

  1. **The scale is stated.** Every payload carries ``scale: "risk"`` and
     ``scale_note``. A number without its direction is how the inversion bug
     survived for months.
  2. **No verdict without coverage.** If nothing reported, the band is
     ``unknown`` and the score is ``None`` — never a green "All Clear" produced
     by an empty query. "Blind" and "clean" are different answers and a security
     product may not conflate them.
"""

from __future__ import annotations

import logging
import os
import sqlite3
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

try:
    from . import insight_service
except Exception:  # pragma: no cover - defensive import
    insight_service = None  # type: ignore[assignment]

# Beyond this, the verdict is labelled as of an older moment rather than "now".
STALE_SECONDS = int(os.getenv("AMOSKYS_VERDICT_STALE_SECONDS", "900"))

SCALE_NOTE = "0 = nothing to do · 100 = act now"

BAND_TONE = {
    "calm": "calm",
    "amber": "amber",
    "red": "red",
    "unknown": "unknown",
}


def _parse_dt(raw) -> datetime | None:
    if not raw:
        return None
    if isinstance(raw, (int, float)):
        try:
            return datetime.fromtimestamp(float(raw), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    text = str(raw).strip().replace("Z", "+00:00")
    for candidate in (text, text.split(".")[0]):
        try:
            dt = datetime.fromisoformat(candidate)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _age_seconds(dt: datetime | None) -> int | None:
    if dt is None:
        return None
    return max(0, int((datetime.now(timezone.utc) - dt).total_seconds()))


def _humanise(seconds: int | None) -> str:
    if seconds is None:
        return "unknown"
    if seconds < 90:
        return f"{seconds}s ago"
    if seconds < 5400:
        return f"{seconds // 60}m ago"
    if seconds < 172800:
        return f"{seconds // 3600}h ago"
    return f"{seconds // 86400}d ago"


def _coverage(allowed_device_ids: list[str] | None) -> dict:
    """What actually reported, so the verdict can refuse to speak without data."""
    blank = {
        "available": False,
        "devices_total": 0,
        "devices_reporting": 0,
        "last_event_at": None,
        "last_event_age_seconds": None,
        "last_event_age_human": "never",
        "reason": "No telemetry store reachable",
    }
    if insight_service is None:
        return blank
    db_path = insight_service.resolve_db_path()
    if not db_path:
        return blank
    try:
        db = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5.0)
    except sqlite3.Error:
        return blank
    try:
        scope, params = insight_service._scope_sql(allowed_device_ids, " WHERE ")
        row = db.execute(
            "SELECT COUNT(DISTINCT device_id) AS reporting, MAX(timestamp_dt) AS latest "
            "FROM security_events" + scope,
            params,
        ).fetchone()
        reporting = row[0] if row else 0
        latest = row[1] if row else None
        try:
            total = db.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        except sqlite3.Error:
            total = reporting
        age = _age_seconds(_parse_dt(latest))
        return {
            "available": bool(reporting) and latest is not None,
            "devices_total": total,
            "devices_reporting": reporting,
            "last_event_at": latest,
            "last_event_age_seconds": age,
            "last_event_age_human": _humanise(age),
            "reason": (
                None if reporting else "No device has reported any security event"
            ),
        }
    except sqlite3.Error:
        return blank
    finally:
        db.close()


def _unknown(coverage: dict, subject: str) -> dict:
    """The honest shape when there is nothing to judge."""
    reason = coverage.get("reason") or "No telemetry in the selected window"
    return {
        "score": None,
        "band": "unknown",
        "tone": "unknown",
        "headline": "Not seen",
        "sub_line": reason,
        "scale": "risk",
        "scale_note": SCALE_NOTE,
        "subject": subject,
        "as_of": coverage.get("last_event_at"),
        "age_seconds": coverage.get("last_event_age_seconds"),
        "age_human": coverage.get("last_event_age_human", "never"),
        "stale": True,
        "source": "no coverage",
        "counts": {"live": 0, "suppressed": 0, "requires_investigation": 0},
        "top_factors": [],
        "coverage": coverage,
    }


def _shape(raw: dict, coverage: dict, subject: str) -> dict:
    age = coverage.get("last_event_age_seconds")
    band = raw.get("band") or "calm"
    return {
        "score": int(raw.get("active_risk") or 0),
        "band": band,
        "tone": BAND_TONE.get(band, band),
        "headline": raw.get("headline") or "",
        "sub_line": raw.get("sub_line") or "",
        "scale": "risk",
        "scale_note": SCALE_NOTE,
        "subject": subject,
        "as_of": coverage.get("last_event_at"),
        "age_seconds": age,
        "age_human": coverage.get("last_event_age_human", "unknown"),
        "stale": age is None or age > STALE_SECONDS,
        "source": "fusion verdict (corroboration-gated)",
        "counts": {
            "live": raw.get("live_count", 0),
            "suppressed": raw.get("suppressed_count", 0),
            "requires_investigation": raw.get("requires_investigation", 0),
        },
        "top_factors": raw.get("top_factors") or [],
        "coverage": coverage,
    }


def fleet_verdict(
    allowed_device_ids: list[str] | None = None,
    cache_key: str = "admin",
    force: bool = False,
) -> dict:
    """The one verdict for everything the caller is allowed to see."""
    coverage = _coverage(allowed_device_ids)
    if insight_service is None or not coverage["available"]:
        return _unknown(coverage, "fleet")
    try:
        model = insight_service.get_model(
            force=force, allowed_device_ids=allowed_device_ids, cache_key=cache_key
        )
    except Exception:
        logger.warning("fleet verdict failed", exc_info=True)
        return _unknown(coverage, "fleet")
    raw = (model or {}).get("verdict") or {}
    if not raw:
        return _unknown(coverage, "fleet")
    return _shape(raw, coverage, "fleet")


def device_verdict(
    device_id: str,
    allowed_device_ids: list[str] | None = None,
    cache_key: str = "admin",
    force: bool = False,
) -> dict:
    """The same verdict, scoped to one device — same scale, same vocabulary.

    A device the caller may see but which has reported nothing gets ``unknown``,
    not ``calm``: that is the whole point of this module.
    """
    scope = [device_id]
    if allowed_device_ids is not None and device_id not in allowed_device_ids:
        return _unknown(
            {
                "available": False,
                "devices_total": 0,
                "devices_reporting": 0,
                "last_event_at": None,
                "last_event_age_seconds": None,
                "last_event_age_human": "never",
                "reason": "Device not in your organisation",
            },
            device_id,
        )
    coverage = _coverage(scope)
    if insight_service is None or not coverage["available"]:
        return _unknown(coverage, device_id)
    try:
        model = insight_service.get_model(
            force=force,
            allowed_device_ids=scope,
            cache_key=f"{cache_key}:dev:{device_id}",
        )
    except Exception:
        logger.warning("device verdict failed for %s", device_id, exc_info=True)
        return _unknown(coverage, device_id)
    raw = (model or {}).get("verdict") or {}
    if not raw:
        return _unknown(coverage, device_id)
    return _shape(raw, coverage, device_id)


def badge(verdict: dict) -> dict:
    """Presentation triple for a compact badge, derived from the same payload.

    Kept here so no template invents its own thresholds again.
    """
    band = verdict.get("band", "unknown")
    if band == "unknown":
        return {
            "label": "Not seen",
            "tone": "unknown",
            "detail": verdict.get("sub_line", ""),
        }
    if band == "red":
        return {
            "label": "Act now",
            "tone": "red",
            "detail": verdict.get("sub_line", ""),
        }
    if band == "amber":
        return {
            "label": "Worth a look",
            "tone": "amber",
            "detail": verdict.get("sub_line", ""),
        }
    return {
        "label": "Nothing to do",
        "tone": "calm",
        "detail": verdict.get("sub_line", ""),
    }
