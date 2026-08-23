"""The Ledger — one list that answers "what needs me?".

Replaces the three competing queues (Threats' 146-day-old fusion museum, the
Threat Feed's raw rows, and the incidents-view trio living in a second
application shell) with a single ordered list in the main shell.

Two ideas carry it:

  * **Sorted by "needs you", not by severity.** Severity answers "how bad would
    this be if it were an attack". The owner of the laptop is asking a different
    question — "is this me?" — and ``insight_service.classify_expected`` already
    produces exactly that vocabulary. Recognised activity collapses behind one
    line so the quiet is visible and *earned* rather than merely asserted.

  * **Every row can be answered.** "That's me" / "Not me" write a real verdict
    (see ``verdict_store``) and are forwarded best-effort to the reliability
    loop, so the user's judgement changes both what they see next time and —
    where the loop is reachable — what the detector believes.
"""

from __future__ import annotations

import logging
import sqlite3
from datetime import datetime, timezone

from . import verdict as verdict_mod
from . import verdict_store

logger = logging.getLogger(__name__)

try:
    from . import insight_service
except Exception:  # pragma: no cover - defensive import
    insight_service = None  # type: ignore[assignment]

# Evidence rows fetched per item for the "Show me" drawer.
EVIDENCE_LIMIT = 25

_BAND_RANK = {"red": 0, "amber": 1, "calm": 2}


def _short_when(raw) -> str:
    """A timestamp a person can read in a narrow column.

    The full ISO string is kept alongside it: an evidence row must stay
    copy-pasteable into a query, but it must not wrap over its own description.
    """
    if not raw:
        return "—"
    text = str(raw).replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return text[:16]
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone().strftime("%d %b · %H:%M:%S")


def _item_from_incident(inc: dict, user_verdicts: dict) -> dict:
    key = inc.get("id") or ""
    decided = user_verdicts.get(key)
    band = inc.get("band") or "calm"
    is_expected = inc.get("verdict") == "expected"

    # A user's own judgement outranks the engine's guess, in both directions.
    if decided:
        if decided["verdict"] == verdict_store.MINE:
            band, is_expected = "calm", True
        else:
            band, is_expected = "amber" if band == "calm" else band, False

    return {
        "key": key,
        "title": inc.get("title") or "Unnamed activity",
        "why": inc.get("why") or "",
        "band": band,
        "verdict_label": inc.get("verdict_label") or "",
        "factors": inc.get("factors") or [],
        "mitre": inc.get("mitre") or [],
        "count": inc.get("count") or 0,
        "evidence_count": inc.get("evidence_count", 0),
        "event_ids": (inc.get("event_ids") or [])[:EVIDENCE_LIMIT],
        "row_ids": inc.get("row_ids") or [],
        "has_evidence": bool(inc.get("event_ids")),
        "device_ids": inc.get("device_ids") or [],
        "categories": inc.get("categories") or [],
        "first": inc.get("first"),
        "last": inc.get("last"),
        "recognised": is_expected,
        "user_verdict": decided,
    }


def build(
    allowed_device_ids: list[str] | None = None,
    cache_key: str = "admin",
    org_scope: str = "admin",
    force: bool = False,
) -> dict:
    """The whole ledger payload. Never raises — degrades to an honest empty."""
    canonical = verdict_mod.fleet_verdict(
        allowed_device_ids=allowed_device_ids, cache_key=cache_key, force=force
    )
    taught = verdict_store.summary(org_scope)

    if insight_service is None:
        return {
            "verdict": canonical,
            "needs_you": [],
            "recognised": {"count": 0, "items": []},
            "taught": taught,
            "unavailable": "Insight service not loaded",
        }

    try:
        model = insight_service.get_model(
            force=force, allowed_device_ids=allowed_device_ids, cache_key=cache_key
        )
    except Exception:
        logger.warning("ledger model failed", exc_info=True)
        model = {}

    user_verdicts = verdict_store.get_all(org_scope)
    items = [
        _item_from_incident(i, user_verdicts) for i in (model.get("incidents") or [])
    ]

    needs_you = [i for i in items if not i["recognised"]]
    recognised = [i for i in items if i["recognised"]]
    needs_you.sort(key=lambda i: (_BAND_RANK.get(i["band"], 3), -i["count"]))
    recognised.sort(key=lambda i: -i["count"])

    suppressed_events = canonical.get("counts", {}).get("suppressed", 0)

    return {
        "verdict": canonical,
        "needs_you": needs_you,
        "recognised": {
            "count": len(recognised),
            "event_count": suppressed_events,
            "items": recognised,
        },
        "taught": taught,
        "unavailable": None,
    }


def evidence_for(
    event_ids: list,
    allowed_device_ids: list[str] | None = None,
    limit: int = EVIDENCE_LIMIT,
) -> list[dict]:
    """The rows behind a claim — redacted, org-scoped, and actually reachable.

    The incident drawer used to print 303 event ids as inert text. Naming your
    evidence and then withholding it is the specific thing that made the product
    feel untrustworthy, so this exists to make every claim openable.
    """
    if not event_ids or insight_service is None:
        return []
    db_path = insight_service.resolve_db_path()
    if not db_path:
        return []
    ids = [str(e) for e in event_ids[:limit] if e]
    if not ids:
        return []
    try:
        db = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5.0)
        db.row_factory = sqlite3.Row
    except sqlite3.Error:
        return []
    try:
        placeholders = ",".join("?" * len(ids))
        scope, scope_p = insight_service._scope_sql(allowed_device_ids, " AND ")
        rows = db.execute(
            "SELECT event_id, device_id, timestamp_dt, event_category, description, "
            "risk_score, confidence, final_classification, requires_investigation, "
            "threat_intel_match, mitre_techniques "
            f"FROM security_events WHERE event_id IN ({placeholders})"
            + scope
            + " ORDER BY timestamp_dt DESC",
            tuple(ids) + scope_p,
        ).fetchall()
    except sqlite3.Error:
        logger.warning("evidence lookup failed", exc_info=True)
        return []
    finally:
        db.close()

    out = []
    for r in rows:
        row = dict(r)
        out.append(
            {
                "event_id": row.get("event_id"),
                "device_id": row.get("device_id"),
                "when": _short_when(row.get("timestamp_dt")),
                "when_full": row.get("timestamp_dt"),
                "category": (row.get("event_category") or "").replace("_", " "),
                "description": insight_service._redact(row.get("description")),
                "risk": row.get("risk_score"),
                "confidence": row.get("confidence"),
                "classification": row.get("final_classification"),
                "requires_investigation": bool(row.get("requires_investigation")),
                "threat_intel_match": bool(row.get("threat_intel_match")),
                "mitre": insight_service._j(row.get("mitre_techniques"), []),
            }
        )
    return out


def find_item(
    key: str,
    allowed_device_ids: list[str] | None = None,
    cache_key: str = "admin",
    org_scope: str = "admin",
) -> dict | None:
    """One ledger item by key — used by the feedback and evidence endpoints so
    they operate on the server's view of the item, never on client-supplied
    event ids."""
    payload = build(
        allowed_device_ids=allowed_device_ids, cache_key=cache_key, org_scope=org_scope
    )
    for bucket in (payload["needs_you"], payload["recognised"]["items"]):
        for item in bucket:
            if item["key"] == key:
                return item
    return None
