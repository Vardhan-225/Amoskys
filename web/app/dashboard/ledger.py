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

import hashlib
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


# A signature that could not be READ vouches for nothing. `unknown` is what
# kernel._trust() returns when the signing flags are absent, and folding it in
# with the signed binaries made the grouped item assert "every one of them
# carries a signature identifying where it came from" about software whose
# signature was never established. Not knowing and knowing-it-is-fine are
# different states — that distinction is the whole reason `unknown` exists.
_UNVOUCHED = ("unsigned", "signature-invalid", "unknown")


def _band_after_verdict(band: str, decided: dict | None) -> str:
    """Apply a user's verdict over the engine's band, in both directions."""
    if not decided:
        return band
    if decided["verdict"] == verdict_store.MINE:
        return "calm"
    # "Not me" must never leave an item calm: the person has just said this is
    # not their software.
    return "amber" if band == "calm" else band


def _binary_name(row: dict) -> str:
    return (row.get("first_exe") or "an unnamed binary").rsplit("/", 1)[-1]


def _kernel_item(
    *,
    key,
    title,
    why,
    band,
    verdict_label,
    factors,
    count,
    decided,
    cdhash=None,
    cdhashes=None,
) -> dict:
    """One ledger item from the exec stream, in the shape build() expects."""
    item = {
        "key": key,
        "title": title,
        "why": why,
        # A human's judgement outranks the engine in BOTH directions. Only MINE
        # was honoured here, so "Not me" on a first-run item left it sitting in
        # the calm band with its original wording — the user told the product it
        # was wrong and the product kept its own verdict. That asymmetry is the
        # thing the two buttons exist to remove.
        "band": _band_after_verdict(band, decided),
        "verdict_label": (
            "You said this is not yours"
            if (decided and decided["verdict"] == verdict_store.NOT_MINE)
            else verdict_label
        ),
        "factors": factors,
        "mitre": [],
        "count": count,
        "evidence_count": count,
        "event_ids": [],
        "row_ids": [],
        "has_evidence": False,
        "device_ids": [],
        "categories": ["esf_novel_binary"],
        "first": None,
        "last": None,
        "recognised": bool(decided and decided["verdict"] == verdict_store.MINE),
        "user_verdict": decided,
        "source": "kernel",
    }
    if cdhash:
        item["cdhash"] = cdhash
    if cdhashes:
        # Without these the grouped item reached the feedback endpoint with no
        # binary identity at all, so "That's me" wrote nothing to
        # esf_binary_ledger and reported itself as "derived from flow
        # aggregates" — a control that did nothing and then misdescribed why.
        item["cdhashes"] = [c for c in cdhashes if c]
    return item


def _kernel_items(user_verdicts: dict) -> list[dict]:
    """First-run software, asked about in proportion to what is actually unknown.

    Novelty is the strongest signal the exec stream produces — a cdhash that has
    never run on this machine before is precise in a way a path rule cannot be —
    and it is the one finding a person can genuinely adjudicate: "did you
    install this?"

    But measured live, 17 novel binaries (12 signed, 5 ad-hoc, ZERO unsigned)
    produced 17 separate questions that buried the three real findings. A valid
    signature already answers "where did this come from", and ad-hoc is simply
    how Homebrew ships. So:

      * a binary whose signature cannot vouch for it gets its own question;
      * every other first-run collapses into one.

    That holds in both directions, which matters: crossing the baseline
    threshold must not turn one queue item into twenty overnight.
    """
    try:
        from . import kernel
    except Exception:  # pragma: no cover - defensive import
        return []
    try:
        report = kernel.novel_binaries()
    except Exception:  # pragma: no cover
        logger.debug("novel binary lookup failed", exc_info=True)
        return []
    if not report.get("available") or not report.get("novel"):
        return []

    all_rows = report["novel"]
    baseline_ready = bool(report.get("baseline_ready"))
    # Unvouched is unvouched on day one too. A young baseline makes NOVELTY
    # meaningless — it does not make an unsigned binary trustworthy — so the
    # split holds regardless; only the grouped item's wording changes.
    notable = [r for r in all_rows if (r.get("trust") or "") in _UNVOUCHED]
    routine = [r for r in all_rows if (r.get("trust") or "") not in _UNVOUCHED]

    out: list[dict] = []

    if routine:
        names = ", ".join(_binary_name(r) for r in routine[:4])
        more = f" and {len(routine) - 4} more" if len(routine) > 4 else ""
        # The key is derived from the MEMBERS, not from the concept. A constant
        # key over a changing population meant one "That's me" cleared every
        # first-run program that would ever appear afterwards: tomorrow's newly
        # dropped binary would arrive pre-recognised, in the calm band, without
        # anyone having looked at it. A verdict may only ever clear the things
        # it was actually shown.
        batch_cdhashes = sorted(r.get("cdhash") or "" for r in routine)
        batch_id = hashlib.sha256("|".join(batch_cdhashes).encode()).hexdigest()[:16]
        key = f"binary:batch:{batch_id}"
        decided = user_verdicts.get(key)
        if baseline_ready:
            why = (
                f"The kernel witnessed {names}{more} execute here for the first "
                "time. Each one carries a code signature the kernel could "
                "read, so they are grouped into a single question rather than "
                "asked one at a time — note that an ad-hoc signature proves the "
                "binary has not been altered since it was built, but names no "
                "author. Anything the kernel could not vouch for at all is "
                "listed separately, above."
            )
            label = "Routine software"
        else:
            why = (
                f"The kernel witnessed {names}{more} execute here for the first "
                f"time. {report.get('note') or ''} They are grouped for that "
                "reason: treating a fresh install as one alarm per program "
                "would teach you to ignore them."
            )
            label = "Still learning your normal"
        out.append(
            _kernel_item(
                key=key,
                title=(
                    f"{len(routine)} program{'s' if len(routine) != 1 else ''} "
                    "ran here for the first time"
                ),
                why=why,
                band="calm",
                verdict_label=label,
                factors=[
                    f"{report.get('known_binaries_total', 0)} binaries known so far",
                    "kernel-witnessed",
                    (
                        "signature readable"
                        if baseline_ready
                        else "baseline not established"
                    ),
                ],
                count=len(routine),
                decided=decided,
                cdhashes=batch_cdhashes,
            )
        )

    for row in notable:
        cdhash = row.get("cdhash") or ""
        key = f"binary:{cdhash[:32]}"
        decided = user_verdicts.get(key)
        trust = row.get("trust") or "unknown"
        name = _binary_name(row)
        out.append(
            _kernel_item(
                key=key,
                title=f"First time on this Mac: {name}",
                why=(
                    f"The kernel witnessed {name} execute for the first time "
                    f"{row.get('age_minutes', 0)} minutes ago, and its code "
                    f"signature reads as {trust} — nothing vouches for where it "
                    "came from. Identity is tracked by code hash, so moving or "
                    "renaming it does not make it new again."
                ),
                band="amber",
                verdict_label="Did you install this?",
                factors=[
                    f"signature: {trust}",
                    f"first seen {row.get('age_minutes', 0)}m ago",
                    f"{row.get('exec_count', 1)} run(s)",
                    "kernel-witnessed",
                ],
                count=row.get("exec_count", 1),
                decided=decided,
                cdhash=cdhash,
            )
        )
    return out


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
    items.extend(_kernel_items(user_verdicts))

    needs_you = [i for i in items if not i["recognised"]]
    recognised = [i for i in items if i["recognised"]]
    needs_you.sort(key=lambda i: (_BAND_RANK.get(i["band"], 3), -i["count"]))
    recognised.sort(key=lambda i: -i["count"])

    suppressed_events = canonical.get("counts", {}).get("suppressed", 0)

    # Suppression that formed no correlated story still happened, and the user
    # was told about it in the verdict ("N cleared automatically") while the
    # Recognised section said "Nothing was auto-recognised yet". Group whatever
    # is left by the REASON the engine gave, so every cleared event is
    # accounted for and inspectable rather than only the ones that happened to
    # correlate.
    accounted = sum(i["count"] for i in recognised)
    breakdown = canonical.get("suppression_breakdown") or []
    if breakdown and suppressed_events > accounted:
        for entry in breakdown:
            reason = entry.get("reason") or "recognised activity"
            key = "suppressed:" + hashlib.sha256(reason.encode()).hexdigest()[:12]
            decided = user_verdicts.get(key)
            recognised.append(
                {
                    "key": key,
                    "title": f"{entry.get('count', 0)} events — {reason}",
                    "why": (
                        f"AMOSKYS cleared {entry.get('count', 0)} events for this "
                        f"reason: {reason}. They are listed here rather than hidden "
                        "because a suppression you cannot audit is indistinguishable "
                        "from a blind spot. If this reason is wrong, say so and it "
                        "stops being applied. A few of these may also appear above "
                        "inside a correlated story — this is a breakdown by reason, "
                        "not a separate set of events, so the rows here do not add "
                        "up to the total."
                    ),
                    "band": "calm",
                    "verdict_label": "Cleared automatically",
                    "factors": [reason, "auto-suppressed", "not shown as a finding"],
                    "mitre": [],
                    "count": entry.get("count", 0),
                    "evidence_count": entry.get("count", 0),
                    "event_ids": [],
                    "row_ids": [],
                    "has_evidence": False,
                    "device_ids": [],
                    "categories": [],
                    "first": None,
                    "last": None,
                    "recognised": True,
                    "user_verdict": decided,
                    "source": "suppression",
                }
            )
        recognised.sort(key=lambda i: -i["count"])

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
                # Grade of evidence. A poll sample and a kernel observation are
                # not the same claim, and a row that does not say which it is
                # invites the reader to assume the stronger one.
                "provenance": _provenance(row),
            }
        )
    return out


_KERNEL_SOURCES = ("esf", "sentinel", "kernel")


def _provenance(row: dict) -> str:
    """ "kernel-witnessed" only when the evidence actually came from the kernel."""
    haystack = " ".join(
        str(row.get(field) or "").lower()
        for field in ("description", "event_category", "tier")
    )
    if any(marker in haystack for marker in _KERNEL_SOURCES):
        return "kernel-witnessed"
    return "sampled"


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
