"""Honesty invariants for the canonical verdict, the ledger and the verdict store.

These tests exist to keep three specific regressions from coming back:

  1. A verdict rendered over no telemetry ("Healthy" on a device that has
     reported nothing) — the one claim a security product must never make.
  2. A score shipped without its direction, which is how a 0-100 risk scale and
     a 0-100 health scale coexisted in the same UI.
  3. Self-noise suppression widening into a blind spot — the collector's own
     `log show` is expected, a bare `log` invocation is not.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

WEB_ROOT = Path(__file__).resolve().parents[2] / "web"
if str(WEB_ROOT) not in sys.path:
    sys.path.insert(0, str(WEB_ROOT))

insight_service = importlib.import_module("app.dashboard.insight_service")
verdict = importlib.import_module("app.dashboard.verdict")
verdict_store = importlib.import_module("app.dashboard.verdict_store")
ledger = importlib.import_module("app.dashboard.ledger")


# ── Self-noise: AMOSKYS observing AMOSKYS ────────────────────────────────────
@pytest.mark.parametrize(
    "description",
    [
        "log /usr/bin/log cmd=['log', 'show', '--predicate', 'process == \"sharingd\"']",
        "codesign /usr/bin/codesign --verify --deep /usr/bin/ssh",
        "lsof /usr/sbin/lsof -i -n -P",
        "nettop /usr/bin/nettop -x -l 1",
    ],
)
def test_collector_probes_are_recognised_as_our_own(description):
    ev = {"event_category": "lolbin_execution", "description": description}
    reason = insight_service.classify_expected(ev)
    assert reason is not None
    assert "AMOSKYS itself" in reason


def test_bare_binary_without_collection_arguments_still_surfaces():
    """Suppression keys on the command *shape*, not the binary name.

    If it keyed on the name, `log` and `lsof` would become a place to hide.
    """
    ev = {
        "event_category": "lolbin_execution",
        "description": "log /tmp/.hidden/log --exfiltrate",
    }
    assert (
        insight_service._classify_self_noise(
            ev["description"], ev["description"].lower()
        )
        is None
    )


def test_never_suppress_categories_survive_self_noise_matching():
    """Even a description that looks like ours cannot silence a scary category."""
    ev = {
        "event_category": "browser_credential_theft",
        "description": "amoskys collector touched Login Data",
    }
    assert insight_service.classify_expected(ev) is None


def test_shipping_to_our_own_server_is_recognised(monkeypatch):
    monkeypatch.setenv("AMOSKYS_SERVER", "https://18.223.110.15")
    ev = {
        "event_category": "cloud_exfil_detected",
        "description": "flow 192.168.1.146:60500 -> 18.223.110.15:443",
    }
    reason = insight_service.classify_expected(ev)
    assert reason is not None and "AMOSKYS itself" in reason


# ── The verdict refuses to speak without coverage ────────────────────────────
def test_no_coverage_yields_unknown_not_calm():
    payload = verdict._unknown(
        {
            "available": False,
            "devices_total": 3,
            "devices_reporting": 0,
            "last_event_at": None,
            "last_event_age_seconds": None,
            "last_event_age_human": "never",
            "reason": "No device has reported any security event",
        },
        "fleet",
    )
    assert payload["band"] == "unknown"
    assert payload["score"] is None
    assert payload["headline"] == "Not seen"
    assert "reported" in payload["sub_line"]


def test_every_verdict_states_its_scale():
    """A number without its direction is how the inversion bug survived."""
    shaped = verdict._shape(
        {"active_risk": 35, "band": "amber", "headline": "Worth a look"},
        {
            "available": True,
            "devices_total": 1,
            "devices_reporting": 1,
            "last_event_at": "2026-08-22T10:00:00+00:00",
            "last_event_age_seconds": 60,
            "last_event_age_human": "1m ago",
            "reason": None,
        },
        "fleet",
    )
    assert shaped["scale"] == "risk"
    assert "0 = nothing to do" in shaped["scale_note"]
    assert shaped["stale"] is False


def test_stale_reading_is_flagged():
    shaped = verdict._shape(
        {"active_risk": 10, "band": "calm", "headline": "You're OK"},
        {
            "available": True,
            "devices_total": 1,
            "devices_reporting": 1,
            "last_event_at": "2026-06-01T10:00:00+00:00",
            "last_event_age_seconds": verdict.STALE_SECONDS + 1,
            "last_event_age_human": "53d ago",
            "reason": None,
        },
        "fleet",
    )
    assert shaped["stale"] is True


def test_badge_never_reads_all_clear_for_unknown():
    assert verdict.badge({"band": "unknown", "sub_line": "x"})["label"] == "Not seen"
    assert verdict.badge({"band": "calm", "sub_line": "x"})["label"] == "Nothing to do"


# ── The verdict store: the button's persistence ──────────────────────────────
@pytest.fixture()
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("AMOSKYS_VERDICT_DB", str(tmp_path / "verdicts.db"))
    return verdict_store


def test_verdict_roundtrip_and_undo(store):
    store.record(
        "inc-test",
        "org-1",
        store.MINE,
        title="Your deploy workflow",
        event_ids=["e1", "e2"],
        categories=["full_kill_chain"],
        decided_by="owner@example.com",
        upstream_status="unavailable",
    )
    saved = store.get_all("org-1")
    assert saved["inc-test"]["verdict"] == store.MINE
    assert saved["inc-test"]["event_ids"] == ["e1", "e2"]
    assert store.summary("org-1") == {
        "total": 1,
        "mine": 1,
        "not_mine": 0,
        "upstream_applied": 0,
    }

    # Re-deciding overwrites rather than duplicating.
    store.record("inc-test", "org-1", store.NOT_MINE, title="Your deploy workflow")
    assert store.summary("org-1")["not_mine"] == 1
    assert store.summary("org-1")["total"] == 1

    assert store.clear("inc-test", "org-1") is True
    assert store.clear("inc-test", "org-1") is False
    assert store.get_all("org-1") == {}


def test_verdicts_are_scoped_per_tenant(store):
    store.record("inc-shared", "org-1", store.MINE)
    assert "inc-shared" in store.get_all("org-1")
    assert store.get_all("org-2") == {}


def test_invalid_verdict_rejected(store):
    with pytest.raises(ValueError):
        store.record("inc-test", "org-1", "probably-fine")


# ── The ledger honours the human over the engine ─────────────────────────────
def _incident(**over):
    base = {
        "id": "inc-x",
        "title": "Periodic DNS lookups flagged",
        "why": "…",
        "band": "amber",
        "verdict": "look",
        "verdict_label": "Worth a look",
        "count": 54,
        "evidence_count": 54,
        "event_ids": ["e1"],
        "row_ids": [1],
        "device_ids": ["dev-1"],
        "categories": ["dns_beaconing_suspected"],
    }
    base.update(over)
    return base


def test_thats_me_moves_an_item_out_of_the_queue():
    item = ledger._item_from_incident(
        _incident(),
        {"inc-x": {"verdict": verdict_store.MINE, "decided_at": 1.0}},
    )
    assert item["recognised"] is True
    assert item["band"] == "calm"


def test_not_me_keeps_an_expected_item_in_front_of_you():
    item = ledger._item_from_incident(
        _incident(band="calm", verdict="expected"),
        {"inc-x": {"verdict": verdict_store.NOT_MINE, "decided_at": 1.0}},
    )
    assert item["recognised"] is False
    assert item["band"] == "amber"


def test_undecided_item_keeps_the_engine_verdict():
    item = ledger._item_from_incident(_incident(), {})
    assert item["recognised"] is False
    assert item["band"] == "amber"
    assert item["user_verdict"] is None


def test_flow_derived_item_admits_it_has_no_rows():
    item = ledger._item_from_incident(
        _incident(event_ids=[], row_ids=[], evidence_count=0), {}
    )
    assert item["has_evidence"] is False


# ── Feedback routing ─────────────────────────────────────────────────────────
def test_categories_map_to_the_probe_whose_weight_moves():
    routes_ledger = importlib.import_module("app.dashboard.routes_ledger")
    assert routes_ledger._agents_for(["dns_beaconing_suspected"]) == ["dns_agent"]
    assert routes_ledger._agents_for(["macos_launchagent_new"]) == ["persistence_agent"]
    assert routes_ledger._agents_for(["browser_credential_theft"]) == ["auth_agent"]
    assert routes_ledger._agents_for(["something_unmapped"]) == []


# ── The front-page sentence ──────────────────────────────────────────────────
def _v(band, live, suppressed):
    return {"band": band, "counts": {"live": live, "suppressed": suppressed}}


def test_narrative_never_claims_clean_while_items_wait():
    """The old line said "traffic appears clean" whenever the *critical*
    counter was zero — directly above a kill chain showing 1.1K exploit
    events. The sentence now comes from the same verdict as the number."""
    line = verdict.narrative(_v("amber", 111, 694), item_count=3)
    assert "clean" not in line.lower()
    assert "3 things worth a look" in line
    assert "111 unexplained events" in line
    assert "694" in line


def test_narrative_separates_grouped_items_from_raw_events():
    """111 events grouped into 3 items must not read as "111 things"."""
    line = verdict.narrative(_v("amber", 111, 0), item_count=3)
    assert "111 things" not in line


def test_narrative_for_no_coverage_is_a_gap_not_an_all_clear():
    line = verdict.narrative(_v("unknown", 0, 0))
    assert "not an all-clear" in line


def test_narrative_calm_still_accounts_for_what_was_suppressed():
    line = verdict.narrative(_v("calm", 0, 694), item_count=0)
    assert "694" in line


def test_narrative_names_a_single_device():
    line = verdict.narrative(_v("calm", 0, 5), device_names=["Akash's MacBook Air"])
    assert "Akash's MacBook Air" in line
