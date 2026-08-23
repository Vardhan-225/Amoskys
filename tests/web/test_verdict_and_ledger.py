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


# ── Kernel novelty in the queue ──────────────────────────────────────────────
def _novel(n, *, baseline_ready, trust="signed"):
    return {
        "available": True,
        "baseline_ready": baseline_ready,
        "known_binaries_total": 900 if baseline_ready else 58,
        "note": (
            None if baseline_ready else "Only 58 binaries have ever been recorded here"
        ),
        "novel": [
            {
                "cdhash": f"cd{i}",
                "first_exe": f"/opt/thing{i}",
                "trust": trust,
                "age_minutes": 3,
                "exec_count": 1,
            }
            for i in range(n)
        ],
    }


def test_a_young_ledger_collapses_novelty_into_one_item(monkeypatch):
    """Six "first time on this Mac" alarms on day one teaches people to ignore
    the queue. The exec stream says its own baseline is not ready; the ledger
    has to respect that."""
    kernel = importlib.import_module("app.dashboard.kernel")
    monkeypatch.setattr(
        kernel, "novel_binaries", lambda *a, **k: _novel(6, baseline_ready=False)
    )
    items = ledger._kernel_items({})
    assert len(items) == 1
    assert items[0]["title"] == "6 programs ran here for the first time"
    assert items[0]["verdict_label"] == "Still learning your normal"
    assert "grouped for that reason" in items[0]["why"]


def test_an_established_baseline_still_groups_vouched_software(monkeypatch):
    """Superseded expectation: this used to assert one item per binary. Listing
    every signed first-run separately is exactly what buried the real findings
    when the baseline crossed its threshold on the live machine."""
    kernel = importlib.import_module("app.dashboard.kernel")
    monkeypatch.setattr(
        kernel, "novel_binaries", lambda *a, **k: _novel(3, baseline_ready=True)
    )
    items = ledger._kernel_items({})
    assert len(items) == 1
    assert items[0]["title"].startswith("3 programs")
    assert items[0]["verdict_label"] == "Routine software"


def test_unsigned_first_runs_raise_the_band_even_while_learning(monkeypatch):
    kernel = importlib.import_module("app.dashboard.kernel")
    monkeypatch.setattr(
        kernel,
        "novel_binaries",
        lambda *a, **k: _novel(2, baseline_ready=False, trust="unsigned"),
    )
    item = ledger._kernel_items({})[0]
    assert item["band"] == "amber"
    assert "unsigned" in item["why"]


def test_signed_first_runs_do_not_manufacture_alarm(monkeypatch):
    kernel = importlib.import_module("app.dashboard.kernel")
    monkeypatch.setattr(
        kernel,
        "novel_binaries",
        lambda *a, **k: _novel(2, baseline_ready=False, trust="signed"),
    )
    assert ledger._kernel_items({})[0]["band"] == "calm"


def test_kernel_items_carry_their_provenance(monkeypatch):
    """Only an individually-listed binary carries a cdhash — the grouped item
    stands for many, so it identifies none."""
    kernel = importlib.import_module("app.dashboard.kernel")
    monkeypatch.setattr(
        kernel,
        "novel_binaries",
        lambda *a, **k: _novel(1, baseline_ready=True, trust="unsigned"),
    )
    item = ledger._kernel_items({})[0]
    assert item["source"] == "kernel"
    assert "kernel-witnessed" in item["factors"]
    assert item["cdhash"] == "cd0"


def test_signed_first_runs_are_one_question_not_seventeen(monkeypatch):
    """Measured live: 17 novel binaries (12 signed, 5 ad-hoc, 0 unsigned) became
    17 separate "did you install this?" items and buried three real findings.
    A valid signature already answers where software came from."""
    kernel = importlib.import_module("app.dashboard.kernel")
    rows = _novel(17, baseline_ready=True, trust="signed")
    monkeypatch.setattr(kernel, "novel_binaries", lambda *a, **k: rows)
    items = ledger._kernel_items({})
    assert len(items) == 1
    assert items[0]["band"] == "calm"
    assert "17 programs" in items[0]["title"]
    assert items[0]["verdict_label"] == "Routine software"


def test_an_unvouched_binary_still_gets_its_own_question(monkeypatch):
    kernel = importlib.import_module("app.dashboard.kernel")
    mixed = _novel(3, baseline_ready=True, trust="signed")
    mixed["novel"].append(
        {
            "cdhash": "evil",
            "first_exe": "/tmp/.hidden/impl",
            "trust": "unsigned",
            "age_minutes": 2,
            "exec_count": 1,
        }
    )
    monkeypatch.setattr(kernel, "novel_binaries", lambda *a, **k: mixed)
    items = ledger._kernel_items({})
    titles = [i["title"] for i in items]
    assert any("impl" in t for t in titles), titles
    assert any("3 programs" in t for t in titles), titles
    unsigned = [i for i in items if "impl" in i["title"]][0]
    assert unsigned["band"] == "amber"
    assert "nothing vouches for where it came from" in unsigned["why"]


def test_crossing_the_baseline_threshold_does_not_multiply_the_queue(monkeypatch):
    """One item before the baseline, one item after — the threshold must not
    turn a single question into twenty overnight."""
    kernel = importlib.import_module("app.dashboard.kernel")
    for ready in (False, True):
        monkeypatch.setattr(
            kernel,
            "novel_binaries",
            lambda *a, r=ready, **k: _novel(20, baseline_ready=r),
        )
        assert len(ledger._kernel_items({})) == 1, f"baseline_ready={ready}"
