"""Evidence must survive a store that is missing optional columns.

evidence_for() exists because, in its own words, naming your evidence and then
withholding it is what made the product feel untrustworthy. It then selected a
fixed column list against tiers whose schemas have diverged: the device store
carries requires_investigation and (since migration 019) score_factors; the
fleet cache carries neither. Naming an absent column raises sqlite3.Error, the
handler turns that into [], and the drawer answered "no evidence" while the
rows sat in the table.

Measured on server/fleet.db before the fix: 0 rows returned for 3 real event
ids. After: 3 rows, with why=None to say the reasons are not recorded HERE —
which is a different statement from "there were no reasons".
"""
import sqlite3

import pytest

from app.dashboard import ledger


def _store(tmp_path, columns: str, rows: list[tuple]):
    p = tmp_path / "evidence.db"
    db = sqlite3.connect(p)
    db.execute(f"CREATE TABLE security_events ({columns})")
    db.executemany(
        "INSERT INTO security_events VALUES (%s)" % ",".join("?" * len(rows[0])), rows
    )
    db.commit()
    db.close()
    return str(p)


MINIMAL = "event_id TEXT, device_id TEXT, timestamp_dt TEXT, event_category TEXT"
FULL = MINIMAL + ", risk_score REAL, final_classification TEXT, score_factors TEXT"


@pytest.fixture(autouse=True)
def _no_scope(monkeypatch):
    monkeypatch.setattr(ledger.insight_service, "_scope_sql", lambda a, j: ("", ()))


def test_evidence_survives_a_store_without_optional_columns(tmp_path, monkeypatch):
    """The regression that mattered: one absent column returned zero evidence."""
    path = _store(tmp_path, MINIMAL, [("e1", "mac-1", "2026-09-02T12:00:00", "exec")])
    monkeypatch.setattr(ledger.insight_service, "resolve_db_path", lambda: path)
    out = ledger.evidence_for(["e1"])
    assert len(out) == 1, "a missing optional column must not erase the evidence"
    assert out[0]["event_id"] == "e1"
    assert out[0]["why"] is None, "not recorded here — not 'no reasons'"


def test_reasons_are_returned_when_the_store_has_them(tmp_path, monkeypatch):
    path = _store(tmp_path, FULL, [(
        "e2", "mac-1", "2026-09-02T12:00:00", "execute_to_exfil", 0.7, "malicious",
        '[{"name": "Independent Corroboration", "contribution": 0.0, '
        '"detail": "Cap lifted \\u2014 corroborated by: downloaded_and_untrusted"}]',
    )])
    monkeypatch.setattr(ledger.insight_service, "resolve_db_path", lambda: path)
    out = ledger.evidence_for(["e2"])
    assert len(out) == 1
    why = out[0]["why"]
    assert why and why[0]["name"] == "Independent Corroboration"
    assert "downloaded_and_untrusted" in why[0]["detail"]


def test_a_store_missing_identity_returns_nothing_rather_than_guessing(
    tmp_path, monkeypatch
):
    """Without an id and a time a row cannot honestly be shown as evidence."""
    path = _store(tmp_path, "device_id TEXT, event_category TEXT", [("mac-1", "exec")])
    monkeypatch.setattr(ledger.insight_service, "resolve_db_path", lambda: path)
    assert ledger.evidence_for(["e3"]) == []
