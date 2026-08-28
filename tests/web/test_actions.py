"""Guard rails for response actions — the part of the UI that can break a machine.

The device-side executor sends SIGKILL, writes pf rules and edits /etc/hosts.
Everything here exists so that a web request cannot reach those without an
admin, a reason, and a target that the server itself found in the evidence.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

WEB_ROOT = Path(__file__).resolve().parents[2] / "web"
if str(WEB_ROOT) not in sys.path:
    sys.path.insert(0, str(WEB_ROOT))

actions = importlib.import_module("app.dashboard.actions")


@pytest.fixture()
def live(monkeypatch):
    monkeypatch.setenv("AMOSKYS_RESPONSE_ENABLED", "1")
    monkeypatch.setenv("CC_OPERATOR_KEY", "test-key")
    monkeypatch.setenv("AMOSKYS_OPS_SERVER", "http://127.0.0.1:9")
    return actions


# ── Two switches, both default off ───────────────────────────────────────────
def test_disabled_by_default(monkeypatch):
    monkeypatch.delenv("AMOSKYS_RESPONSE_ENABLED", raising=False)
    state = actions.availability()
    assert state["available"] is False
    assert "switched off" in state["reason"]


def test_enabled_but_no_operator_key_is_still_unavailable(monkeypatch):
    monkeypatch.setenv("AMOSKYS_RESPONSE_ENABLED", "1")
    monkeypatch.delenv("CC_OPERATOR_KEY", raising=False)
    state = actions.availability()
    assert state["available"] is False
    assert "operator key" in state["reason"]


# ── The rollback text must be true ───────────────────────────────────────────
def test_every_action_declares_its_reversibility():
    for command_type, spec in actions.ACTION_CATALOGUE.items():
        assert spec["reversibility"] in (
            actions.AUTOMATIC,
            actions.MANUAL,
            actions.IRREVERSIBLE,
        ), command_type
        assert spec["rollback"].get("detail"), command_type


def test_manual_rollbacks_carry_the_literal_undo_command():
    """ "Reversible by hand" without the command is not a rollback plan."""
    for command_type, spec in actions.ACTION_CATALOGUE.items():
        if spec["reversibility"] == actions.MANUAL:
            assert spec["rollback"].get("shell"), command_type


def test_irreversible_actions_do_not_pretend_to_offer_an_undo():
    kill = actions.ACTION_CATALOGUE["KILL_PROCESS"]
    assert kill["reversibility"] == actions.IRREVERSIBLE
    assert "shell" not in kill["rollback"]
    assert "command_type" not in kill["rollback"]


def test_isolate_has_a_real_counter_command():
    assert (
        actions.ACTION_CATALOGUE["ISOLATE"]["rollback"]["command_type"] == "UNISOLATE"
    )


# ── Targets come from evidence, never from the client ────────────────────────
def _rows(*descriptions):
    return [{"description": d} for d in descriptions]


def test_targets_are_read_out_of_evidence():
    found = actions.derive_targets(
        _rows(
            "process spawned pid=4821 /usr/local/bin/thing",
            "flow 192.168.1.146:60500 -> 203.0.113.9:443",
            "dns query for evil-lookup.example.com",
            "file created ~/Library/LaunchAgents/com.evil.plist",
        )
    )
    assert "4821" in found["pid"]
    assert "203.0.113.9" in found["ip"]
    assert "evil-lookup.example.com" in found["domain"]
    assert any("LaunchAgents" in p for p in found["path"])


def test_loopback_is_never_a_target():
    found = actions.derive_targets(_rows("flow 127.0.0.1:5001 -> 127.0.0.1:8443"))
    assert found["ip"] == []


def test_our_own_server_is_never_a_target(monkeypatch):
    monkeypatch.setenv("AMOSKYS_OPS_SERVER", "https://18.223.110.15")
    found = actions.derive_targets(
        _rows("flow 192.168.1.146:60500 -> 18.223.110.15:443")
    )
    assert "18.223.110.15" not in found["ip"]


def test_a_bundle_id_is_not_offered_as_a_domain():
    """Measured on real evidence: com.amoskys.live.plist matched the domain
    pattern and would have been offered as "sinkhole this domain"."""
    found = actions.derive_targets(
        _rows("file created ~/Library/LaunchAgents/com.amoskys.live.plist")
    )
    assert found["domain"] == []


# ── Proposals ────────────────────────────────────────────────────────────────
def test_actions_needing_a_target_are_not_offered_without_one():
    offered = actions.propose({"device_ids": ["dev-1"]}, _rows("nothing useful here"))
    types = {a["command_type"] for a in offered}
    assert "KILL_PROCESS" not in types
    assert "BLOCK_IP" not in types
    assert "COLLECT_NOW" in types  # needs no target
    assert "ISOLATE" in types


def test_a_pid_in_evidence_unlocks_kill():
    offered = actions.propose(
        {"device_ids": ["dev-1"]}, _rows("suspicious exec pid=991 /tmp/x")
    )
    kill = [a for a in offered if a["command_type"] == "KILL_PROCESS"]
    assert kill and kill[0]["options"] == ["991"]
    assert kill[0]["reversibility"] == actions.IRREVERSIBLE


# ── Dispatch refuses more than it accepts ────────────────────────────────────
def test_dispatch_refused_when_switched_off(monkeypatch):
    monkeypatch.delenv("AMOSKYS_RESPONSE_ENABLED", raising=False)
    payload, status = actions.dispatch(
        "dev-1", "ISOLATE", None, "because", "console:me", {}
    )
    assert status == 503
    assert payload["error"] == "response_disabled"


def test_dispatch_requires_a_reason(live):
    payload, status = actions.dispatch(
        "dev-1", "ISOLATE", None, "   ", "console:me", {}
    )
    assert status == 400
    assert payload["error"] == "reason_required"


def test_dispatch_refuses_a_target_not_present_in_the_evidence(live):
    payload, status = actions.dispatch(
        "dev-1",
        "QUARANTINE_FILE",
        "/etc/passwd",
        "looks bad",
        "console:me",
        {"path": ["~/Library/LaunchAgents/com.evil.plist"]},
    )
    assert status == 400
    assert payload["error"] == "target_not_in_evidence"


def test_dispatch_refuses_an_unknown_verb(live):
    payload, status = actions.dispatch(
        "dev-1", "RM_RF_SLASH", None, "no", "console:me", {}
    )
    assert status == 400
    assert payload["error"] == "unknown_action"


def test_ops_unreachable_fails_closed_and_says_so(live):
    payload, status = actions.dispatch(
        "dev-1", "COLLECT_NOW", None, "checking", "console:me", {}
    )
    assert status == 502
    assert "nothing was queued" in payload["detail"].lower()


def test_action_log_unavailable_is_not_reported_as_no_actions(live):
    payload, status = actions.ledger()
    assert payload["commands"] == []
    assert "not the same as 'no actions'" in payload["unavailable"]


# ── The pinned CA must be found, and never silently skipped ──────────────────
def test_ops_ca_resolves_from_the_package_not_the_cwd(monkeypatch, tmp_path):
    """gunicorn runs with --chdir /opt/amoskys/web, where a relative
    "deploy/certs/ops-ca.pem" does not exist. The old code let os.path.exists()
    return False and then sent the operator bearer token with verify=False to a
    bare IP — no hostname check to fall back on."""
    monkeypatch.delenv("AMOSKYS_OPS_CA", raising=False)
    monkeypatch.chdir(tmp_path)  # a CWD with no deploy/ directory
    assert actions._DEFAULT_OPS_CA.is_absolute()
    assert actions._ops_ca() == str(actions._DEFAULT_OPS_CA)


def test_tls_verification_is_never_disabled(monkeypatch, tmp_path):
    """verify=False disables TLS entirely. If the pin is unavailable the worst
    acceptable outcome is the system trust store, never no verification.

    The session is now built by _ops_session(); this asserts the same contract
    against it.
    """
    monkeypatch.setenv("AMOSKYS_OPS_CA", str(tmp_path / "absent.pem"))
    session = actions._ops_session()
    assert session.verify is not False


def test_the_ops_session_pins_rather_than_hostname_matching(monkeypatch):
    """The ops certificate is self-signed with NO subjectAltName and the ops URL
    is a bare IP, so passing verify=<ca> to requests fails hostname matching and
    every response action dies in TLS — surfacing to the operator as "the fleet
    backend did not answer". The pinned adapter validates the chain and
    suppresses only the SAN match.
    """
    ca = actions._ops_ca()
    assert ca, "the packaged ops CA should resolve with no env override"
    session = actions._ops_session()
    adapter = session.get_adapter("https://18.223.110.15/")
    assert type(adapter).__name__ == "_PinnedCAAdapter"


def test_a_tls_failure_is_not_reported_as_an_unreachable_backend():
    """They need different things done about them: one is a certificate, the
    other is connectivity."""
    import requests as _rq

    kind, detail = actions._describe_request_error(_rq.exceptions.SSLError("bad cert"))
    assert kind == "ops_tls_failed"
    assert "certificate" in detail
    kind, _ = actions._describe_request_error(_rq.exceptions.ConnectionError("down"))
    assert kind == "ops_unreachable"


def test_a_missing_pinned_ca_makes_the_surface_unavailable(monkeypatch, tmp_path):
    monkeypatch.setenv("AMOSKYS_RESPONSE_ENABLED", "1")
    monkeypatch.setenv("CC_OPERATOR_KEY", "k")
    monkeypatch.setenv("AMOSKYS_OPS_CA", str(tmp_path / "absent.pem"))
    state = actions.availability()
    assert state["available"] is False
    assert "unverified channel" in state["reason"]
