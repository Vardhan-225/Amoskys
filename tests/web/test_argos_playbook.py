"""Unit tests for the engagement playbook."""

from __future__ import annotations

from amoskys.agents.Web.argos.reasoning import (
    EngagementState,
    default_playbook,
)


def test_default_playbook_stage1_moves_available_for_stage1_state():
    state = EngagementState(target_host="example.com", stage=1)
    pb = default_playbook()
    moves = pb.available_moves(state)
    assert moves
    # All available moves must be stage 1.
    assert all(m.stage == 1 for m in moves)
    # Preflight should be the highest-priority available.
    assert moves[0].move_id == "preflight.robots_and_security_txt"


def test_stage2_moves_blocked_without_consent():
    """Without a verified consent token, no Stage-2 move fires — only
    Stage-1 moves (including the consent-verify move itself, which is
    the gate transitioning us to Stage 2)."""
    state = EngagementState(target_host="example.com", stage=2, consent_verified=False)
    pb = default_playbook()
    moves = pb.available_moves(state)
    ids = {m.move_id for m in moves}

    # Consent-verify is stage=1 (no consent needed to READ a DNS TXT).
    # It's available here so the engagement has a path to Stage 2.
    assert "consent.verify_dns_txt" in ids

    # All genuine stage=2 moves must be blocked — no scanning, no
    # probing, no report delivery without consent.
    for blocked_id in (
        "scan.ast_plugin_inventory",
        "scan.live_cve_match",
        "probe.nuclei_templates",
        "report.pentest_deliverable",
    ):
        assert blocked_id not in ids, f"stage-2 move {blocked_id} leaked through"


def test_stage2_moves_unlock_with_consent():
    state = EngagementState(
        target_host="example.com",
        stage=2,
        consent_verified=True,
        plugin_inventory=[{"slug": "akismet", "ver": "5.2"}],
        moves_executed=["preflight.robots_and_security_txt",
                        "recon.dns_and_tls",
                        "recon.stealth_sweep"],
    )
    pb = default_playbook()
    moves = pb.available_moves(state)
    ids = {m.move_id for m in moves}
    assert "scan.ast_plugin_inventory" in ids
    assert "scan.live_cve_match" in ids


def test_permanent_block_halts_all_moves():
    state = EngagementState(
        target_host="example.com", got_permanent_block=True,
    )
    moves = default_playbook().available_moves(state)
    assert moves == []


def test_budget_exhaustion_prevents_expensive_moves():
    state = EngagementState(
        target_host="example.com",
        http_request_budget_remaining=10,  # less than stealth_sweep's 25
    )
    pb = default_playbook()
    available = pb.available_moves(state)
    ids = {m.move_id for m in available}
    assert "recon.stealth_sweep" not in ids  # cost=25 > budget=10
    assert "preflight.robots_and_security_txt" in ids  # cost=2 < budget


def test_pitch_report_requires_stealth_sweep_first():
    # With no prior moves, pitch.generate_report should not be available.
    state = EngagementState(target_host="example.com")
    pb = default_playbook()
    avail = pb.available_moves(state)
    assert not any(m.move_id == "pitch.generate_report" for m in avail)

    # After stealth_sweep executed, pitch is available.
    state.moves_executed.append("recon.stealth_sweep")
    avail = pb.available_moves(state)
    assert any(m.move_id == "pitch.generate_report" for m in avail)


def test_next_move_returns_highest_priority_available():
    state = EngagementState(target_host="example.com")
    pb = default_playbook()
    move = pb.next_move(state)
    assert move is not None
    # Preflight is priority 100 — the highest.
    assert move.move_id == "preflight.robots_and_security_txt"

    # Execute it, next should be DNS/TLS (priority 95).
    state.moves_executed.append(move.move_id)
    move2 = pb.next_move(state)
    assert move2 is not None
    assert move2.move_id == "recon.dns_and_tls"


def test_as_dict_reports_state_and_availability():
    state = EngagementState(target_host="example.com")
    d = default_playbook().as_dict(state)
    assert "state" in d
    assert "all_moves" in d
    assert "available_now" in d
    assert d["state"]["target_host"] == "example.com"
    # Must have some moves available for a fresh stage-1 state.
    assert len(d["available_now"]) > 0
    # Every move must have a mandate.
    for m in d["all_moves"]:
        assert m["mandate"], f"move {m['move_id']} missing mandate"


def test_every_move_has_mandate_and_tool_hint():
    """The operator mandate contract: no move ships without a mandate
    + a tool_hint."""
    pb = default_playbook()
    for m in pb.moves:
        assert m.mandate, f"move {m.move_id} missing mandate"
        assert m.tool_hint, f"move {m.move_id} missing tool_hint"
        assert m.description, f"move {m.move_id} missing description"
