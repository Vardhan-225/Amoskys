"""The kill-chain matcher must speak the language the probes emit.

SEQUENCE_KILL_CHAIN fired 0 times in 17,265 incidents — the entire lifetime of
the database. Not rarely: never. The matcher expected 15 category names, the
probes emitted 90, and the overlap was ZERO.

Both halves were built correctly and never introduced to each other. The
sequences speak in generic security nouns ("auth_failure", "process_exec",
"exfiltration"); every macOS probe emits a specific event name
("process_spawned", "macos_launchagent_new", "dns_beaconing_detected").

This class of bug is invisible by construction — a matcher that never matches
looks exactly like a machine with no attacks on it — so it is asserted rather
than left to be rediscovered by staging an attack that produces nothing.
"""

import pytest

from amoskys.intel.scoring import SequenceScorer

# Categories this system's probes are known to emit, from 7 days of live
# telemetry. Not exhaustive — it is the floor a sequence may rely on.
KNOWN_EMITTED = {
    "process_spawned", "lolbin_execution", "execution_from_temp",
    "clickfix_attack", "execute_to_exfil", "corr_lolbin_network",
    "macos_download_new", "message_to_download", "quarantine_evasion_pattern",
    "macos_launchagent_new", "macos_launchagent_removed", "macos_cron_new",
    "macos_shell_profile_new", "temporal_persistence_activation",
    "tcc_permission_granted", "tcc_permission_denied",
    "credential_access_indirect", "sudo_escalation",
    "dns_beaconing_suspected", "dns_beaconing_detected",
    "new_external_connection", "new_domain_first_seen",
    "connection_burst_detected", "long_lived_connection",
}


def _terms():
    return {t for seq in SequenceScorer.ATTACK_SEQUENCES for t in seq}


def test_at_least_one_sequence_is_fully_matchable():
    """A sequence whose every term is emitted CAN fire. Without one, the rule
    is decorative — which is exactly what it was."""
    matchable = [
        seq for seq in SequenceScorer.ATTACK_SEQUENCES
        if all(t in KNOWN_EMITTED for t in seq)
    ]
    assert matchable, (
        "no ATTACK_SEQUENCE is composed entirely of categories this system "
        "emits, so SEQUENCE_KILL_CHAIN cannot fire — the state that produced "
        "0 incidents in 17,265"
    )


def test_a_meaningful_share_of_sequences_are_live():
    """Guards against the live chains being deleted while the dead ones stay."""
    matchable = sum(
        1 for seq in SequenceScorer.ATTACK_SEQUENCES
        if all(t in KNOWN_EMITTED for t in seq)
    )
    assert matchable >= 5, f"only {matchable} sequences are matchable"


def test_the_vocabularies_overlap():
    overlap = _terms() & KNOWN_EMITTED
    assert len(overlap) >= 10, (
        f"only {len(overlap)} chain terms are emitted by any probe; the "
        "matcher and the probes are drifting apart again"
    )


def test_the_red_team_chain_shape_is_representable():
    """download -> execute -> persist, the staged infostealer's exact shape.

    It produced four loose probe hits and no chain, because no sequence
    described it.
    """
    shape = {"macos_download_new", "process_spawned", "macos_launchagent_new"}
    assert any(shape.issubset(set(seq)) for seq in SequenceScorer.ATTACK_SEQUENCES), (
        "the download->execute->persist progression has no sequence"
    )


def test_a_live_chain_actually_scores():
    """End to end through the scorer, not just a vocabulary assertion."""
    scorer = SequenceScorer(window_seconds=1800)
    import time as _t
    now = _t.time()
    score = 0.0
    for i, cat in enumerate(
        ["macos_download_new", "process_spawned", "macos_launchagent_new"]
    ):
        score, name = scorer.record_and_score("dev", cat, now + i)
    assert score >= 0.66, f"a complete live chain scored {score}, below the 0.66 gate"


def test_unrelated_events_do_not_score():
    """The matcher must stay quiet on background noise."""
    scorer = SequenceScorer(window_seconds=1800)
    import time as _t
    now = _t.time()
    score = 0.0
    for i, cat in enumerate(["high_cpu", "new_domain_first_seen", "high_cpu"]):
        score, _ = scorer.record_and_score("dev2", cat, now + i)
    assert score < 0.66, f"background noise scored {score}"
