"""Can AMOSKYS tell itself from an adversary — without becoming a hiding place?

Measured before this module existed: 28.5% of all security_events, and 99.5%
of `lolbin_execution`, were AMOSKYS observing its own probe toolchain. The
danger in fixing that is obvious and severe — a self-model is the most
attractive thing on the machine to impersonate.
"""

import os

import pytest

from amoskys.identity.self_model import (
    FOREIGN, IMPOSTOR, SELF, UNKNOWN, SelfModel,
)


@pytest.fixture
def sm(tmp_path):
    m = SelfModel(repo_root=str(tmp_path))
    m.own_hashes["AAAA"] = "sentinel"
    m.own_paths[str(tmp_path / "sentinel")] = "AAAA"
    m.interpreters.add(str(tmp_path / "python3"))
    return m


# ── rule 1: identity is cryptographic, not positional ────────────────────
def test_path_alone_never_grants_trust(sm, tmp_path):
    """Drop a binary in the AMOSKYS tree and it must NOT inherit trust."""
    r = sm.classify(exe=str(tmp_path / "macos-esf-shim" / "evil"), cdhash=None)
    assert r["attribution"] != SELF
    assert r["suppress"] is False


def test_matching_cdhash_is_self(sm, tmp_path):
    r = sm.classify(exe=str(tmp_path / "sentinel"), cdhash="AAAA")
    assert r["attribution"] == SELF and r["suppress"] is True


# ── rule 3: self-identity inverts into tamper detection ──────────────────
def test_wrong_hash_at_our_own_path_is_an_impostor_not_a_suppression(sm, tmp_path):
    """The most alarming thing this module can find.

    A self-model's natural failure mode is to become an attacker's hiding
    place. The check that would grant trust must therefore also be the check
    that raises the alarm — and it runs FIRST, so a mismatch can never be
    reached only after something has been waved through.
    """
    r = sm.classify(exe=str(tmp_path / "sentinel"), cdhash="DIFFERENT")
    assert r["attribution"] == IMPOSTOR
    assert r["suppress"] is False
    assert r["confidence"] >= 0.99
    assert r["evidence"]["expected_cdhash"] == "AAAA"
    assert r["evidence"]["observed_cdhash"] == "DIFFERENT"


# ── interpreters are not identity ────────────────────────────────────────
def test_interpreter_is_never_registered_as_identity(tmp_path):
    """amoskys-venv/bin/python is a symlink to the SHARED homebrew python.

    Registering its cdhash as AMOSKYS would mark every Python on the machine
    as self — including an attacker payload — turning the self-model into the
    best hiding place on the box.
    """
    m = SelfModel(repo_root=str(tmp_path))
    b = m.bootstrap()
    assert "interpreters_excluded" in b
    for h, role in m.own_hashes.items():
        assert role != "runtime", "an interpreter must not hold hash identity"


def test_same_interpreter_opposite_verdicts_by_argv(sm, tmp_path):
    """Same binary, same cdhash — argv is the only discriminator."""
    py = str(tmp_path / "python3")
    ours = sm.classify(exe=py, cdhash="SHARED", argv=["python", "-m", "amoskys.shipper"])
    theirs = sm.classify(exe=py, cdhash="SHARED", argv=["python", "/tmp/payload.py"])
    assert ours["attribution"] == SELF and ours["suppress"] is True
    assert theirs["attribution"] == FOREIGN and theirs["suppress"] is False


def test_argv_based_trust_is_weaker_than_a_hash_match(sm, tmp_path):
    """argv is attacker-controllable; a code signature is not. The confidence
    must say so, or a weaker claim silently inherits a stronger one's weight."""
    hashed = sm.classify(exe=str(tmp_path / "sentinel"), cdhash="AAAA")
    argv_based = sm.classify(exe=str(tmp_path / "python3"), cdhash="S",
                             argv=["python", "-m", "amoskys.collector_main"])
    assert argv_based["confidence"] < hashed["confidence"]


# ── probe tools need ancestry ────────────────────────────────────────────
def test_probe_tool_without_amoskys_ancestry_is_not_suppressed(sm):
    """`log` fired 807 times here — attacker-plausible every single time.

    Ancestry is the only thing separating 'our unified-log sensor' from
    'someone reading your system log'. Suppressing on the tool name alone
    would hand an attacker a free pass to the most useful tools on the box.
    """
    r = sm.classify(exe="/usr/bin/log", cdhash="X", ancestry=[])
    assert r["attribution"] == UNKNOWN
    assert r["suppress"] is False


def test_probe_tool_with_amoskys_ancestry_is_self(sm):
    r = sm.classify(exe="/usr/bin/log", cdhash="X",
                    ancestry=[{"cdhash": "AAAA", "exe": "/x/sentinel"}])
    assert r["attribution"] == SELF and r["suppress"] is True


def test_unknown_binary_is_foreign(sm):
    r = sm.classify(exe="/tmp/whatever", cdhash="ZZZZ")
    assert r["attribution"] == FOREIGN and r["suppress"] is False


def test_every_verdict_carries_its_evidence(sm, tmp_path):
    """A bare label is untraceable the moment it is wrong."""
    for kwargs in (
        {"exe": str(tmp_path / "sentinel"), "cdhash": "AAAA"},
        {"exe": str(tmp_path / "sentinel"), "cdhash": "WRONG"},
        {"exe": "/usr/bin/log", "cdhash": "X"},
        {"exe": "/tmp/x", "cdhash": "Z"},
    ):
        r = sm.classify(**kwargs)
        assert r["evidence"], f"no evidence for {kwargs}"
        assert r["reason"]
