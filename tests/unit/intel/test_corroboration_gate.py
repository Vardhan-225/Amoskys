"""The corroboration gate must count independent witnesses, not just IOCs.

Measured before this change, on a live machine:

    max risk_score ever produced : 0.70
    risk 0.30-0.50               : 7,006  (77% of all scored events)
    risk 0.90-1.00               : 0
    incidents 24h                : 986, all critical/high, none ever closed

A red-team exercise ran a real five-stage kill chain — unsigned binary from
Downloads, 114KB read from Chrome's credential store, LaunchAgent persistence,
outbound beacon — and it peaked at 0.53. Indistinguishable from Google Drive
sync. The cause was one line:

    corroborated = bool(threat_intel_match) or foreign

An IOC hit or a foreign IP. Nothing else counted, including the kernel itself
returning would_deny on that exact binary.
"""

import pytest

from amoskys.intel.scoring import _corroborating_witnesses


def test_the_original_two_witnesses_still_count():
    assert "threat_intel_match" in _corroborating_witnesses({"threat_intel_match": True})
    assert "foreign_source" in _corroborating_witnesses({"geo_src_country": "RU"})


def test_a_domestic_uncorroborated_event_has_no_witnesses():
    """The gate must still bite — this is what stops probes self-certifying."""
    assert _corroborating_witnesses({"geo_src_country": "US"}) == []
    assert _corroborating_witnesses({}) == []


def test_kernel_would_deny_is_corroboration():
    """The strongest independent signal on the machine, previously ignored.

    The ESF Sentinel evaluated the exec against its own policy, at the kernel,
    before the process ran. A different sensor with different physics reaching
    the same conclusion cannot be influenced by the probe being judged — which
    is the entire test the gate is meant to apply.
    """
    w = _corroborating_witnesses({"esf_decision": "would_deny", "geo_src_country": "US"})
    assert "kernel_would_deny" in w


def test_unsigned_at_exec_is_corroboration():
    """The kernel's view of the signature AT EXEC — not a later re-read of a
    file the attacker can change afterwards."""
    assert "unsigned_at_exec" in _corroborating_witnesses({"esf_untrusted": True})


def test_novel_binary_is_corroboration():
    assert "novel_binary" in _corroborating_witnesses({"esf_novel_binary": True})


def test_the_red_team_chain_would_now_be_corroborated():
    """The exercise that exposed this: domestic IP, no IOC, real attack."""
    event = {
        "geo_src_country": "US",
        "threat_intel_match": False,
        "esf_decision": "would_deny",
        "esf_untrusted": True,
        "esf_novel_binary": True,
    }
    w = _corroborating_witnesses(event)
    assert len(w) == 3
    assert set(w) == {"kernel_would_deny", "unsigned_at_exec", "novel_binary"}


def test_an_allowed_exec_is_not_corroboration():
    """Only a would_deny counts. A witnessed exec the kernel was happy with is
    evidence of normality, and must not lift the cap."""
    assert _corroborating_witnesses({"esf_decision": "allow"}) == []
