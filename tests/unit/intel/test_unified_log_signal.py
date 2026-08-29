"""Extracting signal from a 21M-events/day stream that scored zero.

unified_log is 60% of all AMOSKYS telemetry — 21,013,545 events/day — and not
one of them ever carried a risk score. The data is rich (full message, process,
subsystem, category); nothing read it.
"""

from amoskys.intel.unified_log_signal import (
    evaluate, evaluate_many, evaluate_with_rarity,
)


def _rec(event_type, message, subsystem="", process="p"):
    return {"event_type": event_type, "message": message,
            "subsystem": subsystem, "process": process}


def test_xpc_teardown_is_not_a_security_finding():
    """The measurement that killed keyword matching.

    A keyword sweep matched 96.33% of the xpc stream on words like "failed"
    and "invalid" — but they are ordinary connection-teardown vocabulary. Eight
    million events a day would have arrived pre-labelled as findings.
    """
    assert evaluate(_rec("xpc", "[0xb2ac] invalidated after a failed init")) is None
    assert evaluate(_rec("xpc", "[0xb2ac] Connection returned listener port")) is None


def test_sharing_chatter_is_muted():
    assert evaluate(_rec("sharing", "Nearby clear duplicate filter cache type 3")) is None


def test_a_real_trust_failure_is_caught():
    r = evaluate(_rec("security", "Trust evaluate failure: [leaf AnchorTrusted]",
                      subsystem="com.apple.securityd"))
    assert r and r["rule"] == "cert_trust_failure"
    assert r["why"]


def test_every_finding_explains_itself():
    """A pattern that cannot say why it fired does not belong here."""
    r = evaluate(_rec("gatekeeper", "Error checking with notarization daemon: 3"))
    assert r and r["why"] and len(r["why"]) > 40


def test_rarity_gate_suppresses_what_the_machine_always_says():
    """The measured false positive that pattern-matching could never fix.

    "Platform binary prompting is 'Deny' because: is Platform Binary" is TCC
    explaining it will NOT prompt — the word Deny appears inside the
    explanation. It occurred 30 times in 60,000 events, and no refinement of
    the regex distinguishes it from a real denial. Frequency does.
    """
    # The corpus must be large enough to RESOLVE the threshold. At 61 records
    # a single occurrence is 1/61 = 0.016 share, above a 0.01 cut — so the rare
    # item suppresses itself. That is the same sample-granularity limit
    # documented on evaluate_with_rarity, reproduced here in miniature: rarity
    # cannot be measured finer than one over the corpus size.
    routine = [_rec("tcc", "Platform binary prompting is 'Deny' because: is Platform Binary",
                    subsystem="com.apple.TCC")] * 300
    rare = [_rec("tcc", "Deny access to kTCCServiceCamera for /tmp/evil",
                 subsystem="com.apple.TCC")]
    r = evaluate_with_rarity(routine + rare, max_share=0.01)
    kept = {f["message"] for f in r["findings"]}
    assert any("kTCCServiceCamera" in m for m in kept)
    assert not any("Platform Binary" in m for m in kept)
    assert r["suppressed_as_routine"] >= 300


def test_bits_are_measured_not_assumed():
    """Once a rate exists, the measurement replaces the rule's static weight."""
    recs = [_rec("tcc", "Deny access to kTCCServiceCamera for /tmp/evil",
                 subsystem="com.apple.TCC")] + [
        _rec("xpc", f"unrelated {i}") for i in range(999)]
    r = evaluate_with_rarity(recs, max_share=0.01)
    assert r["count"] == 1
    assert r["findings"][0]["bits"] > 9.0, "rarity should exceed the static prior"


def test_yield_is_reported_with_its_denominator():
    """A finding count without its denominator is unreadable — the difference
    between 6-from-60,000 and 6-from-6."""
    r = evaluate_many([_rec("xpc", "invalidated after a failed init")] * 100)
    assert r["examined"] == 100 and r["count"] == 0 and r["silent"] == 100
