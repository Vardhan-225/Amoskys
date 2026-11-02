"""A saturated trust model must not report nominal.

IGRIS's AMRDR coherence checked three things — quarantined agents, min weight
below 0.5, and drift — and fell through to "nominal" otherwise. Every one hunts
for weights that are too LOW. A model that has never been contradicted sits at
0.9998 and passes all of them.

Measured live 2026-09-02: 26,643 observations, ground_truth_match = 1 on every
single one, beta frozen at 1.0, weights 0.999874 / 0.999884 / 0.999438 — a
spread of 4.46e-04. Coherence reported AMRDR nominal, which is the healthiest
reading available, for a trust model arithmetically incapable of preferring one
sensor over another.

Separately, metrics defaulted min_weight to 1.0 when there were NO agent states
at all, so an empty trust model also reported perfect reliability.
"""
from amoskys.igris.coherence import assess

BASE = {"amrdr.quarantined_count": 0, "amrdr.drifting_count": 0}


def _amrdr(metrics):
    return assess({**BASE, **metrics})["subsystem_status"].get("amrdr")


def test_the_measured_live_shape_is_not_nominal():
    """The regression: high uniform weights previously read as healthy."""
    assert _amrdr({
        "amrdr.min_weight": 0.999438,
        "amrdr.informative": False,
        "amrdr.counterexamples": 0,
        "amrdr.observations": 26650,
    }) == "uninformative"


def test_the_reason_states_the_consequence_not_just_the_fact():
    a = assess({**BASE, "amrdr.min_weight": 0.999438, "amrdr.informative": False,
                "amrdr.counterexamples": 0, "amrdr.observations": 26650})
    joined = " ".join(a["reasons"])
    assert "never recorded a counterexample" in joined
    assert "cannot distinguish one sensor from another" in joined, (
        "an operator needs to know what the saturation costs, not only that it exists"
    )


def test_an_earned_weight_still_reads_nominal():
    """The check must not be permanently red, or it will be ignored."""
    assert _amrdr({"amrdr.min_weight": 0.80, "amrdr.informative": True,
                   "amrdr.counterexamples": 100}) == "nominal"


def test_an_unmeasurable_model_is_not_nominal():
    """Absence must not fall through to the healthiest available reading."""
    assert _amrdr({"amrdr.min_weight": None, "amrdr.informative": None}) == "unmeasurable"


def test_a_genuinely_low_weight_still_degrades():
    """The original check must survive the new branch."""
    assert _amrdr({"amrdr.min_weight": 0.3, "amrdr.informative": True,
                   "amrdr.counterexamples": 50}) == "degraded"


def test_quarantine_still_outranks_saturation():
    """A trust breakdown is more urgent than an uninformative model."""
    assert _amrdr({"amrdr.min_weight": 0.999, "amrdr.informative": False,
                   "amrdr.counterexamples": 0,
                   "amrdr.quarantined_count": 2}) == "critical"
