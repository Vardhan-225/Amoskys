"""A trust model that has never been contradicted must not read as confident.

Measured on the live store 2026-09-02: 26,643 observations, ground_truth_match
= 1 on every one, beta frozen at 1.0, fusion weights 0.999874 / 0.999884 /
0.999438 — a spread of 4.46e-04. Every conventional health check passes: the
store is populated, the writes are current, the numbers are well-formed. The
model is nonetheless incapable of preferring one sensor over another.

sd=0.000126 looks like a tight posterior. It is the variance of a model that
has never recorded a counterexample.
"""
import sqlite3

import pytest

from amoskys.intel.reliability_integrity import measure


def _store(tmp_path, observations, agents):
    p = tmp_path / "reliability.db"
    db = sqlite3.connect(p)
    db.execute("CREATE TABLE observation_log (id INTEGER PRIMARY KEY, "
               "agent_id TEXT, timestamp_ns INTEGER, ground_truth_match INTEGER, reason TEXT)")
    db.execute("CREATE TABLE agent_reliability (agent_id TEXT PRIMARY KEY, "
               "alpha REAL, beta REAL, fusion_weight REAL)")
    db.executemany("INSERT INTO observation_log (agent_id, timestamp_ns, ground_truth_match, reason) "
                   "VALUES (?,?,?,?)", observations)
    db.executemany("INSERT INTO agent_reliability VALUES (?,?,?,?)", agents)
    db.commit(); db.close()
    return str(p)


def test_the_live_shape_reads_as_uninformative(tmp_path):
    """The exact measured condition: many observations, zero disagreements."""
    obs = [("process", i, 1, "") for i in range(500)]
    agents = [("process", 7931.0, 1.0, 0.999874),
              ("network", 8625.0, 1.0, 0.999884),
              ("SECURITY", 1778.0, 1.0, 0.999438)]
    m = measure(_store(tmp_path, obs, agents))
    assert m["state"] == "uninformative"
    assert m["counterexamples"] == 0
    assert m["beta_max"] == 1.0
    assert m["weight_spread"] < 1e-3
    # It must say what to do, not merely that something is off.
    assert "never having been contradicted" in m["detail"]
    assert "Nothing here has failed" in m["detail"]


def test_a_model_that_has_seen_disagreement_reads_as_informative(tmp_path):
    """The check must not be permanently red — that would make it worthless."""
    obs = [("process", i, 1, "") for i in range(400)] + \
          [("process", i, 0, "missed") for i in range(100)]
    agents = [("process", 400.0, 100.0, 0.80), ("network", 900.0, 20.0, 0.978)]
    m = measure(_store(tmp_path, obs, agents))
    assert m["state"] == "informative", m
    assert m["counterexamples"] == 100
    assert m["weight_spread"] > 1e-3


def test_uniform_weights_are_uninformative_even_with_disagreements(tmp_path):
    """Counterexamples alone are not enough if the weights still cannot separate."""
    obs = [("process", i, 1, "") for i in range(400)] + \
          [("process", i, 0, "missed") for i in range(50)]
    agents = [("process", 400.0, 50.0, 0.9991), ("network", 400.0, 50.0, 0.9992)]
    m = measure(_store(tmp_path, obs, agents))
    assert m["state"] == "uninformative"


def test_a_missing_store_is_unmeasurable_not_healthy(tmp_path):
    """Absence of the store must never render as a working trust model."""
    m = measure(str(tmp_path / "nope.db"))
    assert m["state"] == "unmeasurable"
    assert m["counterexamples"] is None, "None, not 0 — 0 would assert a measurement"


def test_a_store_with_no_agents_is_unmeasurable(tmp_path):
    m = measure(_store(tmp_path, [("p", 1, 1, "")], []))
    assert m["state"] == "unmeasurable"


def test_measure_never_raises_on_a_corrupt_store(tmp_path):
    p = tmp_path / "junk.db"
    p.write_bytes(b"not a database at all")
    assert measure(str(p))["state"] == "unmeasurable"
