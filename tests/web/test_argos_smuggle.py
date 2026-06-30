"""Tests for argos/smuggle — HTTP request smuggling probes + detector."""

from __future__ import annotations

import pytest

from amoskys.agents.Web.argos.smuggle import (
    SmuggleProbe,
    SmuggleReport,
    SmuggleTechnique,
    build_cl_te_probe,
    build_h2_downgrade_probe,
    build_te_cl_probe,
    build_te_te_probe,
    detect_smuggling,
)

# ──────────────────────────────────────────────────────────────────
# probe builders — shape + wire-level correctness
# ──────────────────────────────────────────────────────────────────


def test_cl_te_probe_has_both_cl_and_te_headers():
    p = build_cl_te_probe("https://example.com/")
    raw = p.raw_bytes.decode()
    assert "Content-Length:" in raw
    assert "Transfer-Encoding: chunked" in raw
    assert "GET / HTTP/1.1" in raw  # smuggled request
    assert p.technique == SmuggleTechnique.CL_TE
    assert p.port == 443
    assert p.use_tls is True


def test_te_cl_probe_smuggles_a_post():
    p = build_te_cl_probe("https://example.com/", smuggled_path="/admin")
    raw = p.raw_bytes.decode()
    assert "Transfer-Encoding: chunked" in raw
    assert "GET /admin HTTP/1.1" in raw
    # Chunk-size line followed by CRLF is required for valid chunked framing
    assert "\r\n0\r\n\r\n" in raw  # final terminator present
    assert p.technique == SmuggleTechnique.TE_CL


def test_te_te_obfuscation_variant_included_verbatim():
    p = build_te_te_probe(
        "http://example.com/", te_obfuscation="Transfer-Encoding : chunked"
    )
    raw = p.raw_bytes.decode()
    # Obfuscated TE header preserved
    assert "Transfer-Encoding : chunked" in raw
    assert p.port == 80
    assert p.use_tls is False
    assert p.technique == SmuggleTechnique.TE_TE


def test_h2_downgrade_probe_emits_h1_equivalent_wire():
    p = build_h2_downgrade_probe("https://example.com/")
    raw = p.raw_bytes.decode()
    assert raw.startswith("POST / HTTP/1.1")
    assert "Content-Length: 0" in raw  # h2 CL pseudo-header → 0
    assert "Transfer-Encoding: chunked" in raw
    assert "GET / HTTP/1.1" in raw
    assert p.technique == SmuggleTechnique.H2_CL


def test_probe_to_dict_is_serializable_and_hides_body():
    p = build_cl_te_probe("https://a.b/")
    d = p.to_dict()
    assert d["technique"] == SmuggleTechnique.CL_TE
    assert isinstance(d["raw_bytes_len"], int)
    assert "raw_bytes" not in d  # raw bytes never leak to reports


# ──────────────────────────────────────────────────────────────────
# detect_smuggling — timing logic via injected sender
# ──────────────────────────────────────────────────────────────────


class _FakeSender:
    def __init__(self, scripted):
        """scripted: list of (status, elapsed_ms, note) per call."""
        self.scripted = list(scripted)
        self.calls = 0

    def __call__(self, host, port, use_tls, raw_bytes, timeout):
        if self.calls >= len(self.scripted):
            # fallback: innocent baseline
            return (200, 50, "")
        r = self.scripted[self.calls]
        self.calls += 1
        return r


def test_detect_smuggling_flags_timeout_as_suspicious():
    """One technique times out — should be marked vulnerable."""
    # 3 baseline samples ~50ms, then 4 probes: cl.te, te.cl, te.te, h2.cl
    sender = _FakeSender(
        [
            (200, 50, ""),  # baseline 1
            (200, 55, ""),  # baseline 2
            (200, 48, ""),  # baseline 3
            (0, 6000, "read-timeout"),  # CL.TE hangs
            (200, 60, ""),  # TE.CL normal
            (200, 70, ""),  # TE.TE normal
            (200, 65, ""),  # H2.CL normal
        ]
    )
    rep = detect_smuggling("https://example.com/", sender=sender)
    assert rep.vulnerable is True
    cl_te = [r for r in rep.results if r["technique"] == SmuggleTechnique.CL_TE][0]
    assert cl_te["vulnerable"] is True
    assert "timeout" in cl_te["note"]


def test_detect_smuggling_all_clean_when_no_timing_anomaly():
    sender = _FakeSender(
        [
            (200, 50, ""),  # baseline 1
            (200, 55, ""),  # baseline 2
            (200, 48, ""),  # baseline 3
            (200, 52, ""),
            (200, 60, ""),
            (200, 58, ""),
            (200, 54, ""),
        ]
    )
    rep = detect_smuggling("https://example.com/", sender=sender)
    assert rep.vulnerable is False
    assert all(not r["vulnerable"] for r in rep.results)


def test_detect_smuggling_three_sigma_catches_slow_probe():
    # baseline mean=50ms stdev~2ms → 3σ threshold floored at mean+500=550ms
    # A probe at 3s must be flagged
    sender = _FakeSender(
        [
            (200, 50, ""),
            (200, 52, ""),
            (200, 48, ""),
            (200, 3000, ""),  # CL.TE slow — 3s
            (200, 60, ""),
            (200, 55, ""),
            (200, 58, ""),
        ]
    )
    rep = detect_smuggling("https://example.com/", sender=sender)
    cl_te = [r for r in rep.results if r["technique"] == SmuggleTechnique.CL_TE][0]
    assert cl_te["vulnerable"] is True
    assert cl_te["latency_ms"] == 3000


def test_report_to_dict_survives_json_roundtrip():
    import json

    sender = _FakeSender([(200, 40, ""), (200, 42, ""), (200, 41, "")])
    rep = detect_smuggling(
        "https://example.com/", techniques=[SmuggleTechnique.CL_TE], sender=sender
    )
    j = json.dumps(rep.to_dict())
    assert "baseline_latency_ms" in j


def test_report_unknown_technique_recorded_as_error():
    sender = _FakeSender([(200, 40, ""), (200, 41, ""), (200, 42, "")])
    rep = detect_smuggling(
        "https://example.com/", techniques=["made-up"], sender=sender
    )
    assert any("unknown technique" in e for e in rep.errors)
    assert rep.vulnerable is False
