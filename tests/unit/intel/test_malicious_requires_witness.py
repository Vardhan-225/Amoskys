"""No malicious verdict without a witness the scoring probe cannot influence.

Measured on this machine over four days: 158 malicious verdicts. Replayed
against this rule, 2 survive — both kernel-witnessed execute_to_exfil from a
genuinely downloaded dropper. The other 156 were:

    /bin/sleep                   20x
    /usr/bin/log                 18x
    Chrome talking to Google     38x
    Chrome Helper (Renderer)      8x

The top severity band, on the most innocuous binary on a Unix system, roughly
forty times a day.

The corroboration requirement previously applied ONLY to categories carrying a
risk floor. Everything else reached malicious on composite score alone — or via
the never-downgrade rule preserving the probe's own CRITICAL stamp, because
capped_uncorroborated is False for an ungated category. A probe that raises its
own score and then certifies it has proved nothing, and the arithmetic cannot
tell the difference.
"""
import pytest

from amoskys.intel.scoring import _corroborating_witnesses


def _ev(**kw):
    return {"event_category": "process_spawned", "severity": "critical", **kw}


class TestWhatCountsAsAWitness:
    """A witness must be something the probe cannot produce about itself."""

    def test_a_bare_high_severity_event_has_none(self):
        assert _corroborating_witnesses(_ev()) == []

    def test_the_probes_own_severity_is_not_a_witness(self):
        """Severity is the probe's own opinion. Measured at 0.039 bits."""
        assert _corroborating_witnesses(_ev(severity="critical", risk_score=1.0)) == []

    def test_threat_intel_is_a_witness(self):
        assert "threat_intel_match" in _corroborating_witnesses(
            _ev(threat_intel_match=True)
        )

    def test_a_foreign_source_is_a_witness(self):
        assert "foreign_source" in _corroborating_witnesses(_ev(geo_src_country="RU"))

    def test_a_kernel_observation_of_provenance_is_a_witness(self):
        w = _corroborating_witnesses(_ev(
            esf_decision="would_deny", esf_untrusted=True, esf_novel_binary=True,
            esf_quarantine="0083;6a7e118c;Safari;UUID",
        ))
        assert "downloaded_and_untrusted" in w
        assert "kernel_would_deny_on_download" in w


class TestTheMeasuredFalsePositives:
    """Each of these was an actual malicious verdict on this machine."""

    @pytest.mark.parametrize("subject,event", [
        ("/bin/sleep", _ev(exe="/bin/sleep")),
        ("/usr/bin/log", _ev(event_category="lolbin_execution", exe="/usr/bin/log")),
        ("Chrome->Google", _ev(event_category="cdn_masquerade_high_volume",
                               domain="Google", geo_src_country="US")),
        ("connection burst", _ev(event_category="connection_burst_detected",
                                 domain="Google", geo_src_country="US")),
    ])
    def test_no_witness_is_available_for_any_of_them(self, subject, event):
        assert _corroborating_witnesses(event) == [], (
            f"{subject} produced a malicious verdict with nothing independent "
            "supporting it"
        )


def test_a_local_build_is_not_corroborated_by_rarity_alone():
    """The base-rate error, kept pinned.

    kernel_would_deny fired 6 times in 657,764 execs and all 6 were the
    operator's own compiler. Rarity is not malice, and an ad-hoc signature
    without provenance cannot tell a local build from a dropper.
    """
    assert _corroborating_witnesses(_ev(
        esf_decision="would_deny", esf_untrusted=True,
        esf_novel_binary=True, esf_quarantine=None,
    )) == []
