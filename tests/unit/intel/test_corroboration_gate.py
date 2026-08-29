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


def test_would_deny_on_a_local_build_is_NOT_corroboration():
    """The correction that measurement forced.

    Over 657,764 real executions this machine produced 6 would_deny events —
    1-in-109,627, 16.7 bits, genuinely rare. And ALL SIX were locally-built
    ad-hoc binaries: rustup, the rust toolchain, two red-team test binaries,
    one probe of mine. Zero were malware.

    Rarity and malice are different properties. Counting would_deny alone
    meant a developer running `cargo build` would lift the cap on any
    co-occurring probe chain — the exact false-positive path the gate exists
    to prevent, reintroduced by the fix for it.
    """
    w = _corroborating_witnesses(
        {"esf_decision": "would_deny", "esf_untrusted": True,
         "geo_src_country": "US"})
    assert "kernel_would_deny" not in w
    assert "kernel_would_deny_on_download" not in w


def test_untrusted_alone_is_NOT_corroboration():
    """4,520 of 657,764 execs are untrusted — 1-in-145 — and every one is
    ad-hoc, which is how every local build is signed. Zero were truly
    unsigned: on Apple silicon a binary needs at least an ad-hoc signature to
    execute, so the case this was named for cannot occur."""
    assert _corroborating_witnesses({"esf_untrusted": True}) == []


def test_downloaded_and_untrusted_IS_corroboration():
    """Provenance is the discriminator a signature cannot provide.

    Ad-hoc means "I compiled it" and "I downloaded it" equally. The quarantine
    xattr separates them and names the source agent. This population —
    untrusted AND arrived from somewhere — has occurred zero times in 657,764
    executions.
    """
    w = _corroborating_witnesses({
        "esf_untrusted": True,
        "esf_quarantine": "0083;6a7e118c;Safari;UUID",
        "geo_src_country": "US",
    })
    assert "downloaded_and_untrusted" in w


def test_would_deny_counts_only_alongside_provenance():
    """On its own it is the toolchain; on a downloaded binary it is the thing
    this tier was built to catch."""
    w = _corroborating_witnesses({
        "esf_decision": "would_deny",
        "esf_untrusted": True,
        "esf_quarantine": "0083;6a7e118c;Safari;UUID",
    })
    assert "kernel_would_deny_on_download" in w


def test_novelty_requires_provenance_too():
    """A novel untrusted LOCAL binary is a developer's first build.

    138 such events in 657,764 execs — rare at 12.2 bits, and entirely benign.
    Rarity is not malice, and this is the third witness the base rates forced
    me to narrow.
    """
    assert _corroborating_witnesses({"esf_novel_binary": True}) == []
    assert _corroborating_witnesses(
        {"esf_novel_binary": True, "esf_untrusted": True}) == []
    assert "novel_downloaded_binary" in _corroborating_witnesses(
        {"esf_novel_binary": True, "esf_untrusted": True,
         "esf_quarantine": "0083;x;Safari;U"})


def test_a_locally_compiled_dropper_is_NOT_corroborated():
    """The limitation, asserted so it cannot be forgotten.

    Every ESF witness requires provenance, so an attacker who compiles on the
    target produces none of them. That is what the data supports — without
    provenance, a witness fires on the toolchain — but it means such a chain
    must be escalated by BEHAVIOUR, not by the kernel's view of the binary.
    The red-team binary was cc-compiled and correctly yields nothing here.
    """
    locally_built_dropper = {
        "esf_decision": "would_deny", "esf_untrusted": True,
        "esf_novel_binary": True, "geo_src_country": "US",
    }
    assert _corroborating_witnesses(locally_built_dropper) == []


def test_a_downloaded_dropper_is_corroborated_a_local_build_is_not():
    """The distinction the whole change exists for, in one test.

    Both are ad-hoc. Both would_deny. Only one arrived from somewhere.
    """
    dropper = {"esf_decision": "would_deny", "esf_untrusted": True,
               "esf_novel_binary": True, "geo_src_country": "US",
               "esf_quarantine": "0083;6a7e118c;Safari;UUID"}
    rustc = {"esf_decision": "would_deny", "esf_untrusted": True,
             "esf_novel_binary": True, "geo_src_country": "US"}
    assert len(_corroborating_witnesses(dropper)) >= 2
    assert _corroborating_witnesses(rustc) == [], (
        "a locally-built toolchain binary must not lift the cap")


def test_an_allowed_exec_is_not_corroboration():
    assert _corroborating_witnesses({"esf_decision": "allow"}) == []
