"""A detector with nothing to match against must ABSTAIN, not acquit.

Regression tests for a failure that ran undetected for 52 days on the live
machine: all 1,155 indicators shared a single expires_at that passed on
2026-07-01, so every subsequent flow was stamped threat_intel_match=False and
the dashboard reported the feed HEALTHY. "0 matched" against an empty corpus is
arithmetic, not evidence.

The tri-state contract these tests defend:
    True  -> matched a live indicator
    False -> checked against a live corpus, no match (a real negative)
    None  -> NOT CHECKED; corpus empty or fully expired
"""

import os
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

from amoskys.enrichment.threat_intel import ThreatIntelEnricher

PAST = (datetime.now(timezone.utc) - timedelta(days=52)).isoformat()
FUTURE = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
BAD_IP = "6.6.6.6"
CLEAN_IP = "93.184.216.34"


def _enricher(tmp_path, name, expires_at):
    e = ThreatIntelEnricher(os.path.join(str(tmp_path), name))
    e._conn.execute(
        "INSERT INTO indicators (indicator,type,severity,source,added_at,expires_at)"
        " VALUES (?,?,?,?,?,?)",
        (BAD_IP, "ip", "critical", "test", FUTURE, expires_at),
    )
    e._conn.commit()
    e._armed_checked_at = 0.0  # force the armed-state TTL to re-evaluate
    return e


def test_expired_corpus_abstains_instead_of_acquitting(tmp_path):
    """Rows on disk but none active: the verdict must be None, not False."""
    e = _enricher(tmp_path, "expired.db", PAST)
    on_disk = e._conn.execute("SELECT COUNT(*) FROM indicators").fetchone()[0]

    assert on_disk == 1, "row is present, so a naive COUNT(*) would look healthy"
    assert e.indicator_count() == 0, "but nothing is ACTIVE"
    assert e.armed is False

    event = {"dst_ip": BAD_IP}
    e.enrich_event(event)
    assert event["threat_intel_match"] is None
    assert event["threat_intel_state"] == "unarmed"


def test_live_corpus_still_convicts_and_clears(tmp_path):
    """Abstention must not cost real detections."""
    e = _enricher(tmp_path, "live.db", FUTURE)
    assert e.armed is True

    bad = {"dst_ip": BAD_IP}
    e.enrich_event(bad)
    assert bad["threat_intel_match"] is True

    clean = {"dst_ip": CLEAN_IP}
    e.enrich_event(clean)
    assert clean["threat_intel_match"] is False, "a real negative stays False"


def test_corpus_expiring_mid_run_stops_stale_convictions(tmp_path):
    """The cliff: a feed does not empty at startup, it empties on a Tuesday.

    check_indicator() is LRU-cached, so a hit recorded while the corpus was
    live kept being served after expiry — an expired feed producing confident
    convictions. That is the mirror of the acquittal bug and it beat the
    abstain branch, because matches were evaluated before armed-state was.
    """
    e = _enricher(tmp_path, "cliff.db", FUTURE)
    first = {"dst_ip": BAD_IP}
    e.enrich_event(first)
    assert first["threat_intel_match"] is True, "primes the LRU with a hit"

    e._conn.execute("UPDATE indicators SET expires_at = ?", (PAST,))
    e._conn.commit()
    e._armed_checked_at = 0.0

    after = {"dst_ip": BAD_IP}
    e.enrich_event(after)
    assert e.armed is False
    assert after["threat_intel_match"] is None, "stale conviction leaked from cache"


def test_rearming_clears_stale_misses(tmp_path):
    """The other direction: a cached MISS must not survive a feed refresh."""
    e = _enricher(tmp_path, "rearm.db", PAST)
    miss = {"dst_ip": BAD_IP}
    e.enrich_event(miss)
    assert miss["threat_intel_match"] is None

    e._conn.execute("UPDATE indicators SET expires_at = ?", (FUTURE,))
    e._conn.commit()
    e._armed_checked_at = 0.0

    hit = {"dst_ip": BAD_IP}
    e.enrich_event(hit)
    assert e.armed is True
    assert hit["threat_intel_match"] is True, "stale miss survived the refresh"


@pytest.mark.parametrize("field", ["src_ip", "dst_ip", "source_ip"])
def test_abstention_applies_to_every_ip_field(tmp_path, field):
    e = _enricher(tmp_path, f"fields-{field}.db", PAST)
    event = {field: BAD_IP}
    e.enrich_event(event)
    assert event["threat_intel_match"] is None
