"""The corroborator cache must not freeze a race, and pid is not an identity.

Both failures were found on a LIVE dropper run (2026-08-30):

  esf_exec_events id=980163 pid=85170 decision=would_deny
                  quarantine='00c3;...;Safari;...'   ts=...287596423710
  execute_to_exfil id=110315 pid=85170 composite=0.40 ts=...289163299072

1.6s apart, well inside the 30s window, and no witness attached. The dropper's
FIRST event (process_spawned) had been enriched before the ESF collector
flushed the exec row, so the lookup missed, cached None, and held it for the
full 300s TTL. The execute_to_exfil that arrived 1.6s later — with the exec row
by then sitting in the table — read the stale None and scored 0.40.

The second defect was found while fixing the first: pid 85170 was reused 13
times on that machine, and a positive cached on pid alone would serve one
execution's kernel record for a different execution's event. That direction is
worse: a witness LIFTS the cap to malicious, so a wrong one manufactures a
verdict instead of missing one.
"""
import time

from amoskys.intel.esf_corroboration import ESFCorroborator, _MATCH_WINDOW_NS

EXEC_TS = 1_788_128_287_596_423_710
EVENT_TS = 1_788_128_289_163_299_072  # 1.6s later, as measured


class _Store:
    """A store whose exec row lands partway through, like the real collector."""

    def __init__(self):
        self.row = None
        self.lookups = 0

    def land_the_exec_row(self):
        self.row = ("would_deny", 1, 1, 1, 0, "cd01", EXEC_TS,
                    "00c3;6a7e118c;Safari;A1540A0B")

    class _Pool:
        def __init__(self, outer):
            self.outer = outer

        def connection(self):
            outer = self.outer

            class _Ctx:
                def __enter__(self):
                    class _DB:
                        def execute(self, sql, params=()):
                            if "esf_binary_ledger" in sql:
                                class _R:
                                    def fetchone(self_):
                                        return (EXEC_TS,)
                                return _R()
                            outer.lookups += 1
                            row = outer.row

                            class _R2:
                                def fetchone(self_):
                                    return row
                            return _R2()
                    return _DB()

                def __exit__(self, *a):
                    return False
            return _Ctx()

    @property
    def _read_pool(self):
        return self._Pool(self)


def test_a_miss_is_not_cached_so_a_later_event_still_finds_the_witness():
    """The exact live failure: miss, row lands, next event must see it."""
    store = _Store()
    cor = ESFCorroborator(store)

    early = {"pid": "85170", "timestamp_ns": EXEC_TS - 500_000_000}
    cor.enrich(early)
    assert "esf_decision" not in early, "nothing to find yet — correct"

    store.land_the_exec_row()  # the ESF collector flushes

    later = {"pid": "85170", "timestamp_ns": EVENT_TS}
    cor.enrich(later)
    assert later.get("esf_decision") == "would_deny", (
        "a cached negative froze the race and cost the detection"
    )
    assert later.get("esf_quarantine", "").split(";")[2] == "Safari"


def test_a_hit_is_still_cached():
    """Not caching negatives must not mean not caching at all."""
    store = _Store()
    store.land_the_exec_row()
    cor = ESFCorroborator(store)

    for _ in range(5):
        cor.enrich({"pid": "85170", "timestamp_ns": EVENT_TS})
    assert store.lookups == 1, f"expected one lookup, made {store.lookups}"


def test_a_cached_witness_is_not_served_to_a_different_execution():
    """pid is recycled. A witness lifts the cap, so a wrong one is expensive."""
    store = _Store()
    store.land_the_exec_row()
    cor = ESFCorroborator(store)

    first = {"pid": "85170", "timestamp_ns": EVENT_TS}
    cor.enrich(first)
    assert first.get("esf_decision") == "would_deny"

    # Same pid, hours later: a different process that inherited the number.
    store.row = None  # no exec row in ITS window
    reused = {"pid": "85170", "timestamp_ns": EVENT_TS + 4 * _MATCH_WINDOW_NS}
    cor.enrich(reused)
    assert "esf_decision" not in reused, (
        "the earlier execution's kernel record was attached to an unrelated "
        "process — that manufactures a malicious verdict"
    )
