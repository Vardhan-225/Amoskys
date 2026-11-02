"""The corroborator must accept a pid in whichever type the caller has.

The analyzer converts every attribute with str(v) before it reaches the scorer,
so pids arrive as '81786'. An earlier version required isinstance(pid, int) and
returned early on 100% of real events -- no kernel witness ever attached, and
the corroboration gate stayed capped at 0.40 no matter what the kernel saw.

The failure was invisible: the scorer kept producing plausible numbers. Only a
direct measurement of attribution rate (0/800) surfaced it. These tests exist so
a type check can never silently reintroduce that.
"""
import pytest
from amoskys.intel.esf_corroboration import ESFCorroborator


class _Store:
    def __init__(self, rows):
        self._rows = rows

    class _Pool:
        def __init__(self, rows):
            self._rows = rows

        def connection(self):
            rows = self._rows

            class _Ctx:
                def __enter__(self):
                    class _DB:
                        row_factory = None

                        def execute(self, *a, **k):
                            return rows

                    return _DB()

                def __exit__(self, *a):
                    return False

            return _Ctx()

    @property
    def _read_pool(self):
        return self._Pool(self._rows)


@pytest.mark.parametrize("pid_value", [81786, "81786"])
def test_pid_accepted_as_int_and_string(pid_value):
    """Both forms must reach the lookup. The same dict is built from a DB
    column (int) in one path and from proto attributes (str) in another."""
    cor = ESFCorroborator(_Store([]))
    ev = {"pid": pid_value, "timestamp_ns": 1}
    cor.enrich(ev)  # must not raise, must not early-return on the string


@pytest.mark.parametrize("bad", [None, "", "not-a-pid", -1, 0, "0", []])
def test_unusable_pids_return_cleanly(bad):
    cor = ESFCorroborator(_Store([]))
    ev = {"pid": bad, "timestamp_ns": 1}
    cor.enrich(ev)
    assert not any(k.startswith("esf_") for k in ev)
