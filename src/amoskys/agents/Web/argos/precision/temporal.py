"""Temporal discipline for APT-grade probing.

A commodity scanner (nuclei, wpscan) fires every probe it has as
fast as rate-limits allow — 15 requests per second for tens of
minutes. A defender sees a sustained spike in one tight window and
blocks the source IP.

An APT-grade attacker fires one probe every 3-6 hours, aligned to
the target's business-hours timezone, with gaussian-jittered start
times so no two probes are predictably spaced. Over a week, a probe
plan of 20 findings is done. The defender sees 20 lone requests over
168 hours, none correlated to each other by timing — and zero of
them look like scanner traffic by shape.

Scheduling strategy
-------------------
Given N probes and a target timezone, we produce a SchedulePlan:
    - one fire-time per probe, sorted chronologically
    - only in "business-hours" windows of the target's local timezone
      (e.g. 08:00-18:00 local)
    - minimum gap between any two probes: default 3h ± 1h
    - total duration spread: default 3-14 days

The output is deterministic given the seed so the operator can
schedule it via cron / at-jobs.

Why business-hours?
-------------------
The signal the defender watches for is "request from an unknown source
at 3am when the business is closed." A real customer at 11am Tuesday
in the target's time zone looks normal. An APT understands this.
"""

from __future__ import annotations

import datetime
import random
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

try:
    from zoneinfo import ZoneInfo
except ImportError:  # py <3.9
    ZoneInfo = None  # type: ignore


@dataclass
class TargetTimezone:
    """Target's assumed timezone and business hours.

    Defaults to US/Eastern 8am-6pm, which maps OK to both US SMBs and
    most Europe/EU target traffic windows. Override if the target is
    obviously elsewhere (country-specific TLD, language detection,
    CDN POP).
    """
    tz_name: str = "America/New_York"
    biz_start_hour: int = 8       # inclusive local time
    biz_end_hour:   int = 18      # exclusive local time
    biz_days: Tuple[int, ...] = (0, 1, 2, 3, 4)  # Mon-Fri (Python: Mon=0)


@dataclass
class SchedulePlan:
    """The schedule the operator should execute."""
    probe_count:    int
    total_hours:    float
    probe_times:    List[datetime.datetime] = field(default_factory=list)
    seed:           int = 0
    notes:          List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "probe_count": self.probe_count,
            "total_hours": self.total_hours,
            "probe_times": [t.isoformat() for t in self.probe_times],
            "seed":        self.seed,
            "notes":       self.notes,
        }


def _in_biz_hours(dt: datetime.datetime, tz: TargetTimezone) -> bool:
    """Is this datetime within the target's business hours?"""
    if ZoneInfo is None:
        # Fallback: assume UTC alignment — still reasonable.
        local = dt
    else:
        try:
            local = dt.astimezone(ZoneInfo(tz.tz_name))
        except Exception:
            local = dt
    if local.weekday() not in tz.biz_days:
        return False
    if local.hour < tz.biz_start_hour or local.hour >= tz.biz_end_hour:
        return False
    return True


def _next_biz_instant(dt: datetime.datetime, tz: TargetTimezone) -> datetime.datetime:
    """Advance dt forward to the next business-hours instant."""
    out = dt
    # Worst case we skip up to 72 hours (long weekend).
    for _ in range(72 * 4):
        if _in_biz_hours(out, tz):
            return out
        out = out + datetime.timedelta(minutes=15)
    return out


def low_slow_schedule(
    probe_count:    int,
    tz:             Optional[TargetTimezone] = None,
    start_at:       Optional[datetime.datetime] = None,
    min_gap_hours:  float = 3.0,
    gap_stddev_hr:  float = 1.0,
    max_span_days:  int = 14,
    seed:           Optional[int] = None,
) -> SchedulePlan:
    """Generate a low-and-slow probe schedule.

    Parameters
    ----------
    probe_count :   number of probes to fit into the schedule
    tz :            target's timezone + business hours (defaults to
                    America/New_York 8-18 Mon-Fri)
    start_at :      UTC datetime to start planning from. Defaults to
                    next Monday 8am target-local-time.
    min_gap_hours : minimum delta between consecutive probes
    gap_stddev_hr : gaussian jitter on the gap
    max_span_days : total plan must fit within this many days
    seed :          RNG seed for reproducibility. None = random.

    Returns SchedulePlan with probe_times sorted ascending.
    """
    tz = tz or TargetTimezone()
    rng = random.Random(seed) if seed is not None else random.Random()

    if start_at is None:
        start_at = datetime.datetime.now(datetime.timezone.utc)
    # Snap to next business-hours instant.
    cur = _next_biz_instant(start_at, tz)

    probe_times: List[datetime.datetime] = []
    notes: List[str] = []
    max_end = start_at + datetime.timedelta(days=max_span_days)

    for i in range(probe_count):
        gap = rng.gauss(min_gap_hours + 1.5, gap_stddev_hr)
        # Floor at min_gap; cap at 8h to avoid unbounded tails.
        gap = max(min_gap_hours, min(gap, 8.0))
        candidate = cur + datetime.timedelta(hours=gap)
        candidate = _next_biz_instant(candidate, tz)
        if candidate > max_end:
            notes.append(
                f"probe {i+1}/{probe_count}: schedule exceeded max_span_days; "
                "consider splitting across multiple weeks."
            )
            break
        probe_times.append(candidate)
        cur = candidate

    total_hours = 0.0
    if probe_times:
        total_hours = (probe_times[-1] - probe_times[0]).total_seconds() / 3600

    return SchedulePlan(
        probe_count=len(probe_times),
        total_hours=round(total_hours, 2),
        probe_times=probe_times,
        seed=seed or 0,
        notes=notes,
    )


# ---- Diurnal anti-fingerprint helpers ----------------------------


def humanlike_delay_seconds(rng: Optional[random.Random] = None) -> float:
    """Short-range delay for within-session behavior (not probe-to-probe).

    This is for small within-request timing — e.g. delay between a
    probe's HEAD and its GET. Longer probe-to-probe gaps come from
    low_slow_schedule.
    """
    rng = rng or random.Random()
    # Truncated gaussian centered at 4s, stddev 2s.
    x = rng.gauss(4.0, 2.0)
    return max(1.0, min(x, 15.0))
