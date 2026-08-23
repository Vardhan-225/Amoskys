#!/usr/bin/env python3
"""Summarise a Sentinel MONITOR capture so ENFORCE can be an evidence-based call.

    python3 scripts/sentinel_fp_report.py logs/sentinel_monitor.log

MONITOR exists to answer one question: if AMOSKYS_ENFORCE=1 had been set, what
would have been killed? A raw log answers that badly — thousands of near
duplicate lines, and the three or four interesting ones buried among them.

The grouping is deliberately by (untrust-kind, directory), not by path. On a
developer machine the same rule fires hundreds of times across one build tree,
and counting paths makes a single benign toolchain look like a swarm. Counting
DIRECTORIES shows that it is one place, once.

Reading the output: a WOULD-DENY count of zero is NOT a clean bill of health.
It can equally mean the rule cannot fire — which was true here until the
RISKY_PREFIXES precedence bug was fixed, when the whole policy had silently
collapsed to "/Downloads/ or /Library/Caches/". Check `distinct rules fired`
below: if it is 0, the run proved nothing about false positives.
"""

import os
import re
import sys
from collections import Counter, defaultdict

LINE = re.compile(r"(WOULD-DENY|DENIED) exec (?P<path>.+?) — (?P<why>.+)$")


def main(paths):
    if not paths:
        print(__doc__)
        return 1
    by_reason = Counter()
    by_dir = defaultdict(Counter)
    examples = {}
    total = enforced = started = 0

    for p in paths:
        if not os.path.exists(p):
            print("  missing: %s" % p)
            continue
        with open(p, "r", errors="replace") as fh:
            for raw in fh:
                if "guarding exec" in raw:
                    started += 1
                m = LINE.search(raw.rstrip("\n"))
                if not m:
                    continue
                total += 1
                if raw.startswith("DENIED"):
                    enforced += 1
                why, path = m.group("why").strip(), m.group("path").strip()
                by_reason[why] += 1
                by_dir[why][os.path.dirname(path)] += 1
                examples.setdefault(why, path)

    print("\nSentinel MONITOR report")
    print("  sessions started : %d" % started)
    print("  would-deny events: %d" % total)
    if enforced:
        print("  ACTUALLY DENIED  : %d   <-- this capture was NOT monitor-only" % enforced)
    print("  distinct rules   : %d" % len(by_reason))

    if not total:
        print("\n  No WOULD-DENY lines.")
        print("  This is NOT evidence the rule is safe to enforce. It is equally")
        print("  consistent with a rule that cannot fire. Confirm the policy is")
        print("  live before drawing any conclusion — see the module docstring.")
        return 0

    print("\n  By rule (most frequent first):")
    for why, n in by_reason.most_common():
        dirs = by_dir[why]
        print("\n    %-46s %6d events across %d dirs" % (why[:46], n, len(dirs)))
        print("      e.g. %s" % examples[why])
        for d, dn in dirs.most_common(5):
            print("        %6d  %s" % (dn, d))
        if len(dirs) > 5:
            print("        ... %d more directories" % (len(dirs) - 5))

    print("\n  Before setting AMOSKYS_ENFORCE=1, every line above is a process")
    print("  that would have been killed. Anything you recognise as your own")
    print("  toolchain is a false positive and needs an exclusion first.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
