"""Extract the security-relevant fraction of the unified-log stream.

THE PROBLEM THIS SOLVES, measured before it was written:

    unified_log true volume : 20,821,599 events/day  (241/second)
    stored raw              :    368,187
    carrying any risk score :          0

Sixty percent of all AMOSKYS telemetry, and not one event scored. The data is
not junk — every row carries the full log message, process, subsystem and
category — but nothing ever read it. It was collected, stored, rolled up, and
never looked at.

WHY NOT JUST GREP FOR "denied" AND "failed". Because it does not work, and the
measurement says so plainly. A keyword sweep over these messages matches 96.33%
of the xpc stream:

    [0xb2aca1400] invalidated after a failed init
    [0xb2aca1400] invalidated after the last release of the connection object

That is ordinary XPC teardown vocabulary colliding with security words. Eight
million events a day would arrive pre-labelled as findings, which is precisely
the 1,314-alerts-at-0.039-bits failure that made the severity field worthless.

So the extractors below are SPECIFIC. Each one names a subsystem, a message
shape and a reason it matters. A pattern that cannot say why it fired does not
belong here.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

# Streams that carry no security-relevant content at any volume. Excluded
# wholesale rather than filtered, because filtering implies something worth
# keeping and these are connection-lifecycle chatter: 64% of the xpc stream is
# three message shapes about connections opening and closing.
_MUTE_TYPES = {"xpc", "sharing"}


class _Rule:
    __slots__ = ("name", "subsystem", "pattern", "bits", "why")

    def __init__(self, name: str, subsystem: Optional[str], pattern: str,
                 bits: float, why: str):
        self.name = name
        self.subsystem = subsystem
        self.pattern = re.compile(pattern, re.I)
        self.bits = bits
        self.why = why


# Each rule earns its place by naming a specific, checkable condition.
_RULES: List[_Rule] = [
    _Rule(
        "tcc_denied", "com.apple.TCC",
        r"\bdeny\b|denied.*(?:kTCCService|access)|AccessRequest.*deny",
        9.0,
        "TCC refused a privacy-sensitive request. Denials are rare on a "
        "settled machine and each one names a client asking for something it "
        "does not have.",
    ),
    _Rule(
        "notarization_failure", None,
        r"notariz\w*\s+(?:daemon\s+)?(?:error|fail|denied)|Error checking with notarization",
        11.0,
        "Notarization could not be confirmed. Gatekeeper's verdict on whether "
        "Apple has ever seen this binary, and a failure here precedes running "
        "something unvetted.",
    ),
    _Rule(
        "cert_trust_failure", "com.apple.securityd",
        r"invalid basic constraints|chain.*(?:invalid|untrusted)|"
        r"trust\s+(?:evaluat\w+\s+)?fail|revoked|certificate.*expired",
        10.0,
        "Certificate validation failed. TLS interception, an expired root, or "
        "a forged chain all surface here first.",
    ),
    _Rule(
        "gatekeeper_reject", None,
        r"rejected|denied.*(?:execution|launch)|blocked.*(?:app|binary)|"
        r"unsigned.*(?:reject|deny)",
        12.0,
        "Gatekeeper refused to run something. The most direct statement macOS "
        "makes about code it does not trust.",
    ),
    _Rule(
        "keychain_access_failure", None,
        r"keychain.*(?:denied|unauthoriz|failed to (?:read|unlock))|"
        r"SecKeychain.*errSec(?:AuthFailed|Interaction)",
        11.0,
        "A keychain read was refused. Credential theft attempts show up as a "
        "process asking for items it has no entitlement to.",
    ),
    _Rule(
        "privilege_failure", None,
        r"not permitted|operation not permitted.*(?:setuid|root)|"
        r"authorization.*(?:denied|fail)",
        9.0,
        "A privileged operation was refused. On its own it is usually benign; "
        "in a burst from one process it is an escalation attempt failing.",
    ),
]


def evaluate(attrs: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Score one unified-log observation, or return None if it carries nothing.

    Returning None is the common case by design — the point is that the vast
    majority of 20.8M daily events say nothing, and a scorer that finds
    something in most of them has only rediscovered the keyword problem.
    """
    et = str(attrs.get("event_type") or "")
    if et in _MUTE_TYPES:
        return None
    message = str(attrs.get("message") or "")
    if not message:
        return None
    subsystem = str(attrs.get("subsystem") or "")

    for rule in _RULES:
        if rule.subsystem and rule.subsystem not in subsystem:
            continue
        m = rule.pattern.search(message)
        if not m:
            continue
        return {
            "rule": rule.name,
            "bits": rule.bits,
            "why": rule.why,
            "matched": m.group(0)[:80],
            "process": attrs.get("process"),
            "subsystem": subsystem,
            "message": message[:400],
        }
    return None


def evaluate_many(records) -> Dict[str, Any]:
    """Score a batch and report the yield, including how much said nothing.

    The `examined` and `silent` counts are returned deliberately. A finding
    count without its denominator is unreadable — it is the difference between
    "6 findings from 60,000 events" and "6 findings from 6 events", and only
    one of those is reassuring.
    """
    findings, by_rule, silent = [], {}, 0
    for attrs in records:
        r = evaluate(attrs)
        if r is None:
            silent += 1
            continue
        findings.append(r)
        by_rule[r["rule"]] = by_rule.get(r["rule"], 0) + 1
    n = len(findings) + silent
    return {
        "examined": n,
        "findings": findings,
        "count": len(findings),
        "silent": silent,
        "by_rule": by_rule,
        "yield_rate": (len(findings) / n) if n else 0.0,
    }


# ── Rarity gate ──────────────────────────────────────────────────────────────
#
# The rules above, run raw, yielded 1.137% of the stream — 238,124 findings a
# day once scaled to the true 20.8M volume. Unusable, and the samples show why:
#
#     "Leaf has invalid basic constraints"                x345   trustd doing
#                                                                normal chain work
#     "Error checking with notarization daemon: 3"        x301
#     "Platform binary prompting is 'Deny' because: is Platform Binary"
#
# That last one is not a denial at all — it is TCC explaining that it will NOT
# prompt for a platform binary, and the word "Deny" appears inside the
# explanation. No amount of pattern refinement fixes that class of error,
# because the pattern cannot see that the machine says this ten thousand times
# a day and has always said it.
#
# So the gate is the same one that worked everywhere else today: a message
# shape that this machine emits constantly carries no information, whatever
# words are in it. Surprisal is measured against what the machine actually
# does, not against a list of scary strings.

import collections
import math


def _shape(message: str) -> str:
    """Normalise a message to its SHAPE: hex, digits and paths collapsed.

    Without this, every occurrence looks unique because it carries a different
    pointer or pid, and a frequency count over raw text finds nothing repeated.
    """
    s = re.sub(r"0x[0-9a-f]+", "<h>", message)
    s = re.sub(r"\b\d+\b", "<n>", s)
    s = re.sub(r"/[^\s,]+", "<p>", s)
    return s[:120]


def evaluate_with_rarity(records, *, max_share: float = 0.0002) -> Dict[str, Any]:
    """Score a batch, then keep only shapes this machine rarely emits.

    max_share is the fraction of the corpus above which a shape is considered
    routine. At the default, a message shape appearing more than twice in
    10,000 events is background noise for this machine — however alarming its
    wording.

    Two passes on purpose. The first builds the baseline from the SAME corpus
    being judged, which is exactly the self-inclusion trap that broke the
    privilege detector earlier today — but here it is correct and deliberate:
    the question is not "is this event new" but "is this SHAPE common", and a
    shape's own occurrences are what make it common. Excluding them would make
    a shape appearing 10,000 times look as rare as one appearing once.

    KNOWN LIMITATION, stated because the numbers look better than they are.
    Rarity here is measured within the batch, and a batch is not the machine. A
    shape seen once in a 60,000-event sample is NOT rare at 21M events/day — it
    is on track for roughly 350 occurrences, which is background. Scaling a
    per-batch rate to a daily volume therefore overstates rarity for exactly
    the tail this gate exists to find, and the threshold sweep shows it: yield
    falls from 4,203/day to zero with nothing usable in between, because the
    sample cannot resolve anything rarer than one-in-sixty-thousand.

    The fix is a PERSISTENT shape ledger, the same shape as esf_binary_ledger:
    accumulate counts across days so "rare" is measured against what this
    machine actually does over time rather than against one window. Until that
    exists, treat the output as a filtered stream to review, not an alert
    feed — and do not read the projected per-day figures as a rate anyone
    could act on.
    """
    scored = []
    shapes = collections.Counter()
    for attrs in records:
        r = evaluate(attrs)
        if r is None:
            continue
        sh = _shape(r["message"])
        r["shape"] = sh
        shapes[sh] += 1
        scored.append(r)

    n = max(len(records), 1)
    kept, suppressed = [], collections.Counter()
    for r in scored:
        occurrences = shapes[r["shape"]]
        share = occurrences / n
        if share > max_share:
            suppressed[r["shape"]] += 1
            continue
        # Surprisal replaces the rule's static weight once there is a measured
        # rate: a rule cannot know in advance how often THIS machine says a
        # thing, and the measurement is strictly better than the guess.
        r["occurrences"] = occurrences
        r["bits"] = round(-math.log2(share), 1)
        kept.append(r)

    kept.sort(key=lambda r: -r["bits"])
    return {
        "examined": len(records),
        "matched_rules": len(scored),
        "findings": kept,
        "count": len(kept),
        "suppressed_as_routine": sum(suppressed.values()),
        "routine_shapes": suppressed.most_common(5),
        "yield_rate": len(kept) / n,
    }
