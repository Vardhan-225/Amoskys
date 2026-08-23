"""Cryptographic self-knowledge: can AMOSKYS tell itself from an adversary?

Measured on this machine before this module existed: 28.5% of all
security_events, and 99.5% of the `lolbin_execution` category, were AMOSKYS
observing its OWN probe toolchain. `log show` fired 807 times because the
unified-log sensor runs it. The `exfil` chain resolved to `claude`, `ssh` and
`curl` — a debugging session. The `clickfix_attack` chain resolved to a human
reading commands in a chat window and pasting them into Terminal.

None of those detections were wrong about the BEHAVIOUR. They were wrong about
the ACTOR, and an organism that cannot distinguish its own immune response from
an infection will always be inflamed.

THREE RULES, and the third is the one that makes this safe:

  1. IDENTITY IS CRYPTOGRAPHIC, NOT POSITIONAL. Self-recognition keyed on paths
     or process names is trivially forged: drop a binary at a trusted path,
     inherit its trust, become invisible. Identity here is the cdhash the
     KERNEL verified at exec time, which an attacker cannot choose without
     also possessing the corresponding signature.

  2. SUPPRESSION IS RECORDED, NEVER SILENT. Every self-attribution is written
     down with the evidence that produced it. A self-model that quietly deletes
     events is a blind spot that reports itself as calm — the same failure as a
     dead threat-intel feed reading HEALTHY, moved to the identity layer.

  3. SELF-IDENTITY INVERTS INTO TAMPER DETECTION. A binary sitting at one of
     AMOSKYS's own paths whose hash AMOSKYS does NOT recognise is not
     suppressed. It is the single most alarming thing this module can find:
     something is impersonating the monitor. The natural failure mode of a
     self-model is to become an attacker's hiding place, so the check that
     would grant trust is also the check that raises the alarm.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import subprocess
from typing import Any, Dict, Optional, Set

logger = logging.getLogger(__name__)

SELF = "self"
FOREIGN = "foreign"
IMPOSTOR = "impostor"
UNKNOWN = "unknown"

# Paths AMOSKYS occupies. Used ONLY to decide where an impostor check applies —
# never on its own to grant trust. Rule 1: position raises the question,
# cryptography answers it.
_OWN_PATH_MARKERS = (
    "/Amoskys_recovered/",
    "/amoskys-venv/",
    "/macos-esf-shim/",
)

# Tools AMOSKYS's probes invoke. Being on this list is NOT trust — it only
# means "this could plausibly be us", which then has to be corroborated by
# ancestry. Every one of these is also a genuine attacker tool, which is
# exactly why `lolbin_execution` fires on them in the first place.
_PROBE_TOOLS = {
    "log", "lsof", "nettop", "pgrep", "ps", "dscl", "system_profiler",
    "sqlite3", "codesign", "security", "networksetup", "ioreg", "launchctl",
    "spctl", "profiles", "who", "last", "df", "diskutil",
}

_CDHASH_RE = re.compile(r"CDHash=([0-9a-f]+)", re.I)

# Interpreters carry NO identity, wherever they live. Enumerating their paths
# does not work: amoskys-venv/bin/python resolves to
#   .../Versions/3.13/bin/python3.13
# but CPython re-execs itself through its framework bundle, so the kernel
# actually reports
#   .../Versions/3.13/Resources/Python.app/Contents/MacOS/Python
# — a path the symlink never names. Matching by NAME covers every such
# re-exec, every version bump, and every install location at once.
#
# The rule is principled rather than a workaround: for an interpreter the
# binary is a substrate, not an actor. `python evil.py` and
# `python -m amoskys.shipper` share a cdhash and share nothing else, so the
# identity has to come from the arguments.
_INTERPRETER_NAMES = re.compile(
    r"^(python(\d(\.\d+)?)?|Python|node|deno|bun|ruby|perl|php|osascript"
    r"|sh|bash|zsh|dash|ksh|fish|env)$"
)


def _is_interpreter(path: str) -> bool:
    return bool(_INTERPRETER_NAMES.match(os.path.basename(path or "")))


def cdhash_of(path: str) -> Optional[str]:
    """Read a binary's code directory hash via codesign.

    Falls back to None rather than to a content hash: a SHA-256 of the file is
    not the same claim. cdhash covers the signed code pages as the kernel
    evaluates them, and substituting a weaker identity while keeping the same
    field name would silently downgrade every trust decision made from it.
    """
    try:
        out = subprocess.run(
            ["codesign", "-dvvv", path],
            capture_output=True, text=True, timeout=5,
        ).stderr
    except Exception:
        return None
    m = _CDHASH_RE.search(out or "")
    return m.group(1).lower() if m else None


def _find_repo_root() -> str:
    """Walk up until a repo marker appears.

    Counting os.path.dirname() calls is off-by-one bait — the first version of
    this resolved to .../src and registered ZERO binaries, silently producing a
    self-model that recognised nothing. Anchoring on real markers survives the
    module being moved.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    for _ in range(8):
        if any(os.path.exists(os.path.join(here, m))
               for m in ("pyproject.toml", "macos-esf-shim", ".git")):
            return here
        parent = os.path.dirname(here)
        if parent == here:
            break
        here = parent
    return os.getcwd()


class SelfModel:
    """What AMOSKYS knows about its own body."""

    def __init__(self, repo_root: Optional[str] = None, store=None):
        self.repo_root = os.path.realpath(
            repo_root or os.getenv("AMOSKYS_ROOT") or _find_repo_root()
        )
        self.store = store
        self.own_hashes: Dict[str, str] = {}      # cdhash -> role
        self.own_paths: Dict[str, str] = {}       # realpath -> cdhash
        self.attributions: Dict[str, int] = {
            SELF: 0, FOREIGN: 0, IMPOSTOR: 0, UNKNOWN: 0
        }
        self.unresolved_paths: Set[str] = set()
        # Shared interpreters. Never identity — see bootstrap().
        self.interpreters: Set[str] = set()

    # ── registration ──────────────────────────────────────────────────────
    def register(self, path: str, role: str) -> bool:
        """Learn one of our own binaries by hash."""
        rp = os.path.realpath(path)
        if not os.path.exists(rp):
            return False
        h = cdhash_of(rp)
        if not h:
            # An unsigned interpreter (common for a venv python) has no cdhash.
            # Recorded as unresolved rather than trusted by path, because
            # trusting it by path is precisely the hole rule 1 exists to close.
            self.unresolved_paths.add(rp)
            logger.debug("no cdhash for %s — will not be trusted by path", rp)
            return False
        self.own_hashes[h] = role
        self.own_paths[rp] = h
        return True

    def bootstrap(self) -> Dict[str, Any]:
        """Register the binaries AMOSKYS actually runs as.

        INTERPRETERS ARE DELIBERATELY EXCLUDED. amoskys-venv/bin/python is a
        symlink to the SHARED homebrew interpreter
        (/opt/homebrew/Cellar/python@3.13/.../python3.13), so registering its
        cdhash as "AMOSKYS" would mark every Python process on this machine as
        self — including an attacker's payload. The self-model would have
        become the best hiding place on the box, which is the exact failure
        rule 3 exists to prevent, arriving through the front door.

        For an interpreter the meaningful identity is the SCRIPT, not the
        binary: `python evil.py` and `python -m amoskys.shipper` share a
        cdhash and share nothing else. Interpreters are therefore tracked
        separately and resolved through argv (see _interpreter_identity).
        """
        candidates = [
            (os.path.join(self.repo_root, "macos-esf-shim",
                          "AmoskysSentinel.app", "Contents", "MacOS",
                          "amoskys-sentinel"), "sentinel"),
        ]
        for p, role in candidates:
            self.register(p, role)
        for interp in ("python", "python3"):
            rp = os.path.realpath(
                os.path.join(self.repo_root, "amoskys-venv", "bin", interp))
            if os.path.exists(rp):
                self.interpreters.add(rp)
        return {
            "interpreters_excluded": sorted(self.interpreters),
            "root": self.repo_root,
            "registered": len(self.own_hashes),
            "roles": sorted(set(self.own_hashes.values())),
            "unresolved": sorted(self.unresolved_paths),
            "note": (
                "Unresolved paths carry no cdhash (typically an ad-hoc signed "
                "interpreter). They are NOT trusted — position alone never "
                "grants trust here."
            ),
        }

    # ── attribution ───────────────────────────────────────────────────────
    def classify(
        self, *, exe: str, cdhash: Optional[str] = None,
        argv: Optional[list] = None, ancestry: Optional[list] = None,
    ) -> Dict[str, Any]:
        """Decide whether an observation is AMOSKYS acting, or something else.

        Returns a verdict WITH its evidence, always. A bare label would be
        untraceable the moment it was wrong, and the whole point of this module
        is that its mistakes must be findable.
        """
        rp = os.path.realpath(exe) if exe else ""
        in_own_tree = any(m in rp for m in _OWN_PATH_MARKERS)
        base = os.path.basename(rp)

        # RULE 3 FIRST, deliberately. The impostor check runs BEFORE any path
        # that could grant trust, so a hash mismatch can never be reached only
        # after something has already been waved through.
        if rp in self.own_paths and cdhash and cdhash != self.own_paths[rp]:
            self.attributions[IMPOSTOR] += 1
            return {
                "attribution": IMPOSTOR,
                "confidence": 0.99,
                "reason": (
                    "A binary at one of AMOSKYS's own paths has a cdhash that "
                    "does not match the registered one. Either AMOSKYS was "
                    "rebuilt, or something is impersonating the monitor."
                ),
                "evidence": {
                    "path": rp,
                    "expected_cdhash": self.own_paths[rp],
                    "observed_cdhash": cdhash,
                },
                "suppress": False,
            }

        # An interpreter is identified by WHAT IT IS RUNNING, never by itself.
        if rp in self.interpreters or _is_interpreter(rp):
            return self._interpreter_identity(rp, argv or [])

        if cdhash and cdhash in self.own_hashes:
            self.attributions[SELF] += 1
            return {
                "attribution": SELF,
                "confidence": 0.99,
                "reason": f"cdhash matches registered AMOSKYS {self.own_hashes[cdhash]}",
                "evidence": {"cdhash": cdhash, "role": self.own_hashes[cdhash]},
                "suppress": True,
            }

        # A probe tool is only ours if an AMOSKYS process launched it. `log`
        # fired 807 times here — attacker-plausible every time, and ours every
        # time, and the ONLY thing separating those two readings is ancestry.
        if base in _PROBE_TOOLS:
            # The parent is CLASSIFIED, not merely hash-matched. AMOSKYS runs
            # its probes from a shared interpreter whose own path contains no
            # AMOSKYS marker (/opt/homebrew/...), so a hash-or-path test on the
            # parent fails for every probe we actually launch — which is most
            # of them. Recursing one level resolves the parent through ITS
            # argv, which is where the identity lives.
            launched_by_us = False
            for a in (ancestry or []):
                if a.get("cdhash") in self.own_hashes:
                    launched_by_us = True
                    break
                if any(m in (a.get("exe") or "") for m in _OWN_PATH_MARKERS):
                    launched_by_us = True
                    break
                pexe = a.get("exe") or ""
                if _is_interpreter(pexe):
                    pv = self._interpreter_identity(
                        os.path.realpath(pexe), a.get("argv") or [])
                    # Undo the counter bump from the nested call: this is an
                    # ancestry probe, not an observation in its own right.
                    self.attributions[pv["attribution"]] -= 1
                    if pv["attribution"] == SELF:
                        launched_by_us = True
                        break
            if launched_by_us:
                self.attributions[SELF] += 1
                return {
                    "attribution": SELF,
                    "confidence": 0.90,
                    "reason": (
                        f"{base} is a probe tool AND was launched by an AMOSKYS "
                        "process. Ancestry is required: the tool alone is "
                        "attacker-plausible."
                    ),
                    "evidence": {"tool": base, "ancestry_depth": len(ancestry or [])},
                    "suppress": True,
                }
            self.attributions[UNKNOWN] += 1
            return {
                "attribution": UNKNOWN,
                "confidence": 0.5,
                "reason": (
                    f"{base} is a tool AMOSKYS also uses, but nothing in its "
                    "ancestry is AMOSKYS. Not suppressed — an unattributed "
                    "lolbin is the interesting case, not the boring one."
                ),
                "evidence": {"tool": base, "ancestry_depth": len(ancestry or [])},
                "suppress": False,
            }

        if in_own_tree and not cdhash:
            self.attributions[UNKNOWN] += 1
            return {
                "attribution": UNKNOWN,
                "confidence": 0.4,
                "reason": (
                    "Inside the AMOSKYS tree but carries no cdhash, so identity "
                    "cannot be established. Position is not identity."
                ),
                "evidence": {"path": rp},
                "suppress": False,
            }

        self.attributions[FOREIGN] += 1
        return {
            "attribution": FOREIGN,
            "confidence": 0.8,
            "reason": "no AMOSKYS identity matched",
            "evidence": {"path": rp, "cdhash": cdhash},
            "suppress": False,
        }

    def _interpreter_identity(self, rp: str, argv: list) -> Dict[str, Any]:
        """Resolve a shared interpreter through its arguments.

        `python -m amoskys.shipper` is AMOSKYS. `python /tmp/x.py` is not.
        They are the same binary with the same cdhash, so the ONLY thing that
        separates them is argv — which is attacker-controllable, and therefore
        yields a lower confidence than a hash match and is stated as such.
        """
        joined = " ".join(str(a) for a in argv)
        runs_amoskys = (
            " -m amoskys" in f" {joined}"
            or "amoskys." in joined
            or any(m in joined for m in _OWN_PATH_MARKERS)
        )
        if runs_amoskys:
            self.attributions[SELF] += 1
            return {
                "attribution": SELF,
                "confidence": 0.75,
                "reason": (
                    "Shared interpreter running AMOSKYS code. Confidence is "
                    "lower than a cdhash match on purpose: argv is "
                    "attacker-controllable, while a code signature is not."
                ),
                "evidence": {"interpreter": rp, "argv": argv[:6]},
                "suppress": True,
            }
        self.attributions[FOREIGN] += 1
        return {
            "attribution": FOREIGN,
            "confidence": 0.85,
            "reason": (
                "Shared interpreter NOT running AMOSKYS code. The binary is "
                "one AMOSKYS also uses — which is exactly why the interpreter "
                "itself is never registered as identity."
            ),
            "evidence": {"interpreter": rp, "argv": argv[:6]},
            "suppress": False,
        }

    def classify_group(self, *, exe: str, cdhash: Optional[str],
                       executions: list) -> Dict[str, Any]:
        """Classify a deduped alert across ALL of its executions.

        Judging one representative row misreads the group. On live data the
        dedup's representative argv was `['Python', '-']` while its siblings
        were `-m pytest` and `-m black` — the same binary doing several
        different things, only some of them ours.

        Suppression requires EVERY execution to be self. One foreign use is
        enough to keep the finding, because the conservative direction for a
        blindness-adjacent decision is to show the operator too much rather
        than to hide something on the strength of a sibling.
        """
        if not executions:
            return self.classify(exe=exe, cdhash=cdhash, argv=[])
        verdicts = [
            self.classify(exe=e.get("exe") or exe, cdhash=cdhash,
                          argv=e.get("argv") or [])
            for e in executions
        ]
        all_self = all(v["attribution"] == SELF for v in verdicts)
        impostor = next((v for v in verdicts if v["attribution"] == IMPOSTOR), None)
        if impostor:
            return impostor
        base = verdicts[0]
        n_self = sum(1 for v in verdicts if v["attribution"] == SELF)
        return {
            "attribution": SELF if all_self else base["attribution"],
            "confidence": min(v["confidence"] for v in verdicts),
            "reason": (
                base["reason"] if all_self else
                f"{n_self}/{len(verdicts)} executions are AMOSKYS; the rest are "
                "not, so the finding is kept. One foreign use of a shared "
                "binary is not excused by a sibling that happens to be ours."
            ),
            "evidence": {
                "executions": len(verdicts),
                "self_count": n_self,
                "argvs": [e.get("argv") for e in executions[:4]],
            },
            "suppress": all_self,
        }

    def stats(self) -> Dict[str, Any]:
        total = sum(self.attributions.values())
        return {
            **self.attributions,
            "total": total,
            "self_fraction": (self.attributions[SELF] / total) if total else 0.0,
            "registered_hashes": len(self.own_hashes),
        }
