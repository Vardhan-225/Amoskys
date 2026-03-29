"""
Forensic Context Enricher — Cross-Agent Attribution
====================================================

When a probe fires (e.g., "new LaunchAgent detected"), the event carries
what the detecting agent knows — typically just the file path. But an
analyst needs the full story: WHO created it, WHAT process wrote it,
HOW (command line), and WHERE it fits in the kill chain.

This enricher runs post-collection in the analyzer pipeline. It joins
security events with recent process and observation data to fill in
forensic context that no single agent can provide alone.

Context added:
    - WHO: username, file_owner from stat()
    - WHAT: process_name, pid, exe, cmdline of the writer
    - HOW: parent_name, ppid (process ancestry)
    - CHAIN: kill_chain_stage from MITRE tactic mapping
    - HASH: sha256 of file artifacts (persistence binaries, scripts)

Design:
    - Non-destructive: only fills fields that are NULL/empty
    - Fast: uses in-memory process cache, stat() for files
    - Bounded: won't chase beyond 2 levels of process ancestry
"""

from __future__ import annotations

import hashlib
import logging
import os
import stat
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger("amoskys.enrichment.forensic")

# ── MITRE Tactic → Kill Chain Stage mapping ────────────────────────────
# Maps MITRE ATT&CK tactic IDs to Lockheed Martin kill chain stages.
_TACTIC_TO_KILL_CHAIN = {
    "TA0043": "reconnaissance",  # Reconnaissance
    "TA0042": "weaponization",  # Resource Development
    "TA0001": "delivery",  # Initial Access
    "TA0002": "exploitation",  # Execution
    "TA0003": "installation",  # Persistence
    "TA0004": "exploitation",  # Privilege Escalation
    "TA0005": "installation",  # Defense Evasion
    "TA0006": "exploitation",  # Credential Access
    "TA0007": "reconnaissance",  # Discovery
    "TA0008": "c2",  # Lateral Movement
    "TA0009": "actions_on_objectives",  # Collection
    "TA0010": "actions_on_objectives",  # Exfiltration
    "TA0011": "c2",  # Command and Control
    "TA0040": "actions_on_objectives",  # Impact
}

# MITRE Technique → Tactic (common mappings for techniques probes emit)
_TECHNIQUE_TO_TACTIC = {
    # Persistence
    "T1543": "TA0003",
    "T1543.001": "TA0003",
    "T1543.004": "TA0003",
    "T1053": "TA0003",
    "T1053.003": "TA0003",
    "T1546": "TA0003",
    "T1546.004": "TA0003",
    "T1547": "TA0003",
    "T1547.015": "TA0003",
    "T1098": "TA0003",
    "T1098.004": "TA0003",
    # Execution
    "T1059": "TA0002",
    "T1059.004": "TA0002",
    "T1059.006": "TA0002",
    "T1204": "TA0002",
    "T1204.002": "TA0002",
    # Defense Evasion
    "T1218": "TA0005",
    "T1218.011": "TA0005",
    "T1553": "TA0005",
    "T1553.001": "TA0005",
    "T1070": "TA0005",
    "T1070.004": "TA0005",
    "T1036": "TA0005",
    "T1027": "TA0005",
    "T1564": "TA0005",
    "T1564.001": "TA0005",
    # Privilege Escalation
    "T1548": "TA0004",
    "T1548.003": "TA0004",
    "T1548.006": "TA0004",
    # Credential Access
    "T1555": "TA0006",
    "T1555.001": "TA0006",
    "T1555.003": "TA0006",
    "T1552": "TA0006",
    "T1056": "TA0006",
    "T1056.002": "TA0006",
    # Discovery
    "T1082": "TA0007",
    "T1016": "TA0007",
    "T1018": "TA0007",
    "T1046": "TA0007",
    "T1135": "TA0007",
    # Lateral Movement
    "T1021": "TA0008",
    "T1021.004": "TA0008",
    # C2
    "T1071": "TA0011",
    "T1071.001": "TA0011",
    "T1105": "TA0011",
    "T1573": "TA0011",
    # Exfiltration
    "T1567": "TA0010",
    "T1567.002": "TA0010",
    "T1048": "TA0010",
    # Collection
    "T1113": "TA0009",
    "T1115": "TA0009",
    "T1005": "TA0009",
    # Impact
    "T1486": "TA0040",
    "T1485": "TA0040",
    "T1489": "TA0040",
}


def _resolve_kill_chain_stage(mitre_techniques: str) -> Optional[str]:
    """Derive kill chain stage from MITRE technique IDs."""
    if not mitre_techniques:
        return None
    import json

    # Handle multiple serialization formats:
    # - '["T1059"]'                       (normal JSON array)
    # - '"[\\"T1059\\"]"'                 (double-escaped from DB)
    # - 'T1059,T1204'                     (comma-separated)
    raw = str(mitre_techniques)
    techs = []
    try:
        parsed = json.loads(raw)
        # First decode may yield a string that needs second decode
        if isinstance(parsed, str):
            parsed = json.loads(parsed)
        techs = parsed if isinstance(parsed, list) else [parsed]
    except (json.JSONDecodeError, TypeError, ValueError):
        techs = [t.strip().strip('"') for t in raw.split(",") if t.strip()]

    # Find the most advanced kill chain stage
    stage_order = [
        "reconnaissance",
        "weaponization",
        "delivery",
        "exploitation",
        "installation",
        "c2",
        "actions_on_objectives",
    ]
    best_stage = None
    best_idx = -1

    for tech in techs:
        tech = tech.strip().strip('"')
        tactic = _TECHNIQUE_TO_TACTIC.get(tech)
        if tactic:
            stage = _TACTIC_TO_KILL_CHAIN.get(tactic)
            if stage:
                idx = stage_order.index(stage) if stage in stage_order else -1
                if idx > best_idx:
                    best_idx = idx
                    best_stage = stage

    return best_stage


def _resolve_file_owner(path: str) -> Optional[str]:
    """Get the file owner username from stat()."""
    if not path:
        return None
    try:
        import pwd

        st = os.stat(path)
        return pwd.getpwuid(st.st_uid).pw_name
    except (OSError, KeyError):
        return None


def _hash_file(path: str, max_size: int = 10 * 1024 * 1024) -> Optional[str]:
    """SHA-256 hash a file. Skip if > max_size or unreadable."""
    if not path:
        return None
    try:
        p = Path(path)
        if not p.is_file() or p.stat().st_size > max_size:
            return None
        h = hashlib.sha256()
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


def _resolve_writer_process(
    path: str, process_cache: Dict[int, Dict[str, Any]]
) -> Dict[str, Any]:
    """Find which process recently had this file open for writing.

    Uses lsof -t to find PIDs with the file open, then looks them up
    in the process cache built from the process agent's last snapshot.
    """
    result: Dict[str, Any] = {}
    if not path:
        return result

    try:
        import subprocess

        proc = subprocess.run(
            ["lsof", "-t", path],
            capture_output=True,
            text=True,
            timeout=3,
        )
        pids = [int(p) for p in proc.stdout.strip().split("\n") if p.strip().isdigit()]
    except Exception:
        pids = []

    # Look up in process cache
    for pid in pids:
        info = process_cache.get(pid)
        if info:
            result["process_name"] = info.get("name", "")
            result["pid"] = pid
            result["exe"] = info.get("exe", "")
            result["cmdline"] = info.get("cmdline", "")
            result["ppid"] = info.get("ppid")
            result["parent_name"] = info.get("parent_name", "")
            result["username"] = info.get("username", "")
            break

    # Fallback: if no cache hit, try psutil directly
    if not result and pids:
        try:
            import psutil

            p = psutil.Process(pids[0])
            result["process_name"] = p.name()
            result["pid"] = p.pid
            result["exe"] = p.exe()
            try:
                result["cmdline"] = " ".join(p.cmdline())
            except (psutil.AccessDenied, psutil.ZombieProcess):
                pass
            result["ppid"] = p.ppid()
            try:
                parent = p.parent()
                result["parent_name"] = parent.name() if parent else ""
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            result["username"] = p.username()
        except Exception:
            pass

    return result


class ForensicContextEnricher:
    """Enriches security events with cross-agent forensic context.

    Call enrich_event() on each security event after basic enrichment
    (GeoIP/ASN/MITRE) but before storage. Non-destructive — only fills
    fields that are NULL/empty.

    Usage:
        enricher = ForensicContextEnricher()
        enricher.update_process_cache(process_snapshot)  # from process agent
        enricher.enrich_event(event_data)
    """

    def __init__(self) -> None:
        # PID → {name, exe, cmdline, ppid, parent_name, username}
        self._process_cache: Dict[int, Dict[str, Any]] = {}
        self._cache_age: float = 0.0

    def update_process_cache(self, processes: list) -> None:
        """Update from process agent's latest snapshot.

        Args:
            processes: List of dicts with keys: pid, name, exe, cmdline, ppid, username
        """
        import time

        self._process_cache.clear()
        for proc in processes:
            pid = proc.get("pid")
            if pid:
                self._process_cache[int(pid)] = proc
        self._cache_age = time.time()

    def enrich_event(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich a security event with forensic context.

        Fills missing fields non-destructively. Only touches NULL/empty values.

        Args:
            event_data: Mutable event dict (modified in place).

        Returns:
            Same dict with forensic fields populated.
        """
        # ── Kill Chain Stage ──
        if not event_data.get("kill_chain_stage"):
            mitre = event_data.get("mitre_techniques", "")
            stage = _resolve_kill_chain_stage(mitre)
            if stage:
                event_data["kill_chain_stage"] = stage

        # ── File Owner ──
        path = event_data.get("path", "")
        if path and not event_data.get("file_owner"):
            owner = _resolve_file_owner(path)
            if owner:
                event_data["file_owner"] = owner
                # Also set username if missing
                if not event_data.get("username"):
                    event_data["username"] = owner

        # ── SHA256 of artifact ──
        if path and not event_data.get("sha256"):
            sha = _hash_file(path)
            if sha:
                event_data["sha256"] = sha

        # ── Process Attribution (for file/persistence events without process context) ──
        if path and not event_data.get("process_name"):
            writer = _resolve_writer_process(path, self._process_cache)
            for field in ("process_name", "pid", "exe", "cmdline", "ppid", "parent_name", "username"):
                if writer.get(field) and not event_data.get(field):
                    event_data[field] = writer[field]

        return event_data
