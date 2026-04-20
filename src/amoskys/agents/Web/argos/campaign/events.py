"""Event bus for live campaign progress streaming.

An EventBus is a thin callable that accepts CampaignEvent and fans
it to subscribers (web UI SocketIO, CLI tail, operator log, etc.).

Events
------
Every stage emits at least:
    STAGE_START  — entering a stage
    STAGE_END    — finishing a stage (success or failure)
And frequently:
    PROGRESS     — "14 of 53 checks done"
    FINDING      — a concrete vulnerability or signal detected
    EVIDENCE     — intermediate evidence (banner, cookie, header)
    DECISION     — adaptive choice (e.g. "WAF=Wordfence → use
                    comment_pad encoder")
    CHAIN        — chain-reasoner composed an exploit path
    LOG          — verbose debug line
    ERROR        — recoverable error in a stage
    FATAL        — unrecoverable; campaign halted
    REPORT       — final JSON/HTML/PDF artifact ready
    DONE         — campaign end-of-life (always last)
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("amoskys.argos.campaign.events")


class EventKind:
    STAGE_START = "stage_start"
    STAGE_END   = "stage_end"
    PROGRESS    = "progress"
    FINDING     = "finding"
    EVIDENCE    = "evidence"
    DECISION    = "decision"
    CHAIN       = "chain"
    LOG         = "log"
    ERROR       = "error"
    FATAL       = "fatal"
    REPORT      = "report"
    DONE        = "done"


@dataclass
class CampaignEvent:
    kind: str                       # EventKind.*
    stage: str                      # "recon", "fingerprint", "chain", ...
    message: str = ""
    data: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    sequence: int = 0

    def to_dict(self):
        return {
            "kind":      self.kind,
            "stage":     self.stage,
            "message":   self.message,
            "data":      dict(self.data),
            "timestamp": self.timestamp,
            "sequence":  self.sequence,
        }


class EventBus:
    """Broadcast events to 0..N subscribers. Thread-safe.

    A subscriber is any callable accepting CampaignEvent. Exceptions
    in a subscriber are caught so one bad subscriber cannot stop
    campaign progress.
    """

    def __init__(self):
        self._subs: List[Callable[[CampaignEvent], None]] = []
        self._seq = 0
        self._lock = threading.Lock()
        self._history: List[CampaignEvent] = []

    def subscribe(self, fn: Callable[[CampaignEvent], None]) -> Callable[[], None]:
        """Register a subscriber. Returns an unsubscribe callable."""
        with self._lock:
            self._subs.append(fn)

        def _unsub():
            with self._lock:
                try:
                    self._subs.remove(fn)
                except ValueError:
                    pass
        return _unsub

    def emit(self, kind: str, stage: str, message: str = "",
             **data: Any) -> CampaignEvent:
        with self._lock:
            self._seq += 1
            evt = CampaignEvent(
                kind=kind, stage=stage, message=message,
                data=dict(data), sequence=self._seq,
            )
            self._history.append(evt)
            subs = list(self._subs)
        for fn in subs:
            try:
                fn(evt)
            except Exception as exc:  # noqa: BLE001
                logger.warning("event subscriber raised: %s", exc)
        return evt

    # Convenience wrappers
    def stage_start(self, stage: str, message: str = "", **data):
        return self.emit(EventKind.STAGE_START, stage, message, **data)

    def stage_end(self, stage: str, message: str = "", **data):
        return self.emit(EventKind.STAGE_END, stage, message, **data)

    def progress(self, stage: str, done: int, total: int, message: str = "", **data):
        return self.emit(EventKind.PROGRESS, stage, message,
                         done=done, total=total, **data)

    def finding(self, stage: str, kind: str, location: str, severity: str,
                evidence: str, **data):
        return self.emit(EventKind.FINDING, stage,
                         f"[{severity.upper()}] {kind} @ {location}",
                         finding_kind=kind, location=location,
                         severity=severity, evidence=evidence, **data)

    def evidence(self, stage: str, message: str, **data):
        return self.emit(EventKind.EVIDENCE, stage, message, **data)

    def decision(self, stage: str, message: str, **data):
        return self.emit(EventKind.DECISION, stage, message, **data)

    def chain(self, name: str, severity: str, cvss: float, narrative: str, **data):
        return self.emit(EventKind.CHAIN, "chain",
                         f"[{severity.upper()} / {cvss:.1f}] {name}",
                         name=name, severity=severity, cvss=cvss,
                         narrative=narrative, **data)

    def log(self, stage: str, message: str, **data):
        return self.emit(EventKind.LOG, stage, message, **data)

    def error(self, stage: str, message: str, **data):
        return self.emit(EventKind.ERROR, stage, message, **data)

    def fatal(self, stage: str, message: str, **data):
        return self.emit(EventKind.FATAL, stage, message, **data)

    def report(self, message: str, **data):
        return self.emit(EventKind.REPORT, "report", message, **data)

    def done(self, message: str = "campaign complete", **data):
        return self.emit(EventKind.DONE, "campaign", message, **data)

    @property
    def history(self) -> List[CampaignEvent]:
        with self._lock:
            return list(self._history)


def null_bus() -> EventBus:
    """Shortcut for callers that don't need streaming."""
    return EventBus()


__all__ = ["EventKind", "CampaignEvent", "EventBus", "null_bus"]
