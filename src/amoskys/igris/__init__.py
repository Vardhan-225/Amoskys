"""
IGRIS — Autonomous Supervisory Intelligence Layer

The layer that watches the watchers.
Calm. Vigilant. Stable. Correct.

Usage:
    from amoskys.igris import start_igris, get_igris

    igris = start_igris()           # Start daemon (singleton)
    status = get_igris().get_status()  # Query status
"""

import threading

from .auditor import Auditor
from .dispatcher import Dispatcher
from .explainer import Explainer
from .supervisor import Igris

__all__ = ["Igris", "Auditor", "Dispatcher", "Explainer", "get_igris", "start_igris"]

_igris_instance = None
_igris_lock = threading.Lock()


def get_igris(**kwargs) -> Igris:
    """Get or create the IGRIS singleton."""
    global _igris_instance
    with _igris_lock:
        if _igris_instance is None:
            _igris_instance = Igris(**kwargs)
        return _igris_instance


def start_igris(**kwargs) -> Igris:
    """Start the IGRIS daemon. Returns the singleton instance."""
    igris = get_igris(**kwargs)
    if not igris.is_running:
        igris.start()
    return igris
