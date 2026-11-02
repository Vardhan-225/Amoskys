"""One answer to "which machine is this".

THE PROBLEM THIS ENDS
---------------------
Device identity was derived independently in at least four places, and they did
not agree. On 2026-09-13 this single Mac was carrying four names at once:

    Akashs-MacBook-Air.local   socket.gethostname(), most local writers
    Mac                        an older hostname
    Mac.attlocal.net           the same Mac on the home network
    b45045f5e1a0c15e           the ops server's registered, AUTHENTICATED id

The last one is authoritative: the fleet ingest overwrites whatever a client
claims with `device_id = g.authenticated_device`, so every row the server holds
is stamped with it. Everything local used a hostname instead, which meant no
local observation could be correlated with anything fleet-wide — the same
machine appeared as several, and "fleet view" was incoherent by construction.

A hostname is not an identity. It changes with the network (`.attlocal.net`),
with macOS sharing settings, and with a DHCP lease. An identity has to survive
all three.

8,642,985 local rows were renamed to the canonical id to make the history
continuous. This module exists so the divergence cannot reopen: every writer
resolves identity HERE, and adding a new writer that calls gethostname()
directly is the mistake this file is meant to make obvious.
"""
from __future__ import annotations

import logging
import os
import socket

logger = logging.getLogger(__name__)

_ENV_VAR = "AMOSKYS_DEVICE_ID"
_warned = False


def resolve_device_id() -> str:
    """The canonical device id: the registered one, else the hostname.

    Falls back rather than failing, because a sensor that refuses to start
    without a registration is worse than one that records under a local name —
    but it says so ONCE, because silently recording under the wrong identity is
    exactly how eight million rows ended up needing a rename.
    """
    global _warned
    configured = os.getenv(_ENV_VAR, "").strip()
    if configured:
        return configured

    host = socket.gethostname()
    if not _warned:
        _warned = True
        logger.warning(
            "%s is not set — recording under the hostname %r. This will NOT "
            "match the id the fleet server assigned to this device, so nothing "
            "written here can be correlated with fleet-wide data. Set %s to the "
            "registered device id.",
            _ENV_VAR, host, _ENV_VAR,
        )
    return host
