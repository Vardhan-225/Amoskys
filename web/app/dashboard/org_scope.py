"""Org → device_id scoping for the web-tier data APIs.

The fleet_cache.db has device_id on every row but NO org_id column, so tenant
isolation is enforced the same way routes_overview does it: resolve the user's
org to its device_ids via the ops command-center fleet/status API, then filter
every query to that allowlist.

Contract (see get_allowed_device_ids):
  - Global admin            -> (None, True)   unrestricted
  - Regular user            -> (ids,  False)  only these device_ids
  - Ops unreachable / no org -> ([],  False)  FAIL CLOSED (no data)

Resolutions are cached 60s per org so a dashboard polling every few seconds
does not hammer the command center.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
import urllib.parse
import urllib.request

# Reuse the single source of truth for ops TLS (pinned CA, no hostname check)
# instead of duplicating the context-building logic here.
from .routes_overview import _ops_ssl_context

logger = logging.getLogger("web.dashboard.org_scope")

_CACHE_TTL_SECONDS = 60.0
_cache: dict[str, tuple[float, list[str]]] = {}  # org_id -> (resolved_at, ids)
_cache_lock = threading.Lock()


def _fetch_org_device_ids(org_id: str) -> list[str] | None:
    """Ask the ops command-center which device_ids belong to this org.

    Returns the list (possibly empty) on success, or None if the command
    center is unreachable / returns garbage — callers MUST treat None as
    'could not resolve' and fail closed.
    """
    try:
        ops_host = os.getenv("AMOSKYS_OPS_SERVER", "https://18.223.110.15").rstrip("/")
        url = (
            f"{ops_host}/api/v1/fleet/status"
            f"?org_id={urllib.parse.quote(org_id, safe='')}"
        )
        rq = urllib.request.Request(url, headers={"Accept": "application/json"})
        ctx = _ops_ssl_context()
        with urllib.request.urlopen(rq, timeout=8, context=ctx) as rsp:
            data = json.loads(rsp.read())
        return [d["device_id"] for d in data.get("devices", []) if d.get("device_id")]
    except Exception as e:
        logger.debug("Failed to resolve devices for org %s from command center: %s", org_id, e)
        return None


def get_allowed_device_ids(user) -> tuple[list[str] | None, bool]:
    """Resolve the device_ids the given user is allowed to see.

    Returns (allowed, is_admin):
      (None, True)  — global admin (role.value == 'admin'): unrestricted.
      (ids,  False) — regular user: only devices in their org.
      ([],   False) — FAIL CLOSED: no org on the user, or ops unreachable.
    """
    role = getattr(user, "role", None) if user else None
    if role is not None and getattr(role, "value", None) == "admin":
        return None, True

    org_id = getattr(user, "org_id", None) if user else None
    if not org_id:
        return [], False  # no org to scope by → no data

    now = time.time()
    with _cache_lock:
        hit = _cache.get(org_id)
        if hit and (now - hit[0]) < _CACHE_TTL_SECONDS:
            return list(hit[1]), False

    ids = _fetch_org_device_ids(org_id)
    if ids is None:
        return [], False  # ops unreachable → fail closed, retry next request

    with _cache_lock:
        _cache[org_id] = (now, ids)
    return list(ids), False
