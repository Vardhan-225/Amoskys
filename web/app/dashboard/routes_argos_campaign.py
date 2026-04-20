"""Argos Campaign routes — live pentest orchestrator over SocketIO.

Workflow:
    1. User visits /dashboard/argos/campaign (the page)
    2. Submits a bug-bounty domain (POST /api/argos/campaign/submit)
    3. Backend spawns a background thread running Campaign.run()
    4. Campaign events stream to the user's SocketIO room in real time
    5. User watches "exactly what is happening" in the browser
    6. Final CampaignReport is persisted + shown as a report card

Scope gate:
    Mode is capped at "report" by default (OSINT only — safe against
    any domain). For "confirm" or "exploit" modes the user must
    supply a consent token: "bounty:<program>" or
    "sow:<client>" — we record it verbatim in the audit log but
    leave scope-of-engagement legal review to the operator.

Rate limit:
    1 campaign per IP per 5 minutes. The orchestrator is heavy
    enough we don't want to accidentally fingerprint-flood a target
    on refresh.
"""

from __future__ import annotations

import html
import json
import logging
import re
import threading
import time
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, List, Optional

from flask import jsonify, render_template, request

from amoskys.agents.Web.argos.campaign import (
    Campaign, CampaignMode, EventBus,
)

from ..middleware import get_current_user, require_login
from ..websocket import socketio
from . import dashboard_bp

logger = logging.getLogger("web.dashboard.argos_campaign")


# ── Active campaign registry ───────────────────────────────────────

_ACTIVE: Dict[str, Dict[str, Any]] = {}         # campaign_id -> {"thread", "bus", "started", "report"}
_LAST_SUBMIT: Dict[str, float] = {}             # ip -> last_submit_timestamp
_SUBMIT_LOCK = threading.Lock()
_RATE_LIMIT_S = 300                             # 5 minutes per IP
_MAX_CAMPAIGN_AGE_S = 3600                      # clean up after an hour


def _purge_old():
    """Drop finished/aged campaigns from registry."""
    now = time.time()
    stale = [cid for cid, meta in _ACTIVE.items()
             if now - meta.get("started", now) > _MAX_CAMPAIGN_AGE_S]
    for cid in stale:
        _ACTIVE.pop(cid, None)


# ── Host validation ────────────────────────────────────────────────

_HOST_RE = re.compile(r"^[a-zA-Z0-9]([-a-zA-Z0-9.]*[a-zA-Z0-9])?$")


def _validate_target(raw: str) -> tuple[Optional[str], Optional[str]]:
    """Accept either 'example.com' or 'https://example.com/'; reject garbage.

    Returns (url, host) or (None, error_message).
    """
    raw = (raw or "").strip()
    if not raw:
        return None, "target is required"
    if "://" not in raw:
        raw = "https://" + raw
    try:
        parsed = urllib.parse.urlparse(raw)
    except Exception as exc:  # noqa: BLE001
        return None, f"invalid URL: {exc}"
    if parsed.scheme not in ("http", "https"):
        return None, f"scheme must be http(s), got '{parsed.scheme}'"
    host = (parsed.hostname or "").lower()
    if not host:
        return None, "no hostname in URL"
    if not _HOST_RE.match(host):
        return None, f"hostname '{host}' has illegal characters"
    # Block IP literals for remote modes (report mode still allows them via localhost)
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", host) and not host.startswith(("127.", "10.", "192.168.", "172.")):
        return None, f"IP literal {host} — only private ranges allowed"
    # Block obvious misuse
    for blocked in ("anthropic.com", "claude.ai", "openai.com", "google.com",
                    "apple.com", "microsoft.com", "amazon.com"):
        if host == blocked or host.endswith("." + blocked):
            return None, f"blocked target: {host} is not in bounty scope"
    return f"{parsed.scheme}://{host}{(':' + str(parsed.port)) if parsed.port else ''}", host


# ── HTTP fetcher used by Campaign when running server-side ─────────


def _default_http_get(url: str, timeout: float = 8.0,
                       headers: Optional[Dict[str, str]] = None):
    """Lightweight GET backed by urllib. Returns (status, headers, body)."""
    try:
        req = urllib.request.Request(url, headers=headers or {
            "User-Agent": "Mozilla/5.0 (compatible; Argos-Campaign/2.3; +https://amoskys.com/argos)",
        })
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(200_000).decode("utf-8", errors="replace")
            return r.status, dict(r.headers.items()), body
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return exc.code, dict(exc.headers.items()) if exc.headers else {}, body
    except Exception as exc:  # noqa: BLE001
        return 0, {}, f"__error__:{exc.__class__.__name__}:{exc}"


# ── Page ────────────────────────────────────────────────────────────

@dashboard_bp.route("/argos/campaign")
@require_login
def argos_campaign_page():
    user = get_current_user()
    return render_template("dashboard/argos-campaign.html", user=user)


# ── API: submit campaign ───────────────────────────────────────────

@dashboard_bp.route("/api/argos/campaign/submit", methods=["POST"])
@require_login
def argos_campaign_submit():
    _purge_old()
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()

    # Rate limit
    with _SUBMIT_LOCK:
        last = _LAST_SUBMIT.get(client_ip, 0)
        if time.time() - last < _RATE_LIMIT_S:
            wait = int(_RATE_LIMIT_S - (time.time() - last))
            return jsonify({
                "ok": False,
                "error": f"rate limit: wait {wait}s before another campaign",
            }), 429
        _LAST_SUBMIT[client_ip] = time.time()

    data = request.get_json(silent=True) or {}
    target_raw = data.get("target", "")
    mode = data.get("mode", CampaignMode.REPORT)
    consent_token = data.get("consent_token", "")

    if mode not in (CampaignMode.REPORT, CampaignMode.CONFIRM, CampaignMode.EXPLOIT):
        return jsonify({"ok": False, "error": f"unknown mode '{mode}'"}), 400

    url, host_or_err = _validate_target(target_raw)
    if url is None:
        return jsonify({"ok": False, "error": host_or_err}), 400
    host = host_or_err

    # For non-REPORT modes, require a consent token
    if mode != CampaignMode.REPORT:
        if not consent_token or not (
            consent_token.startswith("bounty:") or consent_token.startswith("sow:")
        ):
            return jsonify({
                "ok": False,
                "error": ("mode '%s' requires consent_token starting with "
                          "'bounty:<program>' or 'sow:<client>'" % mode),
            }), 400

    campaign_id = f"cmp-{int(time.time() * 1000)}-{hash(host) & 0xFFFF:04x}"
    room = f"argos-campaign-{campaign_id}"

    logger.info("argos campaign submitted: id=%s target=%s mode=%s ip=%s",
                 campaign_id, url, mode, client_ip)

    # Start background campaign
    thread = threading.Thread(
        target=_run_campaign_background,
        args=(campaign_id, url, mode, consent_token, room),
        daemon=True,
        name=f"argos-{campaign_id}",
    )
    _ACTIVE[campaign_id] = {
        "thread":        thread,
        "target":        url,
        "host":          host,
        "mode":          mode,
        "started":       time.time(),
        "room":          room,
        "report":        None,   # filled when done
        "submitted_by":  client_ip,
    }
    thread.start()

    return jsonify({
        "ok":           True,
        "campaign_id":  campaign_id,
        "room":         room,
        "target":       url,
        "mode":         mode,
    })


# ── Background runner ──────────────────────────────────────────────


def _run_campaign_background(campaign_id: str, target_url: str,
                              mode: str, consent_token: str, room: str):
    """Execute Campaign.run() in a background thread, streaming events
    to the room via socketio.emit on the /dashboard namespace."""
    def _emit(evt):
        try:
            socketio.emit("argos_campaign_event", {
                "campaign_id": campaign_id,
                "event":       evt.to_dict(),
            }, to=room, namespace="/dashboard")
        except Exception as exc:  # noqa: BLE001
            logger.warning("socketio emit failed: %s", exc)

    bus = EventBus()
    bus.subscribe(_emit)

    # Kick-off notification so UI can lock the form
    socketio.emit("argos_campaign_started", {
        "campaign_id": campaign_id,
        "target":      target_url,
        "mode":        mode,
    }, to=room, namespace="/dashboard")

    try:
        report = Campaign(
            target_url=target_url,
            mode=mode,
            consent_token=consent_token or None,
            bus=bus,
            http_get=_default_http_get,
        ).run()
        _ACTIVE.setdefault(campaign_id, {})["report"] = report.to_dict()
        socketio.emit("argos_campaign_complete", {
            "campaign_id": campaign_id,
            "report":      report.to_dict(),
        }, to=room, namespace="/dashboard")
    except Exception as exc:  # noqa: BLE001
        logger.exception("campaign %s crashed", campaign_id)
        socketio.emit("argos_campaign_complete", {
            "campaign_id": campaign_id,
            "error":       f"{exc.__class__.__name__}: {exc}",
        }, to=room, namespace="/dashboard")


# ── API: fetch report (for page refresh after completion) ──────────

@dashboard_bp.route("/api/argos/campaign/<campaign_id>")
@require_login
def argos_campaign_detail(campaign_id: str):
    _purge_old()
    meta = _ACTIVE.get(campaign_id)
    if meta is None:
        return jsonify({"ok": False, "error": "campaign not found or aged out"}), 404
    return jsonify({
        "ok":           True,
        "campaign_id":  campaign_id,
        "target":       meta.get("target"),
        "host":         meta.get("host"),
        "mode":         meta.get("mode"),
        "started":      meta.get("started"),
        "report":       meta.get("report"),
        "running":      meta.get("report") is None and meta.get("thread") and meta["thread"].is_alive(),
    })


# ── SocketIO: join campaign room ───────────────────────────────────

from flask_socketio import join_room


@socketio.on("argos_campaign_join", namespace="/dashboard")
def argos_campaign_join(msg):
    """Client subscribes to a campaign's event room."""
    campaign_id = (msg or {}).get("campaign_id", "")
    if not campaign_id or campaign_id not in _ACTIVE:
        socketio.emit("argos_campaign_error",
                      {"error": f"unknown campaign_id: {campaign_id}"},
                      namespace="/dashboard")
        return
    room = _ACTIVE[campaign_id]["room"]
    join_room(room)
    logger.info("client joined argos room %s", room)
    # Replay any events already fired (reconnect resilience)
    # We don't have the bus handle here; the client will rely on the stream
    # from this point on. For reconnect, use /api/argos/campaign/<id> to fetch
    # the full report once complete.
    socketio.emit("argos_campaign_joined",
                  {"campaign_id": campaign_id, "room": room},
                  namespace="/dashboard")
