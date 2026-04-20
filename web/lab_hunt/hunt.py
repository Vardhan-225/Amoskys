"""AMOSKYS Web — WordPress Hunt (lab-side).

A WordPress-explicit pentest flow for lab.amoskys.com. Thin wrapper
around argos.campaign that uses Server-Sent Events (SSE) instead of
SocketIO — keeps the runtime dependency-free since the existing
lab Flask app has no websocket stack.

Deployment target: /opt/amoskys-web/src/app/web_product/hunt.py on
the lab EC2, registered inside the existing web_bp blueprint.

Endpoints (all under /web):
    GET  /web/hunt                         → landing page
    POST /web/hunt/submit                  → start a campaign
    GET  /web/hunt/<id>/stream             → SSE event stream
    GET  /web/hunt/<id>                    → campaign status / report JSON
    GET  /web/hunt/<id>/report.html        → download HTML report
    GET  /web/hunt/<id>/report.json        → download JSON report

SSE vs SocketIO
---------------
Browsers speak EventSource natively. Server writes
    event: argos_event\n
    data: {"kind":...}\n\n
and the client's EventSource.onmessage fires. No external dep, no
websocket handshake. The lab Flask app runs 1 gunicorn worker with
gevent so SSE streams won't block other requests.
"""

from __future__ import annotations

import json
import logging
import queue
import re
import threading
import time
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

from flask import Blueprint, Response, jsonify, render_template, request

from amoskys.agents.Web.argos.campaign import (
    Campaign, CampaignMode, EventBus, render_campaign_html,
)

logger = logging.getLogger("amoskys.lab.hunt")


hunt_bp = Blueprint(
    "hunt",
    __name__,
    url_prefix="/web/hunt",
    template_folder="../templates/web",
)


# ── Campaign registry + rate limit ─────────────────────────────────

_ACTIVE: Dict[str, Dict[str, Any]] = {}
_LAST_SUBMIT: Dict[str, float] = {}
_SUBMIT_LOCK = threading.Lock()
_RATE_LIMIT_S = 180           # 3 minutes per IP
_CAMPAIGN_TTL_S = 3600        # 1 hour


def _purge_old():
    now = time.time()
    stale = [cid for cid, meta in _ACTIVE.items()
             if now - meta.get("started", now) > _CAMPAIGN_TTL_S]
    for cid in stale:
        _ACTIVE.pop(cid, None)


# ── Target validation ─────────────────────────────────────────────

_HOST_RE = re.compile(r"^[a-zA-Z0-9]([-a-zA-Z0-9.]*[a-zA-Z0-9])?$")
_BLOCKED_HOSTS = {
    "anthropic.com", "claude.ai", "openai.com",
    "google.com", "apple.com", "microsoft.com", "amazon.com",
    "github.com", "gitlab.com", "cloudflare.com",
}


def _validate_target(raw: str):
    raw = (raw or "").strip()
    if not raw:
        return None, None, "target is required"
    if "://" not in raw:
        raw = "https://" + raw
    try:
        parsed = urllib.parse.urlparse(raw)
    except Exception as exc:  # noqa: BLE001
        return None, None, f"invalid URL: {exc}"
    if parsed.scheme not in ("http", "https"):
        return None, None, f"scheme must be http(s)"
    host = (parsed.hostname or "").lower()
    if not host or not _HOST_RE.match(host):
        return None, None, "invalid hostname"
    # Block obvious out-of-scope megacorps
    for blocked in _BLOCKED_HOSTS:
        if host == blocked or host.endswith("." + blocked):
            return None, None, f"blocked target: {host} is not in bounty scope"
    port = f":{parsed.port}" if parsed.port else ""
    return f"{parsed.scheme}://{host}{port}", host, None


# ── HTTP getter used by Campaign (urllib) ──────────────────────────

def _http_get(url: str, timeout: float = 8.0,
              headers: Optional[Dict[str, str]] = None):
    try:
        req = urllib.request.Request(url, headers=headers or {
            "User-Agent": "Mozilla/5.0 (compatible; Argos-Hunt/2.4; +https://amoskys.com)",
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


# ── Landing page ──────────────────────────────────────────────────

@hunt_bp.route("/")
def hunt_page():
    return render_template("hunt.html")


# ── Submit campaign ───────────────────────────────────────────────

@hunt_bp.route("/submit", methods=["POST"])
def hunt_submit():
    _purge_old()
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "?").split(",")[0].strip()

    with _SUBMIT_LOCK:
        last = _LAST_SUBMIT.get(ip, 0)
        if time.time() - last < _RATE_LIMIT_S:
            wait = int(_RATE_LIMIT_S - (time.time() - last))
            return jsonify({"ok": False,
                            "error": f"rate limit: wait {wait}s before another hunt"}), 429
        _LAST_SUBMIT[ip] = time.time()

    data = request.get_json(silent=True) or {}
    raw = data.get("target", "")
    mode = data.get("mode", CampaignMode.REPORT)
    consent_token = data.get("consent_token", "")

    if mode not in (CampaignMode.REPORT, CampaignMode.CONFIRM, CampaignMode.EXPLOIT):
        return jsonify({"ok": False, "error": f"unknown mode '{mode}'"}), 400

    url, host, err = _validate_target(raw)
    if err:
        return jsonify({"ok": False, "error": err}), 400

    if mode != CampaignMode.REPORT:
        if not (consent_token.startswith("bounty:") or consent_token.startswith("sow:")):
            return jsonify({
                "ok": False,
                "error": f"mode '{mode}' requires consent_token starting with "
                          f"'bounty:<program>' or 'sow:<client>'",
            }), 400

    campaign_id = f"wp-{int(time.time() * 1000)}-{abs(hash(host)) & 0xFFFF:04x}"

    # Per-campaign event queue for SSE
    q: "queue.Queue" = queue.Queue()
    bus = EventBus()

    def _forward(evt):
        try:
            q.put(evt.to_dict(), block=False)
        except queue.Full:
            pass
    bus.subscribe(_forward)

    meta = {
        "target": url, "host": host, "mode": mode,
        "started": time.time(), "ip": ip,
        "queue": q, "bus": bus,
        "report": None, "thread": None,
    }

    def _runner():
        try:
            rep = Campaign(
                target_url=url, mode=mode,
                consent_token=consent_token or None,
                bus=bus, http_get=_http_get,
            ).run()
            meta["report"] = rep.to_dict()
        except Exception as exc:  # noqa: BLE001
            logger.exception("campaign crashed")
            meta["error"] = f"{exc.__class__.__name__}: {exc}"
        finally:
            # Sentinel for SSE to close the stream cleanly
            q.put({"kind": "__stream_end__"})

    t = threading.Thread(target=_runner, daemon=True, name=f"hunt-{campaign_id}")
    meta["thread"] = t
    _ACTIVE[campaign_id] = meta
    t.start()

    return jsonify({
        "ok": True, "campaign_id": campaign_id,
        "target": url, "mode": mode,
        "stream_url": f"/web/hunt/{campaign_id}/stream",
    })


# ── SSE event stream ──────────────────────────────────────────────

@hunt_bp.route("/<campaign_id>/stream")
def hunt_stream(campaign_id: str):
    meta = _ACTIVE.get(campaign_id)
    if meta is None:
        return jsonify({"ok": False, "error": "unknown campaign"}), 404
    q: queue.Queue = meta["queue"]

    def _gen():
        # Initial hello so the client knows the stream is open
        yield f"event: hello\ndata: {json.dumps({'campaign_id': campaign_id})}\n\n"
        # Pump events until sentinel
        t_start = time.time()
        idle_timeout = 120           # seconds with no events → close stream
        last_evt = time.time()
        while True:
            try:
                evt = q.get(timeout=2.0)
            except queue.Empty:
                # Keepalive comment
                yield ": keepalive\n\n"
                if time.time() - last_evt > idle_timeout:
                    yield f"event: timeout\ndata: {{\"idle\": {idle_timeout}}}\n\n"
                    break
                continue
            last_evt = time.time()
            if isinstance(evt, dict) and evt.get("kind") == "__stream_end__":
                # Send final report marker + done
                rep = meta.get("report")
                if rep is not None:
                    yield f"event: report\ndata: {json.dumps(rep, default=str)}\n\n"
                if meta.get("error"):
                    yield f"event: error\ndata: {json.dumps({'error': meta['error']})}\n\n"
                yield "event: close\ndata: {}\n\n"
                break
            yield f"event: argos_event\ndata: {json.dumps(evt, default=str)}\n\n"
            # Safety ceiling
            if time.time() - t_start > 1200:   # 20 min hard cap
                yield "event: timeout\ndata: {}\n\n"
                break

    return Response(
        _gen(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


# ── Status / report endpoints ──────────────────────────────────────

@hunt_bp.route("/<campaign_id>")
def hunt_status(campaign_id: str):
    _purge_old()
    meta = _ACTIVE.get(campaign_id)
    if meta is None:
        return jsonify({"ok": False, "error": "unknown campaign"}), 404
    running = meta.get("thread") and meta["thread"].is_alive()
    return jsonify({
        "ok": True,
        "campaign_id": campaign_id,
        "target": meta["target"],
        "host":   meta["host"],
        "mode":   meta["mode"],
        "started": meta["started"],
        "running": running,
        "report":  meta.get("report"),
        "error":   meta.get("error"),
    })


@hunt_bp.route("/<campaign_id>/report.html")
def hunt_report_html(campaign_id: str):
    _purge_old()
    meta = _ACTIVE.get(campaign_id)
    if meta is None or meta.get("report") is None:
        return jsonify({"ok": False, "error": "campaign not found or still running"}), 404
    body = render_campaign_html(meta["report"])
    fname = f"argos-hunt-{meta['host']}-{campaign_id}.html"
    return Response(body, mimetype="text/html; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{fname}"'})


@hunt_bp.route("/<campaign_id>/report.json")
def hunt_report_json(campaign_id: str):
    _purge_old()
    meta = _ACTIVE.get(campaign_id)
    if meta is None or meta.get("report") is None:
        return jsonify({"ok": False, "error": "campaign not found or still running"}), 404
    fname = f"argos-hunt-{meta['host']}-{campaign_id}.json"
    return Response(
        json.dumps(meta["report"], indent=2, default=str),
        mimetype="application/json",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )
