"""Patch to append to blueprint.py for the /web/command route.

Paste the three items below into /opt/amoskys-web/src/app/web_product/blueprint.py:

  1. The import at the top
  2. The humantime + humantime_abs template filters
  3. The /command route itself

The separate patch file exists so we can re-deploy cleanly with rsync
rather than editing the live file in place.
"""

# ============ PASTE THIS AT TOP OF blueprint.py ============
# from app.web_product.aegis_live import AegisTail, AEGIS_SENSOR_FAMILIES
# _tail = AegisTail()


# ============ PASTE THESE NEAR THE TOP (after blueprint creation) ============

def _humantime(ts_ns):
    """'5s ago' / '3m ago' / '—' from a nanosecond timestamp."""
    if not ts_ns:
        return "—"
    import time
    delta = time.time() - (ts_ns / 1e9)
    if delta < 0:
        return "in future"
    if delta < 60:
        return f"{int(delta)}s ago"
    if delta < 3600:
        return f"{int(delta/60)}m ago"
    if delta < 86400:
        return f"{int(delta/3600)}h ago"
    return f"{int(delta/86400)}d ago"


def _humantime_abs(ts_ns):
    """'2026-04-18 23:45:12 UTC' from a nanosecond timestamp."""
    if not ts_ns:
        return "—"
    from datetime import datetime, timezone
    return datetime.fromtimestamp(ts_ns / 1e9, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


# web_bp.add_app_template_filter(_humantime, "humantime")
# web_bp.add_app_template_filter(_humantime_abs, "humantime_abs")


# ============ PASTE THIS AS A NEW ROUTE ============

# @web_bp.route("/command")
# def command():
#     """Operator Command Center — real live Aegis feed.
#
#     Auth: checks AMOSKYS_COMMAND_TOKEN in cookie OR ?token= query arg.
#     The token is set on first admin visit via ?token=...; cookie
#     persists for 30 days.
#     """
#     import os
#     from flask import request, make_response, abort
#
#     expected = os.environ.get("AMOSKYS_COMMAND_TOKEN", "")
#     if not expected:
#         abort(503, "Command Center requires AMOSKYS_COMMAND_TOKEN env var")
#
#     provided = request.args.get("token") or request.cookies.get("amoskys_command_token")
#     if provided != expected:
#         abort(404)
#
#     severity = request.args.get("severity")
#     snap = _tail.snapshot(severity_filter=severity)
#
#     last_event_ago = _humantime(snap.last_event_ns) if snap.last_event_ns else None
#
#     response = make_response(render_template(
#         "web/command.html",
#         snap=snap,
#         sensor_catalog=AEGIS_SENSOR_FAMILIES,
#         last_event_ago=last_event_ago,
#     ))
#     # Persist the token as a cookie (auth is per-browser after first token visit)
#     if request.args.get("token"):
#         response.set_cookie(
#             "amoskys_command_token", expected,
#             max_age=30 * 86400, httponly=True,
#             secure=True, samesite="Strict",
#         )
#     return response
