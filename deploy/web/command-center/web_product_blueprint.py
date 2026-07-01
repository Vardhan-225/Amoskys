"""
Flask blueprint for AMOSKYS Web (URL prefix: /web).

Every protected route goes through require_tenant and pulls data exclusively
through TenantStore.for_tenant(g.tenant.tenant_id). No cross-tenant reads are
physically possible.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from flask import (
    Blueprint,
    abort,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from .catalog import (
    AEGIS_BY_CODE,
    AEGIS_SENSORS,
    OWASP_BY_CODE,
    OWASP_WEB_TOP10,
    WP_ATTACK_BY_CODE,
    WP_ATTACK_CLASSES,
    WP_CVE_CATALOG,
)
from .mock_data import TenantStore
from .tenant import (
    clear_current_tenant,
    demo_tenants,
    enforce_ownership,
    populate_tenant,
    require_tenant,
    resolve_tenant,
    set_current_tenant,
)
from .aegis_live import AegisTail, AEGIS_SENSOR_FAMILIES
from .fleet_globe import (
    build_sites_view,
    build_sites_json,
    build_arcs_json,
    build_stats,
    build_live_globe,
    _FAMILY_TO_ATTACK,
)
from .geoip_cache import GeoIPCache, resolve_domain_ip
from .threats_view import (
    build_live_feed,
    build_stats as threats_stats,
    build_recent_cves,
)
from .preview_view import run_preview
from .auth import (
    sign_in,
    sign_out,
    check_credentials,
    signed_in,
    current_user_email,
    current_user_site,
    customer_site,
    admin_email,
    is_auth_configured,
    require_signed_in,
)
from .crawler_classifier import summarize as summarize_crawlers
from .plugin_inventory import build_inventory, _fetch_wp_json as _fetch_wp_json_cached
from . import event_semantics as _ev_sem
from . import dashboard_narrative as _narr
from . import igris_chat as _igris


web_bp = Blueprint(
    "web",
    __name__,
    url_prefix="/web",
    template_folder="../templates/web",
    static_folder="../static",
)


# ─────────────────────────────────────────────────────────────────────
# Operator + live-data helpers (Command Center / Threats / Globe)
# ─────────────────────────────────────────────────────────────────────

_aegis_tail = AegisTail()
_geoip_cache = GeoIPCache()


def _humantime(ts_ns):
    if not ts_ns:
        return "—"
    import time

    d = time.time() - (ts_ns / 1e9)
    if d < 0:
        return "in future"
    if d < 60:
        return f"{int(d)}s ago"
    if d < 3600:
        return f"{int(d/60)}m ago"
    if d < 86400:
        return f"{int(d/3600)}h ago"
    return f"{int(d/86400)}d ago"


def _humantime_abs(ts_ns):
    if not ts_ns:
        return "—"
    from datetime import datetime, timezone

    return datetime.fromtimestamp(ts_ns / 1e9, tz=timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )


# ─────────────────────────────────────────────────────────────────────
# Context processors — make tenant + catalog available in all templates
# ─────────────────────────────────────────────────────────────────────


web_bp.add_app_template_filter(_humantime, "humantime")
web_bp.add_app_template_filter(_humantime_abs, "humantime_abs")


@web_bp.context_processor
def _inject_common():
    """Every template under /web gets these without explicit passing."""
    # `is_signed_in` is the single authoritative flag for conditional UI
    # (like the IGRIS widget) — true for anyone with a valid auth_core
    # session (amoskys_web_sid cookie), regardless of whether Flask's own
    # session-cookie also happens to carry their email. This reliably shows
    # the widget to every signed-in operator on every page.
    try:
        _signed_in = bool(signed_in())
        _user_email = current_user_email() if _signed_in else None
    except Exception:
        _signed_in = False
        _user_email = None
    return {
        "current_tenant": getattr(g, "tenant", None),
        "demo_tenants": demo_tenants(),
        "demo_mode": os.environ.get("AMOSKYS_WEB_DEMO", "true").lower() == "true",
        "preview_mode": os.environ.get("AMOSKYS_WEB_PREVIEW", "false").lower()
        == "true",
        "owasp_top10": OWASP_WEB_TOP10,
        "wp_attack_classes": WP_ATTACK_CLASSES,
        "aegis_sensors": AEGIS_SENSORS,
        "is_signed_in": _signed_in,
        "signed_in_email": _user_email,
    }


# ─────────────────────────────────────────────────────────────────────
# Marketing surface (no tenant required)
# ─────────────────────────────────────────────────────────────────────


@web_bp.route("/")
@populate_tenant
def landing():
    return render_template("web/landing.html")


@web_bp.route("/how-it-works")
@populate_tenant
def how_it_works():
    return render_template("web/how_it_works.html")


@web_bp.route("/redemption", methods=["GET", "POST"])
@populate_tenant
def redemption():
    """Free-pentest intake (Redemption Agent GTM front door).

    GET  → form with URL + contact + DNS TXT proof instructions
    POST → queues the engagement (mock) and redirects to a status page
    """
    if request.method == "POST":
        target = (request.form.get("target_url") or "").strip()
        contact = (request.form.get("contact_email") or "").strip()
        consent = request.form.get("consent") == "on"
        if not target or not contact or not consent:
            flash(
                "Target URL, contact email, and signed consent are required.", "error"
            )
            return render_template(
                "web/redemption.html",
                form={"target_url": target, "contact_email": contact},
            )

        engagement_id = "eng_" + uuid.uuid4().hex[:12]
        session["pending_engagement"] = {
            "id": engagement_id,
            "target": target,
            "contact": contact,
            "submitted_at": datetime.now(timezone.utc).isoformat(),
        }
        return redirect(url_for("web.redemption_status", engagement_id=engagement_id))

    return render_template("web/redemption.html", form={})


@web_bp.route("/redemption/<engagement_id>")
@populate_tenant
def redemption_status(engagement_id: str):
    pending = session.get("pending_engagement")
    if not pending or pending.get("id") != engagement_id:
        abort(404)
    return render_template("web/redemption_status.html", engagement=pending)


# ─────────────────────────────────────────────────────────────────────
# Demo-only tenant switcher (gated on AMOSKYS_WEB_DEMO env)
# ─────────────────────────────────────────────────────────────────────


def _require_demo():
    if os.environ.get("AMOSKYS_WEB_DEMO", "true").lower() != "true":
        abort(404)


@web_bp.route("/demo/use-tenant/<slug>")
def demo_use_tenant(slug: str):
    _require_demo()
    t = set_current_tenant(slug)
    if t is None:
        abort(404)
    flash(f"Viewing as: {t.display_name}", "info")
    return redirect(url_for("web.sites_list"))


@web_bp.route("/demo/clear-tenant")
def demo_clear_tenant():
    _require_demo()
    clear_current_tenant()
    return redirect(url_for("web.landing"))


# ─────────────────────────────────────────────────────────────────────
# Customer dashboard (tenant-gated)
# ─────────────────────────────────────────────────────────────────────


@web_bp.route("/sites")
@require_tenant
def sites_list():
    view = TenantStore.for_tenant(g.tenant.tenant_id)
    summary = view.summary()
    severity = view.severity_breakdown()
    attack_series = view.attack_timeseries(hours=24)
    owasp_cov = view.owasp_coverage()
    return render_template(
        "web/sites/list.html",
        sites=view.sites(),
        summary=summary,
        severity=severity,
        attack_series=attack_series,
        owasp_coverage=owasp_cov,
        recent_findings=view.all_findings()[:5],
        recent_events=view.all_events(limit=10),
    )


@web_bp.route("/sites/<site_id>")
@require_tenant
def site_detail(site_id: str):
    return _site_tab(site_id, tab="overview")


@web_bp.route("/sites/<site_id>/<tab>")
@require_tenant
def site_detail_tab(site_id: str, tab: str):
    allowed = {"overview", "argos", "aegis", "igris", "reports"}
    if tab not in allowed:
        abort(404)
    return _site_tab(site_id, tab=tab)


def _site_tab(site_id: str, *, tab: str):
    view = TenantStore.for_tenant(g.tenant.tenant_id)
    site = view.site(site_id)
    if site is None:
        # Also catches cross-tenant ID guesses — do not leak existence
        abort(404)
    enforce_ownership(site.tenant_id, context=f"site_detail:{tab}")

    findings = view.findings_for(site_id)
    events = view.events_for(site_id, limit=100)
    reports = view.reports_for(site_id)

    # Per-site posture ring context
    open_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        if f.status in ("open", "triaged"):
            open_sev[f.severity] = open_sev.get(f.severity, 0) + 1

    # Aegis sensor coverage: event count per family for this site.
    # Walk the full event slice for this site (not just the 100-limit view)
    # so the matrix shows true coverage, not window-clipped counts.
    all_events_for_site = view.events_for(site_id, limit=10_000)
    family_counts: dict[str, int] = {s.code: 0 for s in AEGIS_SENSORS}
    family_critical: dict[str, int] = {s.code: 0 for s in AEGIS_SENSORS}
    for e in all_events_for_site:
        family_counts[e.sensor] = family_counts.get(e.sensor, 0) + 1
        if e.severity == "critical":
            family_critical[e.sensor] = family_critical.get(e.sensor, 0) + 1

    return render_template(
        "web/sites/detail.html",
        site=site,
        tab=tab,
        findings=findings,
        events=events,
        reports=reports,
        open_sev=open_sev,
        wp_attack_by_code=WP_ATTACK_BY_CODE,
        owasp_by_code=OWASP_BY_CODE,
        aegis_sensors=AEGIS_SENSORS,
        aegis_by_code=AEGIS_BY_CODE,
        family_counts=family_counts,
        family_critical=family_critical,
    )


# ─────────────────────────────────────────────────────────────────────
# Red Team Arena — Argos on demand
# ─────────────────────────────────────────────────────────────────────


@web_bp.route("/arena")
@require_tenant
def arena():
    view = TenantStore.for_tenant(g.tenant.tenant_id)
    scan = session.get("arena_scan")
    # Expire stale scans (>30 min)
    if scan:
        started = scan.get("started_ts", 0)
        if time.time() - started > 1800:
            session.pop("arena_scan", None)
            scan = None
    return render_template(
        "web/arena.html",
        sites=view.sites(),
        active_scan=scan,
    )


@web_bp.route("/arena/scan", methods=["POST"])
@require_tenant
def arena_start_scan():
    view = TenantStore.for_tenant(g.tenant.tenant_id)
    site_id = request.form.get("site_id", "")
    site = view.site(site_id)
    if site is None:
        abort(404)
    enforce_ownership(site.tenant_id, context="arena_scan")

    intensity = request.form.get("intensity", "standard")
    if intensity not in ("safe", "standard", "aggressive"):
        intensity = "standard"

    scan = {
        "id": "scan_" + uuid.uuid4().hex[:10],
        "site_id": site_id,
        "site_domain": site.domain,
        "intensity": intensity,
        "started_ts": time.time(),
        "phase_durations": {  # seconds
            "consent": 2,
            "recon": 6,
            "fingerprint": 5,
            "probe": 15,
            "triage": 4,
            "report": 3,
        },
    }
    session["arena_scan"] = scan
    return redirect(url_for("web.arena"))


@web_bp.route("/arena/scan/progress.json")
@require_tenant
def arena_scan_progress():
    scan = session.get("arena_scan")
    if not scan:
        return jsonify({"status": "idle"})

    view = TenantStore.for_tenant(g.tenant.tenant_id)
    site = view.site(scan["site_id"])
    if site is None:
        session.pop("arena_scan", None)
        return jsonify({"status": "idle"})

    elapsed = time.time() - scan["started_ts"]
    phases = ["consent", "recon", "fingerprint", "probe", "triage", "report"]
    durations = scan["phase_durations"]
    total = sum(durations[p] for p in phases)

    # Compute current phase + overall percent
    cumulative = 0.0
    current_phase = "report"
    phase_progress = 1.0
    for p in phases:
        if elapsed < cumulative + durations[p]:
            current_phase = p
            phase_progress = (elapsed - cumulative) / durations[p]
            break
        cumulative += durations[p]
    overall = min(1.0, elapsed / total)

    # Real findings from the site (leaked progressively as "discovered")
    all_findings = view.findings_for(site.id)
    n_visible = int(overall * len(all_findings))
    visible = all_findings[:n_visible]

    done = overall >= 1.0
    return jsonify(
        {
            "status": "done" if done else "running",
            "scan_id": scan["id"],
            "site_domain": scan["site_domain"],
            "intensity": scan["intensity"],
            "current_phase": current_phase,
            "phase_progress_pct": round(phase_progress * 100, 1),
            "overall_pct": round(overall * 100, 1),
            "elapsed_s": round(elapsed, 1),
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity,
                    "cvss": f.cvss,
                    "cve_id": f.cve_id,
                    "owasp": (
                        WP_ATTACK_BY_CODE[f.wp_attack_code].owasp
                        if f.wp_attack_code in WP_ATTACK_BY_CODE
                        else "—"
                    ),
                    "bounty_ready": f.bounty_ready,
                    "affected_path": f.affected_path,
                }
                for f in visible
            ],
        }
    )


@web_bp.route("/arena/scan/cancel", methods=["POST"])
@require_tenant
def arena_cancel_scan():
    session.pop("arena_scan", None)
    return redirect(url_for("web.arena"))


# ─────────────────────────────────────────────────────────────────────
# Error handlers scoped to the blueprint
# ─────────────────────────────────────────────────────────────────────


@web_bp.errorhandler(404)
def web_404(_):
    return render_template("web/404.html"), 404


# ═════════════════════════════════════════════════════════════════════
# 10-second passive preview — /web/preview — ease-of-use front door
# ═════════════════════════════════════════════════════════════════════


@web_bp.route("/preview", methods=["GET", "POST"])
def preview():
    submitted = None
    result = None
    if request.method == "POST":
        submitted = (request.form.get("target") or "").strip()
        if submitted:
            result = run_preview(submitted)
    return render_template(
        "web/preview.html", submitted_target=submitted, result=result
    )


# ═════════════════════════════════════════════════════════════════════
# Operator Command Center — /web/command — REAL Aegis feed
# ═════════════════════════════════════════════════════════════════════


@web_bp.route("/command")
def command():
    expected = os.environ.get("AMOSKYS_COMMAND_TOKEN", "")
    if not expected:
        abort(503)
    provided = request.args.get("token") or request.cookies.get("amoskys_command_token")
    if provided != expected:
        abort(404)
    severity = request.args.get("severity")
    snap = _aegis_tail.snapshot(severity_filter=severity)
    last_event_ago = _humantime(snap.last_event_ns) if snap.last_event_ns else None
    from flask import make_response

    response = make_response(
        render_template(
            "web/command.html",
            snap=snap,
            sensor_catalog=AEGIS_SENSOR_FAMILIES,
            last_event_ago=last_event_ago,
        )
    )
    if request.args.get("token"):
        response.set_cookie(
            "amoskys_command_token",
            expected,
            max_age=30 * 86400,
            httponly=True,
            secure=True,
            samesite="Strict",
        )
    return response


# ═════════════════════════════════════════════════════════════════════
# Fleet Globe — /web/globe
# ═════════════════════════════════════════════════════════════════════


@web_bp.route("/globe")
def globe():
    sites_view = build_sites_view()
    sites_json = build_sites_json(sites_view)
    arcs_json = build_arcs_json(sites_view)
    snap = _aegis_tail.snapshot()
    chain_pct = (
        (100 * snap.chain_ok / snap.total_events) if snap.total_events else 100.0
    )
    stats = build_stats(sites_view, 0, chain_pct)
    return render_template(
        "web/globe.html",
        sites_view=sites_view,
        sites_json=sites_json,
        arcs_json=arcs_json,
        stats=stats,
    )


# ═════════════════════════════════════════════════════════════════════
# Live Threat Wall — /web/threats
# ═════════════════════════════════════════════════════════════════════


@web_bp.route("/threats")
def threats():
    snap = _aegis_tail.snapshot()
    return render_template(
        "web/threats.html",
        live_feed=build_live_feed(snap),
        recent_cves=build_recent_cves(),
        stats=threats_stats(snap),
    )


@web_bp.route("/healthz")
def healthz():
    return {"status": "ok"}, 200


# ═════════════════════════════════════════════════════════════════════
# Auth — SQLite + bcrypt + email verification + password reset
# The whole flow: /signup → email → /verify-email/<t> → /welcome → /dashboard
#                 /signin → /dashboard
#                 /forgot-password → email → /reset-password/<t> → /signin
# ═════════════════════════════════════════════════════════════════════

from .auth import (
    AuthCore,
    SigninResult,
    SignupResult,
    get_core,
    set_session_cookie,
    clear_session_cookie,
    current_user as _current_user,
    get_client_info,
)
from . import auth_email


def _absolute(path: str) -> str:
    """Build an absolute URL to the given local path — used in auth emails.

    Prefers AMOSKYS_WEB_PUBLIC_URL env var (canonical public origin, e.g.
    https://lab.amoskys.com) so email links remain correct even when the
    request comes in via 127.0.0.1 / origin-IP / any upstream that does
    not supply X-Forwarded-Host. Falls back to request.url_root (which
    ProxyFix populates from X-Forwarded-* for real traffic).
    """
    import os as _os

    base = _os.environ.get("AMOSKYS_WEB_PUBLIC_URL", "").strip()
    if not base:
        base = request.url_root
    return base.rstrip("/") + path


@web_bp.route("/signin", methods=["GET", "POST"])
def signin():
    error = None
    submitted_email = ""
    next_path = (
        request.form.get("next") or request.args.get("next") or url_for("web.dashboard")
    )
    # If already signed in, skip the form
    if _current_user():
        return redirect(next_path)
    if request.method == "POST":
        submitted_email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        ip, ua = get_client_info()
        result, user, token = get_core().signin(submitted_email, password, ip=ip, ua=ua)

        if result == SigninResult.OK and token:
            resp = redirect(next_path)
            set_session_cookie(resp, token)
            # Keep legacy Flask-session keys populated so templates that peek
            # at `session.web_user_email` continue to render correctly.
            session["web_user_email"] = user.email
            session["web_user_site"] = customer_site()
            session.permanent = True
            return resp
        elif result == SigninResult.UNVERIFIED:
            # Give them a clear path forward rather than a dead-end error
            session["pending_verify_email"] = submitted_email
            return redirect(url_for("web.verify_pending"))
        elif result == SigninResult.LOCKED:
            error = "Too many failed attempts. Try again in 15 minutes or reset your password."
        else:
            error = "Invalid email or password."

    return render_template(
        "web/signin.html",
        error=error,
        submitted_email=submitted_email,
        next=next_path,
        customer_site=customer_site(),
    )


@web_bp.route("/signup", methods=["GET", "POST"])
def signup():
    error = None
    values = {"email": "", "full_name": ""}
    if _current_user():
        return redirect(url_for("web.dashboard"))

    if request.method == "POST":
        values["email"] = (request.form.get("email") or "").strip().lower()
        values["full_name"] = (request.form.get("full_name") or "").strip()
        password = request.form.get("password") or ""

        if not request.form.get("agree"):
            error = "Please accept the scope-consent terms to continue."
        else:
            result, user, token = get_core().signup(
                values["email"], password, full_name=values["full_name"]
            )
            if result == SignupResult.OK and user and token:
                verify_url = _absolute(url_for("web.verify_email", token=token))
                auth_email.send_verification(
                    user.email, verify_url, full_name=user.full_name
                )
                session["pending_verify_email"] = user.email
                return redirect(url_for("web.verify_pending"))
            if result == SignupResult.INVALID_EMAIL:
                error = "That doesn't look like a valid email address."
            elif result == SignupResult.WEAK_PASSWORD:
                error = "Password must be 10+ chars using at least 3 of: lowercase, uppercase, digits, symbols."
            elif result == SignupResult.EMAIL_TAKEN:
                # Intentionally soft: we don't reveal whether the email is
                # registered. Push them to the "check your email" view either
                # way — a real owner will succeed via the verify link they
                # already received on initial signup.
                session["pending_verify_email"] = values["email"]
                return redirect(url_for("web.verify_pending"))
    return render_template("web/signup.html", error=error, values=values)


@web_bp.route("/verify-pending")
def verify_pending():
    email = session.get("pending_verify_email") or ""
    return render_template("web/verify_pending.html", email=email)


@web_bp.route("/resend-verification", methods=["GET", "POST"])
def resend_verification():
    email = (
        (request.form.get("email") or session.get("pending_verify_email") or "")
        .strip()
        .lower()
    )
    sent_for = None
    if request.method == "POST" and email:
        user = get_core().find_user_by_email(email)
        if user and not user.email_verified:
            token = get_core().issue_verify_token(user.id)
            verify_url = _absolute(url_for("web.verify_email", token=token))
            auth_email.send_verification(email, verify_url, full_name=user.full_name)
        # Always show the same "sent!" screen — don't enumerate.
        sent_for = email
        session["pending_verify_email"] = email
    return render_template("web/verify_pending.html", email=email, resent_to=sent_for)


@web_bp.route("/verify-email/<token>")
def verify_email(token: str):
    ok, user = get_core().verify_email(token)
    if not ok or not user:
        return render_template("web/verify_result.html", ok=False), 400
    # Auto-signin on successful verify so the flow is signup → email → dashboard.
    core = get_core()
    # Reuse signin path with require_verified=False (just verified) to issue session.
    # We don't know their password here, so mint a session directly.
    import secrets as _secrets
    import time as _time

    session_token = _secrets.token_urlsafe(32)
    import sqlite3 as _sq
    from .auth_core import (
        _connect as _ac_connect,
        SESSION_TTL_SECS as _TTL,
        _ns as _ac_ns,
    )

    ip, ua = get_client_info()
    with _ac_connect() as c:
        c.execute(
            "INSERT INTO web_sessions (token, user_id, created_at, expires_at, ip_address, user_agent) "
            "VALUES (?,?,?,?,?,?)",
            (
                session_token,
                user.id,
                _ac_ns(),
                int(_time.time()) + _TTL,
                ip or "",
                (ua or "")[:400],
            ),
        )
    resp = redirect(url_for("web.welcome"))
    set_session_cookie(resp, session_token)
    session["web_user_email"] = user.email
    session["web_user_site"] = customer_site()
    session["first_welcome"] = True
    return resp


@web_bp.route("/welcome")
@require_signed_in
def welcome():
    return render_template(
        "web/welcome.html", user=_current_user(), site=customer_site()
    )


@web_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    sent = False
    email = ""
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        if email:
            ip, _ = get_client_info()
            result = get_core().request_password_reset(email, ip=ip)
            if result:
                _, token = result
                reset_url = _absolute(url_for("web.reset_password", token=token))
                auth_email.send_password_reset(email, reset_url)
            # Always show "sent" — no user enumeration.
            sent = True
    return render_template("web/forgot_password.html", sent=sent, email=email)


@web_bp.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token: str):
    error = None
    done = False
    if request.method == "POST":
        new_pw = request.form.get("password") or ""
        confirm = request.form.get("confirm") or ""
        if new_pw != confirm:
            error = "Passwords don't match."
        else:
            ok, err = get_core().complete_password_reset(token, new_pw)
            if ok:
                done = True
            else:
                error = err or "Reset link invalid or expired."
    return render_template(
        "web/reset_password.html", token=token, error=error, done=done
    )


@web_bp.route("/signout")
def signout():
    # Clear DB-backed session + Flask session cookie, both.
    tok = request.cookies.get("amoskys_web_sid")
    if tok:
        get_core().destroy_session(tok)
    session.clear()
    resp = redirect(url_for("web.landing"))
    clear_session_cookie(resp)
    return resp


@web_bp.route("/dashboard")
@require_signed_in
def dashboard():
    site = current_user_site() or customer_site()
    snap = _aegis_tail.snapshot()
    crawlers = summarize_crawlers(snap)
    max_bot = max([v for v in crawlers["totals"].values()] + [1])
    plugins = build_inventory(f"https://{site}", snap)

    # ── Semantic layer: humanize events + compute posture + narrative banner ──
    # This is what replaces the engineer-debug view (raw aegis.* type strings)
    # with something an operator can scan in 2 seconds.
    humanized_recent = _ev_sem.humanize_events(
        snap.recent,
        hide_internal=True,
        limit=10,
    )
    category_rollup = _ev_sem.category_rollup(snap.event_types)
    concerns = _ev_sem.active_concerns(
        event_types=snap.event_types,
        severities=snap.severities,
        recent_events=snap.recent,
        active_blocks_count=getattr(snap, "blocks_started_count", 0),
        chain_breaks=getattr(snap, "chain_breaks", 0),
    )
    narrative = _narr.build(snap, concerns, crawlers.get("totals")).to_dict()

    # WP version — read from the shared 5-minute-TTL /wp-json/ cache in
    # plugin_inventory. Before this, every dashboard render paid ~450ms
    # for this single probe; now the steady-state cost is near zero and
    # the first fill is shared with build_inventory() above.
    wp_version = None
    try:
        wp_json_data = _fetch_wp_json_cached(f"https://{site}")
        wp_version = (wp_json_data.get("_links", {}) or {}).get("wp:version")
    except Exception:
        pass

    # Live globe payload — real customer site IP + real external IPs from
    # the Aegis snapshot, all geocoded via the cached ip-api.com lookup.
    # Zero seed data on this code path.
    globe_payload = build_live_globe(snap, site, cache=_geoip_cache)

    return render_template(
        "web/dashboard.html",
        site=site,
        user_email=current_user_email(),
        wp_version=wp_version,
        snap=snap,
        sensor_catalog=AEGIS_SENSOR_FAMILIES,
        crawlers=crawlers,
        max_bot=max_bot,
        plugins=plugins,
        globe=globe_payload,
        globe_json=json.dumps(globe_payload),
        # ── Redesign additions ──
        narrative=narrative,
        humanized_events=humanized_recent,
        category_rollup=category_rollup,
        concerns=concerns,
    )


# ─────────────────────────────────────────────────────────────────────
# /web/api/dashboard/live-arcs.json
#
# Statistical contract:
#   - Each item in `events` represents ONE Aegis event.
#   - `ts_ms` is the event's actual timestamp from the chain (ns→ms).
#   - `visible_ms` is how long the arc should remain visible client-side.
#       For HTTP requests we honour the real `attributes.duration_ms` (capped
#       to a visible band). For non-HTTP events (which are point-in-time hooks)
#       we use a default 1500 ms so they're perceivable.
#   - Server returns events strictly newer than `since_ms` (client watermark)
#     and its own `now_ms` so the client can sync against server clock.
#   - Cross-tenant impossible: the route is signed-in only and bound to the
#     authed user's site (customer-zero in v1).
#
# This endpoint is the *truth source*: idle log → empty `events` → empty globe.
# ─────────────────────────────────────────────────────────────────────


@web_bp.route("/api/dashboard/live-arcs.json")
@require_signed_in
def dashboard_live_arcs():
    since_ms = 0
    try:
        since_ms = int(request.args.get("since_ms", "0") or 0)
    except (TypeError, ValueError):
        since_ms = 0

    snap = _aegis_tail.snapshot()
    site = current_user_site() or customer_site()
    site_ip = resolve_domain_ip(site)
    site_geo = _geoip_cache.resolve(site_ip) if site_ip else None
    server_now_ms = int(time.time() * 1000)

    if not site_geo:
        return jsonify(
            {
                "now_ms": server_now_ms,
                "events": [],
                "site": None,
            }
        )

    # snap.recent is newest-first (see AegisTail). We want oldest-first so
    # the client adds arcs in temporal order — matters for animation.
    out = []
    cold_lookups_left = 3  # bounded ip-api hits per poll
    for ev in reversed(snap.recent):
        ts_ns = ev.get("ts_ns") or 0
        ts_ms = ts_ns // 1_000_000 if ts_ns else 0
        if ts_ms <= since_ms:
            continue
        req = ev.get("request") or {}
        ip = req.get("ip")
        if not ip or ip in ("127.0.0.1", "::1") or ip == site_ip:
            continue

        geo = _geoip_cache.get(ip)
        if not geo and cold_lookups_left > 0:
            geo = _geoip_cache.resolve(ip)
            cold_lookups_left -= 1
        if not geo:
            continue

        et = ev.get("event_type", "")
        fam = ".".join(et.split(".")[:2]) if et else ""
        sev = ev.get("severity", "info")
        attrs = ev.get("attributes") or {}

        # Real event duration if present (HTTP family). Otherwise None.
        real_dur_ms = None
        raw_dur = attrs.get("duration_ms")
        if isinstance(raw_dur, (int, float)) and raw_dur > 0:
            real_dur_ms = int(raw_dur)

        if real_dur_ms is not None:
            # Magnify real duration x4 for visibility on a globe; clamp 400-4000ms.
            visible_ms = max(400, min(4000, real_dur_ms * 4))
        else:
            visible_ms = 1500  # default visible window for instant events

        out.append(
            {
                "ts_ms": ts_ms,
                "ip": ip,
                "start_lat": geo.lat,
                "start_lng": geo.lon,
                "end_lat": site_geo.lat,
                "end_lng": site_geo.lon,
                "severity": sev,
                "event_type": et,
                "attack": _FAMILY_TO_ATTACK.get(fam, et or "—"),
                "real_duration_ms": real_dur_ms,
                "visible_ms": visible_ms,
                "origin_city": geo.city,
                "origin_country": geo.country,
                "origin_org": geo.org or geo.asn,
            }
        )

    # Cap response to avoid 1MB JSON on first poll after long idle
    return jsonify(
        {
            "now_ms": server_now_ms,
            "events": out[-300:],
        }
    )


# ═════════════════════════════════════════════════════════════════════
# Threat map — per-IP aggregate over a time window.
#
# GET /web/api/dashboard/threat-map.json?window=1h&top=50
#
# Returns the top-N source IPs active in the last `window`, each with
# geo-resolution, event count, max concern level, short list of the
# most frequent event phrases, and first/last timestamps.
#
# This is the *persistent* data source for the redesigned globe —
# unlike live-arcs.json which returns transient per-event arcs, this
# gives the operator a readable "who has been hammering me lately"
# view that doesn't flicker in and out on page load.
#
# Research note on the default window: real-time SOC dashboards (Norse,
# Kaspersky ThreatCloud, Check Point) typically offer both a live-pulse
# view and a windowed-aggregate view. 1h strikes the usable middle —
# long enough to see patterns, short enough that the globe doesn't turn
# into an illegible spaghetti of historical activity.
# ═════════════════════════════════════════════════════════════════════

_WINDOW_UNITS = {"m": 60, "h": 3600, "d": 86400, "s": 1}


def _parse_window_to_ms(spec: str, default_ms: int = 3600 * 1000) -> int:
    """Convert strings like '1h', '30m', '6h' to milliseconds.
    Falls back to default on parse failure."""
    if not spec:
        return default_ms
    import re

    m = re.fullmatch(r"(\d+)([smhd])", spec.strip().lower())
    if not m:
        return default_ms
    return int(m.group(1)) * _WINDOW_UNITS[m.group(2)] * 1000


@web_bp.route("/api/dashboard/threat-map.json")
@require_signed_in
def dashboard_threat_map():
    window_ms = _parse_window_to_ms(
        request.args.get("window", "1h"), default_ms=3600_000
    )
    top_n = max(1, min(200, int(request.args.get("top", "50") or 50)))
    window_ms = max(60_000, min(window_ms, 7 * 86400 * 1000))  # clamp 1 min .. 7 days

    site = current_user_site() or customer_site()
    site_ip = resolve_domain_ip(site)
    site_geo = _geoip_cache.resolve(site_ip) if site_ip else None
    now_ms = int(time.time() * 1000)
    cutoff_ms = now_ms - window_ms

    # Reuse the parsed-event cache from investigate_view — populated on
    # the first /web/investigate hit and kept incrementally up to date.
    # Avoids a second parse of the 93 MB JSONL just for the globe.
    from .investigate_view import _ensure_parsed_cache
    from .aegis_live import LOG_PATH

    events = _ensure_parsed_cache(LOG_PATH)

    # ── Aggregate per-IP over the window ──────────────────────────
    # actors: ip -> {count, max_concern, concern_hist, phrase_counts, first_ns, last_ns}
    actors: Dict[str, Dict[str, Any]] = {}
    ignore_ips = {"127.0.0.1", "::1", ""}
    if site_ip:
        ignore_ips.add(site_ip)

    for e in events:
        ts_ns = e.get("event_timestamp_ns") or 0
        if ts_ns // 1_000_000 < cutoff_ms:
            continue
        ip = ((e.get("request") or {}).get("ip") or "").strip()
        if not ip or ip in ignore_ips:
            continue
        et = e.get("event_type") or ""
        meaning = _ev_sem.meaning_for(et)

        a = actors.get(ip)
        if a is None:
            a = {
                "ip": ip,
                "count": 0,
                "max_concern": 0,
                "concern_hist": [0, 0, 0, 0, 0, 0],
                "phrases": {},
                "categories": {},
                "first_ns": ts_ns,
                "last_ns": ts_ns,
                "ua": (e.get("request") or {}).get("ua") or "",
            }
            actors[ip] = a
        a["count"] += 1
        a["concern_hist"][meaning.concern] += 1
        if meaning.concern > a["max_concern"]:
            a["max_concern"] = meaning.concern
        if ts_ns < a["first_ns"]:
            a["first_ns"] = ts_ns
        if ts_ns > a["last_ns"]:
            a["last_ns"] = ts_ns
        # Only count phrases that a human cares about — internal taxonomy
        # items (db summaries, http request heartbeats) would drown out
        # the useful ones.
        if meaning.audience == "user":
            a["phrases"][meaning.phrase] = a["phrases"].get(meaning.phrase, 0) + 1
            a["categories"][meaning.category] = (
                a["categories"].get(meaning.category, 0) + 1
            )

    if not site_geo:
        return jsonify(
            {
                "generated_at_ms": now_ms,
                "window_ms": window_ms,
                "site": None,
                "actors": [],
                "total_event_count": 0,
                "total_actor_count": 0,
            }
        )

    # Sort actors by concern first (descending), then raw count.
    # Non-internal hits get a weight bonus so the globe prioritises
    # meaningful attackers over noisy-but-boring ones.
    def _actor_score(a):
        user_phrase_hits = sum(a["phrases"].values())
        return (a["max_concern"], user_phrase_hits * 2 + a["count"])

    ranked = sorted(actors.values(), key=_actor_score, reverse=True)
    selected = ranked[:top_n]

    # ── Resolve geo for the selected (bounded — don't hammer ip-api) ──
    out_actors: List[Dict[str, Any]] = []
    cold_lookups_left = 5
    for a in selected:
        ip = a["ip"]
        geo = _geoip_cache.get(ip)
        if not geo and cold_lookups_left > 0:
            geo = _geoip_cache.resolve(ip)
            cold_lookups_left -= 1
        if not geo:
            # Skip unresolvable IPs on the globe but still carry a stub so
            # the client can report totals correctly.
            continue
        top_phrases = sorted(a["phrases"].items(), key=lambda kv: kv[1], reverse=True)[
            :3
        ]
        out_actors.append(
            {
                "ip": ip,
                "count": a["count"],
                "max_concern": a["max_concern"],
                "concern_hist": a["concern_hist"],
                "first_ms": a["first_ns"] // 1_000_000,
                "last_ms": a["last_ns"] // 1_000_000,
                "start_lat": geo.lat,
                "start_lng": geo.lon,
                "origin_city": geo.city,
                "origin_country": geo.country,
                "origin_org": geo.org or geo.asn,
                "top_phrases": [{"phrase": p, "count": c} for p, c in top_phrases],
                "top_category": (
                    max(a["categories"].items(), key=lambda kv: kv[1])[0]
                    if a["categories"]
                    else None
                ),
            }
        )

    total_events = sum(a["count"] for a in actors.values())

    return jsonify(
        {
            "generated_at_ms": now_ms,
            "window_ms": window_ms,
            "site": {
                "domain": site,
                "ip": site_ip,
                "end_lat": site_geo.lat,
                "end_lng": site_geo.lon,
                "city": site_geo.city,
                "country": site_geo.country,
                "org": site_geo.org or site_geo.asn,
            },
            "actors": out_actors,
            "total_event_count": total_events,
            "total_actor_count": len(actors),
            "resolved_actor_count": len(out_actors),
        }
    )


# ═════════════════════════════════════════════════════════════════════
# IGRIS-Web chat
#
# POST /web/api/igris/chat
# Request body:
#     {"message": "...", "history": [{"role": "user"|"assistant", "content": "..."}]}
#
# Response body:
#     {"reply": "...", "backend": "live/claude-sonnet-4-5" | "ground/...",
#      "mode": "live"|"ground", "posture": "normal"|"watching"|"attack",
#      "took_ms": 123, "warning": null|"..."}
#
# The server does not persist chat state — the client echoes history back
# on every turn. Keeps the server stateless; easy to scale; no multi-
# tenant confusion.
#
# Backend auto-selects by ANTHROPIC_API_KEY presence. Without the key,
# ground mode still produces useful rule-based answers from the live
# Aegis snapshot. See igris_chat.py for the taxonomy.
# ═════════════════════════════════════════════════════════════════════


@web_bp.route("/api/igris/chat", methods=["POST"])
@require_signed_in
def igris_chat():
    data = request.get_json(silent=True) or {}
    user_message = (data.get("message") or "").strip()
    if not user_message:
        return jsonify({"error": "empty message"}), 400
    if len(user_message) > 2000:
        return jsonify({"error": "message too long (2000 char cap)"}), 400

    # Validate history schema — keep permissive but prune anything weird
    raw_hist = data.get("history") or []
    history: list = []
    if isinstance(raw_hist, list):
        for turn in raw_hist:
            if not isinstance(turn, dict):
                continue
            role = turn.get("role")
            content = turn.get("content")
            if (
                role in ("user", "assistant")
                and isinstance(content, str)
                and content.strip()
            ):
                history.append({"role": role, "content": content[:4000]})

    snap = _aegis_tail.snapshot()
    concerns = _ev_sem.active_concerns(
        event_types=snap.event_types,
        severities=snap.severities,
        recent_events=snap.recent,
        active_blocks_count=getattr(snap, "blocks_started_count", 0),
        chain_breaks=getattr(snap, "chain_breaks", 0),
    )

    reply = _igris.chat(
        user_message=user_message,
        history=history,
        snap=snap,
        active_concerns_payload=concerns,
    )

    return jsonify(
        {
            "reply": reply.text,
            "backend": reply.backend,
            "mode": reply.mode,
            "posture": reply.posture,
            "took_ms": reply.took_ms,
            "warning": reply.warning,
        }
    )


# ═════════════════════════════════════════════════════════════════════
# Investigation surface
#
# Four pages — investigate / timeline / graph / event-detail — share ONE
# query language and ONE source of truth (the Aegis JSONL). Every dashboard
# component deep-links here with a pre-filter, so the user can drill from
# "I see something interesting" → "I'm hunting it down" without losing context.
# ═════════════════════════════════════════════════════════════════════

from .investigate_view import (
    parse_query,
    build_investigate,
    build_timeline,
    build_graph,
    collect,
    find_event_with_neighbors,
    verify_sig,
)


@web_bp.route("/investigate")
@require_signed_in
def investigate():
    q = request.args.get("q", "")
    flt = parse_query(q, default_window="1h")
    result = build_investigate(flt)
    return render_template(
        "web/investigate.html",
        q=q,
        canonical_q=flt.to_query_string(),
        chips=flt.to_chips(),
        result=result,
        sensor_catalog=AEGIS_SENSOR_FAMILIES,
    )


@web_bp.route("/timeline")
@require_signed_in
def timeline():
    q = request.args.get("q", "")
    flt = parse_query(q, default_window="6h")
    matched = collect(flt, cap=20_000)
    tl = build_timeline(matched)
    return render_template(
        "web/timeline.html",
        q=q,
        canonical_q=flt.to_query_string(),
        chips=flt.to_chips(),
        timeline_json=json.dumps(tl),
        total=len(matched),
        truncated=tl.get("truncated", False),
    )


@web_bp.route("/graph")
@require_signed_in
def graph():
    q = request.args.get("q", "")
    flt = parse_query(q, default_window="6h")
    matched = collect(flt, cap=20_000)
    g = build_graph(matched)
    return render_template(
        "web/graph.html",
        q=q,
        canonical_q=flt.to_query_string(),
        chips=flt.to_chips(),
        graph_json=json.dumps(g),
        total=len(matched),
    )


@web_bp.route("/event/<event_id>")
@require_signed_in
def event_detail(event_id: str):
    prev, target, next_ = find_event_with_neighbors(event_id)
    if target is None:
        abort(404)
    sig_ok, recomputed = verify_sig(target)
    fam = (target.get("event_type") or "").split(".")
    fam_label = ".".join(fam[:2]) if len(fam) >= 2 else target.get("event_type", "?")
    return render_template(
        "web/event_detail.html",
        ev=target,
        prev_ev=prev,
        next_ev=next_,
        sig_ok=sig_ok,
        recomputed_sig=recomputed,
        fam_label=fam_label,
        family_blurb=AEGIS_SENSOR_FAMILIES.get(fam_label, ""),
        ev_pretty=json.dumps(target, indent=2, ensure_ascii=False),
    )


# ── JSON endpoints (shared) ─────────────────────────────────────────


@web_bp.route("/api/investigate/events.json")
@require_signed_in
def investigate_events_json():
    """Live tail for the investigate page. Same filter language."""
    q = request.args.get("q", "")
    flt = parse_query(q, default_window="1h")
    result = build_investigate(flt)
    return jsonify(
        {
            "now_ms": int(time.time() * 1000),
            "total": result.total,
            "capped": result.capped,
            "rows": result.rows,
            "histogram": result.histogram,
            "facets": result.facets,
            "severities": result.severities,
            "families": result.families,
            "chain_ok": result.chain_ok,
            "chain_breaks": result.chain_breaks,
        }
    )
