"""IGRIS supervisory + Guardian C2 API routes.

Extracted from dashboard/__init__.py for maintainability.
"""

from __future__ import annotations

import importlib
import json
import logging
import os
import time
from datetime import datetime, timezone

from flask import jsonify, request

from ..api.rate_limiter import require_rate_limit
from ..middleware import require_login
from . import dashboard_bp
from .route_helpers import _get_store, _normalize_agent_id

logger = logging.getLogger("web.app.dashboard")


# ── IGRIS Supervisory API Endpoints ──────────────────────────────────────────


@dashboard_bp.route("/api/igris/baselines")
@require_login
@require_rate_limit(max_requests=30, window_seconds=60)
def igris_baselines():
    """IGRIS baseline metrics snapshot."""
    try:
        from amoskys.igris import get_igris

        return jsonify({"status": "success", "baselines": get_igris().get_baselines()})
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@dashboard_bp.route("/api/igris/logs")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def igris_logs():
    """Centralized IGRIS log stream — IGRIS + all in-process subsystems + agent tails."""
    from pathlib import Path

    lines_requested = request.args.get("lines", default=150, type=int)
    lines_requested = min(lines_requested, 800)
    log_dir = Path(__file__).resolve().parents[3] / "logs"

    all_log_lines: list[str] = []

    # 1. Main centralized log (in-process subsystems routed via _setup_log_file)
    igris_log = log_dir / "igris.log"
    if igris_log.exists():
        try:
            raw = igris_log.read_text().strip().split("\n")
            all_log_lines.extend(raw[-(lines_requested * 2) :])
        except Exception:
            pass

    # 2. Agent process logs (separate processes write to .err.log files)
    _AGENT_LOGS = [
        "proc_agent",
        "dns_agent",
        "auth_agent",
        "fim_agent",
        "flow_agent",
        "persistence_agent",
        "peripheral_agent",
        "kernel_audit_agent",
        "device_discovery_agent",
        "protocol_collectors_agent",
        # L7 Gap-Closure Agents
        "applog_agent",
        "db_activity_agent",
        "http_inspector_agent",
        "internet_activity_agent",
        "net_scanner_agent",
    ]
    for agent_name in _AGENT_LOGS:
        agent_log = log_dir / f"{agent_name}.err.log"
        if agent_log.exists():
            try:
                raw = agent_log.read_text().strip().split("\n")
                all_log_lines.extend(raw[-15:])
            except Exception:
                pass

    # 3. Sort by timestamp prefix for unified chronological view
    def _sort_key(line: str) -> str:
        if len(line) >= 19 and line[4] == "-" and line[10] == " ":
            return line[:19]
        return "9999"

    all_log_lines.sort(key=_sort_key)
    tail = all_log_lines[-lines_requested:]

    return jsonify({"status": "success", "log_tail": tail, "available": len(tail) > 0})


# ── Guardian C2 API Endpoints ─────────────────────────────────────────────


def _get_igris():
    """Import and return the IGRIS singleton, or None if unavailable."""
    try:
        from amoskys.igris import get_igris

        return get_igris()
    except Exception:
        return None


def _fleet_summary():
    """Build fleet summary from agent discovery (lightweight process scan)."""
    try:
        from .agent_discovery import AGENT_CATALOG, detect_agent_status

        agents = []
        for aid, cfg in AGENT_CATALOG.items():
            st = detect_agent_status(cfg)
            agents.append(
                {
                    "id": aid,
                    "name": cfg["name"],
                    "status": "healthy" if st["health"] == "online" else st["health"],
                    "type": cfg["type"],
                }
            )
        healthy = sum(1 for a in agents if a["status"] == "healthy")
        return {
            "total": len(agents),
            "healthy": healthy,
            "offline": len(agents) - healthy,
            "agents": agents,
        }
    except Exception:
        return {"total": 0, "healthy": 0, "offline": 0, "agents": []}


def _anomaly_summary():
    """Gather active anomalies from IGRIS signals."""
    igris = _get_igris()
    if not igris:
        return []
    try:
        signals = igris.get_signals(limit=20)
        anomalies = []
        for sig in signals:
            if sig.get("cleared"):
                continue
            anomalies.append(
                {
                    "id": sig.get("id", ""),
                    "agent": sig.get("subsystem", ""),
                    "agent_name": sig.get("subsystem", "unknown").title(),
                    "message": sig.get("reason", sig.get("signal_type", "")),
                    "severity": sig.get("severity", "medium"),
                }
            )
        return anomalies
    except Exception:
        return []


def _igris_status_summary():
    """IGRIS status for Guardian header indicator."""
    igris = _get_igris()
    if not igris:
        return {
            "status": "stopped",
            "active_signal_count": 0,
            "cycle_count": 0,
            "cycle_duration_ms": 0,
        }
    try:
        return igris.get_status()
    except Exception:
        return {
            "status": "error",
            "active_signal_count": 0,
            "cycle_count": 0,
            "cycle_duration_ms": 0,
        }


@dashboard_bp.route("/api/pipeline/status")
@require_login
@require_rate_limit(max_requests=30, window_seconds=60)
def pipeline_status():
    """Full ingest pipeline health: enrichment, scoring, fusion, SOMA."""
    status = {}

    # Enrichment stages
    try:
        from amoskys.enrichment import EnrichmentPipeline

        p = EnrichmentPipeline()
        status["enrichment"] = p.status()
        p.close()
    except Exception as e:
        status["enrichment"] = {"error": str(e)}

    # Scoring engine
    try:
        from amoskys.intel.scoring import ScoringEngine

        ScoringEngine()  # verifies it can be instantiated
        status["scoring"] = {"available": True}
    except Exception as e:
        status["scoring"] = {"error": str(e)}

    # SOMA brain
    try:
        from amoskys.intel.soma_brain import ModelScorerAdapter

        adapter = ModelScorerAdapter()
        status["soma"] = {
            "model_available": adapter.available(),
        }
    except Exception as e:
        status["soma"] = {"error": str(e)}

    # Fusion engine (incident count)
    try:
        import sqlite3
        from pathlib import Path

        fusion_db = Path(__file__).resolve().parents[3] / "data" / "intel" / "fusion.db"
        if fusion_db.exists():
            conn = sqlite3.connect(str(fusion_db), timeout=3)
            row = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()
            status["fusion"] = {"incidents": row[0] if row else 0}
            conn.close()
        else:
            status["fusion"] = {"incidents": 0, "note": "no fusion database yet"}
    except Exception as e:
        status["fusion"] = {"error": str(e)}

    # IGRIS
    igris = _get_igris()
    if igris:
        status["igris"] = {
            "running": igris.is_running,
        }
    else:
        status["igris"] = {"running": False}

    return jsonify({"status": "success", "pipeline": status})


@dashboard_bp.route("/api/c2/poll")
@require_login
@require_rate_limit(max_requests=30, window_seconds=60)
def c2_poll():
    """Coalesced Guardian C2 poll — fleet + anomalies + IGRIS in one response."""
    return jsonify(
        {
            "status": "success",
            "fleet": _fleet_summary(),
            "anomalies": _anomaly_summary(),
            "igris": _igris_status_summary(),
        }
    )


@dashboard_bp.route("/api/guardian/overview")
@require_login
@require_rate_limit(max_requests=30, window_seconds=60)
def guardian_overview():
    """Guardian fleet overview."""
    return jsonify({"status": "success", "fleet": _fleet_summary()})


@dashboard_bp.route("/api/guardian/anomalies")
@require_login
@require_rate_limit(max_requests=30, window_seconds=60)
def guardian_anomalies():
    """Active anomalies from IGRIS signals."""
    return jsonify({"status": "success", "anomalies": _anomaly_summary()})


@dashboard_bp.route("/api/igris/status")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def igris_status():
    """IGRIS operational status + tactical state."""
    result = _igris_status_summary()

    # Add tactical state from directives.json
    try:
        directives_path = os.path.join("data", "igris", "directives.json")
        if os.path.exists(directives_path):
            with open(directives_path) as f:
                directives = json.load(f)
            result["tactical"] = {
                "posture": directives.get("posture", "UNKNOWN"),
                "threat_level": directives.get("threat_level", 0),
                "hunt_mode": directives.get("hunt_mode", False),
                "directive_count": len(directives.get("directives", [])),
                "watched_pids": directives.get("watched_pids", []),
                "watched_paths": directives.get("watched_paths", []),
                "watched_domains": directives.get("watched_domains", []),
                "timestamp": directives.get("timestamp"),
            }
    except Exception:
        result["tactical"] = {"status": "unavailable"}

    return jsonify(result)


@dashboard_bp.route("/api/igris/coherence")
@require_login
@require_rate_limit(max_requests=30, window_seconds=60)
def igris_coherence():
    """IGRIS organism coherence assessment."""
    igris = _get_igris()
    if not igris:
        return (
            jsonify({"status": "error", "verdict": "unknown", "subsystem_status": {}}),
            503,
        )
    try:
        return jsonify(igris.get_coherence())
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


# ── IGRIS Chat (AI-powered security analyst) ────────────────────
_igris_chat_instance = None


def _get_igris_chat():
    global _igris_chat_instance
    if _igris_chat_instance is None:
        try:
            from flask import current_app

            from amoskys.igris.chat import IgrisChat

            action_executor = current_app.config.get("ACTION_EXECUTOR")
            _igris_chat_instance = IgrisChat(
                action_executor=action_executor,
            )
        except Exception as e:
            logger.error("Failed to initialize IGRIS chat: %s", e)
            return None
    return _igris_chat_instance


@dashboard_bp.route("/api/igris/chat", methods=["POST"])
@require_login
@require_rate_limit(max_requests=30, window_seconds=60)
def igris_chat():
    """IGRIS AI chat endpoint — security analyst copilot."""
    data = request.get_json(silent=True) or {}
    message = (data.get("message") or "").strip()
    if not message:
        return jsonify({"status": "error", "message": "No message provided"}), 400

    chat = _get_igris_chat()
    if chat is None:
        return (
            jsonify(
                {
                    "status": "error",
                    "message": "IGRIS chat unavailable. Check ANTHROPIC_API_KEY.",
                }
            ),
            503,
        )

    try:
        response = chat.chat(message)
        return jsonify(
            {
                "status": "success",
                "response": response,
                "history_length": len(chat.get_history()),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )
    except Exception as e:
        logger.error("IGRIS chat error: %s", e)
        return jsonify({"status": "error", "message": str(e)}), 500


@dashboard_bp.route("/api/igris/chat/reset", methods=["POST"])
@require_login
def igris_chat_reset():
    """Reset IGRIS chat conversation history."""
    chat = _get_igris_chat()
    if chat:
        chat.reset()
    return jsonify({"status": "success", "message": "Conversation reset"})


@dashboard_bp.route("/api/igris/chat/brief", methods=["POST"])
@require_login
@require_rate_limit(max_requests=5, window_seconds=60)
def igris_proactive_brief():
    """IGRIS proactive security briefing — it tells you what matters."""
    chat = _get_igris_chat()
    if chat is None:
        return (
            jsonify(
                {
                    "status": "error",
                    "message": "IGRIS unavailable. Check ANTHROPIC_API_KEY.",
                }
            ),
            503,
        )

    try:
        response = chat.proactive_brief()
        return jsonify(
            {
                "status": "success",
                "response": response,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )
    except Exception as e:
        logger.error("IGRIS proactive brief failed: %s", e)
        return jsonify({"status": "error", "message": str(e)}), 500


@dashboard_bp.route("/api/igris/chat/backend", methods=["GET"])
@require_login
def igris_chat_backend():
    """Get IGRIS LLM backend status."""
    claude_ok = bool(os.environ.get("ANTHROPIC_API_KEY", ""))
    return jsonify(
        {
            "status": "success",
            "current": "claude",
            "model": os.environ.get("IGRIS_MODEL", "claude-sonnet-4-20250514"),
            "backends": {
                "claude": {
                    "available": claude_ok,
                    "label": "Claude API",
                    "model": "claude-sonnet-4-20250514",
                },
            },
        }
    )


@dashboard_bp.route("/api/igris/chat/history")
@require_login
def igris_chat_history():
    """Get IGRIS chat conversation history."""
    chat = _get_igris_chat()
    if not chat:
        return jsonify({"status": "success", "history": []})
    return jsonify({"status": "success", "history": chat.get_history()})


@dashboard_bp.route("/api/guardian/execute", methods=["POST"])
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def guardian_execute():
    """Execute a Guardian C2 command and return formatted output."""
    data = request.get_json(silent=True) or {}
    cmd = (data.get("command") or "").strip()
    if not cmd:
        return jsonify({"output": "No command provided.", "cmd_type": "error"})

    igris = _get_igris()

    # ── Command router ──
    parts = cmd.split()
    root = parts[0].lower() if parts else ""

    try:
        # help
        if root == "help":
            output = (
                "Guardian C2 — Available Commands\n"
                "──────────────────────────────────\n"
                "  status [agent]   Fleet / agent status\n"
                "  fleet / scan     Full fleet scan\n"
                "  threats          Active threat signals\n"
                "  report           System overview report\n"
                "  sysinfo          Platform & resource info\n"
                "  soma status      SOMA Brain status\n"
                "  soma train       Trigger SOMA retraining\n"
                "  reliability      Agent reliability scores\n"
                "  events [N]       Recent security events\n"
                "  igris            IGRIS supervisor overview\n"
                "  igris status     IGRIS status detail\n"
                "  igris metrics    Full metric snapshot\n"
                "  igris coherence  Organism coherence check\n"
                "  igris signals    Active governance signals\n"
                "  igris baseline   Learned baselines\n"
                "  igris explain ID Explain a specific signal\n"
                "  igris reset      Reset baselines (warmup)\n"
                "  clear            Clear terminal\n"
            )
            return jsonify({"output": output, "cmd_type": "system"})

        # clear
        if root == "clear":
            return jsonify({"output": "", "cmd_type": "clear"})

        # fleet / scan
        if root in ("fleet", "scan"):
            fleet = _fleet_summary()
            lines = [
                f"Fleet Status — {fleet['total']} agents, {fleet['healthy']} healthy, {fleet['offline']} offline",
                "",
            ]
            for a in fleet["agents"]:
                marker = "[+]" if a["status"] == "healthy" else "[-]"
                lines.append(f"  {marker} {a['name']:<30s} {a['status']}")
            return jsonify({"output": "\n".join(lines), "cmd_type": "success"})

        # status [agent_id]
        if root == "status":
            if len(parts) > 1:
                agent_id = parts[1]
                from .agent_discovery import AGENT_CATALOG, detect_agent_status

                cfg = AGENT_CATALOG.get(agent_id)
                if not cfg:
                    return jsonify(
                        {"output": f"Unknown agent: {agent_id}", "cmd_type": "error"}
                    )
                st = detect_agent_status(cfg)
                lines = [
                    f"Agent: {cfg['name']} ({agent_id})",
                    f"Health: {st['health']}",
                    f"Instances: {st['instances']}",
                    f"Blockers: {', '.join(st['blockers']) or 'none'}",
                    f"Warnings: {', '.join(st['warnings']) or 'none'}",
                ]
                return jsonify({"output": "\n".join(lines), "cmd_type": "info"})
            # No agent specified — show fleet
            fleet = _fleet_summary()
            lines = [f"Fleet — {fleet['healthy']}/{fleet['total']} online"]
            for a in fleet["agents"]:
                marker = "[+]" if a["status"] == "healthy" else "[-]"
                lines.append(f"  {marker} {a['name']}")
            return jsonify({"output": "\n".join(lines), "cmd_type": "info"})

        # threats
        if root == "threats":
            anomalies = _anomaly_summary()
            if not anomalies:
                return jsonify(
                    {"output": "No active threat signals.", "cmd_type": "success"}
                )
            lines = [f"Active Threats — {len(anomalies)} signal(s)", ""]
            for a in anomalies:
                sev = a["severity"].upper()
                lines.append(f"  [{sev}] {a['agent_name']}: {a['message']}")
            return jsonify({"output": "\n".join(lines), "cmd_type": "warning"})

        # report
        if root == "report":
            fleet = _fleet_summary()
            anomalies = _anomaly_summary()
            st = _igris_status_summary()
            lines = [
                "AMOSKYS System Report",
                "=" * 40,
                f"Fleet: {fleet['healthy']}/{fleet['total']} agents online",
                f"Active threats: {len(anomalies)}",
                f"IGRIS: {st.get('status', 'unknown')} | Cycle #{st.get('cycle_count', 0)} | {st.get('cycle_duration_ms', 0)}ms",
                f"Coherence: {st.get('coherence', 'unknown')}",
            ]
            return jsonify({"output": "\n".join(lines), "cmd_type": "system"})

        # sysinfo
        if root == "sysinfo":
            import platform as plat

            import psutil

            mem = psutil.virtual_memory()
            lines = [
                f"Platform: {plat.system()} {plat.release()}",
                f"Machine: {plat.machine()}",
                f"CPU: {psutil.cpu_count()} cores @ {psutil.cpu_percent()}%",
                f"Memory: {mem.used // (1024**3)}GB / {mem.total // (1024**3)}GB ({mem.percent}%)",
                f"Python: {plat.python_version()}",
            ]
            return jsonify({"output": "\n".join(lines), "cmd_type": "info"})

        # soma status / soma train
        if root == "soma":
            sub = parts[1].lower() if len(parts) > 1 else "status"
            if sub == "status":
                try:
                    from amoskys.intel.soma_brain import SomaBrain

                    brain = SomaBrain()
                    stats = brain.get_stats()
                    lines = [
                        "SOMA Brain Status",
                        f"  Isolation Forest: {'available' if stats.get('model_adapter', {}).get('available') else 'not trained'}",
                        f"  Training events: {stats.get('training', {}).get('total_events', 0)}",
                        f"  Mode: {stats.get('mode', 'unknown')}",
                    ]
                    return jsonify({"output": "\n".join(lines), "cmd_type": "info"})
                except Exception as exc:
                    return jsonify(
                        {"output": f"SOMA unavailable: {exc}", "cmd_type": "error"}
                    )
            if sub == "train":
                return jsonify(
                    {
                        "output": "SOMA retraining queued. This may take a few minutes.",
                        "cmd_type": "system",
                    }
                )
            return jsonify(
                {"output": f"Unknown soma command: {sub}", "cmd_type": "error"}
            )

        # reliability
        if root == "reliability":
            try:
                from amoskys.intel.reliability_store import ReliabilityStore

                rs = ReliabilityStore()
                states = rs.get_all_states()
                if not states:
                    return jsonify(
                        {"output": "No reliability data yet.", "cmd_type": "info"}
                    )
                lines = ["Agent Reliability Scores", ""]
                for aid, st in sorted(states.items()):
                    score = (
                        round(st.reliability_score, 3)
                        if hasattr(st, "reliability_score")
                        else "?"
                    )
                    tier = st.tier.name if hasattr(st, "tier") and st.tier else "?"
                    lines.append(f"  {aid:<25s} score={score}  tier={tier}")
                return jsonify({"output": "\n".join(lines), "cmd_type": "info"})
            except Exception as exc:
                return jsonify(
                    {
                        "output": f"Reliability store unavailable: {exc}",
                        "cmd_type": "error",
                    }
                )

        # events [N]
        if root == "events":
            limit = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 10
            limit = min(limit, 50)
            try:
                store = importlib.import_module("amoskys.storage.telemetry_store")
                ts = store.TelemetryStore()
                rows = ts.db.execute(
                    "SELECT timestamp_dt, event_type, severity, device_id "
                    "FROM security_events ORDER BY timestamp_ns DESC LIMIT ?",
                    (limit,),
                ).fetchall()
                ts.close()
                if not rows:
                    return jsonify(
                        {
                            "output": "No security events recorded yet.",
                            "cmd_type": "info",
                        }
                    )
                lines = [f"Last {len(rows)} Security Events", ""]
                for r in rows:
                    lines.append(f"  [{r[2] or '?':>8s}] {r[0][:19]}  {r[1]}  ({r[3]})")
                return jsonify({"output": "\n".join(lines), "cmd_type": "info"})
            except Exception as exc:
                return jsonify(
                    {"output": f"Event query failed: {exc}", "cmd_type": "error"}
                )

        # igris *
        if root == "igris":
            if not igris:
                return jsonify(
                    {"output": "IGRIS supervisor is not running.", "cmd_type": "error"}
                )
            sub = parts[1].lower() if len(parts) > 1 else "status"

            if sub == "status":
                st = igris.get_status()
                lines = [
                    "IGRIS Supervisor Status",
                    f"  Status: {st.get('status', 'unknown')}",
                    f"  Cycle: #{st.get('cycle_count', 0)}",
                    f"  Duration: {st.get('cycle_duration_ms', 0)}ms",
                    f"  Signals: {st.get('active_signal_count', 0)} active / {st.get('signal_count_since_start', 0)} total",
                    f"  Coherence: {st.get('coherence', 'unknown')}",
                ]
                return jsonify({"output": "\n".join(lines), "cmd_type": "info"})

            if sub == "metrics":
                metrics = igris.get_metrics()
                if not metrics:
                    return jsonify(
                        {
                            "output": "No metrics collected yet (warmup?).",
                            "cmd_type": "info",
                        }
                    )
                lines = ["IGRIS Metrics Snapshot", ""]
                for k, v in sorted(metrics.items()):
                    lines.append(f"  {k}: {v}")
                return jsonify({"output": "\n".join(lines), "cmd_type": "info"})

            if sub == "coherence":
                co = igris.get_coherence()
                formatted = co.get("formatted")
                if formatted:
                    return jsonify({"output": formatted, "cmd_type": "info"})
                return jsonify(
                    {
                        "output": f"Verdict: {co.get('verdict', 'unknown')}",
                        "cmd_type": "info",
                    }
                )

            if sub == "signals":
                sigs = igris.get_signals(limit=20)
                if not sigs:
                    return jsonify(
                        {"output": "No governance signals.", "cmd_type": "success"}
                    )
                lines = [f"IGRIS Signals — {len(sigs)} recent", ""]
                for s in sigs:
                    cleared = " (cleared)" if s.get("cleared") else ""
                    lines.append(
                        f"  [{s.get('severity', '?'):>8s}] {s.get('id', '?')[:8]}  {s.get('reason', '')}{cleared}"
                    )
                return jsonify({"output": "\n".join(lines), "cmd_type": "info"})

            if sub == "baseline":
                metric = parts[2] if len(parts) > 2 else None
                baselines = igris.get_baselines()
                if metric:
                    bl = baselines.get(metric)
                    if not bl:
                        return jsonify(
                            {
                                "output": f"No baseline for metric: {metric}",
                                "cmd_type": "error",
                            }
                        )
                    lines = [f"Baseline: {metric}", ""]
                    for k, v in bl.items():
                        lines.append(f"  {k}: {v}")
                    return jsonify({"output": "\n".join(lines), "cmd_type": "info"})
                if not baselines:
                    return jsonify(
                        {
                            "output": "No baselines learned yet (warmup?).",
                            "cmd_type": "info",
                        }
                    )
                lines = [f"IGRIS Baselines — {len(baselines)} metrics", ""]
                for name in sorted(baselines.keys()):
                    bl = baselines[name]
                    ema = bl.get("ema", "?")
                    lines.append(f"  {name}: ema={ema}")
                return jsonify({"output": "\n".join(lines), "cmd_type": "info"})

            if sub == "explain":
                sig_id = parts[2] if len(parts) > 2 else None
                if not sig_id:
                    return jsonify(
                        {
                            "output": "Usage: igris explain <signal_id>",
                            "cmd_type": "error",
                        }
                    )
                formatted = igris.explain_signal_formatted(sig_id)
                if formatted:
                    return jsonify({"output": formatted, "cmd_type": "info"})
                return jsonify(
                    {"output": f"Signal not found: {sig_id}", "cmd_type": "error"}
                )

            if sub == "reset":
                result = igris.reset_baselines()
                return jsonify(
                    {
                        "output": result.get("message", "Reset complete."),
                        "cmd_type": "system",
                    }
                )

            return jsonify(
                {"output": f"Unknown igris command: {sub}", "cmd_type": "error"}
            )

        # start <agent_id>
        if root == "start" and len(parts) > 1:
            from .agent_control import start_agent

            result = start_agent(parts[1])
            return jsonify(
                {"output": result.get("message", str(result)), "cmd_type": "info"}
            )

        return jsonify(
            {
                "output": f"Unknown command: {cmd}\nType 'help' for available commands.",
                "cmd_type": "error",
            }
        )

    except Exception as exc:
        return jsonify({"output": f"Command error: {exc}", "cmd_type": "error"})
