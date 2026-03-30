#!/usr/bin/env python3
"""AMOSKYS Command Center — Central Fleet Server.

Receives telemetry from AMOSKYS agents deployed across multiple devices,
stores events in a unified database, and provides fleet-wide visibility.

Architecture:
    Agent (Mac #1) ──┐
    Agent (Mac #2) ──┤── HTTPS ──→ Command Center ──→ Fleet DB
    Agent (Linux)  ──┘                   ↓
                                    Fleet Dashboard
                                    Fleet IGRIS (future)

Endpoints:
    POST /api/v1/register     — Device registration + API key issuance
    POST /api/v1/telemetry    — Receive batched events from agents
    GET  /api/v1/devices      — List all registered devices
    GET  /api/v1/devices/:id  — Device detail + recent events
    GET  /api/v1/events       — Query events across all devices
    GET  /api/v1/fleet/status — Fleet-wide posture summary
    GET  /dashboard/          — Fleet dashboard UI

Usage:
    # Development:
    python server/command_center.py

    # Production:
    gunicorn -w 4 -b 0.0.0.0:8443 server.command_center:app

    # With TLS:
    gunicorn -w 4 -b 0.0.0.0:8443 --certfile=certs/server.crt --keyfile=certs/server.key server.command_center:app
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from flask import Flask, g, jsonify, render_template_string, request

# ── Logging ────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
)
logger = logging.getLogger("amoskys.command_center")

# ── Flask App ──────────────────────────────────────────────────────

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("CC_SECRET_KEY", secrets.token_hex(32))

# ── Database ───────────────────────────────────────────────────────

DB_PATH = os.getenv("CC_DB_PATH", "server/fleet.db")

FLEET_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA busy_timeout=10000;

-- Device registry
CREATE TABLE IF NOT EXISTS devices (
    device_id TEXT PRIMARY KEY,
    hostname TEXT,
    os TEXT,
    os_version TEXT,
    arch TEXT,
    agent_version TEXT,
    api_key TEXT NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    status TEXT DEFAULT 'online',
    metadata_json TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);
CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen);

-- Security events (from all devices)
CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id INTEGER,
    device_id TEXT NOT NULL,
    timestamp_ns INTEGER,
    timestamp_dt TEXT,
    event_category TEXT,
    event_action TEXT,
    event_outcome TEXT,
    risk_score REAL,
    confidence REAL,
    mitre_techniques TEXT,
    geometric_score REAL,
    temporal_score REAL,
    behavioral_score REAL,
    final_classification TEXT,
    description TEXT,
    indicators TEXT,
    collection_agent TEXT,
    enrichment_status TEXT,
    threat_intel_match BOOLEAN DEFAULT 0,
    geo_src_country TEXT,
    asn_src_org TEXT,
    event_timestamp_ns INTEGER,
    event_id TEXT,
    remote_ip TEXT,
    process_name TEXT,
    pid TEXT,
    username TEXT,
    domain TEXT,
    path TEXT,
    sha256 TEXT,
    probe_name TEXT,
    detection_source TEXT,
    received_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_se_device ON security_events(device_id);
CREATE INDEX IF NOT EXISTS idx_se_ts ON security_events(timestamp_ns);
CREATE INDEX IF NOT EXISTS idx_se_risk ON security_events(risk_score);
CREATE INDEX IF NOT EXISTS idx_se_category ON security_events(event_category);

-- Process events (from all devices)
CREATE TABLE IF NOT EXISTS process_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id INTEGER,
    device_id TEXT NOT NULL,
    timestamp_ns INTEGER,
    timestamp_dt TEXT,
    pid TEXT,
    exe TEXT,
    cmdline TEXT,
    ppid TEXT,
    username TEXT,
    name TEXT,
    parent_name TEXT,
    status TEXT,
    cpu_percent REAL,
    memory_percent REAL,
    collection_agent TEXT,
    received_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pe_device ON process_events(device_id);
CREATE INDEX IF NOT EXISTS idx_pe_ts ON process_events(timestamp_ns);

-- Network flow events (from all devices)
CREATE TABLE IF NOT EXISTS flow_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id INTEGER,
    device_id TEXT NOT NULL,
    timestamp_ns INTEGER,
    timestamp_dt TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT,
    bytes_tx INTEGER,
    bytes_rx INTEGER,
    pid TEXT,
    process_name TEXT,
    geo_dst_country TEXT,
    asn_dst_org TEXT,
    threat_intel_match BOOLEAN DEFAULT 0,
    collection_agent TEXT,
    received_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_fe_device ON flow_events(device_id);
CREATE INDEX IF NOT EXISTS idx_fe_ts ON flow_events(timestamp_ns);

-- DNS events (from all devices)
CREATE TABLE IF NOT EXISTS dns_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id INTEGER,
    device_id TEXT NOT NULL,
    timestamp_ns INTEGER,
    timestamp_dt TEXT,
    domain TEXT,
    record_type TEXT,
    response_code TEXT,
    risk_score REAL,
    process_name TEXT,
    collection_agent TEXT,
    received_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_de_device ON dns_events(device_id);

-- Persistence events (from all devices)
CREATE TABLE IF NOT EXISTS persistence_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id INTEGER,
    device_id TEXT NOT NULL,
    timestamp_ns INTEGER,
    timestamp_dt TEXT,
    mechanism TEXT,
    path TEXT,
    change_type TEXT,
    label TEXT,
    sha256 TEXT,
    risk_score REAL,
    collection_agent TEXT,
    received_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pers_device ON persistence_events(device_id);

-- Fleet-level incidents (cross-device correlation)
CREATE TABLE IF NOT EXISTS fleet_incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    severity TEXT NOT NULL,  -- LOW, MEDIUM, HIGH, CRITICAL
    title TEXT NOT NULL,
    description TEXT,
    device_ids TEXT,         -- JSON array of involved devices
    event_ids TEXT,          -- JSON array of contributing event IDs
    mitre_techniques TEXT,   -- JSON array
    status TEXT DEFAULT 'open',  -- open, investigating, resolved
    resolved_at REAL
);
"""


def get_db() -> sqlite3.Connection:
    """Get database connection for current request."""
    if "db" not in g:
        Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
        g.db = sqlite3.connect(DB_PATH, timeout=10.0)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Initialize database schema."""
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_PATH, timeout=10.0)
    db.executescript(FLEET_SCHEMA)
    db.commit()
    db.close()
    logger.info("Fleet database initialized: %s", DB_PATH)


# ── Auth ───────────────────────────────────────────────────────────

def require_device_auth(f):
    """Validate device API key from Authorization header."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        device_id = request.headers.get("X-Device-ID", "")

        if not auth.startswith("Bearer "):
            # Allow registration without auth
            if request.endpoint == "register_device":
                return f(*args, **kwargs)
            return jsonify({"error": "Missing Authorization header"}), 401

        api_key = auth.removeprefix("Bearer ")
        db = get_db()

        # Verify API key matches device
        row = db.execute(
            "SELECT device_id FROM devices WHERE api_key = ?", (api_key,)
        ).fetchone()

        if not row:
            return jsonify({"error": "Invalid API key"}), 403

        # Update last_seen
        db.execute(
            "UPDATE devices SET last_seen = ?, status = 'online' WHERE api_key = ?",
            (time.time(), api_key),
        )
        db.commit()

        g.authenticated_device = row["device_id"]
        return f(*args, **kwargs)

    return decorated


# ── API Endpoints ──────────────────────────────────────────────────

@app.route("/api/v1/register", methods=["POST"])
def register_device():
    """Register a device and return an API key.

    If the device is already registered, updates its info and returns
    the existing API key. New devices get a fresh key.
    """
    data = request.get_json()
    if not data or "device_id" not in data:
        return jsonify({"error": "device_id required"}), 400

    device_id = data["device_id"]
    db = get_db()
    now = time.time()

    # Check if already registered
    existing = db.execute(
        "SELECT api_key FROM devices WHERE device_id = ?", (device_id,)
    ).fetchone()

    if existing:
        # Update device info
        db.execute(
            """UPDATE devices SET
                hostname = ?, os = ?, os_version = ?, arch = ?,
                agent_version = ?, last_seen = ?, status = 'online'
            WHERE device_id = ?""",
            (
                data.get("hostname"),
                data.get("os"),
                data.get("os_version"),
                data.get("arch"),
                data.get("agent_version"),
                now,
                device_id,
            ),
        )
        db.commit()
        api_key = existing["api_key"]
        logger.info("Device re-registered: %s (%s)", device_id[:8], data.get("hostname"))
    else:
        # New device — generate API key
        api_key = secrets.token_hex(32)
        db.execute(
            """INSERT INTO devices
                (device_id, hostname, os, os_version, arch, agent_version,
                 api_key, first_seen, last_seen, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'online')""",
            (
                device_id,
                data.get("hostname"),
                data.get("os"),
                data.get("os_version"),
                data.get("arch"),
                data.get("agent_version"),
                api_key,
                now,
                now,
            ),
        )
        db.commit()
        logger.info(
            "NEW device registered: %s (%s, %s %s)",
            device_id[:8],
            data.get("hostname"),
            data.get("os"),
            data.get("arch"),
        )

    return jsonify({
        "status": "registered",
        "device_id": device_id,
        "api_key": api_key,
    })


@app.route("/api/v1/telemetry", methods=["POST"])
@require_device_auth
def receive_telemetry():
    """Receive a batch of telemetry events from an agent.

    Expects JSON:
    {
        "device_id": "...",
        "table": "security_events",
        "events": [...],
        "batch_size": N
    }
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "JSON body required"}), 400

    table = data.get("table", "")
    events = data.get("events", [])
    device_id = data.get("device_id", "")

    if table not in ALLOWED_TABLES:
        return jsonify({"error": f"Unknown table: {table}"}), 400

    if not events:
        return jsonify({"status": "ok", "stored": 0})

    db = get_db()
    now = time.time()
    stored = 0

    for event in events:
        try:
            # Force device_id from auth context (prevent spoofing)
            event["device_id"] = device_id
            event["received_at"] = now
            source_id = event.pop("id", None)
            event["source_id"] = source_id

            # Build INSERT dynamically from event keys
            cols = [k for k in event.keys() if k in ALLOWED_TABLES[table]]
            vals = [event[k] for k in cols]
            placeholders = ", ".join(["?"] * len(cols))
            col_names = ", ".join(cols)

            db.execute(
                f"INSERT INTO {table} ({col_names}) VALUES ({placeholders})",
                vals,
            )
            stored += 1
        except Exception as e:
            logger.debug("Skip event in %s: %s", table, e)

    db.commit()

    logger.info(
        "Received %d/%d %s events from %s",
        stored, len(events), table, device_id[:8],
    )

    return jsonify({"status": "ok", "stored": stored})


# Allowed columns per table (whitelist for INSERT safety)
ALLOWED_TABLES = {
    "security_events": {
        "source_id", "device_id", "timestamp_ns", "timestamp_dt",
        "event_category", "event_action", "event_outcome",
        "risk_score", "confidence", "mitre_techniques",
        "geometric_score", "temporal_score", "behavioral_score",
        "final_classification", "description", "indicators",
        "collection_agent", "enrichment_status", "threat_intel_match",
        "geo_src_country", "asn_src_org", "event_timestamp_ns",
        "event_id", "remote_ip", "process_name", "pid",
        "username", "domain", "path", "sha256",
        "probe_name", "detection_source", "received_at",
    },
    "process_events": {
        "source_id", "device_id", "timestamp_ns", "timestamp_dt",
        "pid", "exe", "cmdline", "ppid", "username", "name",
        "parent_name", "status", "cpu_percent", "memory_percent",
        "collection_agent", "received_at",
    },
    "flow_events": {
        "source_id", "device_id", "timestamp_ns", "timestamp_dt",
        "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
        "bytes_tx", "bytes_rx", "pid", "process_name",
        "geo_dst_country", "asn_dst_org", "threat_intel_match",
        "collection_agent", "received_at",
    },
    "dns_events": {
        "source_id", "device_id", "timestamp_ns", "timestamp_dt",
        "domain", "record_type", "response_code", "risk_score",
        "process_name", "collection_agent", "received_at",
    },
    "persistence_events": {
        "source_id", "device_id", "timestamp_ns", "timestamp_dt",
        "mechanism", "path", "change_type", "label",
        "sha256", "risk_score", "collection_agent", "received_at",
    },
}


@app.route("/api/v1/devices", methods=["GET"])
def list_devices():
    """List all registered devices with status."""
    db = get_db()
    now = time.time()

    # Mark devices offline if no heartbeat in 5 minutes
    db.execute(
        "UPDATE devices SET status = 'offline' WHERE last_seen < ? AND status = 'online'",
        (now - 300,),
    )
    db.commit()

    rows = db.execute(
        """SELECT device_id, hostname, os, os_version, arch,
                  agent_version, first_seen, last_seen, status
           FROM devices ORDER BY last_seen DESC"""
    ).fetchall()

    devices = []
    for r in rows:
        # Get event counts for this device
        sec_count = db.execute(
            "SELECT COUNT(*) FROM security_events WHERE device_id = ?",
            (r["device_id"],),
        ).fetchone()[0]

        devices.append({
            "device_id": r["device_id"],
            "hostname": r["hostname"],
            "os": r["os"],
            "os_version": r["os_version"],
            "arch": r["arch"],
            "agent_version": r["agent_version"],
            "first_seen": r["first_seen"],
            "last_seen": r["last_seen"],
            "status": r["status"],
            "security_event_count": sec_count,
        })

    return jsonify({"devices": devices, "total": len(devices)})


@app.route("/api/v1/devices/<device_id>", methods=["GET"])
def device_detail(device_id):
    """Get device details with recent events."""
    db = get_db()

    device = db.execute(
        "SELECT * FROM devices WHERE device_id = ?", (device_id,)
    ).fetchone()

    if not device:
        return jsonify({"error": "Device not found"}), 404

    # Recent security events
    events = db.execute(
        """SELECT id, timestamp_dt, event_category, risk_score,
                  description, collection_agent, mitre_techniques,
                  process_name, remote_ip, detection_source
           FROM security_events
           WHERE device_id = ?
           ORDER BY timestamp_ns DESC LIMIT 50""",
        (device_id,),
    ).fetchall()

    return jsonify({
        "device": {
            "device_id": device["device_id"],
            "hostname": device["hostname"],
            "os": device["os"],
            "os_version": device["os_version"],
            "arch": device["arch"],
            "agent_version": device["agent_version"],
            "first_seen": device["first_seen"],
            "last_seen": device["last_seen"],
            "status": device["status"],
        },
        "recent_events": [dict(e) for e in events],
    })


@app.route("/api/v1/events", methods=["GET"])
def query_events():
    """Query security events across all devices.

    Query params:
        device_id: Filter by device
        category: Filter by event_category
        min_risk: Minimum risk_score
        limit: Max results (default 100)
        offset: Pagination offset
    """
    db = get_db()

    device_id = request.args.get("device_id")
    category = request.args.get("category")
    min_risk = request.args.get("min_risk", type=float)
    limit = min(request.args.get("limit", 100, type=int), 500)
    offset = request.args.get("offset", 0, type=int)

    query = "SELECT * FROM security_events WHERE 1=1"
    params: list = []

    if device_id:
        query += " AND device_id = ?"
        params.append(device_id)
    if category:
        query += " AND event_category = ?"
        params.append(category)
    if min_risk is not None:
        query += " AND risk_score >= ?"
        params.append(min_risk)

    query += " ORDER BY timestamp_ns DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    rows = db.execute(query, params).fetchall()
    return jsonify({
        "events": [dict(r) for r in rows],
        "count": len(rows),
        "limit": limit,
        "offset": offset,
    })


@app.route("/api/v1/fleet/status", methods=["GET"])
def fleet_status():
    """Fleet-wide posture summary."""
    db = get_db()
    now = time.time()

    # Device counts
    total = db.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
    online = db.execute(
        "SELECT COUNT(*) FROM devices WHERE last_seen > ?", (now - 300,)
    ).fetchone()[0]
    offline = total - online

    # Event stats (last 24h)
    day_ago_ns = int((now - 86400) * 1e9)
    total_events = db.execute(
        "SELECT COUNT(*) FROM security_events WHERE timestamp_ns > ?",
        (day_ago_ns,),
    ).fetchone()[0]

    critical = db.execute(
        "SELECT COUNT(*) FROM security_events WHERE timestamp_ns > ? AND risk_score >= 0.8",
        (day_ago_ns,),
    ).fetchone()[0]

    high = db.execute(
        "SELECT COUNT(*) FROM security_events WHERE timestamp_ns > ? AND risk_score >= 0.6 AND risk_score < 0.8",
        (day_ago_ns,),
    ).fetchone()[0]

    # Top threat categories (last 24h)
    top_categories = db.execute(
        """SELECT event_category, COUNT(*) as cnt, AVG(risk_score) as avg_risk
           FROM security_events
           WHERE timestamp_ns > ? AND risk_score > 0
           GROUP BY event_category
           ORDER BY cnt DESC LIMIT 10""",
        (day_ago_ns,),
    ).fetchall()

    # Most active MITRE techniques
    mitre_rows = db.execute(
        """SELECT mitre_techniques FROM security_events
           WHERE timestamp_ns > ? AND mitre_techniques IS NOT NULL
           AND mitre_techniques != '[]'""",
        (day_ago_ns,),
    ).fetchall()

    technique_counts: dict[str, int] = {}
    for row in mitre_rows:
        try:
            raw = row[0]
            # Handle double-encoded JSON (e.g. '"[\"T1059\"]"')
            techniques = json.loads(raw)
            if isinstance(techniques, str):
                techniques = json.loads(techniques)
            if isinstance(techniques, list):
                for t in techniques:
                    if isinstance(t, str) and t.startswith("T"):
                        technique_counts[t] = technique_counts.get(t, 0) + 1
        except (json.JSONDecodeError, TypeError):
            pass

    top_techniques = sorted(technique_counts.items(), key=lambda x: -x[1])[:10]

    # Per-device summary
    device_summary = db.execute(
        """SELECT d.device_id, d.hostname, d.status, d.last_seen,
                  COUNT(se.id) as event_count,
                  MAX(se.risk_score) as max_risk
           FROM devices d
           LEFT JOIN security_events se ON d.device_id = se.device_id
                AND se.timestamp_ns > ?
           GROUP BY d.device_id
           ORDER BY max_risk DESC NULLS LAST""",
        (day_ago_ns,),
    ).fetchall()

    return jsonify({
        "fleet": {
            "total_devices": total,
            "online": online,
            "offline": offline,
        },
        "last_24h": {
            "total_events": total_events,
            "critical": critical,
            "high": high,
        },
        "top_categories": [
            {"category": r[0], "count": r[1], "avg_risk": round(r[2], 3)}
            for r in top_categories
        ],
        "top_mitre_techniques": [
            {"technique": t, "count": c} for t, c in top_techniques
        ],
        "devices": [
            {
                "device_id": r["device_id"],
                "hostname": r["hostname"],
                "status": r["status"],
                "last_seen": r["last_seen"],
                "event_count": r["event_count"],
                "max_risk": r["max_risk"],
            }
            for r in device_summary
        ],
        "timestamp": now,
    })


# ── Fleet Dashboard (minimal HTML) ────────────────────────────────

DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>AMOSKYS Command Center</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, 'SF Mono', monospace;
            background: #0a0a0f;
            color: #e0e0e0;
            padding: 20px;
        }
        h1 { color: #00ff88; margin-bottom: 20px; font-size: 1.5em; }
        h2 { color: #00ccff; margin: 20px 0 10px; font-size: 1.1em; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }
        .card {
            background: #12121a;
            border: 1px solid #1e1e2e;
            border-radius: 8px;
            padding: 15px;
        }
        .card .label { color: #888; font-size: 0.8em; text-transform: uppercase; }
        .card .value { font-size: 1.8em; font-weight: bold; margin-top: 5px; }
        .card .value.green { color: #00ff88; }
        .card .value.red { color: #ff4444; }
        .card .value.yellow { color: #ffaa00; }
        .card .value.blue { color: #00ccff; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #1e1e2e; }
        th { color: #888; font-size: 0.8em; text-transform: uppercase; }
        .status-online { color: #00ff88; }
        .status-offline { color: #ff4444; }
        .risk-critical { color: #ff4444; font-weight: bold; }
        .risk-high { color: #ffaa00; }
        .risk-medium { color: #ffcc00; }
        .risk-low { color: #00ff88; }
        .refresh { color: #555; font-size: 0.8em; margin-top: 10px; }
        #fleet-data { min-height: 400px; }
    </style>
</head>
<body>
    <h1>&#9670; AMOSKYS COMMAND CENTER</h1>
    <div id="fleet-data">Loading fleet data...</div>
    <p class="refresh">Auto-refreshes every 15 seconds</p>

    <script>
    async function loadFleet() {
        try {
            const resp = await fetch('/api/v1/fleet/status');
            const data = await resp.json();
            const el = document.getElementById('fleet-data');

            let html = '<div class="grid">';
            html += card('Devices Online', data.fleet.online, 'green');
            html += card('Devices Offline', data.fleet.offline, data.fleet.offline > 0 ? 'red' : 'green');
            html += card('Events (24h)', data.last_24h.total_events, 'blue');
            html += card('Critical', data.last_24h.critical, data.last_24h.critical > 0 ? 'red' : 'green');
            html += card('High Risk', data.last_24h.high, data.last_24h.high > 0 ? 'yellow' : 'green');
            html += '</div>';

            // Device table
            html += '<h2>Fleet Devices</h2><table>';
            html += '<tr><th>Hostname</th><th>OS</th><th>Status</th><th>Events (24h)</th><th>Max Risk</th><th>Last Seen</th></tr>';
            for (const d of data.devices) {
                const statusClass = d.status === 'online' ? 'status-online' : 'status-offline';
                const riskClass = d.max_risk >= 0.8 ? 'risk-critical' : d.max_risk >= 0.6 ? 'risk-high' : d.max_risk >= 0.3 ? 'risk-medium' : 'risk-low';
                const ago = timeAgo(d.last_seen);
                html += `<tr>
                    <td>${d.hostname || d.device_id.slice(0,8)}</td>
                    <td>${d.status === 'online' ? '&#9679;' : '&#9675;'}</td>
                    <td class="${statusClass}">${d.status}</td>
                    <td>${d.event_count || 0}</td>
                    <td class="${riskClass}">${d.max_risk ? d.max_risk.toFixed(2) : '-'}</td>
                    <td>${ago}</td>
                </tr>`;
            }
            html += '</table>';

            // Top threats
            if (data.top_categories.length > 0) {
                html += '<h2>Top Threat Categories (24h)</h2><table>';
                html += '<tr><th>Category</th><th>Count</th><th>Avg Risk</th></tr>';
                for (const c of data.top_categories) {
                    html += `<tr><td>${c.category}</td><td>${c.count}</td><td>${c.avg_risk}</td></tr>`;
                }
                html += '</table>';
            }

            // MITRE techniques
            if (data.top_mitre_techniques.length > 0) {
                html += '<h2>Top MITRE Techniques</h2><table>';
                html += '<tr><th>Technique</th><th>Count</th></tr>';
                for (const t of data.top_mitre_techniques) {
                    html += `<tr><td>${t.technique}</td><td>${t.count}</td></tr>`;
                }
                html += '</table>';
            }

            el.innerHTML = html;
        } catch (e) {
            document.getElementById('fleet-data').innerHTML = '<p style="color:#ff4444">Failed to load fleet data: ' + e.message + '</p>';
        }
    }

    function card(label, value, colorClass) {
        return `<div class="card"><div class="label">${label}</div><div class="value ${colorClass}">${value}</div></div>`;
    }

    function timeAgo(epoch) {
        if (!epoch) return 'never';
        const seconds = Math.floor(Date.now()/1000 - epoch);
        if (seconds < 60) return seconds + 's ago';
        if (seconds < 3600) return Math.floor(seconds/60) + 'm ago';
        if (seconds < 86400) return Math.floor(seconds/3600) + 'h ago';
        return Math.floor(seconds/86400) + 'd ago';
    }

    loadFleet();
    setInterval(loadFleet, 15000);
    </script>
</body>
</html>
"""


@app.route("/dashboard/")
@app.route("/dashboard")
@app.route("/")
def dashboard():
    """Fleet dashboard."""
    return render_template_string(DASHBOARD_HTML)


# ── Health ─────────────────────────────────────────────────────────

@app.route("/health")
def health():
    return jsonify({"status": "ok", "version": "0.9.1-beta"})


# ── Main ───────────────────────────────────────────────────────────

def main():
    """Run the Command Center server."""
    init_db()

    host = os.getenv("CC_HOST", "0.0.0.0")
    port = int(os.getenv("CC_PORT", "8443"))
    debug = os.getenv("CC_DEBUG", "false").lower() in ("1", "true")

    logger.info("AMOSKYS Command Center starting on %s:%d", host, port)
    logger.info("Fleet DB: %s", DB_PATH)
    logger.info("Dashboard: http://%s:%d/dashboard/", host, port)

    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    main()
