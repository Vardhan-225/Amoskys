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
    org_id TEXT,
    user_id TEXT,
    deploy_token_hash TEXT,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    status TEXT DEFAULT 'online',
    public_ip TEXT,
    metadata_json TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);
CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen);
CREATE INDEX IF NOT EXISTS idx_devices_org ON devices(org_id);

-- Security events (from all devices)
CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id INTEGER,
    device_id TEXT NOT NULL,
    org_id TEXT,
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
    cmdline TEXT,
    exe TEXT,
    remote_port INTEGER,
    protocol TEXT,
    geo_src_city TEXT,
    geo_src_latitude REAL,
    geo_src_longitude REAL,
    asn_src_number INTEGER,
    asn_src_network_type TEXT,
    received_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_se_device ON security_events(device_id);
CREATE INDEX IF NOT EXISTS idx_se_ts ON security_events(timestamp_ns);
CREATE INDEX IF NOT EXISTS idx_se_risk ON security_events(risk_score);
CREATE INDEX IF NOT EXISTS idx_se_category ON security_events(event_category);
CREATE INDEX IF NOT EXISTS idx_se_dedup ON security_events(source_id, device_id);

-- Process events (from all devices)
CREATE TABLE IF NOT EXISTS process_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id INTEGER,
    device_id TEXT NOT NULL,
    org_id TEXT,
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
CREATE INDEX IF NOT EXISTS idx_pe_dedup ON process_events(source_id, device_id);

-- Network flow events (from all devices)
CREATE TABLE IF NOT EXISTS flow_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id INTEGER,
    device_id TEXT NOT NULL,
    org_id TEXT,
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
    geo_dst_latitude REAL,
    geo_dst_longitude REAL,
    geo_dst_country TEXT,
    geo_dst_city TEXT,
    asn_dst_org TEXT,
    threat_intel_match BOOLEAN DEFAULT 0,
    collection_agent TEXT,
    received_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_fe_device ON flow_events(device_id);
CREATE INDEX IF NOT EXISTS idx_fe_ts ON flow_events(timestamp_ns);
CREATE INDEX IF NOT EXISTS idx_fe_dedup ON flow_events(source_id, device_id);

-- DNS events (from all devices)
CREATE TABLE IF NOT EXISTS dns_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id INTEGER,
    device_id TEXT NOT NULL,
    org_id TEXT,
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
CREATE INDEX IF NOT EXISTS idx_de_dedup ON dns_events(source_id, device_id);
CREATE INDEX IF NOT EXISTS idx_de_ts ON dns_events(timestamp_ns);

-- Persistence events (from all devices)
CREATE TABLE IF NOT EXISTS persistence_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id INTEGER,
    device_id TEXT NOT NULL,
    org_id TEXT,
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
CREATE INDEX IF NOT EXISTS idx_pers_dedup ON persistence_events(source_id, device_id);
CREATE INDEX IF NOT EXISTS idx_pers_ts ON persistence_events(timestamp_ns);

-- FIM events (from all devices)
CREATE TABLE IF NOT EXISTS fim_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id INTEGER,
    device_id TEXT NOT NULL,
    org_id TEXT,
    timestamp_ns INTEGER,
    timestamp_dt TEXT,
    path TEXT,
    file_extension TEXT,
    change_type TEXT,
    new_hash TEXT,
    owner_uid INTEGER,
    is_suid BOOLEAN,
    mtime TEXT,
    size INTEGER,
    risk_score REAL,
    event_type TEXT,
    collection_agent TEXT,
    received_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_fim_device ON fim_events(device_id);
CREATE INDEX IF NOT EXISTS idx_fim_dedup ON fim_events(source_id, device_id);
CREATE INDEX IF NOT EXISTS idx_fim_ts ON fim_events(timestamp_ns);

-- Audit events (from all devices)
CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id INTEGER,
    device_id TEXT NOT NULL,
    org_id TEXT,
    timestamp_ns INTEGER,
    timestamp_dt TEXT,
    event_type TEXT,
    pid TEXT,
    ppid TEXT,
    uid TEXT,
    username TEXT,
    risk_score REAL,
    collection_agent TEXT,
    received_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_device ON audit_events(device_id);
CREATE INDEX IF NOT EXISTS idx_audit_dedup ON audit_events(source_id, device_id);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(timestamp_ns);

-- Observation events (from all devices)
CREATE TABLE IF NOT EXISTS observation_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id INTEGER,
    device_id TEXT NOT NULL,
    org_id TEXT,
    event_id TEXT,
    domain TEXT,
    event_timestamp_ns INTEGER,
    raw_attributes_json TEXT,
    received_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_obs_device ON observation_events(device_id);

-- Peripheral events (from all devices)
CREATE TABLE IF NOT EXISTS peripheral_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id INTEGER,
    device_id TEXT NOT NULL,
    org_id TEXT,
    timestamp_ns INTEGER,
    timestamp_dt TEXT,
    peripheral_device_id TEXT,
    event_type TEXT,
    device_name TEXT,
    device_type TEXT,
    vendor_id TEXT,
    risk_score REAL,
    collection_agent TEXT,
    received_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_periph_device ON peripheral_events(device_id);
CREATE INDEX IF NOT EXISTS idx_periph_dedup ON peripheral_events(source_id, device_id);
CREATE INDEX IF NOT EXISTS idx_periph_ts ON peripheral_events(timestamp_ns);

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
    # Migrate: add columns if missing (existing DBs)
    for col, ctype in [
        ("geo_dst_latitude", "REAL"),
        ("geo_dst_longitude", "REAL"),
        ("geo_dst_city", "TEXT"),
    ]:
        try:
            db.execute(f"ALTER TABLE flow_events ADD COLUMN {col} {ctype}")
        except sqlite3.OperationalError:
            pass
    for col, ctype in [
        ("public_ip", "TEXT"),
    ]:
        try:
            db.execute(f"ALTER TABLE devices ADD COLUMN {col} {ctype}")
        except sqlite3.OperationalError:
            pass  # column already exists
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
            logger.warning("AUTH_FAIL: key=%s (len=%d)", api_key, len(api_key))
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

    Supports two flows:
    1. With deploy_token: validates token, links device to user's org
    2. Without token: anonymous registration (Global view only)

    If the device is already registered, updates its info (heartbeat).
    """
    data = request.get_json()
    if not data or "device_id" not in data:
        return jsonify({"error": "device_id required"}), 400

    device_id = data["device_id"]
    hostname = data.get("hostname", "")
    deploy_token = data.get("deploy_token", "")
    db = get_db()
    now = time.time()

    # Check if already registered — by device_id OR by hostname
    # This prevents duplicate devices when the same Mac reinstalls
    existing = db.execute(
        "SELECT device_id, api_key, org_id FROM devices WHERE device_id = ? OR hostname = ?",
        (device_id, hostname),
    ).fetchone()

    if existing:
        # Use the ORIGINAL device_id (not the new one) to prevent duplicates
        original_device_id = existing["device_id"]

        # Heartbeat — update device info + capture public IP
        public_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        if public_ip and "," in public_ip:
            public_ip = public_ip.split(",")[0].strip()
        db.execute(
            """UPDATE devices SET
                hostname = ?, os = ?, os_version = ?, arch = ?,
                agent_version = ?, last_seen = ?, status = 'online',
                device_id = ?, public_ip = ?
            WHERE device_id = ?""",
            (
                hostname,
                data.get("os"),
                data.get("os_version"),
                data.get("arch"),
                data.get("agent_version"),
                now,
                device_id,  # Update to new device_id if it changed
                public_ip,
                original_device_id,
            ),
        )
        db.commit()

        # If device_id changed (reinstall), return the api_key so agent can use it
        if original_device_id != device_id:
            logger.info("Device re-registered: %s → %s (%s)", original_device_id[:8], device_id[:8], hostname)
            return jsonify({
                "status": "registered",
                "device_id": device_id,
                "api_key": existing["api_key"],
            })

        # Always return api_key so agent can recover after wipe/reinstall
        logger.debug("Heartbeat: %s (%s)", device_id[:8], hostname)
        return jsonify({
            "status": "registered",
            "device_id": device_id,
            "api_key": existing["api_key"],
        })

    # New device — resolve org from payload or deployment token
    org_id = data.get("org_id") or None  # Sent directly by shipper
    user_id = None
    token_hash = None

    if deploy_token and not org_id:
        # Fallback: hash the token and look it up in the web DB
        token_hash = hashlib.sha256(deploy_token.encode()).hexdigest()
        org_id, user_id = _resolve_token_org(token_hash)

    if org_id:
            logger.info(
                "Token validated: device=%s org=%s user=%s",
                device_id[:8], org_id[:8], (user_id or "")[:8],
            )

    # Generate API key
    api_key = secrets.token_hex(32)
    db.execute(
        """INSERT INTO devices
            (device_id, hostname, os, os_version, arch, agent_version,
             api_key, org_id, user_id, deploy_token_hash,
             first_seen, last_seen, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'online')""",
        (
            device_id,
            data.get("hostname"),
            data.get("os"),
            data.get("os_version"),
            data.get("arch"),
            data.get("agent_version"),
            api_key,
            org_id,
            user_id,
            token_hash,
            now,
            now,
        ),
    )
    db.commit()
    logger.info(
        "NEW device: %s (%s, %s %s) org=%s",
        device_id[:8],
        data.get("hostname"),
        data.get("os"),
        data.get("arch"),
        (org_id or "global")[:8],
    )

    return jsonify({
        "status": "registered",
        "device_id": device_id,
        "api_key": api_key,
    })


def _resolve_token_org(token_hash: str) -> tuple[str | None, str | None]:
    """Look up org_id and user_id from a deployment token hash.

    Checks the web database (amoskys.com) for the token.
    Returns (org_id, user_id) or (None, None) if not found.
    """
    # Try to connect to web DB for token validation
    web_db_candidates = [
        os.getenv("AMOSKYS_WEB_DB_PATH", ""),
        "web/data/amoskys_web.db",
        "/opt/amoskys/web/data/amoskys_web.db",
    ]

    for path in web_db_candidates:
        if not path or not os.path.exists(path):
            continue
        try:
            web_db = sqlite3.connect(path, timeout=5.0)
            web_db.row_factory = sqlite3.Row

            # Look up token → user_id
            row = web_db.execute(
                """SELECT user_id FROM agent_tokens
                   WHERE token_hash = ? AND is_consumed = 0
                   AND (expires_at IS NULL OR expires_at > datetime('now'))""",
                (token_hash,),
            ).fetchone()

            if not row:
                web_db.close()
                continue

            user_id = row["user_id"]

            # Mark token as consumed
            web_db.execute(
                "UPDATE agent_tokens SET is_consumed = 1, consumed_at = datetime('now') WHERE token_hash = ?",
                (token_hash,),
            )
            web_db.commit()

            # Look up user → org_id
            user_row = web_db.execute(
                "SELECT org_id FROM users WHERE id = ?", (user_id,)
            ).fetchone()

            web_db.close()

            org_id = user_row["org_id"] if user_row else None
            return org_id, user_id

        except Exception as e:
            logger.debug("Token lookup failed in %s: %s", path, e)

    return None, None


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
    # Use the authenticated device_id (from API key lookup) — not what
    # the shipper claims.  This handles device ID changes after reinstall.
    device_id = g.authenticated_device or data.get("device_id", "")

    if table not in ALLOWED_TABLES:
        return jsonify({"error": f"Unknown table: {table}"}), 400

    if not events:
        return jsonify({"status": "ok", "stored": 0})

    db = get_db()
    now = time.time()
    stored = 0

    # Look up org_id for this device (cached per request)
    device_row = db.execute(
        "SELECT org_id FROM devices WHERE device_id = ?", (device_id,)
    ).fetchone()
    org_id = device_row["org_id"] if device_row else None

    # Pre-fetch existing source_ids for this device in one query (batch dedup)
    # Instead of N individual SELECT queries, do one set lookup.
    source_ids = [e.get("id") for e in events if e.get("id") is not None]
    existing_ids: set = set()
    if source_ids:
        # Query in batches of 500 to avoid SQLite variable limit
        for i in range(0, len(source_ids), 500):
            batch = source_ids[i:i + 500]
            placeholders = ",".join("?" * len(batch))
            try:
                rows = db.execute(
                    f"SELECT source_id FROM {table} WHERE device_id = ? "
                    f"AND source_id IN ({placeholders})",
                    [device_id] + batch,
                ).fetchall()
                existing_ids.update(r[0] for r in rows)
            except Exception:
                pass

    allowed_cols = ALLOWED_TABLES[table]

    for event in events:
        try:
            # Force device_id and org_id from server context (prevent spoofing)
            event["device_id"] = device_id
            event["org_id"] = org_id
            event["received_at"] = now
            source_id = event.pop("id", None)
            event["source_id"] = source_id

            # Batch dedup: skip if source_id already exists
            if source_id is not None and source_id in existing_ids:
                continue

            # Build INSERT dynamically from event keys
            cols = [k for k in event.keys() if k in allowed_cols]
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


@app.route("/api/v1/devices/<device_id>", methods=["DELETE"])
def delete_device(device_id):
    """Delete a device and its events. Used for test cleanup."""
    db = get_db()
    db.execute("DELETE FROM devices WHERE device_id = ?", (device_id,))
    db.commit()
    return jsonify({"status": "deleted"})


# Allowed columns per table (whitelist for INSERT safety)
ALLOWED_TABLES = {
    "security_events": {
        "source_id", "device_id", "org_id", "timestamp_ns", "timestamp_dt",
        "event_category", "event_action", "event_outcome",
        "risk_score", "confidence", "mitre_techniques",
        "geometric_score", "temporal_score", "behavioral_score",
        "final_classification", "description", "indicators",
        "collection_agent", "enrichment_status", "threat_intel_match",
        "geo_src_country", "geo_src_city", "geo_src_latitude", "geo_src_longitude",
        "asn_src_org", "asn_src_number", "asn_src_network_type",
        "event_timestamp_ns",
        "event_id", "remote_ip", "remote_port", "process_name", "pid",
        "exe", "cmdline", "username", "protocol", "domain", "path", "sha256",
        "probe_name", "detection_source", "received_at",
    },
    "process_events": {
        "source_id", "device_id", "org_id", "timestamp_ns", "timestamp_dt",
        "pid", "exe", "cmdline", "ppid", "username", "name",
        "parent_name", "status", "cpu_percent", "memory_percent",
        "collection_agent", "received_at",
    },
    "flow_events": {
        "source_id", "device_id", "org_id", "timestamp_ns", "timestamp_dt",
        "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
        "bytes_tx", "bytes_rx", "pid", "process_name",
        "geo_dst_latitude", "geo_dst_longitude", "geo_dst_country",
        "geo_dst_city", "asn_dst_org", "threat_intel_match",
        "collection_agent", "received_at",
    },
    "dns_events": {
        "source_id", "device_id", "org_id", "timestamp_ns", "timestamp_dt",
        "domain", "record_type", "response_code", "risk_score",
        "process_name", "collection_agent", "received_at",
    },
    "persistence_events": {
        "source_id", "device_id", "org_id", "timestamp_ns", "timestamp_dt",
        "mechanism", "path", "change_type", "label",
        "sha256", "risk_score", "collection_agent", "received_at",
    },
    "fim_events": {
        "source_id", "device_id", "org_id", "timestamp_ns", "timestamp_dt",
        "path", "file_extension", "change_type", "new_hash",
        "owner_uid", "is_suid", "mtime", "size",
        "risk_score", "event_type", "collection_agent", "received_at",
    },
    "audit_events": {
        "source_id", "device_id", "org_id", "timestamp_ns", "timestamp_dt",
        "event_type", "pid", "ppid", "uid", "username",
        "risk_score", "collection_agent", "received_at",
    },
    "observation_events": {
        "source_id", "device_id", "org_id",
        "event_id", "domain", "event_timestamp_ns",
        "raw_attributes_json", "received_at",
    },
    "peripheral_events": {
        "source_id", "device_id", "org_id", "timestamp_ns", "timestamp_dt",
        "peripheral_device_id", "event_type", "device_name",
        "device_type", "vendor_id", "risk_score", "collection_agent", "received_at",
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
                  agent_version, first_seen, last_seen, status, public_ip
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
            "public_ip": r["public_ip"],
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


@app.route("/api/v1/devices/<device_id>/telemetry", methods=["GET"])
def device_telemetry(device_id):
    """Full telemetry dashboard data for a single device.

    Returns everything needed to render a Cortex-style view:
    posture, agents, events by category, processes, network, MITRE, timeline.
    """
    db = get_db()
    now = time.time()
    day_ago_ns = int((now - 86400) * 1e9)

    device = db.execute(
        "SELECT * FROM devices WHERE device_id = ?", (device_id,)
    ).fetchone()
    if not device:
        return jsonify({"error": "Device not found"}), 404

    # Security events (last 24h)
    sec_events = db.execute(
        """SELECT id, timestamp_dt, event_category, risk_score, confidence,
                  description, collection_agent, mitre_techniques,
                  process_name, remote_ip, username, domain, path,
                  detection_source, probe_name, geo_src_country, asn_src_org
           FROM security_events WHERE device_id = ? AND timestamp_ns > ?
           ORDER BY timestamp_ns DESC LIMIT 200""",
        (device_id, day_ago_ns),
    ).fetchall()

    # Category breakdown
    categories = db.execute(
        """SELECT event_category, COUNT(*) as cnt, AVG(risk_score) as avg_risk,
                  MAX(risk_score) as max_risk
           FROM security_events WHERE device_id = ? AND timestamp_ns > ?
           GROUP BY event_category ORDER BY cnt DESC""",
        (device_id, day_ago_ns),
    ).fetchall()

    # Risk distribution
    critical = sum(1 for e in sec_events if (e["risk_score"] or 0) >= 0.8)
    high = sum(1 for e in sec_events if 0.6 <= (e["risk_score"] or 0) < 0.8)
    medium = sum(1 for e in sec_events if 0.3 <= (e["risk_score"] or 0) < 0.6)
    low = sum(1 for e in sec_events if (e["risk_score"] or 0) < 0.3)

    # Posture: weighted risk score
    total_events = len(sec_events)
    if total_events > 0:
        avg_risk = sum((e["risk_score"] or 0) for e in sec_events) / total_events
        max_risk = max((e["risk_score"] or 0) for e in sec_events)
        posture_score = round(1.0 - (avg_risk * 0.6 + max_risk * 0.4), 2)
        posture = "critical" if posture_score < 0.3 else "at_risk" if posture_score < 0.6 else "guarded" if posture_score < 0.8 else "safe"
    else:
        posture_score = 1.0
        posture = "safe"
        avg_risk = 0
        max_risk = 0

    # MITRE techniques
    technique_counts = {}
    for e in sec_events:
        try:
            raw = e["mitre_techniques"]
            if raw:
                parsed = json.loads(raw)
                if isinstance(parsed, str):
                    parsed = json.loads(parsed)
                if isinstance(parsed, list):
                    for t in parsed:
                        if isinstance(t, str) and t.startswith("T"):
                            technique_counts[t] = technique_counts.get(t, 0) + 1
        except (json.JSONDecodeError, TypeError):
            pass

    # Active agents (unique collection_agent values)
    agents = db.execute(
        """SELECT collection_agent, COUNT(*) as cnt, MAX(timestamp_ns) as last_ts
           FROM security_events WHERE device_id = ? AND timestamp_ns > ?
           AND collection_agent IS NOT NULL AND collection_agent != ''
           GROUP BY collection_agent ORDER BY cnt DESC""",
        (device_id, day_ago_ns),
    ).fetchall()

    # Process events (top processes)
    processes = db.execute(
        """SELECT name, pid, exe, cmdline, username, COUNT(*) as cnt
           FROM process_events WHERE device_id = ? AND timestamp_ns > ?
           AND name IS NOT NULL
           GROUP BY name ORDER BY cnt DESC LIMIT 20""",
        (device_id, day_ago_ns),
    ).fetchall()

    # Network connections (top destinations)
    connections = db.execute(
        """SELECT dst_ip, dst_port, protocol, process_name,
                  COUNT(*) as cnt, SUM(bytes_tx) as total_tx, SUM(bytes_rx) as total_rx,
                  geo_dst_country, asn_dst_org
           FROM flow_events WHERE device_id = ? AND timestamp_ns > ?
           AND dst_ip IS NOT NULL
           GROUP BY dst_ip, dst_port ORDER BY cnt DESC LIMIT 20""",
        (device_id, day_ago_ns),
    ).fetchall()

    # DNS queries (top domains)
    dns = db.execute(
        """SELECT domain, COUNT(*) as cnt, AVG(risk_score) as avg_risk
           FROM dns_events WHERE device_id = ? AND timestamp_ns > ?
           AND domain IS NOT NULL
           GROUP BY domain ORDER BY cnt DESC LIMIT 20""",
        (device_id, day_ago_ns),
    ).fetchall()

    # Timeline (events grouped by hour)
    timeline = db.execute(
        """SELECT substr(timestamp_dt, 1, 13) as hour,
                  COUNT(*) as cnt,
                  SUM(CASE WHEN risk_score >= 0.8 THEN 1 ELSE 0 END) as critical,
                  SUM(CASE WHEN risk_score >= 0.6 AND risk_score < 0.8 THEN 1 ELSE 0 END) as high
           FROM security_events WHERE device_id = ? AND timestamp_ns > ?
           GROUP BY hour ORDER BY hour""",
        (device_id, day_ago_ns),
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
            "status": "online" if device["last_seen"] and device["last_seen"] > now - 300 else "offline",
        },
        "posture": {
            "score": posture_score,
            "level": posture,
            "avg_risk": round(avg_risk, 3),
            "max_risk": round(max_risk, 3),
        },
        "summary": {
            "total_events": total_events,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
        },
        "categories": [
            {"category": r[0], "count": r[1], "avg_risk": round(r[2] or 0, 3), "max_risk": round(r[3] or 0, 3)}
            for r in categories
        ],
        "mitre_techniques": sorted(
            [{"technique": t, "count": c} for t, c in technique_counts.items()],
            key=lambda x: -x["count"],
        )[:15],
        "agents": [
            {"name": r[0], "event_count": r[1]}
            for r in agents
        ],
        "processes": [
            {"name": r[0], "pid": r[1], "exe": r[2], "cmdline": r[3], "username": r[4], "count": r[5]}
            for r in processes
        ],
        "connections": [
            {"dst_ip": r[0], "dst_port": r[1], "protocol": r[2], "process": r[3],
             "count": r[4], "bytes_tx": r[5] or 0, "bytes_rx": r[6] or 0,
             "country": r[7], "asn": r[8]}
            for r in connections
        ],
        "dns": [
            {"domain": r[0], "count": r[1], "avg_risk": round(r[2] or 0, 3)}
            for r in dns
        ],
        "timeline": [
            {"hour": r[0], "count": r[1], "critical": r[2] or 0, "high": r[3] or 0}
            for r in timeline
        ],
        "recent_events": [dict(e) for e in sec_events[:50]],
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
    """Fleet posture — scoped by org_id if provided."""
    db = get_db()
    now = time.time()
    org_id = request.args.get("org_id")

    # Org filter clause
    org_filter = ""
    org_params = []
    if org_id:
        org_filter = " AND org_id = ?"
        org_params = [org_id]

    # Device counts
    total = db.execute(f"SELECT COUNT(*) FROM devices WHERE 1=1{org_filter}", org_params).fetchone()[0]
    online = db.execute(
        f"SELECT COUNT(*) FROM devices WHERE last_seen > ?{org_filter}", [now - 300] + org_params
    ).fetchone()[0]
    offline = total - online

    # Event stats (last 24h)
    day_ago_ns = int((now - 86400) * 1e9)
    # Security event org filter (join through devices table)
    se_org = ""
    se_org_params = []
    if org_id:
        se_org = " AND device_id IN (SELECT device_id FROM devices WHERE org_id = ?)"
        se_org_params = [org_id]

    total_events = db.execute(
        f"SELECT COUNT(*) FROM security_events WHERE timestamp_ns > ?{se_org}",
        [day_ago_ns] + se_org_params,
    ).fetchone()[0]

    critical = db.execute(
        f"SELECT COUNT(*) FROM security_events WHERE timestamp_ns > ? AND risk_score >= 0.8{se_org}",
        [day_ago_ns] + se_org_params,
    ).fetchone()[0]

    high = db.execute(
        f"SELECT COUNT(*) FROM security_events WHERE timestamp_ns > ? AND risk_score >= 0.6 AND risk_score < 0.8{se_org}",
        [day_ago_ns] + se_org_params,
    ).fetchone()[0]

    # Top threat categories (last 24h)
    top_categories = db.execute(
        f"""SELECT event_category, COUNT(*) as cnt, AVG(risk_score) as avg_risk
           FROM security_events
           WHERE timestamp_ns > ? AND risk_score > 0{se_org}
           GROUP BY event_category
           ORDER BY cnt DESC LIMIT 10""",
        [day_ago_ns] + se_org_params,
    ).fetchall()

    # Most active MITRE techniques
    mitre_rows = db.execute(
        f"""SELECT mitre_techniques FROM security_events
           WHERE timestamp_ns > ? AND mitre_techniques IS NOT NULL
           AND mitre_techniques != '[]'{se_org}""",
        [day_ago_ns] + se_org_params,
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

    # Per-device summary (include public_ip and org_id for globe markers)
    dev_where = " WHERE 1=1" + (" AND d.org_id = ?" if org_id else "")
    dev_params = [org_id] if org_id else []
    device_summary = db.execute(
        f"""SELECT d.device_id, d.hostname, d.os, d.arch, d.agent_version,
                  d.status, d.last_seen, d.public_ip, d.org_id,
                  COUNT(se.id) as event_count,
                  MAX(se.risk_score) as max_risk,
                  SUM(CASE WHEN se.risk_score >= 0.8 THEN 1 ELSE 0 END) as critical_count,
                  SUM(CASE WHEN se.risk_score >= 0.6 AND se.risk_score < 0.8 THEN 1 ELSE 0 END) as high_count
           FROM devices d
           LEFT JOIN security_events se ON d.device_id = se.device_id
                AND se.timestamp_ns > ?
           {dev_where}
           GROUP BY d.device_id
           ORDER BY max_risk DESC NULLS LAST""",
        [day_ago_ns] + dev_params,
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
                "os": r["os"],
                "arch": r["arch"],
                "agent_version": r["agent_version"],
                "status": r["status"],
                "last_seen": r["last_seen"],
                "public_ip": r["public_ip"],
                "org_id": r["org_id"],
                "event_count": r["event_count"],
                "max_risk": r["max_risk"],
                "critical_count": r["critical_count"],
                "high_count": r["high_count"],
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

@app.route("/api/v1/bulk-export", methods=["GET"])
def bulk_export():
    """Export event tables for fleet sync — time-based, not count-based.

    Uses hours parameter (default 24) to export all events within the
    time window. This ensures the presentation server sees complete data
    instead of a truncated sample.
    """
    db = get_db()
    hours = min(request.args.get("hours", 24, type=int), 72)
    device_id = request.args.get("device_id")
    user_limit = request.args.get("limit", type=int)
    cutoff_ns = int((time.time() - hours * 3600) * 1e9)

    # Tables with timestamp_ns column
    ts_tables = [
        "security_events", "process_events", "flow_events",
        "dns_events", "persistence_events", "audit_events",
        "fim_events", "peripheral_events",
    ]
    # Tables without standard timestamp_ns
    other_tables = ["observation_events"]

    result = {}

    # Per-table row limits for export — prevents massive JSON responses
    # that choke the presentation server (914MB RAM)
    _EXPORT_LIMITS = {
        "flow_events": 30_000,
        "dns_events": 30_000,
        "observation_events": 10_000,
        "process_events": 10_000,
    }

    for table in ts_tables:
        try:
            limit = _EXPORT_LIMITS.get(table, 50_000)
            if user_limit is not None:
                limit = min(limit, user_limit)
            query = f"SELECT * FROM {table} WHERE timestamp_ns > ?"
            params = [cutoff_ns]
            if device_id:
                query += " AND device_id = ?"
                params.append(device_id)
            query += f" ORDER BY id DESC LIMIT {limit}"
            rows = db.execute(query, params).fetchall()
            result[table] = [dict(r) for r in rows]
        except Exception:
            result[table] = []

    for table in other_tables:
        try:
            query = f"SELECT * FROM {table}"
            params = []
            if device_id:
                query += " WHERE device_id = ?"
                params.append(device_id)
            other_limit = min(5000, user_limit) if user_limit is not None else 5000
            query += f" ORDER BY id DESC LIMIT {other_limit}"
            rows = db.execute(query, params).fetchall()
            result[table] = [dict(r) for r in rows]
        except Exception:
            result[table] = []

    return jsonify(result)


@app.route("/health")
def health():
    return jsonify({"status": "ok", "version": "0.9.1-beta"})


# ── Main ───────────────────────────────────────────────────────────

# ── Maintenance ────────────────────────────────────────────────────

def _start_maintenance():
    """Start background maintenance thread for data hygiene."""
    import threading

    def maintenance_loop():
        logger.info("Maintenance thread started")
        while True:
            try:
                _run_maintenance()
            except Exception as e:
                logger.warning("Maintenance error: %s", e)
            time.sleep(300)  # Every 5 minutes

    t = threading.Thread(target=maintenance_loop, name="maintenance", daemon=True)
    t.start()


def _run_maintenance():
    """Run all maintenance tasks."""
    db_path = os.getenv("CC_DB_PATH", "server/fleet.db")
    db = sqlite3.connect(db_path, timeout=10)

    now = time.time()

    # 1. Retention: delete events older than 7 days
    cutoff_ns = int((now - 7 * 86400) * 1e9)
    total_deleted = 0
    for table in ["security_events", "process_events", "flow_events", "dns_events",
                   "persistence_events", "fim_events", "audit_events",
                   "observation_events", "peripheral_events"]:
        try:
            ts_col = "timestamp_ns" if table != "observation_events" else "event_timestamp_ns"
            deleted = db.execute(
                f"DELETE FROM {table} WHERE {ts_col} < ? AND {ts_col} > 0",
                (cutoff_ns,),
            ).rowcount
            total_deleted += deleted
        except Exception:
            pass

    # 2. Cap high-volume tables to prevent unbounded growth.
    # flow_events grows fastest (~4K/hour). Retention already handles age-based
    # cleanup, but row caps protect against bursts. Limits are per-table:
    _TABLE_CAPS = {
        "flow_events": 500_000,       # ~5 days at 4K/hour
        "dns_events": 500_000,        # ~2 days at 12K/hour
        "observation_events": 200_000,
        "process_events": 200_000,
        "security_events": 100_000,
        "audit_events": 100_000,
        "persistence_events": 50_000,
        "fim_events": 50_000,
        "peripheral_events": 50_000,
    }
    for table, max_rows in _TABLE_CAPS.items():
        try:
            count = db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            if count > max_rows:
                excess = count - max_rows
                db.execute(
                    f"DELETE FROM {table} WHERE id IN "
                    f"(SELECT id FROM {table} ORDER BY id ASC LIMIT ?)",
                    (excess,),
                )
                total_deleted += excess
        except Exception:
            pass

    # 3. Mark stale devices offline
    db.execute(
        "UPDATE devices SET status = 'offline' WHERE last_seen < ? AND status = 'online'",
        (now - 300,),
    )

    db.commit()

    # 4. VACUUM periodically (once per hour, tracked by file timestamp)
    vacuum_marker = Path(db_path + ".last_vacuum")
    should_vacuum = True
    if vacuum_marker.exists():
        last_vacuum = vacuum_marker.stat().st_mtime
        should_vacuum = (now - last_vacuum) > 3600  # 1 hour

    if should_vacuum and total_deleted > 100:
        try:
            db.execute("VACUUM")
            vacuum_marker.touch()
            logger.info("Maintenance: VACUUM complete")
        except Exception:
            pass

    db.close()

    if total_deleted > 0:
        logger.info("Maintenance: cleaned %d old/excess rows", total_deleted)


def main():
    """Run the Command Center server."""
    init_db()
    _start_maintenance()

    host = os.getenv("CC_HOST", "0.0.0.0")
    port = int(os.getenv("CC_PORT", "8443"))
    debug = os.getenv("CC_DEBUG", "false").lower() in ("1", "true")

    logger.info("AMOSKYS Command Center starting on %s:%d", host, port)
    logger.info("Fleet DB: %s", DB_PATH)
    logger.info("Dashboard: http://%s:%d/dashboard/", host, port)

    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    main()
