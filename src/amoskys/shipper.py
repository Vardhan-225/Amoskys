#!/usr/bin/env python3
"""AMOSKYS Telemetry Shipper — Ships events to Command Center.

Reads processed events from the local telemetry.db and ships them
to the central AMOSKYS server. Runs as a background thread inside
the Analyzer (Tier 2) process.

Architecture:
    Collector → Queue → Analyzer → telemetry.db
                                       ↓
                                   Shipper (this)
                                       ↓ HTTPS POST
                                   Central Server → fleet DB

The shipper maintains a cursor (last_shipped_id per table) so it
only ships new events. Events are batched for efficiency. If the
server is unreachable, events accumulate locally and ship when
connectivity is restored.

Usage:
    # As part of analyzer (automatic):
    AMOSKYS_SERVER=https://your-server:8443 python -m amoskys.analyzer_main

    # Standalone test:
    AMOSKYS_SERVER=https://your-server:8443 python -m amoskys.shipper
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import shutil
import sqlite3
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import requests

logger = logging.getLogger("amoskys.shipper")

# ── Configuration ──────────────────────────────────────────────────

SHIP_INTERVAL_S = 10          # Ship every 10 seconds
BATCH_SIZE = 200              # Max events per POST
REGISTER_INTERVAL_S = 300     # Re-register every 5 minutes (heartbeat)
CONNECT_TIMEOUT_S = 10
READ_TIMEOUT_S = 30


@dataclass
class ShipperConfig:
    """Shipper configuration, loaded from environment."""
    server_url: str = ""           # e.g. https://ops.amoskys.com
    api_key: str = ""              # Device API key (assigned on registration)
    deploy_token: str = ""         # One-time deployment token (used on first register)
    org_id: str = ""               # Organization ID (links device to user's org)
    device_id: str = ""            # Unique device identifier
    telemetry_db: str = "data/telemetry.db"
    cursor_db: str = "data/shipper_cursor.db"
    config_file: str = ""          # Path to amoskys.env (for persisting API key)
    enabled: bool = False

    @classmethod
    def from_env(cls) -> ShipperConfig:
        server = os.getenv("AMOSKYS_SERVER", "").rstrip("/")
        api_key = os.getenv("AMOSKYS_API_KEY", "")
        deploy_token = os.getenv("AMOSKYS_DEPLOY_TOKEN", "")
        org_id = os.getenv("AMOSKYS_ORG_ID", "")
        device_id = os.getenv("AMOSKYS_DEVICE_ID", "")

        # Auto-generate device_id from hardware if not set
        if not device_id:
            device_id = _generate_device_id()

        data_dir = os.getenv("AMOSKYS_DATA", "data")
        # telemetry.db may be at data_dir/telemetry.db or data_dir/data/telemetry.db
        # (depends on whether CWD is the data dir or its parent)
        telemetry_db = os.path.join(data_dir, "telemetry.db")
        if not os.path.exists(telemetry_db):
            alt = os.path.join(data_dir, "data", "telemetry.db")
            if os.path.exists(alt):
                telemetry_db = alt
        cursor_db = os.path.join(data_dir, "shipper_cursor.db")

        # Config file for persisting API key after first registration
        amoskys_home = os.getenv("AMOSKYS_HOME", "")
        config_file = os.path.join(amoskys_home, "config", "amoskys.env") if amoskys_home else ""

        return cls(
            server_url=server,
            api_key=api_key,
            deploy_token=deploy_token,
            org_id=org_id,
            device_id=device_id,
            telemetry_db=telemetry_db,
            cursor_db=cursor_db,
            config_file=config_file,
            enabled=bool(server),
        )


def _get_hostname() -> str:
    """Get the best hostname for this device.

    Priority (macOS):
      1. scutil --get ComputerName  → user-set device name
      2. scutil --get LocalHostName → Bonjour hostname
      3. socket.gethostname()       → system hostname
      4. platform.node()            → fallback

    Avoids socket.getfqdn() which can return reverse DNS artifacts.
    """
    if platform.system() == "Darwin":
        import subprocess
        for cmd in ["ComputerName", "LocalHostName"]:
            try:
                result = subprocess.run(
                    ["scutil", "--get", cmd],
                    capture_output=True, text=True, timeout=3,
                )
                name = result.stdout.strip()
                if name and len(name) > 1:
                    return name
            except Exception:
                pass

    # Linux / fallback
    import socket
    name = socket.gethostname()
    if name and name != "localhost":
        return name

    return platform.node()


def _generate_device_id() -> str:
    """Generate a stable device ID from hardware serial number.

    Uses IOPlatformSerialNumber on macOS (never changes across reboots,
    reinstalls, or hostname changes). Falls back to MAC address + arch.
    """
    # macOS: use hardware serial (most stable identifier)
    if platform.system() == "Darwin":
        try:
            import subprocess
            result = subprocess.run(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.split("\n"):
                if "IOPlatformSerialNumber" in line:
                    serial = line.split("=")[-1].strip().strip('"')
                    if serial and len(serial) >= 8:
                        return hashlib.sha256(serial.encode()).hexdigest()[:16]
        except Exception:
            pass

    # Linux: use /etc/machine-id (stable across reboots)
    if platform.system() == "Linux":
        try:
            machine_id = open("/etc/machine-id").read().strip()
            if machine_id:
                return hashlib.sha256(machine_id.encode()).hexdigest()[:16]
        except Exception:
            pass

    # Fallback: MAC address + arch (less stable but always available)
    parts = [platform.machine(), platform.system()]
    try:
        parts.append(str(uuid.getnode()))
    except Exception:
        pass
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


# ── Cursor Store ───────────────────────────────────────────────────

class CursorStore:
    """Tracks last-shipped row ID per table in a tiny SQLite DB."""

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS cursors (
        table_name TEXT PRIMARY KEY,
        last_id INTEGER NOT NULL DEFAULT 0,
        updated_at REAL NOT NULL
    );
    """

    def __init__(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.executescript(self._SCHEMA)
        self._lock = threading.Lock()

    def get(self, table: str) -> int:
        with self._lock:
            row = self.db.execute(
                "SELECT last_id FROM cursors WHERE table_name = ?", (table,)
            ).fetchone()
            return row[0] if row else 0

    def set(self, table: str, last_id: int):
        with self._lock:
            self.db.execute(
                "INSERT OR REPLACE INTO cursors (table_name, last_id, updated_at) "
                "VALUES (?, ?, ?)",
                (table, last_id, time.time()),
            )
            self.db.commit()

    def close(self):
        self.db.close()


# ── Shipper ────────────────────────────────────────────────────────

# Tables to ship and their key columns for the fleet server
SHIP_TABLES = {
    "security_events": {
        "columns": [
            "id", "timestamp_ns", "timestamp_dt", "device_id",
            "event_category", "event_action", "event_outcome",
            "risk_score", "confidence", "mitre_techniques",
            "geometric_score", "temporal_score", "behavioral_score",
            "final_classification", "description", "indicators",
            "collection_agent", "enrichment_status", "threat_intel_match",
            "geo_src_country", "geo_src_city", "geo_src_latitude",
            "geo_src_longitude", "asn_src_org", "asn_src_number",
            "asn_src_network_type", "event_timestamp_ns",
            "event_id", "remote_ip", "remote_port",
            "process_name", "pid", "exe", "cmdline",
            "username", "protocol", "domain", "path", "sha256",
            "probe_name", "detection_source",
        ],
    },
    "process_events": {
        "columns": [
            "id", "timestamp_ns", "timestamp_dt", "device_id",
            "pid", "exe", "cmdline", "ppid", "username", "name",
            "parent_name", "status", "cpu_percent", "memory_percent",
            "collection_agent",
        ],
    },
    "flow_events": {
        "columns": [
            "id", "timestamp_ns", "timestamp_dt", "device_id",
            "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
            "bytes_tx", "bytes_rx", "pid", "process_name",
            "geo_dst_latitude", "geo_dst_longitude", "geo_dst_country",
            "geo_dst_city", "asn_dst_org", "threat_intel_match",
            "collection_agent",
        ],
    },
    "dns_events": {
        "columns": [
            "id", "timestamp_ns", "timestamp_dt", "device_id",
            "domain", "record_type", "response_code", "risk_score",
            "process_name", "collection_agent",
        ],
    },
    "persistence_events": {
        "columns": [
            "id", "timestamp_ns", "timestamp_dt", "device_id",
            "mechanism", "path", "change_type", "label",
            "sha256", "risk_score", "collection_agent",
        ],
    },
    "fim_events": {
        "columns": [
            "id", "timestamp_ns", "timestamp_dt", "device_id",
            "path", "file_extension", "change_type", "new_hash",
            "owner_uid", "is_suid", "mtime", "size",
            "risk_score", "event_type", "collection_agent",
        ],
    },
    "audit_events": {
        "columns": [
            "id", "timestamp_ns", "timestamp_dt", "device_id",
            "event_type", "pid", "ppid", "uid", "username",
            "risk_score", "collection_agent",
        ],
    },
    "observation_events": {
        "columns": [
            "id", "event_id", "device_id", "domain",
            "event_timestamp_ns", "raw_attributes_json",
        ],
    },
    "peripheral_events": {
        "columns": [
            "id", "timestamp_ns", "timestamp_dt", "device_id",
            "peripheral_device_id", "event_type", "device_name",
            "device_type", "vendor_id", "risk_score", "collection_agent",
        ],
    },
}


class TelemetryShipper:
    """Ships telemetry from local DB to the AMOSKYS Command Center.

    The shipper reads from the same telemetry.db that the dashboard uses,
    using a cursor to track what's already been shipped. Events are batched
    and sent via HTTPS POST with API key auth.

    Thread-safe: designed to run in a background thread.
    """

    def __init__(self, config: ShipperConfig):
        self.config = config
        self.cursors = CursorStore(config.cursor_db)
        self._session = requests.Session()
        self._session.verify = False  # Ops server may use self-signed cert
        self._session.headers.update({
            "Content-Type": "application/json",
            "X-Device-ID": config.device_id,
            "User-Agent": "AMOSKYS-Agent/0.9.1",
        })
        if config.api_key:
            self._session.headers["Authorization"] = f"Bearer {config.api_key}"

        self._shutdown = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._registered = False
        self._last_register = 0.0
        self._stats = {
            "shipped": 0,
            "failed": 0,
            "last_ship_time": 0.0,
            "last_error": "",
        }

    @property
    def stats(self) -> dict:
        return dict(self._stats)

    def start(self):
        """Start shipper in a background thread."""
        if not self.config.enabled:
            logger.info("Shipper disabled (no AMOSKYS_SERVER set)")
            return

        logger.info(
            "Shipper starting — server=%s device=%s",
            self.config.server_url,
            self.config.device_id[:8] + "...",
        )
        self._thread = threading.Thread(
            target=self._run_loop,
            name="amoskys-shipper",
            daemon=True,
        )
        self._thread.start()

    def stop(self):
        """Stop shipper gracefully."""
        self._shutdown.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=15)
        self.cursors.close()
        self._session.close()
        logger.info("Shipper stopped (shipped=%d)", self._stats["shipped"])

    def _run_loop(self):
        """Main shipper loop."""
        while not self._shutdown.is_set():
            try:
                # Register/heartbeat
                now = time.time()
                if now - self._last_register > REGISTER_INTERVAL_S:
                    self._register()
                    self._last_register = now

                # Ship events from each table
                if self._registered:
                    self._ship_all_tables()

                # Poll for commands from MCP server
                if self._registered:
                    self._poll_commands()

            except Exception as e:
                logger.error("Shipper cycle failed: %s", e)
                self._stats["last_error"] = str(e)

            self._shutdown.wait(timeout=SHIP_INTERVAL_S)

    def _register(self):
        """Register this device with the Command Center.

        First registration includes the deployment token (one-time use).
        The server validates the token, links the device to the user's org,
        and returns an API key. Subsequent calls are heartbeats.
        """
        try:
            payload = {
                "device_id": self.config.device_id,
                "hostname": _get_hostname(),
                "os": platform.system(),
                "os_version": platform.release(),
                "arch": platform.machine(),
                "agent_version": "0.9.1-beta",
                "python_version": platform.python_version(),
            }

            # Include deployment token + org_id on first registration
            if self.config.deploy_token and not self.config.api_key:
                payload["deploy_token"] = self.config.deploy_token
            if self.config.org_id:
                payload["org_id"] = self.config.org_id

            resp = self._session.post(
                f"{self.config.server_url}/api/v1/register",
                json=payload,
                timeout=(CONNECT_TIMEOUT_S, READ_TIMEOUT_S),
            )

            if resp.status_code == 200:
                data = resp.json()
                # Accept API key from server — handles first registration,
                # re-registration after wipe, and key rotation.
                server_key = data.get("api_key", "")
                if server_key and server_key != self.config.api_key:
                    self.config.api_key = server_key
                    self._session.headers["Authorization"] = f"Bearer {server_key}"
                    self._persist_api_key(server_key)
                    self.config.deploy_token = ""
                    logger.info("API key updated (device=%s)", self.config.device_id[:8])
                elif server_key and not self.config.api_key:
                    self.config.api_key = server_key
                    self._session.headers["Authorization"] = f"Bearer {server_key}"
                    self._persist_api_key(server_key)
                    self.config.deploy_token = ""
                    logger.info("Registered with API key (device=%s)", self.config.device_id[:8])
                self._registered = True
                if not server_key:
                    logger.debug("Heartbeat OK (device=%s)", self.config.device_id[:8])
            else:
                logger.warning("Registration failed: %d %s", resp.status_code, resp.text[:200])

        except requests.ConnectionError:
            logger.debug("Command Center unreachable — will retry")
        except Exception as e:
            logger.warning("Registration error: %s", e)

    def _persist_api_key(self, api_key: str):
        """Write API key to config file so it survives agent restarts.

        Replaces existing AMOSKYS_API_KEY line if present (no duplicates).
        """
        config_file = self.config.config_file
        if not config_file:
            return
        try:
            # Read existing config, strip old key lines
            lines = []
            if os.path.exists(config_file):
                with open(config_file) as f:
                    lines = [ln for ln in f.readlines()
                             if not ln.strip().startswith("AMOSKYS_API_KEY=")]
            # Append new key
            lines.append(f"AMOSKYS_API_KEY={api_key}\n")
            with open(config_file, "w") as f:
                f.writelines(lines)
            logger.info("API key persisted to %s", config_file)
        except OSError as e:
            logger.warning("Could not persist API key: %s", e)

    def _ship_all_tables(self):
        """Ship new events from all tracked tables."""
        if not Path(self.config.telemetry_db).exists():
            return

        try:
            db = sqlite3.connect(
                self.config.telemetry_db,
                timeout=5.0,
                check_same_thread=False,
            )
            db.row_factory = sqlite3.Row

            for table, meta in SHIP_TABLES.items():
                try:
                    self._ship_table(db, table, meta["columns"])
                except Exception as e:
                    logger.debug("Ship %s failed: %s", table, e)

            db.close()
        except Exception as e:
            logger.warning("Cannot open telemetry DB: %s", e)

    def _ship_table(self, db: sqlite3.Connection, table: str, columns: list[str]):
        """Ship new rows from a single table."""
        last_id = self.cursors.get(table)

        # Check which columns actually exist in the table
        try:
            cursor = db.execute(f"PRAGMA table_info({table})")
            existing_cols = {row[1] for row in cursor.fetchall()}
        except Exception:
            return

        # Filter to columns that exist
        valid_cols = [c for c in columns if c in existing_cols]
        if "id" not in valid_cols:
            return

        col_list = ", ".join(valid_cols)
        rows = db.execute(
            f"SELECT {col_list} FROM {table} WHERE id > ? ORDER BY id LIMIT ?",
            (last_id, BATCH_SIZE),
        ).fetchall()

        if not rows:
            return

        # Convert to list of dicts
        events = []
        max_id = last_id
        for row in rows:
            event = {valid_cols[i]: row[i] for i in range(len(valid_cols))}
            # Ensure device_id is set
            if not event.get("device_id"):
                event["device_id"] = self.config.device_id
            events.append(event)
            max_id = max(max_id, event["id"])

        # Ship batch
        payload = {
            "device_id": self.config.device_id,
            "table": table,
            "events": events,
            "batch_size": len(events),
        }

        try:
            resp = self._session.post(
                f"{self.config.server_url}/api/v1/telemetry",
                json=payload,
                timeout=(CONNECT_TIMEOUT_S, READ_TIMEOUT_S),
            )

            if resp.status_code == 200:
                self.cursors.set(table, max_id)
                self._stats["shipped"] += len(events)
                self._stats["last_ship_time"] = time.time()
                logger.info(
                    "Shipped %d %s events (id %d→%d)",
                    len(events), table, last_id, max_id,
                )
            else:
                self._stats["failed"] += len(events)
                self._stats["last_error"] = f"{resp.status_code}: {resp.text[:100]}"
                logger.warning(
                    "Ship %s failed: %d %s",
                    table, resp.status_code, resp.text[:200],
                )

        except requests.ConnectionError:
            logger.debug("Server unreachable — %d %s events queued", len(events), table)
        except Exception as e:
            self._stats["failed"] += len(events)
            self._stats["last_error"] = str(e)
            logger.warning("Ship error: %s", e)


    # ── Command Polling (MCP → Device) ──────────────────────────

    def _poll_commands(self):
        """Poll the Command Center for pending commands and execute them."""
        try:
            resp = self._session.get(
                f"{self.config.server_url}/api/v1/devices/{self.config.device_id}/commands",
                timeout=(CONNECT_TIMEOUT_S, READ_TIMEOUT_S),
            )
            if resp.status_code != 200:
                return

            data = resp.json()
            commands = data.get("commands", [])
            if not commands:
                return

            logger.info("Received %d command(s) from MCP server", len(commands))

            for cmd in commands:
                cmd_id = cmd.get("id", "")
                cmd_type = cmd.get("command_type", "")
                payload = cmd.get("payload", "{}")
                if isinstance(payload, str):
                    try:
                        payload = json.loads(payload)
                    except (json.JSONDecodeError, TypeError):
                        payload = {}

                result = self._execute_command(cmd_type, payload)

                # Report result back
                try:
                    self._session.post(
                        f"{self.config.server_url}/api/v1/devices/"
                        f"{self.config.device_id}/commands/{cmd_id}/result",
                        json=result,
                        timeout=(CONNECT_TIMEOUT_S, READ_TIMEOUT_S),
                    )
                except Exception as e:
                    logger.warning("Failed to report command result: %s", e)

        except Exception as e:
            # Non-fatal — command polling is best-effort
            logger.debug("Command poll failed: %s", e)

    def _execute_command(self, cmd_type: str, payload: dict) -> dict:
        """Execute a command locally on this device."""
        logger.info("Executing command: %s payload=%s", cmd_type, payload)

        try:
            if cmd_type == "START_AGENT":
                return self._cmd_agent_lifecycle("start", payload.get("agent_name", ""))
            elif cmd_type == "STOP_AGENT":
                return self._cmd_agent_lifecycle("stop", payload.get("agent_name", ""))
            elif cmd_type == "RESTART_AGENT":
                return self._cmd_agent_lifecycle("restart", payload.get("agent_name", ""))
            elif cmd_type == "COLLECT_NOW":
                return self._cmd_collect_now()
            elif cmd_type == "UPDATE_CONFIG":
                return self._cmd_update_config(payload)
            elif cmd_type == "KILL_PROCESS":
                return self._cmd_kill_process(payload)
            elif cmd_type == "BLOCK_IP":
                return self._cmd_block_ip(payload)
            elif cmd_type == "BLOCK_DOMAIN":
                return self._cmd_block_domain(payload)
            elif cmd_type == "ISOLATE":
                return self._cmd_isolate(payload)
            elif cmd_type == "UNISOLATE":
                return self._cmd_unisolate()
            elif cmd_type == "QUARANTINE_FILE":
                return self._cmd_quarantine_file(payload)
            else:
                return {"success": False, "error": f"Unknown command: {cmd_type}"}
        except Exception as e:
            logger.exception("Command execution failed: %s", cmd_type)
            return {"success": False, "error": str(e)}

    def _cmd_agent_lifecycle(self, action: str, agent_name: str) -> dict:
        """Start/stop/restart an agent via subprocess."""
        if not agent_name:
            return {"success": False, "error": "No agent_name provided"}
        import subprocess
        try:
            result = subprocess.run(
                [sys.executable, "-m", "amoskys.launcher", action, "--agents-only"],
                capture_output=True, text=True, timeout=30,
                env={**os.environ, "AMOSKYS_AGENT": agent_name},
            )
            return {
                "success": result.returncode == 0,
                "output": result.stdout[-500:] if result.stdout else "",
                "error": result.stderr[-500:] if result.stderr else "",
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Agent lifecycle command timed out"}

    def _cmd_collect_now(self) -> dict:
        """Trigger immediate data collection."""
        import subprocess
        try:
            result = subprocess.run(
                [sys.executable, "-m", "amoskys.launcher", "collect"],
                capture_output=True, text=True, timeout=60,
            )
            return {
                "success": result.returncode == 0,
                "output": result.stdout[-500:] if result.stdout else "",
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Collection timed out"}

    def _cmd_update_config(self, payload: dict) -> dict:
        """Update a local configuration value."""
        key = payload.get("key", "")
        value = payload.get("value", "")
        if not key:
            return {"success": False, "error": "No config key provided"}
        # Write to environment config file
        config_path = Path(self.config.config_file)
        if config_path.exists():
            content = config_path.read_text()
        else:
            content = ""
        # Update or append
        lines = content.splitlines()
        found = False
        for i, line in enumerate(lines):
            if line.startswith(f"{key}="):
                lines[i] = f"{key}={value}"
                found = True
                break
        if not found:
            lines.append(f"{key}={value}")
        config_path.write_text("\n".join(lines) + "\n")
        return {"success": True, "output": f"Set {key}={value}"}

    def _cmd_kill_process(self, payload: dict) -> dict:
        """Kill a process by PID."""
        pid = payload.get("pid")
        if not pid:
            return {"success": False, "error": "No PID provided"}
        try:
            os.kill(int(pid), 9)  # SIGKILL
            return {"success": True, "output": f"Killed PID {pid}"}
        except ProcessLookupError:
            return {"success": False, "error": f"PID {pid} not found"}
        except PermissionError:
            return {"success": False, "error": f"Permission denied for PID {pid}"}

    def _cmd_block_ip(self, payload: dict) -> dict:
        """Block an IP using pf (macOS) or iptables (Linux)."""
        ip = payload.get("ip", "")
        duration = payload.get("duration_s", 3600)
        if not ip:
            return {"success": False, "error": "No IP provided"}

        import subprocess
        if platform.system() == "Darwin":
            # macOS: use pf
            rule = f'block drop from {ip} to any\nblock drop from any to {ip}\n'
            anchor_file = Path("/tmp/amoskys_block.rules")
            # Append rule
            with open(anchor_file, "a") as f:
                f.write(rule)
            result = subprocess.run(
                ["sudo", "pfctl", "-a", "amoskys", "-f", str(anchor_file)],
                capture_output=True, text=True, timeout=10,
            )
            return {
                "success": result.returncode == 0,
                "output": f"Blocked {ip} for {duration}s via pf",
                "error": result.stderr[:200] if result.stderr else "",
            }
        else:
            # Linux: use iptables
            result = subprocess.run(
                ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True, text=True, timeout=10,
            )
            return {
                "success": result.returncode == 0,
                "output": f"Blocked {ip} via iptables",
                "error": result.stderr[:200] if result.stderr else "",
            }

    def _cmd_block_domain(self, payload: dict) -> dict:
        """Block a domain by adding to /etc/hosts (sinkhole)."""
        domain = payload.get("domain", "")
        if not domain:
            return {"success": False, "error": "No domain provided"}
        try:
            hosts_line = f"\n127.0.0.1 {domain}  # AMOSKYS-BLOCK\n"
            with open("/etc/hosts", "a") as f:
                f.write(hosts_line)
            # Flush DNS cache
            import subprocess
            if platform.system() == "Darwin":
                subprocess.run(["sudo", "dscacheutil", "-flushcache"],
                               capture_output=True, timeout=5)
            return {"success": True, "output": f"Sinkholed {domain}"}
        except PermissionError:
            return {"success": False, "error": "Need root to modify /etc/hosts"}

    def _cmd_isolate(self, payload: dict) -> dict:
        """Network-isolate this device (allow only AMOSKYS traffic)."""
        import subprocess
        server_ip = self.config.server_url.split("://")[-1].split(":")[0]
        if platform.system() == "Darwin":
            rules = (
                f"pass out proto tcp to {server_ip} port 8443\n"
                f"pass in proto tcp from {server_ip} port 8443\n"
                "block all\n"
            )
            Path("/tmp/amoskys_isolate.rules").write_text(rules)
            result = subprocess.run(
                ["sudo", "pfctl", "-a", "amoskys_isolate", "-f",
                 "/tmp/amoskys_isolate.rules"],
                capture_output=True, text=True, timeout=10,
            )
            return {
                "success": result.returncode == 0,
                "output": "Device isolated — only AMOSKYS traffic allowed",
            }
        return {"success": False, "error": "Isolation not implemented for this OS"}

    def _cmd_unisolate(self) -> dict:
        """Remove network isolation."""
        import subprocess
        if platform.system() == "Darwin":
            result = subprocess.run(
                ["sudo", "pfctl", "-a", "amoskys_isolate", "-F", "all"],
                capture_output=True, text=True, timeout=10,
            )
            return {
                "success": result.returncode == 0,
                "output": "Network isolation removed",
            }
        return {"success": False, "error": "Unisolation not implemented for this OS"}

    def _cmd_quarantine_file(self, payload: dict) -> dict:
        """Quarantine a file — move to secure location, strip permissions."""
        file_path = payload.get("path", "")
        if not file_path:
            return {"success": False, "error": "No path provided"}
        src = Path(file_path)
        if not src.exists():
            return {"success": False, "error": f"File not found: {file_path}"}
        quarantine_dir = Path("data/quarantine")
        quarantine_dir.mkdir(parents=True, exist_ok=True)
        dst = quarantine_dir / f"{src.name}.{int(time.time())}"
        import shutil
        shutil.move(str(src), str(dst))
        os.chmod(str(dst), 0o000)  # Remove all permissions
        return {
            "success": True,
            "output": f"Quarantined {file_path} → {dst}",
        }


# ── Standalone mode ────────────────────────────────────────────────

def main():
    """Run shipper standalone (for testing)."""
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
    )

    config = ShipperConfig.from_env()
    if not config.enabled:
        print("Set AMOSKYS_SERVER environment variable to enable shipping.")
        print("Example: AMOSKYS_SERVER=http://localhost:8443 python -m amoskys.shipper")
        return 1

    shipper = TelemetryShipper(config)
    shipper.start()

    try:
        while True:
            time.sleep(30)
            logger.info("Shipper stats: %s", shipper.stats)
    except KeyboardInterrupt:
        shipper.stop()

    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
