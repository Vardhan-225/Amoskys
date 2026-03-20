#!/usr/bin/env python3
"""NetworkSentinel Collectors — Eyes on the Wire.

Two collectors that see what every other AMOSKYS agent misses:

1. AccessLogCollector  — Tails AMOSKYS's own HTTP access logs.
   Every request that touches the dashboard is parsed, timestamped,
   and fed to probes. No request escapes. Not one.

2. ConnectionStateCollector — Snapshots every TCP/UDP connection
   on the box via lsof. Captures attacker IPs that nettop misses
   because nettop only sees "current" flows.

These collectors produce HTTPTransaction objects (same as http_inspector)
so all existing probes can consume them without modification.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from amoskys.agents.os.macos.http_inspector.agent_types import HTTPTransaction

logger = logging.getLogger("NetworkSentinel.Collector")

# ── AMOSKYS structured log format ────────────────────────────────────────────
# Human-readable:
#   2026-03-09 18:24:44 | INFO | amoskys.http | logging.py:726 |
#       GET /path -> 200 [192.168.237.132] user=anon 0ms
#
# We extract: method, path, status, src_ip, duration, user
# ─────────────────────────────────────────────────────────────────────────────

_AMOSKYS_LOG_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})"
    r"\s*\|.*?\|\s*"
    r"(?P<method>GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+"
    r"(?P<path>\S+)\s+->\s+"
    r"(?P<status>\d{3})\s+"
    r"\[(?P<src_ip>[^\]]+)\]\s+"
    r"user=(?P<user>\S+)\s+"
    r"(?P<duration_ms>\d+)ms"
)

# User-Agent extraction from JSON logs
_UA_RE = re.compile(r'"user_agent"\s*:\s*"([^"]*)"')


class AccessLogCollector:
    """Tails AMOSKYS web access logs. Reads only new lines each cycle.

    This is the missing link. Flask logged every single one of those
    17,273 Kali requests. Method, path, status, IP, timing — all there.
    Nobody was reading them. Now we are.
    """

    def __init__(
        self,
        log_paths: Optional[List[str]] = None,
        *,
        max_lines_per_cycle: int = 50_000,
    ):
        if log_paths:
            self.log_paths = [str(p) for p in log_paths]
        else:
            # Auto-discover AMOSKYS log locations
            # collector.py is 6 levels deep: src/amoskys/agents/os/macos/network_sentinel/
            project_root = Path(__file__).resolve().parents[6]
            self.log_paths = [
                str(project_root / "logs" / "amoskys_web.log"),
                str(project_root / "logs" / "dashboard_attack.log"),
            ]
        self.max_lines = max_lines_per_cycle
        self._file_positions: Dict[str, int] = {}
        self._file_inodes: Dict[str, int] = {}

    def collect(self) -> List[HTTPTransaction]:
        """Read new log lines since last collection, parse into HTTPTransaction."""
        transactions: List[HTTPTransaction] = []

        for log_path in self.log_paths:
            path = Path(log_path)
            if not path.exists():
                continue

            try:
                stat = path.stat()
                current_inode = stat.st_ino
                current_size = stat.st_size
                last_pos = self._file_positions.get(log_path, 0)
                last_inode = self._file_inodes.get(log_path, 0)

                # Log rotation detection: inode changed or file shrank
                if current_inode != last_inode or current_size < last_pos:
                    logger.info(
                        "Log rotation detected for %s (inode %d->%d, size %d->%d)",
                        log_path,
                        last_inode,
                        current_inode,
                        last_pos,
                        current_size,
                    )
                    last_pos = 0

                if current_size <= last_pos:
                    continue  # No new data

                lines_read = 0
                with open(log_path, "r", errors="replace") as f:
                    f.seek(last_pos)
                    # Read all remaining content then split — avoids
                    # iterator/tell() conflict in Python
                    remaining = f.read()
                    end_pos = f.tell()

                for line in remaining.split("\n"):
                    if lines_read >= self.max_lines:
                        break
                    line = line.strip()
                    if not line:
                        continue

                    txn = self._parse_line(line)
                    if txn:
                        transactions.append(txn)
                    lines_read += 1

                self._file_positions[log_path] = end_pos
                self._file_inodes[log_path] = current_inode

                if lines_read > 0:
                    logger.info(
                        "Parsed %d lines from %s → %d HTTP transactions",
                        lines_read,
                        Path(log_path).name,
                        len(transactions),
                    )

            except PermissionError:
                logger.warning("Permission denied: %s", log_path)
            except Exception as e:
                logger.error("Failed to read %s: %s", log_path, e)

        return transactions

    def _parse_line(self, line: str) -> Optional[HTTPTransaction]:
        """Parse a single AMOSKYS log line. Handles both formats."""
        # Try JSON format first (production)
        if line.startswith("{"):
            return self._parse_json_line(line)
        # Try human-readable format (development)
        return self._parse_human_line(line)

    def _parse_human_line(self, line: str) -> Optional[HTTPTransaction]:
        """Parse: 2026-03-09 18:24:44 | INFO | ... | GET /path -> 200 [IP] user=x 5ms"""
        m = _AMOSKYS_LOG_RE.search(line)
        if not m:
            return None

        try:
            ts_str = m.group("timestamp")
            timestamp = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S").replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            timestamp = datetime.now(timezone.utc)

        method = m.group("method")
        raw_path = m.group("path")
        status = int(m.group("status"))
        src_ip = m.group("src_ip")
        # Extract query params from path
        parsed = urlparse(raw_path)
        query_params = {}
        if parsed.query:
            qs = parse_qs(parsed.query, keep_blank_values=True)
            query_params = {k: v[0] if v else "" for k, v in qs.items()}

        # Extract User-Agent if present in the line (JSON logs have it)
        headers: Dict[str, str] = {}
        ua_match = _UA_RE.search(line)
        if ua_match:
            headers["user-agent"] = ua_match.group(1)

        return HTTPTransaction(
            timestamp=timestamp,
            method=method,
            url=raw_path,
            host="",
            path=parsed.path or "/",
            query_params=query_params,
            request_headers=headers,
            request_body=None,
            response_status=status,
            content_type="",
            src_ip=src_ip,
            dst_ip="127.0.0.1",
            bytes_sent=0,
            bytes_received=0,
            process_name="amoskys_dashboard",
            is_tls=False,
        )

    def _parse_json_line(self, line: str) -> Optional[HTTPTransaction]:
        """Parse JSON-structured log line (production format)."""
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        # Must be an HTTP request log
        ctx = data.get("context", {})
        extra = data.get("extra", {})
        method = ctx.get("method")
        path = ctx.get("path")
        src_ip = ctx.get("remote_addr")

        if not method or not path:
            return None

        status = extra.get("status_code", 0)

        try:
            ts_str = data.get("timestamp", "")
            if ts_str:
                timestamp = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            else:
                timestamp = datetime.now(timezone.utc)
        except ValueError:
            timestamp = datetime.now(timezone.utc)

        headers: Dict[str, str] = {}
        ua = ctx.get("user_agent", "")
        if ua:
            headers["user-agent"] = ua

        parsed = urlparse(path)
        query_params = {}
        if parsed.query:
            qs = parse_qs(parsed.query, keep_blank_values=True)
            query_params = {k: v[0] if v else "" for k, v in qs.items()}

        return HTTPTransaction(
            timestamp=timestamp,
            method=method,
            url=path,
            host="",
            path=parsed.path or "/",
            query_params=query_params,
            request_headers=headers,
            request_body=None,
            response_status=status or 0,
            content_type="",
            src_ip=src_ip or "0.0.0.0",
            dst_ip="127.0.0.1",
            bytes_sent=0,
            bytes_received=int(extra.get("content_length", 0)),
            process_name="amoskys_dashboard",
            is_tls=False,
        )

    def reset(self):
        """Reset file positions — re-read everything from the top."""
        self._file_positions.clear()
        self._file_inodes.clear()
        logger.info("AccessLogCollector reset — will re-read all logs")


class ConnectionStateCollector:
    """Snapshots all TCP/UDP connections on the box via lsof.

    Unlike nettop (which only sees flows with active bytes),
    lsof -i sees EVERY connection — ESTABLISHED, LISTEN, TIME_WAIT,
    SYN_SENT. If a port scanner touched us, the connection state
    might still be in TIME_WAIT when we look.
    """

    def collect(self) -> List[Dict[str, Any]]:
        """Snapshot current network connections."""
        connections: List[Dict[str, Any]] = []

        try:
            result = subprocess.run(
                ["lsof", "-i", "-n", "-P", "+c", "0"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.returncode != 0:
                return connections

            for line in result.stdout.strip().split("\n")[1:]:  # skip header
                conn = self._parse_lsof_line(line)
                if conn:
                    connections.append(conn)

        except subprocess.TimeoutExpired:
            logger.warning("lsof timed out")
        except FileNotFoundError:
            logger.debug("lsof not available")
        except Exception as e:
            logger.error("Connection snapshot failed: %s", e)

        return connections

    def _parse_lsof_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse lsof -i output line."""
        # Format: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
        parts = line.split()
        if len(parts) < 9:
            return None

        try:
            process_name = parts[0]
            pid = int(parts[1])
            user = parts[2]
            protocol = parts[7]  # TCP or UDP
            name = parts[8] if len(parts) > 8 else ""
            state = parts[9] if len(parts) > 9 else ""

            # Strip parentheses from state: (ESTABLISHED) -> ESTABLISHED
            state = state.strip("()")

            # Parse NAME: src_ip:port->dst_ip:port or *:port
            src_ip, src_port, dst_ip, dst_port = "", 0, "", 0

            if "->" in name:
                src_part, dst_part = name.split("->", 1)
                src_ip, src_port = self._split_addr(src_part)
                dst_ip, dst_port = self._split_addr(dst_part)
            elif ":" in name:
                src_ip, src_port = self._split_addr(name)

            return {
                "process_name": process_name,
                "pid": pid,
                "user": user,
                "protocol": protocol,
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "state": state,
                "timestamp": time.time_ns(),
            }
        except (ValueError, IndexError):
            return None

    @staticmethod
    def _split_addr(addr: str) -> Tuple[str, int]:
        """Split IP:port, handling IPv6 [::1]:port."""
        if addr.startswith("["):
            # IPv6: [::1]:port
            bracket_end = addr.index("]")
            ip = addr[1:bracket_end]
            port_str = addr[bracket_end + 2 :] if bracket_end + 2 < len(addr) else "0"
        elif addr.count(":") > 1:
            # IPv6 without brackets
            ip = addr
            port_str = "0"
        else:
            # IPv4: 1.2.3.4:80 or *:80
            parts = addr.rsplit(":", 1)
            ip = parts[0] if parts[0] != "*" else "0.0.0.0"
            port_str = parts[1] if len(parts) > 1 else "0"

        try:
            port = int(port_str)
        except ValueError:
            port = 0

        return ip, port
