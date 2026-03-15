"""
MeshStore — SQLite storage and forensic query layer for mesh events.

Provides timeline queries, event correlation, and replay capabilities
for IGRIS Orchestrator and the dashboard incident timeline UI.
"""

from __future__ import annotations

import json
import sqlite3
import time
from typing import Dict, List, Optional

from .events import EventType, SecurityEvent, Severity


class MeshStore:
    """Queryable storage for mesh events — forensic replay and correlation."""

    def __init__(self, db_path: str = "data/mesh_events.db"):
        self._db_path = db_path

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def get_timeline(
        self,
        seconds: int = 300,
        event_types: Optional[List[EventType]] = None,
        min_severity: Optional[Severity] = None,
        related_pid: Optional[int] = None,
        related_ip: Optional[str] = None,
        limit: int = 200,
    ) -> List[Dict]:
        """Get a timeline of mesh events for forensic replay.

        Returns events sorted by timestamp (newest first).
        """
        cutoff = time.time_ns() - (seconds * 1_000_000_000)
        conn = self._connect()

        query = "SELECT * FROM mesh_events WHERE timestamp_ns > ?"
        params: list = [cutoff]

        if event_types:
            placeholders = ",".join("?" * len(event_types))
            query += f" AND event_type IN ({placeholders})"
            params.extend(et.value for et in event_types)

        if min_severity:
            sevs = [s.value for s in Severity if s.numeric >= min_severity.numeric]
            placeholders = ",".join("?" * len(sevs))
            query += f" AND severity IN ({placeholders})"
            params.extend(sevs)

        if related_pid:
            query += " AND related_pid = ?"
            params.append(related_pid)

        if related_ip:
            query += " AND related_ip = ?"
            params.append(related_ip)

        query += " ORDER BY timestamp_ns DESC LIMIT ?"
        params.append(limit)

        rows = conn.execute(query, params).fetchall()
        conn.close()

        return [
            {
                "event_id": r["event_id"],
                "event_type": r["event_type"],
                "source_agent": r["source_agent"],
                "severity": r["severity"],
                "payload": json.loads(r["payload"]) if r["payload"] else {},
                "timestamp_ns": r["timestamp_ns"],
                "related_pid": r["related_pid"],
                "related_ip": r["related_ip"],
                "related_domain": r["related_domain"],
                "mitre_technique": r["mitre_technique"],
                "confidence": r["confidence"],
            }
            for r in rows
        ]

    def get_kill_chain_events(
        self, pid: int, seconds: int = 600
    ) -> List[Dict]:
        """Get all mesh events related to a specific PID.

        Used to reconstruct the kill chain for an incident report.
        """
        return self.get_timeline(
            seconds=seconds, related_pid=pid, limit=500,
        )

    def get_action_history(
        self, seconds: int = 3600, limit: int = 50
    ) -> List[Dict]:
        """Get recent actions taken by IGRIS."""
        return self.get_timeline(
            seconds=seconds,
            event_types=[EventType.ACTION_TAKEN, EventType.ACTION_FAILED],
            limit=limit,
        )

    def get_severity_distribution(self, seconds: int = 300) -> Dict[str, int]:
        """Get event counts by severity for the dashboard."""
        cutoff = time.time_ns() - (seconds * 1_000_000_000)
        conn = self._connect()
        rows = conn.execute(
            """SELECT severity, COUNT(*) as cnt
               FROM mesh_events WHERE timestamp_ns > ?
               GROUP BY severity""",
            (cutoff,),
        ).fetchall()
        conn.close()
        return {r["severity"]: r["cnt"] for r in rows}

    def get_active_threats(self, seconds: int = 300) -> List[Dict]:
        """Get high/critical events that haven't been resolved.

        An event is considered resolved if there's an ACTION_TAKEN
        event referencing the same PID or IP.
        """
        cutoff = time.time_ns() - (seconds * 1_000_000_000)
        conn = self._connect()

        threats = conn.execute(
            """SELECT * FROM mesh_events
               WHERE timestamp_ns > ?
               AND severity IN ('high', 'critical')
               AND event_type NOT IN ('action_taken', 'action_failed')
               ORDER BY timestamp_ns DESC LIMIT 50""",
            (cutoff,),
        ).fetchall()

        # Check which have been acted on
        actions = conn.execute(
            """SELECT payload FROM mesh_events
               WHERE timestamp_ns > ?
               AND event_type = 'action_taken'""",
            (cutoff,),
        ).fetchall()
        conn.close()

        acted_pids = set()
        acted_ips = set()
        for a in actions:
            try:
                p = json.loads(a["payload"])
                if "pid" in str(p.get("target", "")):
                    acted_pids.add(p.get("target"))
                if "." in str(p.get("target", "")):
                    acted_ips.add(p.get("target"))
            except (json.JSONDecodeError, TypeError):
                pass

        result = []
        for t in threats:
            is_resolved = (
                str(t["related_pid"]) in acted_pids
                or t["related_ip"] in acted_ips
            )
            entry = {
                "event_id": t["event_id"],
                "event_type": t["event_type"],
                "severity": t["severity"],
                "source_agent": t["source_agent"],
                "related_pid": t["related_pid"],
                "related_ip": t["related_ip"],
                "timestamp_ns": t["timestamp_ns"],
                "resolved": is_resolved,
            }
            result.append(entry)

        return result

    def get_mesh_stats(self) -> Dict[str, Any]:
        """Get overall mesh statistics for the dashboard."""
        conn = self._connect()
        now = time.time_ns()
        hour_ago = now - 3_600_000_000_000
        five_min = now - 300_000_000_000

        total = conn.execute(
            "SELECT COUNT(*) FROM mesh_events"
        ).fetchone()[0]
        last_hour = conn.execute(
            "SELECT COUNT(*) FROM mesh_events WHERE timestamp_ns > ?",
            (hour_ago,),
        ).fetchone()[0]
        last_5min = conn.execute(
            "SELECT COUNT(*) FROM mesh_events WHERE timestamp_ns > ?",
            (five_min,),
        ).fetchone()[0]
        critical = conn.execute(
            "SELECT COUNT(*) FROM mesh_events WHERE severity = 'critical' AND timestamp_ns > ?",
            (hour_ago,),
        ).fetchone()[0]

        conn.close()
        return {
            "total_events": total,
            "events_last_hour": last_hour,
            "events_last_5min": last_5min,
            "critical_last_hour": critical,
            "events_per_minute": round(last_5min / 5, 1),
        }
