"""Signal and incident management mixin for TelemetryStore."""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("TelemetryStore")


class SignalMixin:
    """Incident management and signal layer (Directive 3) methods."""

    def create_incident(self, data: Dict[str, Any]) -> Optional[int]:
        """Create a security incident."""
        now = datetime.now(timezone.utc).isoformat()
        try:
            cursor = self.db.execute(
                """INSERT INTO incidents (
                    created_at, updated_at, title, description, severity,
                    status, assignee, source_event_ids, mitre_techniques,
                    indicators
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    now,
                    now,
                    data.get("title", "Untitled Incident"),
                    data.get("description", ""),
                    data.get("severity", "medium"),
                    data.get("status", "open"),
                    data.get("assignee"),
                    json.dumps(data.get("source_event_ids", [])),
                    json.dumps(data.get("mitre_techniques", []))
                    if isinstance(data.get("mitre_techniques"), list)
                    else (data.get("mitre_techniques") or "[]"),
                    json.dumps(data.get("indicators", {})),
                ),
            )
            self._commit()
            return cursor.lastrowid
        except sqlite3.Error as e:
            logger.error("Failed to create incident: %s", e)
            return None

    def update_incident(self, incident_id: int, data: Dict[str, Any]) -> bool:
        """Update an existing incident."""
        now = datetime.now(timezone.utc).isoformat()
        now_ns = int(time.time() * 1e9)
        sets = ["updated_at = ?", "last_activity_ns = ?"]
        params: list = [now, now_ns]
        allowed = {
            "title",
            "description",
            "severity",
            "status",
            "assignee",
            "assigned_to",
            "resolution_notes",
            "resolution_summary",
            "investigation_notes",
            "containment_actions",
            "signal_ids",
            "timeline_events",
            "sla_deadline_ns",
        }
        for k, v in data.items():
            if k in allowed:
                sets.append(f"{k} = ?")
                params.append(v)
        if data.get("status") == "resolved" and not data.get("resolved_at"):
            sets.append("resolved_at = ?")
            params.append(now)
        params.append(incident_id)
        try:
            self.db.execute(
                f"UPDATE incidents SET {', '.join(sets)} WHERE id = ?", params
            )
            self._commit()
            return True
        except sqlite3.Error as e:
            logger.error("Failed to update incident: %s", e)
            return False

    def get_incidents(
        self,
        status: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Get incidents with optional status filter and pagination."""
        with self._lock:
            try:
                if status:
                    cursor = self.db.execute(
                        "SELECT * FROM incidents WHERE status = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
                        (status, limit, offset),
                    )
                else:
                    cursor = self.db.execute(
                        "SELECT * FROM incidents ORDER BY created_at DESC LIMIT ? OFFSET ?",
                        (limit, offset),
                    )
                return [dict(r) for r in cursor.fetchall()]
            except sqlite3.Error as e:
                logger.error("Failed to get incidents: %s", e)
                return []

    def get_incidents_count(self, status: Optional[str] = None) -> int:
        """Get total count of incidents, optionally filtered by status."""
        with self._lock:
            try:
                if status:
                    row = self.db.execute(
                        "SELECT COUNT(*) FROM incidents WHERE status = ?",
                        (status,),
                    ).fetchone()
                else:
                    row = self.db.execute("SELECT COUNT(*) FROM incidents").fetchone()
                return int(row[0]) if row else 0
            except sqlite3.Error as e:
                logger.error("Failed to get incidents count: %s", e)
                return 0

    def get_incidents_status_counts(self) -> Dict[str, int]:
        """Get counts per status for incident summary cards."""
        with self._lock:
            try:
                cursor = self.db.execute(
                    "SELECT status, COUNT(*) FROM incidents GROUP BY status"
                )
                return {row[0]: row[1] for row in cursor.fetchall()}
            except sqlite3.Error as e:
                logger.error("Failed to get incidents status counts: %s", e)
                return {}

    def get_incidents_severity_counts(self) -> Dict[str, int]:
        """Get counts per severity for incident charts (all incidents)."""
        with self._lock:
            try:
                counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                cursor = self.db.execute(
                    "SELECT severity, COUNT(*) FROM incidents GROUP BY severity"
                )
                for row in cursor.fetchall():
                    severity = str(row[0] or "").lower()
                    if severity in counts:
                        counts[severity] = row[1]
                return counts
            except sqlite3.Error as e:
                logger.error("Failed to get incidents severity counts: %s", e)
                return {"critical": 0, "high": 0, "medium": 0, "low": 0}

    def get_incident(self, incident_id: int) -> Optional[Dict[str, Any]]:
        """Get a single incident by ID."""
        with self._lock:
            try:
                cursor = self.db.execute(
                    "SELECT * FROM incidents WHERE id = ?", (incident_id,)
                )
                row = cursor.fetchone()
                return dict(row) if row else None
            except sqlite3.Error as e:
                logger.error("Failed to get incident: %s", e)
                return None

    # ── Signals Layer (Directive 3) ──────────────────────────────────────────

    _SIGNAL_MERGE_WINDOW_NS = int(3600 * 1e9)  # 1h merge window
    _SIGNAL_AUTO_EXPIRE_NS = int(2 * 3600 * 1e9)  # 2h auto-expire (IGRIS directive)

    def create_signal(
        self,
        device_id: str,
        signal_type: str,
        trigger_summary: str,
        contributing_event_ids: List[int],
        risk_score: float,
    ) -> Optional[str]:
        """Create a new signal or merge into existing open signal."""
        import secrets

        now_ns = int(time.time() * 1e9)
        merge_cutoff = now_ns - self._SIGNAL_MERGE_WINDOW_NS

        try:
            existing = self.db.execute(
                """SELECT id, signal_id, contributing_event_ids, risk_score
                   FROM signals
                   WHERE device_id = ? AND signal_type = ? AND status = 'open'
                     AND created_ns > ?
                   ORDER BY created_ns DESC LIMIT 1""",
                (device_id, signal_type, merge_cutoff),
            ).fetchone()

            if existing:
                old_ids = json.loads(existing[2]) if existing[2] else []
                merged_ids = list(set(old_ids + contributing_event_ids))
                new_risk = max(existing[3], risk_score)
                self.db.execute(
                    """UPDATE signals SET contributing_event_ids = ?,
                       risk_score = ?, updated_ns = ?
                       WHERE id = ?""",
                    (json.dumps(merged_ids), new_risk, now_ns, existing[0]),
                )
                self._commit()
                logger.info(
                    "Merged into signal %s: %d events, risk=%.2f",
                    existing[1],
                    len(merged_ids),
                    new_risk,
                )
                return existing[1]

        except sqlite3.Error:
            pass

        signal_id = f"SIG-{secrets.token_hex(8)}"
        try:
            self.db.execute(
                """INSERT INTO signals (
                    signal_id, device_id, created_ns, signal_type,
                    trigger_summary, contributing_event_ids, risk_score,
                    status, updated_ns
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'open', ?)""",
                (
                    signal_id,
                    device_id,
                    now_ns,
                    signal_type,
                    trigger_summary,
                    json.dumps(contributing_event_ids),
                    risk_score,
                    now_ns,
                ),
            )
            self._commit()
            logger.info(
                "Created signal %s: type=%s device=%s risk=%.2f",
                signal_id,
                signal_type,
                device_id,
                risk_score,
            )
            return signal_id
        except sqlite3.Error as e:
            logger.error("Failed to create signal: %s", e)
            return None

    def promote_signal(self, signal_id: str) -> Optional[int]:
        """Promote a signal to an incident. Returns incident ID."""
        now_ns = int(time.time() * 1e9)
        try:
            row = self.db.execute(
                "SELECT * FROM signals WHERE signal_id = ? AND status = 'open'",
                (signal_id,),
            ).fetchone()
            if not row:
                return None

            sig = dict(row)
            event_ids = (
                json.loads(sig["contributing_event_ids"])
                if sig["contributing_event_ids"]
                else []
            )

            incident_id = self.create_incident(
                {
                    "title": f"[{sig['signal_type'].upper()}] {sig['trigger_summary']}",
                    "description": f"Auto-promoted from signal {signal_id}",
                    "severity": (
                        "critical"
                        if sig["risk_score"] >= 0.8
                        else "high" if sig["risk_score"] >= 0.5 else "medium"
                    ),
                    "source_event_ids": event_ids,
                }
            )

            if incident_id:
                self.db.execute(
                    """UPDATE signals SET status = 'promoted',
                       promoted_to_incident = ?, updated_ns = ?
                       WHERE signal_id = ?""",
                    (incident_id, now_ns, signal_id),
                )
                self.db.execute(
                    "UPDATE incidents SET signal_ids = ? WHERE id = ?",
                    (json.dumps([signal_id]), incident_id),
                )
                self._commit()
                logger.info("Promoted signal %s → incident #%d", signal_id, incident_id)

            return incident_id
        except sqlite3.Error as e:
            logger.error("Failed to promote signal: %s", e)
            return None

    def dismiss_signal(
        self, signal_id: str, dismissed_by: str = "system", reason: str = ""
    ) -> bool:
        """Dismiss a signal. Feeds back into AMRDR for tuning."""
        now_ns = int(time.time() * 1e9)
        try:
            self.db.execute(
                """UPDATE signals SET status = 'dismissed',
                   dismissed_by = ?, dismissed_reason = ?, updated_ns = ?
                   WHERE signal_id = ? AND status = 'open'""",
                (dismissed_by, reason, now_ns, signal_id),
            )
            self._commit()
            return True
        except sqlite3.Error as e:
            logger.error("Failed to dismiss signal: %s", e)
            return False

    def get_signals(
        self, status: Optional[str] = None, limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Get signals with optional status filter."""
        try:
            if status:
                cursor = self.db.execute(
                    "SELECT * FROM signals WHERE status = ? ORDER BY created_ns DESC LIMIT ?",
                    (status, limit),
                )
            else:
                cursor = self.db.execute(
                    "SELECT * FROM signals ORDER BY created_ns DESC LIMIT ?",
                    (limit,),
                )
            return [dict(r) for r in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error("Failed to get signals: %s", e)
            return []

    def expire_stale_signals(self) -> int:
        """Auto-expire open signals older than 2h with no promotion.

        Stale signals teach operators to ignore signals. If a signal
        sits open for 2 hours without being promoted to an incident,
        it's noise — dismiss it automatically.
        """
        now_ns = int(time.time() * 1e9)
        cutoff_ns = now_ns - self._SIGNAL_AUTO_EXPIRE_NS
        try:
            result = self.db.execute(
                """UPDATE signals SET status = 'expired',
                   dismissed_by = 'igris_auto', dismissed_reason = 'expired — no escalation in 2h',
                   updated_ns = ?
                   WHERE status = 'open' AND created_ns < ?""",
                (now_ns, cutoff_ns),
            )
            self._commit()
            if result.rowcount > 0:
                logger.info("IGRIS auto-expired %d stale signals", result.rowcount)
            return result.rowcount
        except sqlite3.Error:
            return 0

    def evaluate_auto_signals(self) -> List[str]:
        """Evaluate auto-signal rules against recent security events."""
        created = []
        now_ns = int(time.time() * 1e9)
        window_10m = now_ns - int(600 * 1e9)
        window_1h = now_ns - int(3600 * 1e9)

        with self._read_pool.connection() as rdb:
            # Rule 1: Risk threshold (>= 0.8)
            try:
                high_risk = rdb.execute(
                    """SELECT id, device_id, risk_score, event_category,
                              mitre_techniques
                       FROM security_events
                       WHERE timestamp_ns > ? AND risk_score >= 0.8""",
                    (window_1h,),
                ).fetchall()

                device_events: Dict[str, list] = {}
                for row in high_risk:
                    did = row[1]
                    device_events.setdefault(did, []).append(row)

                for device_id, events in device_events.items():
                    event_ids = [e[0] for e in events]
                    max_risk = max(e[2] for e in events)
                    categories = [e[3] for e in events if e[3]]
                    sig_id = self.create_signal(
                        device_id=device_id,
                        signal_type="threshold",
                        trigger_summary=f"{len(events)} high-risk event(s): {', '.join(list(set(categories))[:3])}",
                        contributing_event_ids=event_ids,
                        risk_score=max_risk,
                    )
                    if sig_id:
                        created.append(sig_id)
            except sqlite3.Error:
                pass

            # Rule 2: Anomaly burst (5+ events in 10min)
            try:
                burst_rows = rdb.execute(
                    """SELECT device_id, COUNT(*) as cnt,
                              GROUP_CONCAT(id) as ids, MAX(risk_score) as max_r
                       FROM security_events
                       WHERE timestamp_ns > ? AND risk_score > 0
                       GROUP BY device_id
                       HAVING cnt >= 5""",
                    (window_10m,),
                ).fetchall()

                for row in burst_rows:
                    device_id = row[0]
                    count = row[1]
                    event_ids = [int(x) for x in row[2].split(",")]
                    sig_id = self.create_signal(
                        device_id=device_id,
                        signal_type="anomaly_burst",
                        trigger_summary=f"{count} security events in 10 min",
                        contributing_event_ids=event_ids,
                        risk_score=row[3],
                    )
                    if sig_id:
                        created.append(sig_id)
            except sqlite3.Error:
                pass

            # Rule 3: Kill chain progression (2+ tactics in 1h)
            try:
                tactic_rows = rdb.execute(
                    """SELECT device_id, mitre_techniques, id
                       FROM security_events
                       WHERE timestamp_ns > ? AND mitre_techniques IS NOT NULL
                         AND mitre_techniques != '[]'""",
                    (window_1h,),
                ).fetchall()

                device_tactics: Dict[str, Dict[str, list]] = {}
                for row in tactic_rows:
                    device_id = row[0]
                    try:
                        techniques = json.loads(row[1]) if row[1] else []
                    except json.JSONDecodeError:
                        continue
                    device_tactics.setdefault(device_id, {})
                    for tech in techniques:
                        device_tactics[device_id].setdefault(tech, []).append(row[2])

                for device_id, techs in device_tactics.items():
                    if len(techs) >= 2:
                        all_ids = []
                        for ids in techs.values():
                            all_ids.extend(ids)
                        sig_id = self.create_signal(
                            device_id=device_id,
                            signal_type="kill_chain",
                            trigger_summary=f"{len(techs)} MITRE techniques: {', '.join(list(techs.keys())[:4])}",
                            contributing_event_ids=list(set(all_ids)),
                            risk_score=0.75,
                        )
                        if sig_id:
                            created.append(sig_id)
            except sqlite3.Error:
                pass

        self.expire_stale_signals()

        return created

    def build_incident_timeline(
        self, device_id: str, start_ns: int, end_ns: int, limit: int = 200
    ) -> List[Dict[str, Any]]:
        """Assemble cross-agent timeline for incident investigation."""
        timeline: List[Dict[str, Any]] = []

        _SIGNIFICANCE = {
            "security": 10,
            "process": 3,
            "flow": 4,
            "dns": 3,
            "audit": 5,
            "fim": 6,
            "persistence": 8,
            "peripheral": 4,
            "observation": 1,
        }

        tables = [
            ("security_events", "security", "device_id"),
            ("process_events", "process", "device_id"),
            ("flow_events", "flow", "device_id"),
            ("dns_events", "dns", "device_id"),
            ("audit_events", "audit", "device_id"),
            ("fim_events", "fim", "device_id"),
            ("persistence_events", "persistence", "device_id"),
        ]

        with self._read_pool.connection() as rdb:
            for table, source, dev_col in tables:
                try:
                    rows = rdb.execute(
                        f"""SELECT timestamp_ns, * FROM {table}
                            WHERE {dev_col} = ? AND timestamp_ns BETWEEN ? AND ?
                            ORDER BY timestamp_ns
                            LIMIT ?""",
                        (device_id, start_ns, end_ns, limit),
                    ).fetchall()
                    for row in rows:
                        row_dict = dict(row)
                        timeline.append(
                            {
                                "ts": row_dict.get("timestamp_ns", 0),
                                "source": source,
                                "significance": _SIGNIFICANCE.get(source, 1),
                                "data": row_dict,
                            }
                        )
                except sqlite3.Error:
                    pass

        timeline.sort(key=lambda x: (x["ts"], -x["significance"]))

        collapsed: List[Dict[str, Any]] = []
        run_source = None
        run_count = 0
        for entry in timeline:
            if entry["significance"] <= 2 and entry["source"] == run_source:
                run_count += 1
                if run_count <= 3:
                    collapsed.append(entry)
                elif run_count == 4:
                    collapsed.append(
                        {
                            "ts": entry["ts"],
                            "source": entry["source"],
                            "significance": 0,
                            "data": {
                                "_collapsed": True,
                                "_message": f"...and more {entry['source']} events",
                            },
                        }
                    )
            else:
                run_source = entry["source"]
                run_count = 1
                collapsed.append(entry)

        return collapsed[:limit]
