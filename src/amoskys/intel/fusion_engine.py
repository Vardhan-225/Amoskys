"""
Fusion Engine - Intelligence Correlation Orchestrator

Ingests telemetry events from multiple agents, correlates them across
time windows, and emits higher-level intelligence objects:
- Incidents (attack chains)
- DeviceRiskSnapshots (security posture)

Architecture:
    Agents → EventBus → WAL/DB → FusionEngine → Incidents + Risk DB
"""

import json
import logging
import sqlite3
import time
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

from amoskys.intel.models import (
    DeviceRiskSnapshot,
    Incident,
    RiskLevel,
    Severity,
    TelemetryEventView,
)
from amoskys.intel.rules import evaluate_rules
from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2

logger = logging.getLogger(__name__)


class FusionEngine:
    """Intelligence correlation engine

    Maintains sliding windows of events per device, runs correlation rules,
    and emits incidents + device risk scores.

    Attributes:
        db_path: Path to fusion intelligence database
        window_minutes: Size of correlation window in minutes
        device_state: Per-device event buffers and state
        db: SQLite connection for incidents/risk persistence
    """

    def __init__(
        self,
        db_path: str = "data/intel/fusion.db",
        window_minutes: int = 30,
        eval_interval: int = 60,
    ):
        """Initialize fusion engine

        Args:
            db_path: Path to intelligence database
            window_minutes: Correlation window size (default: 30 minutes)
            eval_interval: How often to evaluate rules in seconds
        """
        self.db_path = db_path
        self.window_minutes = window_minutes
        self.eval_interval = eval_interval

        # Per-device state: event buffers + risk scores
        self.device_state: Dict[str, Dict] = defaultdict(
            lambda: {
                "events": [],
                "risk_score": 10,  # Base score
                "last_eval": None,
                "known_ips": set(),
                "incident_count": 0,
            }
        )

        # Metrics tracking
        self.metrics = {
            "total_events_processed": 0,
            "total_incidents_created": 0,
            "total_evaluations": 0,
            "incidents_by_severity": defaultdict(int),
            "incidents_by_rule": defaultdict(int),
            "devices_tracked": 0,
            "last_eval_duration_ms": 0,
        }

        # Initialize database
        self._init_db()

        logger.info(f"FusionEngine initialized: {db_path}, window={window_minutes}m")

    def _init_db(self):
        """Initialize SQLite database for incidents and device risk"""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

        self.db = sqlite3.connect(self.db_path, isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")

        # Incidents table
        self.db.execute(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY,
                device_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                tactics TEXT NOT NULL,
                techniques TEXT NOT NULL,
                rule_name TEXT NOT NULL,
                summary TEXT NOT NULL,
                start_ts TEXT,
                end_ts TEXT,
                event_ids TEXT NOT NULL,
                metadata TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """
        )
        self.db.execute(
            "CREATE INDEX IF NOT EXISTS idx_incidents_device ON incidents(device_id)"
        )
        self.db.execute(
            "CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents(created_at)"
        )

        # Device risk snapshots table
        self.db.execute(
            """
            CREATE TABLE IF NOT EXISTS device_risk (
                device_id TEXT PRIMARY KEY,
                score INTEGER NOT NULL,
                level TEXT NOT NULL,
                reason_tags TEXT NOT NULL,
                supporting_events TEXT NOT NULL,
                metadata TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """
        )

        logger.info("Fusion database schema initialized")

    def ingest_telemetry_from_db(self, telemetry_db_path: str):
        """Ingest telemetry events from agent database

        Reads recent events from agent WAL/DB and adds them to device buffers.

        Args:
            telemetry_db_path: Path to agent telemetry database
        """
        try:
            db = sqlite3.connect(telemetry_db_path, timeout=5.0)

            # Query recent events (last window_minutes)
            cutoff = datetime.now() - timedelta(minutes=self.window_minutes)
            cutoff_ns = int(cutoff.timestamp() * 1e9)

            # This assumes a unified events table - adapt to your schema
            # For now, we'll skip actual DB ingestion and focus on the correlation logic
            # In production, you'd query from flowagent.db, proc_agent.db, etc.

            db.close()
            logger.debug(f"Ingested events from {telemetry_db_path}")

        except Exception as e:
            logger.error(f"Failed to ingest from {telemetry_db_path}: {e}")

    def add_event(self, event: TelemetryEventView):
        """Add event to device buffer and trim old events

        Args:
            event: Normalized telemetry event view
        """
        device_id = event.device_id
        state = self.device_state[device_id]

        # Add to event buffer
        state["events"].append(event)

        # Update metrics
        self.metrics["total_events_processed"] += 1

        # Trim events outside window
        cutoff = datetime.now() - timedelta(minutes=self.window_minutes)
        state["events"] = [e for e in state["events"] if e.timestamp >= cutoff]

        # Track known IPs for anomaly detection
        if event.security_event:
            source_ip = event.security_event.get("source_ip")
            if source_ip:
                state["known_ips"].add(source_ip)

        logger.debug(
            f"Added event {event.event_id} to {device_id} buffer ({len(state['events'])} events)"
        )

    def evaluate_device(
        self, device_id: str
    ) -> tuple[List[Incident], DeviceRiskSnapshot]:
        """Evaluate correlation rules and update device risk for a single device

        Args:
            device_id: Device to evaluate

        Returns:
            Tuple of (new incidents, updated risk snapshot)
        """
        state = self.device_state[device_id]
        events = state["events"]

        if not events:
            logger.debug(f"No events for {device_id}, skipping evaluation")
            return [], self._get_current_risk_snapshot(device_id)

        # Run correlation rules
        incidents = evaluate_rules(events, device_id)

        # Update device risk score based on recent events + incidents
        risk_snapshot = self._calculate_device_risk(device_id, events, incidents)

        # Update state
        state["last_eval"] = datetime.now()
        state["incident_count"] += len(incidents)

        logger.info(
            f"Evaluated {device_id}: {len(incidents)} incidents, risk={risk_snapshot.score}"
        )

        return incidents, risk_snapshot

    def _calculate_device_risk(
        self,
        device_id: str,
        events: List[TelemetryEventView],
        new_incidents: List[Incident],
    ) -> DeviceRiskSnapshot:
        """Calculate device risk score from events and incidents

        Implements the scoring model:
        - Base: 10 points
        - Failed SSH: +5 each (cap at +20)
        - Successful SSH from new IP: +15
        - New SSH key: +30
        - New LaunchAgent in /Users: +25
        - Suspicious sudo: +30
        - HIGH incident: +20
        - CRITICAL incident: +40
        - Decay: -10 per 10 minutes without risky events
        - Clamp: [0, 100]

        Args:
            device_id: Device being evaluated
            events: Recent events in window
            new_incidents: Incidents fired in this evaluation

        Returns:
            DeviceRiskSnapshot
        """
        state = self.device_state[device_id]
        score = state["risk_score"]  # Start from current score
        reason_tags = []
        supporting_events = []

        # Count event types
        failed_ssh_count = 0
        new_ssh_keys = 0
        new_launch_agents = 0
        suspicious_sudo_count = 0
        successful_ssh_new_ip = 0

        for event in events:
            # Failed SSH attempts
            if (
                event.event_type == "SECURITY"
                and event.security_event
                and event.security_event.get("event_action") == "SSH"
                and event.security_event.get("event_outcome") == "FAILURE"
            ):
                failed_ssh_count += 1
                supporting_events.append(event.event_id)

            # Successful SSH from new IP
            elif (
                event.event_type == "SECURITY"
                and event.security_event
                and event.security_event.get("event_action") == "SSH"
                and event.security_event.get("event_outcome") == "SUCCESS"
            ):
                source_ip = event.security_event.get("source_ip")
                # Simple new IP detection (in production, use better baseline)
                if source_ip and source_ip not in ["127.0.0.1", "localhost"]:
                    successful_ssh_new_ip += 1
                    supporting_events.append(event.event_id)

            # SSH key changes
            elif (
                event.event_type == "AUDIT"
                and event.audit_event
                and event.audit_event.get("object_type") == "SSH_KEYS"
            ):
                new_ssh_keys += 1
                supporting_events.append(event.event_id)

            # Launch agents in user directories
            elif (
                event.event_type == "AUDIT"
                and event.audit_event
                and event.audit_event.get("object_type")
                in ["LAUNCH_AGENT", "LAUNCH_DAEMON"]
                and "/Users/" in event.attributes.get("file_path", "")
            ):
                new_launch_agents += 1
                supporting_events.append(event.event_id)

            # Suspicious sudo
            elif (
                event.event_type == "SECURITY"
                and event.security_event
                and event.security_event.get("event_action") == "SUDO"
            ):
                command = event.attributes.get("sudo_command", "")
                if any(
                    pattern in command
                    for pattern in ["rm -rf", "/etc/sudoers", "LaunchAgent"]
                ):
                    suspicious_sudo_count += 1
                    supporting_events.append(event.event_id)

        # Apply scoring rules
        if failed_ssh_count > 0:
            points = min(failed_ssh_count * 5, 20)  # Cap at +20
            score += points
            reason_tags.append(f"ssh_brute_force_attempts_{failed_ssh_count}")

        if successful_ssh_new_ip > 0:
            score += successful_ssh_new_ip * 15
            reason_tags.append(f"ssh_logins_new_ip_{successful_ssh_new_ip}")

        if new_ssh_keys > 0:
            score += new_ssh_keys * 30
            reason_tags.append(f"new_ssh_keys_{new_ssh_keys}")

        if new_launch_agents > 0:
            score += new_launch_agents * 25
            reason_tags.append(f"new_persistence_{new_launch_agents}")

        if suspicious_sudo_count > 0:
            score += suspicious_sudo_count * 30
            reason_tags.append(f"suspicious_sudo_{suspicious_sudo_count}")

        # Add incident contributions
        for incident in new_incidents:
            if incident.severity == Severity.CRITICAL:
                score += 40
                reason_tags.append(f"incident_critical_{incident.rule_name}")
            elif incident.severity == Severity.HIGH:
                score += 20
                reason_tags.append(f"incident_high_{incident.rule_name}")

            supporting_events.extend(incident.event_ids)

        # Decay: reduce score over time if no recent risky events
        if state["last_eval"]:
            time_since_eval = (datetime.now() - state["last_eval"]).total_seconds()
            decay_periods = int(time_since_eval / 600)  # Every 10 minutes
            if decay_periods > 0 and not reason_tags:
                score -= decay_periods * 10
                reason_tags.append(f"score_decay_{decay_periods}x10min")

        # Clamp [0, 100]
        score = max(0, min(100, score))

        # Update state
        state["risk_score"] = score

        # Map to level
        level = DeviceRiskSnapshot.score_to_level(score)

        snapshot = DeviceRiskSnapshot(
            device_id=device_id,
            score=score,
            level=level,
            reason_tags=reason_tags[:10],  # Limit to 10 most recent
            supporting_events=supporting_events[:50],  # Limit to 50
            metadata={
                "event_count": str(len(events)),
                "incident_count": str(len(new_incidents)),
                "window_minutes": str(self.window_minutes),
            },
        )

        return snapshot

    def _get_current_risk_snapshot(self, device_id: str) -> DeviceRiskSnapshot:
        """Get current risk snapshot for device (no evaluation)

        Args:
            device_id: Device ID

        Returns:
            DeviceRiskSnapshot with current score
        """
        state = self.device_state[device_id]
        score = state["risk_score"]
        level = DeviceRiskSnapshot.score_to_level(score)

        return DeviceRiskSnapshot(
            device_id=device_id,
            score=score,
            level=level,
            metadata={"window_minutes": str(self.window_minutes)},
        )

    def persist_incident(self, incident: Incident):
        """Save incident to database

        Args:
            incident: Incident to persist
        """
        try:
            self.db.execute(
                """
                INSERT OR REPLACE INTO incidents
                (incident_id, device_id, severity, tactics, techniques, rule_name,
                 summary, start_ts, end_ts, event_ids, metadata, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident.incident_id,
                    incident.device_id,
                    incident.severity.value,
                    json.dumps(incident.tactics),
                    json.dumps(incident.techniques),
                    incident.rule_name,
                    incident.summary,
                    incident.start_ts.isoformat() if incident.start_ts else None,
                    incident.end_ts.isoformat() if incident.end_ts else None,
                    json.dumps(incident.event_ids),
                    json.dumps(incident.metadata),
                    incident.created_at.isoformat(),
                ),
            )
            logger.info(f"Persisted incident: {incident.incident_id}")
        except Exception as e:
            logger.error(f"Failed to persist incident {incident.incident_id}: {e}")

    def persist_risk_snapshot(self, snapshot: DeviceRiskSnapshot):
        """Save device risk snapshot to database

        Args:
            snapshot: Risk snapshot to persist
        """
        try:
            self.db.execute(
                """
                INSERT OR REPLACE INTO device_risk
                (device_id, score, level, reason_tags, supporting_events, metadata, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot.device_id,
                    snapshot.score,
                    snapshot.level.value,
                    json.dumps(snapshot.reason_tags),
                    json.dumps(snapshot.supporting_events),
                    json.dumps(snapshot.metadata),
                    snapshot.updated_at.isoformat(),
                ),
            )
            logger.debug(
                f"Persisted risk snapshot for {snapshot.device_id}: {snapshot.score}"
            )
        except Exception as e:
            logger.error(
                f"Failed to persist risk snapshot for {snapshot.device_id}: {e}"
            )

    def evaluate_all_devices(self):
        """Evaluate all devices with pending events

        Runs correlation rules for each device and persists results.
        Logs structured metrics for observability.
        """
        start_time = time.time()

        total_incidents_this_cycle = 0
        devices_evaluated = 0

        for device_id in list(self.device_state.keys()):
            try:
                incidents, risk_snapshot = self.evaluate_device(device_id)

                # Persist incidents
                for incident in incidents:
                    self.persist_incident(incident)

                    # Update metrics
                    self.metrics["total_incidents_created"] += 1
                    self.metrics["incidents_by_severity"][incident.severity.value] += 1
                    self.metrics["incidents_by_rule"][incident.rule_name] += 1

                    # Structured log for each incident
                    logger.warning(
                        f"INCIDENT_CREATED | "
                        f"device_id={device_id} | "
                        f"incident_id={incident.incident_id} | "
                        f"rule={incident.rule_name} | "
                        f"severity={incident.severity.value} | "
                        f"tactics={','.join(incident.tactics)} | "
                        f"techniques={','.join(incident.techniques)}"
                    )

                # Persist risk snapshot
                self.persist_risk_snapshot(risk_snapshot)

                devices_evaluated += 1
                total_incidents_this_cycle += len(incidents)

            except Exception as e:
                logger.error(f"Failed to evaluate {device_id}: {e}", exc_info=True)

        # Update global metrics
        self.metrics["total_evaluations"] += 1
        self.metrics["devices_tracked"] = len(self.device_state)

        duration_ms = int((time.time() - start_time) * 1000)
        self.metrics["last_eval_duration_ms"] = duration_ms

        # Structured evaluation summary
        logger.info(
            f"EVALUATION_COMPLETE | "
            f"devices={devices_evaluated} | "
            f"incidents={total_incidents_this_cycle} | "
            f"duration_ms={duration_ms} | "
            f"avg_events_per_device={sum(len(s['events']) for s in self.device_state.values()) / max(1, len(self.device_state)):.1f}"
        )

    def get_recent_incidents(
        self, device_id: Optional[str] = None, limit: int = 100
    ) -> List[Dict]:
        """Retrieve recent incidents from database

        Args:
            device_id: Optional filter by device
            limit: Maximum incidents to return

        Returns:
            List of incident dictionaries
        """
        query = "SELECT * FROM incidents"
        params = []

        if device_id:
            query += " WHERE device_id = ?"
            params.append(device_id)

        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        rows = self.db.execute(query, params).fetchall()

        incidents = []
        for row in rows:
            incidents.append(
                {
                    "incident_id": row[0],
                    "device_id": row[1],
                    "severity": row[2],
                    "tactics": json.loads(row[3]),
                    "techniques": json.loads(row[4]),
                    "rule_name": row[5],
                    "summary": row[6],
                    "start_ts": row[7],
                    "end_ts": row[8],
                    "event_ids": json.loads(row[9]),
                    "metadata": json.loads(row[10]),
                    "created_at": row[11],
                }
            )

        return incidents

    def get_device_risk(self, device_id: str) -> Optional[Dict]:
        """Retrieve current risk snapshot for device

        Args:
            device_id: Device to query

        Returns:
            Risk snapshot dictionary or None
        """
        row = self.db.execute(
            "SELECT * FROM device_risk WHERE device_id = ?", (device_id,)
        ).fetchone()

        if not row:
            return None

        return {
            "device_id": row[0],
            "score": row[1],
            "level": row[2],
            "reason_tags": json.loads(row[3]),
            "supporting_events": json.loads(row[4]),
            "metadata": json.loads(row[5]),
            "updated_at": row[6],
        }

    def run_once(self):
        """Run single evaluation pass

        For testing and manual invocation.
        """
        logger.info("=" * 60)
        logger.info("Running Fusion Engine evaluation pass")
        logger.info("=" * 60)

        start = time.time()

        # Evaluate all devices
        self.evaluate_all_devices()

        # Print summary
        total_devices = len(self.device_state)
        total_incidents = sum(s["incident_count"] for s in self.device_state.values())

        logger.info(f"Evaluation complete in {time.time() - start:.2f}s")
        logger.info(f"Devices: {total_devices}, Total incidents: {total_incidents}")

        # Print recent incidents
        recent = self.get_recent_incidents(limit=10)
        if recent:
            logger.info("\nRecent Incidents:")
            for inc in recent:
                logger.info(
                    f"  [{inc['severity']}] {inc['rule_name']}: {inc['summary']}"
                )

        # Print device risk
        logger.info("\nDevice Risk Snapshots:")
        for device_id in self.device_state.keys():
            risk = self.get_device_risk(device_id)
            if risk:
                logger.info(
                    f"  {device_id}: {risk['level']} (score={risk['score']}) - {risk['reason_tags']}"
                )

    def run(self, interval: Optional[int] = None):
        """Main evaluation loop

        Args:
            interval: Seconds between evaluations (default: from init)
        """
        interval = interval or self.eval_interval

        logger.info("Fusion Engine starting...")
        logger.info(f"Evaluation interval: {interval}s")
        logger.info(f"Correlation window: {self.window_minutes} minutes")

        cycle = 0
        while True:
            cycle += 1
            logger.info(f"Cycle #{cycle} - {datetime.now().isoformat()}")

            try:
                self.evaluate_all_devices()
            except Exception as e:
                logger.error(f"Evaluation cycle failed: {e}", exc_info=True)

            logger.info(f"Next evaluation in {interval}s...")
            time.sleep(interval)


def main():
    """CLI entrypoint"""
    import argparse

    parser = argparse.ArgumentParser(
        description="AMOSKYS Fusion Intelligence Engine",
        epilog="Examples:\n"
        "  amoskys-fusion --once                    # Single evaluation pass\n"
        "  amoskys-fusion --interval 60             # Continuous evaluation\n"
        "  amoskys-fusion --list-incidents          # Show recent incidents\n"
        "  amoskys-fusion --risk macbook-pro        # Show device risk\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Operational modes
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--once", action="store_true", help="Run single evaluation pass and exit"
    )
    mode_group.add_argument(
        "--list-incidents", action="store_true", help="List recent incidents and exit"
    )
    mode_group.add_argument(
        "--risk",
        type=str,
        metavar="DEVICE_ID",
        help="Show device risk snapshot and exit",
    )

    # Query filters
    parser.add_argument(
        "--device", type=str, metavar="DEVICE_ID", help="Filter incidents by device ID"
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Limit number of incidents to show (default: 20)",
    )
    parser.add_argument(
        "--severity",
        type=str,
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        help="Filter incidents by severity",
    )

    # Engine configuration
    parser.add_argument(
        "--interval",
        type=int,
        default=60,
        help="Evaluation interval in seconds (default: 60)",
    )
    parser.add_argument(
        "--window",
        type=int,
        default=30,
        help="Correlation window in minutes (default: 30)",
    )
    parser.add_argument(
        "--db",
        type=str,
        default="data/intel/fusion.db",
        help="Intelligence database path",
    )

    # Output formatting
    parser.add_argument("--json", action="store_true", help="Output in JSON format")
    parser.add_argument(
        "--verbose", action="store_true", help="Show detailed information"
    )

    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    engine = FusionEngine(
        db_path=args.db, window_minutes=args.window, eval_interval=args.interval
    )

    # Query modes (read-only)
    if args.list_incidents:
        _list_incidents_cli(engine, args)
        return

    if args.risk:
        _show_device_risk_cli(engine, args.risk, args)
        return

    # Operational modes (evaluation)
    if args.once:
        engine.run_once()
    else:
        engine.run(interval=args.interval)


def _list_incidents_cli(engine: FusionEngine, args):
    """CLI handler for --list-incidents"""
    import json as jsonlib

    incidents = engine.get_recent_incidents(device_id=args.device, limit=args.limit)

    # Apply severity filter if specified
    if args.severity:
        incidents = [inc for inc in incidents if inc["severity"] == args.severity]

    if args.json:
        print(jsonlib.dumps(incidents, indent=2))
        return

    # Pretty print
    if not incidents:
        print("No incidents found.")
        return

    print("=" * 80)
    print(f"Recent Incidents ({len(incidents)} total)")
    print("=" * 80)
    print()

    for inc in incidents:
        severity_icon = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🟢",
            "INFO": "🔵",
        }.get(inc["severity"], "⚪")

        print(f"{severity_icon} [{inc['severity']}] {inc['rule_name']}")
        print(f"   Device: {inc['device_id']}")
        print(f"   Summary: {inc['summary']}")
        print(f"   Tactics: {', '.join(inc['tactics'])}")
        print(f"   Techniques: {', '.join(inc['techniques'])}")
        print(f"   Created: {inc['created_at']}")

        if args.verbose:
            print(f"   Event IDs: {', '.join(inc['event_ids'][:5])}")
            if len(inc["event_ids"]) > 5:
                print(f"              ... and {len(inc['event_ids']) - 5} more")
            print(f"   Metadata: {inc['metadata']}")

        print()


def _show_device_risk_cli(engine: FusionEngine, device_id: str, args):
    """CLI handler for --risk DEVICE_ID"""
    import json as jsonlib

    risk = engine.get_device_risk(device_id)

    if not risk:
        print(f"No risk data found for device: {device_id}")
        return

    if args.json:
        print(jsonlib.dumps(risk, indent=2))
        return

    # Pretty print
    level_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(
        risk["level"], "⚪"
    )

    print("=" * 80)
    print(f"Device Risk Snapshot: {device_id}")
    print("=" * 80)
    print()
    print(f"{level_icon} Risk Level: {risk['level']}")
    print(f"   Score: {risk['score']}/100")
    print(f"   Updated: {risk['updated_at']}")
    print()
    print("Contributing Factors:")
    for tag in risk["reason_tags"]:
        print(f"  • {tag}")

    if args.verbose and risk["supporting_events"]:
        print()
        print(f"Supporting Events ({len(risk['supporting_events'])}):")
        for event_id in risk["supporting_events"][:10]:
            print(f"  - {event_id}")
        if len(risk["supporting_events"]) > 10:
            print(f"  ... and {len(risk['supporting_events']) - 10} more")

    print()


if __name__ == "__main__":
    main()
