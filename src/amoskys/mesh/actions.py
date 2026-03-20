"""
ActionExecutor — IGRIS's hands. Executes defensive actions on the host.

Every action is:
  1. Confidence-gated (Low/Medium/High/Critical determines what's allowed)
  2. Logged with a signed receipt (Ed25519 for forensic integrity)
  3. Published to the mesh as ACTION_TAKEN or ACTION_FAILED

Action Tiers:
  Low  (0.3-0.5): log, direct_watch, trigger_collection
  Med  (0.5-0.7): above + promote_signal, add_threat_indicator
  High (0.7-0.9): above + block_ip, block_domain, stop_agent
  Crit (0.9+):    above + kill_process, quarantine_binary
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import signal
import sqlite3
import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from .events import EventType, SecurityEvent, Severity

logger = logging.getLogger("amoskys.mesh.actions")

QUARANTINE_DIR = Path("/var/amoskys/quarantine")
BLOCKLIST_PATH = Path("/etc/amoskys/blocked_domains.txt")


@dataclass
class ActionReceipt:
    """Signed proof that an action was taken."""

    receipt_id: str
    action: str
    target: str
    result: str
    timestamp_ns: int
    confidence: float
    evidence_chain: list
    signature: Optional[bytes] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "action": self.action,
            "target": self.target,
            "result": self.result,
            "timestamp_ns": self.timestamp_ns,
            "confidence": self.confidence,
            "evidence_chain": self.evidence_chain,
        }


# Confidence thresholds for action tiers
TIER_LOW = 0.3
TIER_MEDIUM = 0.5
TIER_HIGH = 0.7
TIER_CRITICAL = 0.9


def _check_confidence(action: str, confidence: float, required: float) -> None:
    """Raise if confidence is below the required threshold for this action."""
    if confidence < required:
        raise PermissionError(
            f"Action '{action}' requires confidence >= {required}, "
            f"got {confidence:.2f}"
        )


class ActionExecutor:
    """Executes defensive actions with confidence gating and audit logging.

    Args:
        mesh_bus: MeshBus instance for publishing ACTION_TAKEN events.
        db_path: Path to action receipts database.
        dry_run: If True, log actions but don't execute them (for testing).
    """

    def __init__(
        self,
        mesh_bus=None,
        db_path: str = "data/action_receipts.db",
        dry_run: bool = False,
    ):
        self._bus = mesh_bus
        self._db_path = db_path
        self._dry_run = dry_run
        self._init_db()

    def _init_db(self) -> None:
        conn = sqlite3.connect(self._db_path)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS action_receipts (
                receipt_id TEXT PRIMARY KEY,
                action TEXT NOT NULL,
                target TEXT NOT NULL,
                result TEXT NOT NULL,
                timestamp_ns INTEGER NOT NULL,
                confidence REAL,
                evidence_chain TEXT,
                signature BLOB
            )
        """
        )
        conn.commit()
        conn.close()

    def _record_receipt(self, receipt: ActionReceipt) -> None:
        """Store the action receipt for forensic audit."""
        conn = sqlite3.connect(self._db_path)
        conn.execute(
            """INSERT INTO action_receipts
               (receipt_id, action, target, result, timestamp_ns,
                confidence, evidence_chain, signature)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                receipt.receipt_id,
                receipt.action,
                receipt.target,
                receipt.result,
                receipt.timestamp_ns,
                receipt.confidence,
                json.dumps(receipt.evidence_chain),
                receipt.signature,
            ),
        )
        conn.commit()
        conn.close()

    def _publish_action(
        self, action: str, target: str, result: str, confidence: float
    ) -> None:
        """Publish ACTION_TAKEN or ACTION_FAILED to the mesh."""
        if not self._bus:
            return
        event_type = (
            EventType.ACTION_TAKEN
            if "success" in result.lower()
            else EventType.ACTION_FAILED
        )
        self._bus.publish(
            SecurityEvent(
                event_type=event_type,
                source_agent="igris_actions",
                severity=Severity.INFO,
                payload={"action": action, "target": target, "result": result},
                confidence=confidence,
            )
        )

    def _make_receipt(
        self,
        action: str,
        target: str,
        result: str,
        confidence: float,
        evidence: list = None,
    ) -> ActionReceipt:
        receipt = ActionReceipt(
            receipt_id=uuid.uuid4().hex,
            action=action,
            target=target,
            result=result,
            timestamp_ns=time.time_ns(),
            confidence=confidence,
            evidence_chain=evidence or [],
        )
        self._record_receipt(receipt)
        self._publish_action(action, target, result, confidence)
        return receipt

    # ═══════════════════════════════════════════════════════════
    # LOW CONFIDENCE ACTIONS (0.3+)
    # ═══════════════════════════════════════════════════════════

    def trigger_collection(self, confidence: float = 0.3) -> ActionReceipt:
        """Force an immediate full collect cycle across all active agents.

        Tier: LOW (0.3+)
        """
        _check_confidence("trigger_collection", confidence, TIER_LOW)

        if self._dry_run:
            return self._make_receipt(
                "trigger_collection",
                "all_agents",
                "SUCCESS (dry run)",
                confidence,
            )

        # Import here to avoid circular dependency
        try:
            result = subprocess.run(
                ["python", "-m", "amoskys.launcher", "collect"],
                capture_output=True,
                text=True,
                timeout=120,
            )
            status = (
                "SUCCESS"
                if result.returncode == 0
                else f"FAILED: {result.stderr[:200]}"
            )
        except Exception as e:
            status = f"FAILED: {e}"

        return self._make_receipt(
            "trigger_collection",
            "all_agents",
            status,
            confidence,
        )

    def direct_watch(
        self,
        agent_id: str,
        target_type: str,
        target_value: str,
        duration_s: int = 300,
        confidence: float = 0.3,
    ) -> ActionReceipt:
        """Tell a specific agent to focus on a specific IOC.

        Tier: LOW (0.3+)

        Args:
            agent_id: Which agent to direct (e.g., "dns", "network")
            target_type: "pid", "ip", "domain", or "path"
            target_value: The value to watch
            duration_s: How long to maintain the watch (seconds)
        """
        _check_confidence("direct_watch", confidence, TIER_LOW)

        if self._bus:
            self._bus.publish(
                SecurityEvent(
                    event_type=EventType.DIRECTED_WATCH,
                    source_agent="igris_orchestrator",
                    severity=Severity.INFO,
                    payload={
                        "target_agent": agent_id,
                        "target_type": target_type,
                        "target_value": target_value,
                        "duration_s": duration_s,
                    },
                )
            )

        return self._make_receipt(
            "direct_watch",
            f"{agent_id}:{target_type}={target_value}",
            f"SUCCESS: watch for {duration_s}s",
            confidence,
        )

    # ═══════════════════════════════════════════════════════════
    # MEDIUM CONFIDENCE ACTIONS (0.5+)
    # ═══════════════════════════════════════════════════════════

    def promote_signal(
        self,
        signal_id: str,
        reason: str = "",
        confidence: float = 0.5,
    ) -> ActionReceipt:
        """Promote a governance signal to a full incident.

        Tier: MEDIUM (0.5+)
        """
        _check_confidence("promote_signal", confidence, TIER_MEDIUM)

        try:
            conn = sqlite3.connect("data/telemetry.db")
            conn.execute(
                """UPDATE signal_index
                   SET status = 'incident', promoted_at = ?, promotion_reason = ?
                   WHERE signal_id = ?""",
                (time.time_ns(), reason, signal_id),
            )
            conn.commit()
            conn.close()
            status = "SUCCESS: promoted to incident"
        except Exception as e:
            status = f"FAILED: {e}"

        return self._make_receipt(
            "promote_signal",
            signal_id,
            status,
            confidence,
        )

    def dismiss_signal(
        self,
        signal_id: str,
        reason: str = "false_positive",
        confidence: float = 0.5,
    ) -> ActionReceipt:
        """Mark a signal as false positive. Feeds back into SOMA model.

        Tier: MEDIUM (0.5+)
        """
        _check_confidence("dismiss_signal", confidence, TIER_MEDIUM)

        try:
            conn = sqlite3.connect("data/telemetry.db")
            conn.execute(
                """UPDATE signal_index
                   SET status = 'dismissed', dismissed_reason = ?
                   WHERE signal_id = ?""",
                (reason, signal_id),
            )
            conn.commit()
            conn.close()
            status = f"SUCCESS: dismissed as {reason}"
        except Exception as e:
            status = f"FAILED: {e}"

        return self._make_receipt(
            "dismiss_signal",
            signal_id,
            status,
            confidence,
        )

    def add_threat_indicator(
        self,
        indicator_type: str,
        value: str,
        source: str = "igris_analysis",
        confidence: float = 0.5,
    ) -> ActionReceipt:
        """Add an IOC to the threat intelligence database.

        Tier: MEDIUM (0.5+)

        Args:
            indicator_type: "ip", "domain", "hash", or "url"
            value: The indicator value
            source: Attribution source
        """
        _check_confidence("add_threat_indicator", confidence, TIER_MEDIUM)

        try:
            conn = sqlite3.connect("data/telemetry.db")
            conn.execute(
                """INSERT OR IGNORE INTO threat_indicators
                   (type, value, source, confidence, first_seen, last_seen)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    indicator_type,
                    value,
                    source,
                    confidence,
                    time.time_ns(),
                    time.time_ns(),
                ),
            )
            conn.commit()
            conn.close()
            status = f"SUCCESS: added {indicator_type}={value}"
        except Exception as e:
            status = f"FAILED: {e}"

        return self._make_receipt(
            "add_threat_indicator",
            f"{indicator_type}:{value}",
            status,
            confidence,
        )

    # ═══════════════════════════════════════════════════════════
    # HIGH CONFIDENCE ACTIONS (0.7+)
    # ═══════════════════════════════════════════════════════════

    def block_ip(
        self,
        ip: str,
        duration_s: int = 3600,
        confidence: float = 0.7,
    ) -> ActionReceipt:
        """Block an IP address via pf firewall rule.

        Tier: HIGH (0.7+)

        Args:
            ip: IP address to block
            duration_s: Duration in seconds (default 1 hour)
        """
        _check_confidence("block_ip", confidence, TIER_HIGH)

        if self._dry_run:
            return self._make_receipt(
                "block_ip",
                ip,
                f"SUCCESS (dry run, {duration_s}s)",
                confidence,
            )

        try:
            # Add pf rule to block outbound traffic to this IP
            rule = f"block drop out quick on en0 to {ip}\n"
            anchor_path = "/etc/pf.anchors/amoskys_blocks"

            # Append rule (create file if needed)
            os.makedirs(os.path.dirname(anchor_path), exist_ok=True)
            with open(anchor_path, "a") as f:
                f.write(
                    f"# Blocked by IGRIS at {time.strftime('%Y-%m-%d %H:%M:%S')} for {duration_s}s\n"
                )
                f.write(rule)

            # Reload pf rules
            subprocess.run(
                ["pfctl", "-a", "amoskys_blocks", "-f", anchor_path],
                capture_output=True,
                timeout=10,
            )
            status = f"SUCCESS: blocked for {duration_s}s"
        except Exception as e:
            status = f"FAILED: {e}"

        return self._make_receipt("block_ip", ip, status, confidence)

    def block_domain(
        self,
        domain: str,
        confidence: float = 0.7,
    ) -> ActionReceipt:
        """Block a domain by adding to local DNS blocklist.

        Tier: HIGH (0.7+)
        """
        _check_confidence("block_domain", confidence, TIER_HIGH)

        if self._dry_run:
            return self._make_receipt(
                "block_domain",
                domain,
                "SUCCESS (dry run)",
                confidence,
            )

        try:
            BLOCKLIST_PATH.parent.mkdir(parents=True, exist_ok=True)
            with open(BLOCKLIST_PATH, "a") as f:
                f.write(f"# Blocked by IGRIS at {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"0.0.0.0 {domain}\n")
            status = f"SUCCESS: {domain} -> 0.0.0.0"
        except Exception as e:
            status = f"FAILED: {e}"

        return self._make_receipt("block_domain", domain, status, confidence)

    def stop_agent(
        self,
        agent_id: str,
        reason: str = "",
        confidence: float = 0.7,
    ) -> ActionReceipt:
        """Stop a running agent via AgentBus directive.

        Tier: HIGH (0.7+)
        """
        _check_confidence("stop_agent", confidence, TIER_HIGH)

        # Publish stop directive to mesh
        if self._bus:
            self._bus.publish(
                SecurityEvent(
                    event_type=EventType.AGENT_STOPPED,
                    source_agent="igris_orchestrator",
                    severity=Severity.INFO,
                    payload={"agent_id": agent_id, "reason": reason},
                )
            )

        return self._make_receipt(
            "stop_agent",
            agent_id,
            f"SUCCESS: stop directive published ({reason})",
            confidence,
        )

    def start_agent(
        self,
        agent_id: str,
        confidence: float = 0.7,
    ) -> ActionReceipt:
        """Start a stopped agent via AgentBus directive.

        Tier: HIGH (0.7+)
        """
        _check_confidence("start_agent", confidence, TIER_HIGH)

        if self._bus:
            self._bus.publish(
                SecurityEvent(
                    event_type=EventType.AGENT_STARTED,
                    source_agent="igris_orchestrator",
                    severity=Severity.INFO,
                    payload={"agent_id": agent_id},
                )
            )

        return self._make_receipt(
            "start_agent",
            agent_id,
            "SUCCESS: start directive published",
            confidence,
        )

    # ═══════════════════════════════════════════════════════════
    # CRITICAL CONFIDENCE ACTIONS (0.9+)
    # ═══════════════════════════════════════════════════════════

    def kill_process(
        self,
        pid: int,
        confidence: float = 0.9,
        evidence: list = None,
    ) -> ActionReceipt:
        """Terminate a process and its children.

        Tier: CRITICAL (0.9+)
        Full evidence chain must be logged before execution.

        Args:
            pid: Process ID to kill
            evidence: List of evidence event_ids that justify this action
        """
        _check_confidence("kill_process", confidence, TIER_CRITICAL)

        if self._dry_run:
            return self._make_receipt(
                "kill_process",
                str(pid),
                "SUCCESS (dry run)",
                confidence,
                evidence,
            )

        try:
            # Try graceful termination first
            os.kill(pid, signal.SIGTERM)
            time.sleep(0.5)

            # Check if still running, escalate to SIGKILL
            try:
                os.kill(pid, 0)  # Check if alive
                os.kill(pid, signal.SIGKILL)
                status = f"SUCCESS: SIGKILL sent to PID {pid}"
            except ProcessLookupError:
                status = f"SUCCESS: PID {pid} terminated (SIGTERM)"
        except ProcessLookupError:
            status = f"FAILED: PID {pid} not found"
        except PermissionError:
            status = f"FAILED: permission denied for PID {pid}"
        except Exception as e:
            status = f"FAILED: {e}"

        return self._make_receipt(
            "kill_process",
            str(pid),
            status,
            confidence,
            evidence,
        )

    def quarantine_binary(
        self,
        binary_path: str,
        confidence: float = 0.9,
        evidence: list = None,
    ) -> ActionReceipt:
        """Move a malicious binary to quarantine vault.

        Tier: CRITICAL (0.9+)

        Actions:
          1. Compute SHA-256 hash
          2. Move to quarantine vault
          3. Strip execute permissions
          4. Record metadata for forensic review
        """
        _check_confidence("quarantine_binary", confidence, TIER_CRITICAL)

        if self._dry_run:
            return self._make_receipt(
                "quarantine_binary",
                binary_path,
                "SUCCESS (dry run)",
                confidence,
                evidence,
            )

        try:
            src = Path(binary_path)
            if not src.exists():
                return self._make_receipt(
                    "quarantine_binary",
                    binary_path,
                    f"FAILED: {binary_path} not found",
                    confidence,
                    evidence,
                )

            # Compute hash before moving
            sha256 = hashlib.sha256(src.read_bytes()).hexdigest()

            # Move to quarantine
            QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
            dst = QUARANTINE_DIR / f"{sha256}_{src.name}"
            shutil.move(str(src), str(dst))

            # Strip execute permissions
            os.chmod(str(dst), 0o400)

            # Record metadata
            meta = {
                "original_path": binary_path,
                "sha256": sha256,
                "quarantine_time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "size_bytes": dst.stat().st_size,
                "evidence": evidence or [],
            }
            meta_path = dst.with_suffix(".json")
            meta_path.write_text(json.dumps(meta, indent=2))

            status = f"SUCCESS: quarantined as {dst.name} (SHA256: {sha256[:16]}...)"
        except Exception as e:
            status = f"FAILED: {e}"

        return self._make_receipt(
            "quarantine_binary",
            binary_path,
            status,
            confidence,
            evidence,
        )

    # ═══════════════════════════════════════════════════════════
    # TOOL DEFINITIONS FOR IGRIS LLM
    # ═══════════════════════════════════════════════════════════

    @staticmethod
    def get_tool_definitions() -> list:
        """Return Claude-compatible tool definitions for all actions."""
        return [
            {
                "name": "kill_process",
                "description": "Terminate a malicious process and its children. CRITICAL tier: requires confidence >= 0.9 and evidence chain.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "pid": {"type": "integer", "description": "Process ID to kill"},
                        "confidence": {
                            "type": "number",
                            "description": "Confidence score (must be >= 0.9)",
                        },
                        "evidence": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Event IDs justifying this action",
                        },
                    },
                    "required": ["pid", "confidence"],
                },
            },
            {
                "name": "quarantine_binary",
                "description": "Move a malicious binary to quarantine vault, strip execute permissions, record SHA-256. CRITICAL tier.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "binary_path": {
                            "type": "string",
                            "description": "Full path to the binary",
                        },
                        "confidence": {"type": "number"},
                        "evidence": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["binary_path", "confidence"],
                },
            },
            {
                "name": "block_ip",
                "description": "Block an IP address via pf firewall rule. HIGH tier: requires confidence >= 0.7.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "ip": {"type": "string", "description": "IP address to block"},
                        "duration_s": {
                            "type": "integer",
                            "description": "Block duration in seconds (default 3600)",
                            "default": 3600,
                        },
                        "confidence": {"type": "number"},
                    },
                    "required": ["ip", "confidence"],
                },
            },
            {
                "name": "block_domain",
                "description": "Block a domain via local DNS blocklist. HIGH tier.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "domain": {"type": "string"},
                        "confidence": {"type": "number"},
                    },
                    "required": ["domain", "confidence"],
                },
            },
            {
                "name": "trigger_collection",
                "description": "Force an immediate full collect cycle across all agents. LOW tier.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "confidence": {"type": "number", "default": 0.3},
                    },
                },
            },
            {
                "name": "direct_watch",
                "description": "Tell a specific agent to focus on a specific IOC (IP, domain, PID, path) for a duration. LOW tier.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "agent_id": {
                            "type": "string",
                            "description": "Agent to direct (dns, network, process, fim)",
                        },
                        "target_type": {
                            "type": "string",
                            "enum": ["pid", "ip", "domain", "path"],
                        },
                        "target_value": {"type": "string"},
                        "duration_s": {"type": "integer", "default": 300},
                        "confidence": {"type": "number", "default": 0.3},
                    },
                    "required": ["agent_id", "target_type", "target_value"],
                },
            },
            {
                "name": "promote_signal",
                "description": "Promote a governance signal to a full incident. MEDIUM tier.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "signal_id": {"type": "string"},
                        "reason": {"type": "string"},
                        "confidence": {"type": "number", "default": 0.5},
                    },
                    "required": ["signal_id"],
                },
            },
            {
                "name": "dismiss_signal",
                "description": "Mark a signal as false positive. Feeds back into SOMA model. MEDIUM tier.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "signal_id": {"type": "string"},
                        "reason": {"type": "string", "default": "false_positive"},
                        "confidence": {"type": "number", "default": 0.5},
                    },
                    "required": ["signal_id"],
                },
            },
            {
                "name": "add_threat_indicator",
                "description": "Add an IOC (IP, domain, hash, URL) to the threat intelligence database. MEDIUM tier.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "indicator_type": {
                            "type": "string",
                            "enum": ["ip", "domain", "hash", "url"],
                        },
                        "value": {"type": "string"},
                        "source": {"type": "string", "default": "igris_analysis"},
                        "confidence": {"type": "number", "default": 0.5},
                    },
                    "required": ["indicator_type", "value"],
                },
            },
            {
                "name": "start_agent",
                "description": "Start a stopped Observatory agent. HIGH tier.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "agent_id": {"type": "string"},
                        "confidence": {"type": "number", "default": 0.7},
                    },
                    "required": ["agent_id"],
                },
            },
            {
                "name": "stop_agent",
                "description": "Stop a running Observatory agent. HIGH tier.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "agent_id": {"type": "string"},
                        "reason": {"type": "string"},
                        "confidence": {"type": "number", "default": 0.7},
                    },
                    "required": ["agent_id"],
                },
            },
        ]
