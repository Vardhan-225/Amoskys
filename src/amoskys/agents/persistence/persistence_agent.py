#!/usr/bin/env python3
"""
AMOSKYS Persistence Guard Agent (PersistenceGuardAgent)

Monitors persistence mechanisms for backdoors and malware:
- Launch Agents (/Library/LaunchAgents, ~/Library/LaunchAgents)
- Launch Daemons (/Library/LaunchDaemons)
- Cron jobs (crontab)
- SSH authorized_keys
- Login items

Purpose: Detect persistence implants, backdoors, and unauthorized changes
"""

import os
import json
import plistlib
import subprocess
import time
import logging
import hashlib
import grpc
import socket
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Set

from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2
from amoskys.proto import universal_telemetry_pb2_grpc as universal_pbrpc
from amoskys.config import get_config
from amoskys.agents.common import LocalQueue

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("PersistenceGuardAgent")

config = get_config()
EVENTBUS_ADDRESS = config.agent.bus_address
CERT_DIR = config.agent.cert_dir
QUEUE_PATH = getattr(config.agent, "persistence_queue_path", "data/queue/persistence_agent.db")
SNAPSHOT_PATH = getattr(config.agent, "persistence_snapshot_path", "data/persistence_snapshot.json")


class PersistenceGuardAgent:
    """Persistence mechanism monitoring agent"""

    # Paths to monitor for launch agents/daemons
    LAUNCHD_PATHS = [
        "/Library/LaunchAgents",
        "/Library/LaunchDaemons",
        "/System/Library/LaunchAgents",
        "/System/Library/LaunchDaemons",
    ]

    # User-specific paths (will be expanded per user)
    USER_LAUNCHD_TEMPLATE = "{home}/Library/LaunchAgents"
    USER_SSH_KEYS_TEMPLATE = "{home}/.ssh/authorized_keys"

    def __init__(self, queue_path=None, snapshot_path=None):
        """Initialize agent with local queue for offline resilience

        Args:
            queue_path: Path to queue database (default: from config)
            snapshot_path: Path to persistence snapshot file (default: from config)
        """
        self.queue_path = queue_path or QUEUE_PATH
        self.snapshot_path = snapshot_path or SNAPSHOT_PATH

        self.queue = LocalQueue(
            path=self.queue_path,
            max_bytes=50 * 1024 * 1024,  # 50MB
            max_retries=10
        )

        # Load existing snapshot or create new
        self.snapshot = self._load_snapshot()

        logger.info(f"PersistenceGuardAgent initialized: {self.queue_path}")

    def _get_grpc_channel(self):
        """Create gRPC channel to EventBus with mTLS"""
        try:
            with open(f"{CERT_DIR}/ca.crt", "rb") as f:
                ca_cert = f.read()
            with open(f"{CERT_DIR}/agent.crt", "rb") as f:
                client_cert = f.read()
            with open(f"{CERT_DIR}/agent.key", "rb") as f:
                client_key = f.read()

            credentials = grpc.ssl_channel_credentials(
                root_certificates=ca_cert,
                private_key=client_key,
                certificate_chain=client_cert
            )
            channel = grpc.secure_channel(EVENTBUS_ADDRESS, credentials)
            logger.debug("Created secure gRPC channel with mTLS")
            return channel
        except FileNotFoundError as e:
            logger.error("Certificate not found: %s", e)
            return None
        except Exception as e:
            logger.error("Failed to create gRPC channel: %s", str(e))
            return None

    def _load_snapshot(self) -> Dict:
        """Load existing persistence snapshot from disk

        Returns:
            Snapshot dictionary or empty dict if not exists
        """
        if os.path.exists(self.snapshot_path):
            try:
                with open(self.snapshot_path, 'r') as f:
                    snapshot = json.load(f)
                logger.info(f"Loaded snapshot with {len(snapshot)} entries")
                return snapshot
            except Exception as e:
                logger.error(f"Failed to load snapshot: {e}")
                return {}
        return {}

    def _save_snapshot(self, snapshot: Dict):
        """Save persistence snapshot to disk

        Args:
            snapshot: Snapshot dictionary to save
        """
        try:
            os.makedirs(os.path.dirname(self.snapshot_path) or ".", exist_ok=True)
            with open(self.snapshot_path, 'w') as f:
                json.dump(snapshot, f, indent=2)
            logger.debug(f"Saved snapshot with {len(snapshot)} entries")
        except Exception as e:
            logger.error(f"Failed to save snapshot: {e}")

    def _get_file_hash(self, path: str) -> Optional[str]:
        """Calculate SHA256 hash of file

        Args:
            path: File path

        Returns:
            Hex digest of SHA256 hash or None if error
        """
        try:
            with open(path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception as e:
            logger.debug(f"Failed to hash {path}: {e}")
            return None

    def _scan_launchd(self) -> Dict[str, Dict]:
        """Scan all launch agents and daemons

        Returns:
            Dictionary mapping path to metadata
        """
        entries = {}

        # Scan system paths
        for base_path in self.LAUNCHD_PATHS:
            if not os.path.exists(base_path):
                continue

            try:
                for filename in os.listdir(base_path):
                    if not filename.endswith('.plist'):
                        continue

                    full_path = os.path.join(base_path, filename)
                    entries[full_path] = self._get_launchd_metadata(full_path)
            except PermissionError:
                logger.debug(f"Permission denied: {base_path}")
            except Exception as e:
                logger.debug(f"Error scanning {base_path}: {e}")

        # Scan user-specific launch agents
        try:
            users = self._get_users()
            for user in users:
                user_path = self.USER_LAUNCHD_TEMPLATE.format(home=user['home'])
                if os.path.exists(user_path):
                    try:
                        for filename in os.listdir(user_path):
                            if not filename.endswith('.plist'):
                                continue

                            full_path = os.path.join(user_path, filename)
                            entries[full_path] = self._get_launchd_metadata(full_path)
                    except Exception as e:
                        logger.debug(f"Error scanning {user_path}: {e}")
        except Exception as e:
            logger.debug(f"Error getting users: {e}")

        return entries

    def _get_launchd_metadata(self, path: str) -> Dict:
        """Extract metadata from launch agent/daemon plist

        Args:
            path: Path to .plist file

        Returns:
            Metadata dictionary
        """
        metadata = {
            'type': 'LAUNCH_DAEMON' if '/LaunchDaemons/' in path else 'LAUNCH_AGENT',
            'mtime': os.path.getmtime(path),
            'hash': self._get_file_hash(path),
            'program': None,
            'program_arguments': None,
            'run_at_load': False,
            'keep_alive': False
        }

        try:
            with open(path, 'rb') as f:
                plist = plistlib.load(f)

            metadata['program'] = plist.get('Program')
            metadata['program_arguments'] = plist.get('ProgramArguments', [])
            metadata['run_at_load'] = plist.get('RunAtLoad', False)
            metadata['keep_alive'] = plist.get('KeepAlive', False)
        except Exception as e:
            logger.debug(f"Failed to parse plist {path}: {e}")

        return metadata

    def _scan_crontabs(self) -> Dict[str, Dict]:
        """Scan cron jobs for all users

        Returns:
            Dictionary mapping "cron:user" to metadata
        """
        entries = {}

        try:
            # Get current user's crontab
            result = subprocess.run(
                ['crontab', '-l'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                current_user = os.getenv('USER', 'unknown')
                cron_lines = [line for line in result.stdout.splitlines() if line.strip() and not line.startswith('#')]

                if cron_lines:
                    entries[f"cron:{current_user}"] = {
                        'type': 'CRON',
                        'user': current_user,
                        'entries': cron_lines,
                        'hash': hashlib.sha256(result.stdout.encode()).hexdigest()
                    }
        except subprocess.TimeoutExpired:
            logger.warning("crontab command timed out")
        except Exception as e:
            logger.debug(f"Failed to read crontab: {e}")

        return entries

    def _scan_ssh_keys(self) -> Dict[str, Dict]:
        """Scan SSH authorized_keys for all users

        Returns:
            Dictionary mapping path to metadata
        """
        entries = {}

        try:
            users = self._get_users()
            for user in users:
                keys_path = self.USER_SSH_KEYS_TEMPLATE.format(home=user['home'])

                if os.path.exists(keys_path):
                    try:
                        with open(keys_path, 'r') as f:
                            content = f.read()

                        # Parse keys
                        keys = [line.strip() for line in content.splitlines() if line.strip() and not line.startswith('#')]

                        entries[keys_path] = {
                            'type': 'SSH_KEYS',
                            'user': user['name'],
                            'mtime': os.path.getmtime(keys_path),
                            'hash': hashlib.sha256(content.encode()).hexdigest(),
                            'key_count': len(keys),
                            'keys': keys[:10]  # Store first 10 for reference
                        }
                    except Exception as e:
                        logger.debug(f"Failed to read SSH keys {keys_path}: {e}")
        except Exception as e:
            logger.debug(f"Error scanning SSH keys: {e}")

        return entries

    def _get_users(self) -> List[Dict]:
        """Get list of users on the system

        Returns:
            List of user dictionaries with 'name' and 'home'
        """
        users = []

        try:
            # On macOS, use dscl to list users
            result = subprocess.run(
                ['dscl', '.', 'list', '/Users'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                for username in result.stdout.splitlines():
                    username = username.strip()

                    # Skip system users
                    if username.startswith('_') or username in ['daemon', 'nobody', 'root']:
                        continue

                    # Get home directory
                    home_result = subprocess.run(
                        ['dscl', '.', 'read', f'/Users/{username}', 'NFSHomeDirectory'],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )

                    if home_result.returncode == 0:
                        # Parse output: "NFSHomeDirectory: /Users/username"
                        home = home_result.stdout.split(':', 1)[1].strip()
                        users.append({'name': username, 'home': home})
        except Exception as e:
            logger.debug(f"Failed to get users: {e}")

        # Fallback: at least get current user
        if not users:
            current_user = os.getenv('USER')
            home = os.path.expanduser('~')
            if current_user:
                users.append({'name': current_user, 'home': home})

        return users

    def _scan_all(self) -> Dict[str, Dict]:
        """Scan all persistence mechanisms

        Returns:
            Combined snapshot of all persistence entries
        """
        snapshot = {}

        # Scan each mechanism
        snapshot.update(self._scan_launchd())
        snapshot.update(self._scan_crontabs())
        snapshot.update(self._scan_ssh_keys())

        return snapshot

    def _detect_changes(self, old_snapshot: Dict, new_snapshot: Dict) -> List[Dict]:
        """Detect changes between snapshots

        Args:
            old_snapshot: Previous snapshot
            new_snapshot: Current snapshot

        Returns:
            List of change events
        """
        changes = []

        # Detect additions
        for path, metadata in new_snapshot.items():
            if path not in old_snapshot:
                changes.append({
                    'operation': 'CREATED',
                    'path': path,
                    'type': metadata['type'],
                    'metadata': metadata
                })

        # Detect modifications
        for path, new_meta in new_snapshot.items():
            if path in old_snapshot:
                old_meta = old_snapshot[path]

                # Check if hash changed
                if new_meta.get('hash') != old_meta.get('hash'):
                    changes.append({
                        'operation': 'MODIFIED',
                        'path': path,
                        'type': new_meta['type'],
                        'metadata': new_meta,
                        'old_metadata': old_meta
                    })

        # Detect deletions
        for path in old_snapshot:
            if path not in new_snapshot:
                changes.append({
                    'operation': 'DELETED',
                    'path': path,
                    'type': old_snapshot[path]['type'],
                    'metadata': old_snapshot[path]
                })

        return changes

    def _create_telemetry(self, changes: List[Dict]) -> telemetry_pb2.DeviceTelemetry:
        """Create DeviceTelemetry protobuf from persistence changes

        Args:
            changes: List of change event dictionaries

        Returns:
            DeviceTelemetry protobuf message
        """
        timestamp_ns = int(time.time() * 1e9)
        device_id = socket.gethostname()

        # Convert changes to AuditEvent protobuf
        telemetry_events = []
        for change in changes:
            # Map operation to severity
            severity = "INFO"
            if change['operation'] == 'CREATED':
                severity = "WARN"  # New persistence is suspicious
            elif change['operation'] == 'MODIFIED':
                severity = "WARN"  # Modification is suspicious
            elif change['operation'] == 'DELETED':
                severity = "INFO"  # Deletion might be cleanup

            # Calculate risk
            risk_score = 0.3  # Default moderate risk for any persistence change
            if change['type'] == 'SSH_KEYS':
                risk_score = 0.8  # SSH keys are high risk
            elif change['type'] in ['LAUNCH_DAEMON', 'LAUNCH_AGENT']:
                # Check if it's a suspicious location
                if '/Users/' in change['path']:
                    risk_score = 0.7  # User launch agents are more suspicious

            audit_event = telemetry_pb2.AuditEvent(
                audit_category="CHANGE",
                action_performed=change['operation'],
                object_type=change['type'],
                object_id=change['path'],
                actor_type="SYSTEM",
                before_value=json.dumps(change.get('old_metadata', {})) if change.get('old_metadata') else None,
                after_value=json.dumps(change['metadata']),
                retention_required=True,
                retention_days=90  # Keep persistence changes for 90 days
            )

            # Build attributes
            attributes = {
                'persistence_type': change['type'],
                'file_path': change['path']
            }

            if change['type'] in ['LAUNCH_DAEMON', 'LAUNCH_AGENT']:
                if change['metadata'].get('program'):
                    attributes['target_program'] = str(change['metadata']['program'])
                if change['metadata'].get('program_arguments'):
                    attributes['program_args'] = str(change['metadata']['program_arguments'])

            telemetry_event = telemetry_pb2.TelemetryEvent(
                event_id=f"persist_{device_id}_{timestamp_ns}_{len(telemetry_events)}",
                event_type="AUDIT",
                severity=severity,
                event_timestamp_ns=timestamp_ns,
                audit_event=audit_event,
                source_component="persistence_agent",
                attributes=attributes,
                confidence_score=0.95
            )
            telemetry_events.append(telemetry_event)

        # Device metadata
        try:
            ip_addr = socket.gethostbyname(socket.gethostname())
        except:
            ip_addr = "127.0.0.1"

        metadata = telemetry_pb2.DeviceMetadata(
            manufacturer="Apple",
            model=socket.gethostname(),
            ip_address=ip_addr,
            protocols=["PERSISTENCE"]
        )

        # Build DeviceTelemetry
        device_telemetry = telemetry_pb2.DeviceTelemetry(
            device_id=device_id,
            device_type="HOST",
            protocol="PERSISTENCE",
            metadata=metadata,
            events=telemetry_events,
            timestamp_ns=timestamp_ns,
            collection_agent="persistence-agent",
            agent_version="1.0.0"
        )

        return device_telemetry

    def _publish_telemetry(self, device_telemetry):
        """Publish telemetry to EventBus with queue fallback"""
        try:
            channel = self._get_grpc_channel()
            if not channel:
                logger.warning("No gRPC channel, queueing telemetry")
                return self._queue_telemetry(device_telemetry)

            timestamp_ns = int(time.time() * 1e9)
            idempotency_key = f"{device_telemetry.device_id}_persist_{timestamp_ns}"
            envelope = telemetry_pb2.UniversalEnvelope(
                version="v1",
                ts_ns=timestamp_ns,
                idempotency_key=idempotency_key,
                device_telemetry=device_telemetry,
                signing_algorithm="Ed25519",
                priority="HIGH",  # Persistence changes are high priority
                requires_acknowledgment=True
            )

            stub = universal_pbrpc.UniversalEventBusStub(channel)
            ack = stub.PublishTelemetry(envelope, timeout=5.0)

            if ack.status == telemetry_pb2.UniversalAck.OK:
                logger.info("Published persistence telemetry (queue: %d pending)", self.queue.size())
                return True
            else:
                logger.warning("Publish status: %s, queueing", ack.status)
                return self._queue_telemetry(device_telemetry)

        except grpc.RpcError as e:
            logger.warning("RPC failed: %s, queueing telemetry", e.code())
            return self._queue_telemetry(device_telemetry)
        except Exception as e:
            logger.error("Publish failed: %s, queueing telemetry", str(e))
            return self._queue_telemetry(device_telemetry)

    def _queue_telemetry(self, device_telemetry):
        """Queue telemetry for later retry"""
        try:
            timestamp_ns = int(time.time() * 1e9)
            idempotency_key = f"{device_telemetry.device_id}_persist_{timestamp_ns}"
            queued = self.queue.enqueue(device_telemetry, idempotency_key)

            if queued:
                logger.info("Queued persistence telemetry (queue: %d items, %d bytes)",
                           self.queue.size(), self.queue.size_bytes())

            return True
        except Exception as e:
            logger.error("Failed to queue telemetry: %s", str(e))
            return False

    def _drain_queue(self):
        """Attempt to drain queued telemetry to EventBus"""
        queue_size = self.queue.size()
        if queue_size == 0:
            return 0

        logger.info("Draining persistence queue (%d events pending)...", queue_size)

        def publish_fn(telemetry):
            try:
                channel = self._get_grpc_channel()
                if not channel:
                    raise Exception("No gRPC channel")

                timestamp_ns = int(time.time() * 1e9)
                envelope = telemetry_pb2.UniversalEnvelope(
                    version="v1",
                    ts_ns=timestamp_ns,
                    idempotency_key=f"{telemetry.device_id}_persist_{timestamp_ns}_retry",
                    device_telemetry=telemetry,
                    signing_algorithm="Ed25519",
                    priority="HIGH",
                    requires_acknowledgment=True
                )

                stub = universal_pbrpc.UniversalEventBusStub(channel)
                ack = stub.PublishTelemetry(envelope, timeout=5.0)
                return ack
            except Exception as e:
                logger.debug("Drain publish failed: %s", str(e))
                raise

        try:
            drained = self.queue.drain(publish_fn, limit=100)
            if drained > 0:
                logger.info("Drained %d persistence events from queue (%d remaining)",
                           drained, self.queue.size())
            return drained
        except Exception as e:
            logger.debug("Persistence queue drain error: %s", str(e))
            return 0

    def collect(self):
        """Collect and publish persistence changes once"""
        try:
            # Try to drain any queued events first
            self._drain_queue()

            # Scan current state
            logger.info("Scanning persistence mechanisms...")
            new_snapshot = self._scan_all()

            # Detect changes
            changes = self._detect_changes(self.snapshot, new_snapshot)

            if not changes:
                logger.debug("No persistence changes detected")
                # Update snapshot even if no changes
                self.snapshot = new_snapshot
                self._save_snapshot(new_snapshot)
                return True

            logger.info(f"Found {len(changes)} persistence changes")
            for change in changes:
                logger.info(f"  {change['operation']}: {change['path']} ({change['type']})")

            # Create telemetry
            device_telemetry = self._create_telemetry(changes)

            # Publish or queue
            success = self._publish_telemetry(device_telemetry)

            # Update snapshot
            self.snapshot = new_snapshot
            self._save_snapshot(new_snapshot)

            if success:
                logger.info("Persistence collection complete (%d changes)", len(changes))
            else:
                logger.warning("Persistence collection failed (queued for retry)")

            return True

        except Exception as e:
            logger.error("Persistence collection error: %s", str(e), exc_info=True)
            return False

    def run(self, interval=300):
        """Main collection loop

        Args:
            interval: Seconds between collections (default: 300s = 5 minutes)
        """
        logger.info("AMOSKYS Persistence Guard Agent starting...")
        logger.info("EventBus: %s", EVENTBUS_ADDRESS)
        logger.info("Collection interval: %ds", interval)

        cycle = 0
        while True:
            cycle += 1
            logger.info("=" * 60)
            logger.info("Cycle #%d - %s", cycle, datetime.now().isoformat())
            logger.info("=" * 60)

            self.collect()

            logger.info("Next collection in %ds...", interval)
            time.sleep(interval)


def main():
    """Entry point"""
    agent = PersistenceGuardAgent()
    agent.run(interval=300)


if __name__ == '__main__':
    main()
