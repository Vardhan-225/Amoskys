"""Integration tests for the telemetry receipt ledger and process genealogy.

Verifies:
1. Receipt ledger tracks events through 4 pipeline checkpoints
2. IGRIS reconciliation detects gaps
3. Process genealogy persists spawn chains and handles exits
4. Persistence event routing matches T1543 probes
"""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import time

import pytest


@pytest.fixture
def store():
    """Create a temporary TelemetryStore for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_telemetry.db")
        from amoskys.storage.telemetry_store import TelemetryStore

        s = TelemetryStore(db_path=db_path)
        yield s
        s.close()


# ---------------------------------------------------------------------------
# Receipt Ledger Tests
# ---------------------------------------------------------------------------


class TestReceiptLedger:
    def test_receipt_emit_creates_record(self, store):
        store.receipt_emit("evt-001", "macos_process", "host-1")
        result = store.receipt_reconcile("macos_process")
        assert result["emitted"] == 1
        assert result["queued"] == 0
        assert result["persisted"] == 0

    def test_receipt_full_pipeline(self, store):
        """Walk an event through all 4 checkpoints."""
        store.receipt_emit("evt-002", "macos_process", "host-1")
        store.receipt_queued("evt-002", "macos_process")
        store.receipt_wal("evt-002", "macos_process")
        store.receipt_persisted("evt-002", "macos_process", "process_events")

        result = store.receipt_reconcile("macos_process")
        assert result["emitted"] == 1
        assert result["queued"] == 1
        assert result["wal_processed"] == 1
        assert result["persisted"] == 1
        assert len(result["gaps"]) == 0

    def test_receipt_detects_wal_gap(self, store):
        """Event emitted and queued but never WAL-processed = gap."""
        store.receipt_emit("evt-003", "macos_dns", "host-1")
        store.receipt_queued("evt-003", "macos_dns")
        # Deliberately skip WAL and persist

        result = store.receipt_reconcile("macos_dns")
        assert result["emitted"] == 1
        assert result["wal_processed"] == 0
        assert result["persisted"] == 0
        assert len(result["gaps"]) >= 1
        gap = result["gaps"][0]
        assert gap["boundary"] == "queue→wal"
        assert "evt-003" in gap["event_ids"]

    def test_receipt_detects_persist_gap(self, store):
        """Event reaches WAL but never persisted = routing/extraction bug."""
        store.receipt_emit("evt-004", "macos_persistence", "host-1")
        store.receipt_queued("evt-004", "macos_persistence")
        store.receipt_wal("evt-004", "macos_persistence")
        # Deliberately skip persist

        result = store.receipt_reconcile("macos_persistence")
        assert result["wal_processed"] == 1
        assert result["persisted"] == 0
        assert len(result["gaps"]) >= 1
        gap = result["gaps"][0]
        assert gap["boundary"] == "wal→persist"

    def test_receipt_multiple_agents(self, store):
        """Reconciliation can filter by agent or show all."""
        store.receipt_emit("evt-a", "macos_process", "host-1")
        store.receipt_persisted("evt-a", "macos_process", "process_events")
        store.receipt_emit("evt-b", "macos_dns", "host-1")
        # DNS event NOT persisted

        all_result = store.receipt_reconcile()
        assert all_result["emitted"] == 2
        assert all_result["persisted"] == 1

        proc_result = store.receipt_reconcile("macos_process")
        assert proc_result["persisted"] == 1
        assert len(proc_result["gaps"]) == 0


# ---------------------------------------------------------------------------
# Process Genealogy Tests
# ---------------------------------------------------------------------------


class TestProcessGenealogy:
    def test_upsert_and_retrieve_spawn_chain(self, store):
        """Build a 3-level spawn chain: launchd → bash → malware."""
        now_ns = time.time_ns()

        # PID 1: launchd
        store.upsert_genealogy(
            {
                "device_id": "host-1",
                "pid": 1,
                "ppid": 0,
                "name": "launchd",
                "exe": "/sbin/launchd",
                "first_seen_ns": now_ns - 1000,
                "last_seen_ns": now_ns,
                "is_alive": True,
            }
        )
        # PID 4510: bash
        store.upsert_genealogy(
            {
                "device_id": "host-1",
                "pid": 4510,
                "ppid": 1,
                "name": "bash",
                "exe": "/bin/bash",
                "username": "attacker",
                "parent_name": "launchd",
                "first_seen_ns": now_ns - 500,
                "last_seen_ns": now_ns,
                "is_alive": True,
            }
        )
        # PID 4523: malware
        store.upsert_genealogy(
            {
                "device_id": "host-1",
                "pid": 4523,
                "ppid": 4510,
                "name": "malware",
                "exe": "/tmp/malware",
                "username": "attacker",
                "parent_name": "bash",
                "first_seen_ns": now_ns - 100,
                "last_seen_ns": now_ns,
                "is_alive": True,
            }
        )

        # Walk the chain from malware up to launchd
        chain = store.get_spawn_chain("host-1", 4523)
        assert len(chain) == 3
        assert chain[0]["name"] == "malware"
        assert chain[1]["name"] == "bash"
        assert chain[2]["name"] == "launchd"

    def test_mark_process_exited(self, store):
        now_ns = time.time_ns()
        store.upsert_genealogy(
            {
                "device_id": "host-1",
                "pid": 9999,
                "ppid": 1,
                "name": "short-lived",
                "exe": "/tmp/short",
                "first_seen_ns": now_ns - 100,
                "last_seen_ns": now_ns,
                "is_alive": True,
            }
        )

        store.mark_process_exited("host-1", 9999, now_ns, exit_status=0)

        chain = store.get_spawn_chain("host-1", 9999)
        assert len(chain) == 1
        assert chain[0]["is_alive"] == 0
        assert chain[0]["exit_time_ns"] == now_ns

    def test_get_children(self, store):
        now_ns = time.time_ns()
        store.upsert_genealogy(
            {
                "device_id": "host-1",
                "pid": 100,
                "ppid": 1,
                "name": "parent",
                "first_seen_ns": now_ns,
            }
        )
        store.upsert_genealogy(
            {
                "device_id": "host-1",
                "pid": 101,
                "ppid": 100,
                "name": "child1",
                "first_seen_ns": now_ns,
            }
        )
        store.upsert_genealogy(
            {
                "device_id": "host-1",
                "pid": 102,
                "ppid": 100,
                "name": "child2",
                "first_seen_ns": now_ns,
            }
        )

        children = store.get_children("host-1", 100)
        assert len(children) == 2
        names = {c["name"] for c in children}
        assert names == {"child1", "child2"}

    def test_genealogy_survives_process_exit(self, store):
        """After a process exits, its genealogy record persists."""
        now_ns = time.time_ns()
        store.upsert_genealogy(
            {
                "device_id": "host-1",
                "pid": 555,
                "ppid": 1,
                "name": "ephemeral",
                "exe": "/tmp/ephemeral",
                "first_seen_ns": now_ns,
            }
        )
        store.mark_process_exited("host-1", 555, now_ns + 1000)

        # Record still exists and is queryable
        chain = store.get_spawn_chain("host-1", 555)
        assert len(chain) == 1
        assert chain[0]["name"] == "ephemeral"
        assert chain[0]["is_alive"] == 0


# ---------------------------------------------------------------------------
# Persistence Routing Fix Tests
# ---------------------------------------------------------------------------


class TestPersistenceRouting:
    def test_launchagent_category_matches(self):
        """macos_launchagent_added should route to persistence_events."""
        from amoskys.storage.wal_processor import WALProcessor

        wp = WALProcessor.__new__(WALProcessor)

        assert wp._is_persistence_event(
            "macos_persistence", "macos_launchagent_added", []
        )
        assert wp._is_persistence_event("other_agent", "macos_launchagent_added", [])
        assert wp._is_persistence_event(
            "other_agent", "macos_launchdaemon_modified", []
        )
        assert wp._is_persistence_event("other_agent", "macos_cron_added", [])
        assert wp._is_persistence_event("other_agent", "macos_ssh_key_added", [])

    def test_mitre_technique_routes_persistence(self):
        """T1543.001 from any agent should route to persistence_events."""
        from amoskys.storage.wal_processor import WALProcessor

        wp = WALProcessor.__new__(WALProcessor)

        # T1543.001 from realtime sensor (not a persistence agent)
        assert wp._is_persistence_event(
            "realtime_sensor", "process_spawn", ["T1543.001"]
        )
        assert wp._is_persistence_event(
            "macos_infostealer_guard", "some_event", ["T1543.004"]
        )
        assert wp._is_persistence_event("any_agent", "any_event", ["T1053.003"])

    def test_non_persistence_does_not_match(self):
        """Regular events should not falsely match persistence routing."""
        from amoskys.storage.wal_processor import WALProcessor

        wp = WALProcessor.__new__(WALProcessor)

        assert not wp._is_persistence_event("macos_process", "process_spawn", [])
        assert not wp._is_persistence_event("macos_network", "c2_beacon", ["T1071"])
        assert not wp._is_persistence_event("macos_dns", "dns_dga", ["T1568"])
