"""Phase 2 — Data Integrity Tests.

Validates the pipeline guarantees that matter:
    1. At-least-once delivery (no silent drops)
    2. FIFO ordering per device stream
    3. Idempotent writes (duplicate idem keys rejected)
    4. Crash recovery (kill -9 → restart → data intact)
    5. Backpressure (oldest dropped when full, not newest)
    6. Protobuf round-trip fidelity through SQLite

Claims covered: CL-06, CL-07, CL-08, CL-25
"""

import os
import sqlite3
import time

import pytest

from amoskys.agents.common.local_queue import LocalQueue
from amoskys.agents.common.queue_adapter import LocalQueueAdapter
from amoskys.proto import universal_telemetry_pb2 as pb


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def queue_path(tmp_path):
    return str(tmp_path / "test_queue.db")


@pytest.fixture
def queue(queue_path):
    return LocalQueue(path=queue_path, max_bytes=50 * 1024 * 1024)


@pytest.fixture
def adapter(queue_path):
    return LocalQueueAdapter(
        queue_path=queue_path,
        agent_name="test_agent",
        device_id="host-test-001",
    )


def _make_telemetry(device_id: str, event_id: str, payload: str = "") -> pb.DeviceTelemetry:
    """Build a minimal DeviceTelemetry protobuf."""
    t = pb.DeviceTelemetry(
        device_id=device_id,
        device_type="endpoint",
        collection_agent="test_agent",
        timestamp_ns=int(time.time() * 1e9),
    )
    ev = t.events.add()
    ev.event_id = event_id
    ev.event_type = "TEST"
    ev.severity = "INFO"
    ev.event_timestamp_ns = int(time.time() * 1e9)
    if payload:
        ev.attributes["payload"] = payload
    return t


# ===================================================================
# 1. At-Least-Once Delivery
# ===================================================================


class TestAtLeastOnce:
    """Every enqueued event must be drained exactly once on success."""

    def test_enqueue_then_drain_all(self, queue):
        """N enqueued events → drain returns N, queue empty."""
        n = 50
        for i in range(n):
            t = _make_telemetry("dev1", f"ev-{i}")
            queue.enqueue(t, f"key-{i}")
        assert queue.size() == n

        drained = queue.drain(lambda t: type("A", (), {"status": 0})(), limit=100)
        assert drained == n
        assert queue.size() == 0

    def test_partial_drain_resumes(self, queue):
        """If drain stops at limit, remaining events survive."""
        for i in range(20):
            queue.enqueue(_make_telemetry("dev1", f"ev-{i}"), f"key-{i}")

        drained1 = queue.drain(lambda t: type("A", (), {"status": 0})(), limit=5)
        assert drained1 == 5
        assert queue.size() == 15

        drained2 = queue.drain(lambda t: type("A", (), {"status": 0})(), limit=100)
        assert drained2 == 15
        assert queue.size() == 0

    def test_drain_failure_retains_events(self, queue):
        """If publish fails, events stay in queue for retry."""
        for i in range(5):
            queue.enqueue(_make_telemetry("dev1", f"ev-{i}"), f"key-{i}")

        def fail_publish(t):
            raise ConnectionError("EventBus down")

        drained = queue.drain(fail_publish, limit=10)
        assert drained == 0
        assert queue.size() == 5  # all retained

    def test_drain_retry_status_stops(self, queue):
        """RETRY status (1) stops drain but retains events."""
        for i in range(5):
            queue.enqueue(_make_telemetry("dev1", f"ev-{i}"), f"key-{i}")

        drained = queue.drain(
            lambda t: type("A", (), {"status": 1})(),  # RETRY
            limit=10,
        )
        assert drained == 0
        assert queue.size() == 5


# ===================================================================
# 2. FIFO Ordering Per Stream
# ===================================================================


class TestFIFOOrdering:
    """Events must drain in insertion order per device stream."""

    def test_fifo_single_device(self, queue):
        """Single-device stream drains in insertion order."""
        ids = [f"ev-{i}" for i in range(20)]
        for eid in ids:
            queue.enqueue(_make_telemetry("dev1", eid), f"key-{eid}")

        drained_ids = []

        def capture(t):
            drained_ids.append(t.events[0].event_id)
            return type("A", (), {"status": 0})()

        queue.drain(capture, limit=100)
        assert drained_ids == ids

    def test_fifo_interleaved_devices(self, queue):
        """Interleaved devices still drain in global insertion order."""
        sequence = []
        for i in range(10):
            dev = f"dev-{i % 3}"
            eid = f"ev-{i}"
            queue.enqueue(_make_telemetry(dev, eid), f"key-{i}")
            sequence.append(eid)

        drained_ids = []

        def capture(t):
            drained_ids.append(t.events[0].event_id)
            return type("A", (), {"status": 0})()

        queue.drain(capture, limit=100)
        assert drained_ids == sequence


# ===================================================================
# 3. Idempotent Writes
# ===================================================================


class TestIdempotentWrites:
    """Duplicate idempotency keys must be silently rejected."""

    def test_duplicate_key_rejected(self, queue):
        """Same idem key → second enqueue returns False, size stays 1."""
        t = _make_telemetry("dev1", "ev-1")
        assert queue.enqueue(t, "same-key") is True
        assert queue.enqueue(t, "same-key") is False
        assert queue.size() == 1

    def test_different_keys_accepted(self, queue):
        """Different idem keys → both accepted."""
        t = _make_telemetry("dev1", "ev-1")
        assert queue.enqueue(t, "key-a") is True
        assert queue.enqueue(t, "key-b") is True
        assert queue.size() == 2

    def test_adapter_generates_unique_keys(self, adapter):
        """LocalQueueAdapter auto-generates unique keys per enqueue."""
        event = {"event_type": "METRIC", "severity": "INFO"}
        adapter.enqueue(event)
        adapter.enqueue(event)
        adapter.enqueue(event)
        assert adapter.size() == 3  # all unique keys


# ===================================================================
# 4. Crash Recovery
# ===================================================================


class TestCrashRecovery:
    """Queue data must survive process termination (CL-25)."""

    def test_data_survives_connection_close(self, queue_path):
        """Enqueue → close connection → reopen → data present."""
        q1 = LocalQueue(path=queue_path)
        for i in range(10):
            q1.enqueue(_make_telemetry("dev1", f"ev-{i}"), f"key-{i}")
        assert q1.size() == 10
        q1.db.close()

        # Reopen — data must survive
        q2 = LocalQueue(path=queue_path)
        assert q2.size() == 10

        # Drain and verify FIFO order
        drained_ids = []

        def capture(t):
            drained_ids.append(t.events[0].event_id)
            return type("A", (), {"status": 0})()

        q2.drain(capture, limit=100)
        assert len(drained_ids) == 10
        assert drained_ids == [f"ev-{i}" for i in range(10)]

    def test_wal_mode_active(self, queue_path):
        """Queue DB must use WAL journal mode for crash safety."""
        q = LocalQueue(path=queue_path)
        row = q.db.execute("PRAGMA journal_mode").fetchone()
        assert row[0].lower() == "wal"

    def test_db_readable_after_unclean_close(self, queue_path):
        """Simulate unclean close — DB should still be readable.

        We write data, then deliberately don't call close() on the
        connection (simulating a crash). The WAL should auto-recover.
        """
        q = LocalQueue(path=queue_path)
        for i in range(5):
            q.enqueue(_make_telemetry("dev1", f"ev-{i}"), f"key-{i}")
        # Don't close — let garbage collector handle it
        del q

        # Reopen and verify
        q2 = LocalQueue(path=queue_path)
        assert q2.size() == 5


# ===================================================================
# 5. Backpressure
# ===================================================================


class TestBackpressure:
    """Queue drops oldest events when full, preserving newest."""

    def test_oldest_dropped_when_over_limit(self, tmp_path):
        """When max_bytes exceeded, oldest events are dropped first."""
        path = str(tmp_path / "small_queue.db")
        # Very small limit to trigger backpressure easily
        q = LocalQueue(path=path, max_bytes=500)

        # Enqueue events until backpressure triggers
        for i in range(100):
            t = _make_telemetry("dev1", f"ev-{i}", payload="X" * 20)
            q.enqueue(t, f"key-{i}")

        # Queue should be under limit
        assert q.size_bytes() <= 500 + 200  # some overhead tolerance
        # And should have dropped oldest events
        assert q.size() < 100

        # The surviving events should be the most recent ones
        drained_ids = []

        def capture(t):
            drained_ids.append(t.events[0].event_id)
            return type("A", (), {"status": 0})()

        q.drain(capture, limit=200)
        # Last event should definitely survive
        assert "ev-99" in drained_ids

    def test_zero_size_queue_drops_everything(self, tmp_path):
        """max_bytes=0 means every enqueue triggers backpressure."""
        path = str(tmp_path / "zero_queue.db")
        q = LocalQueue(path=path, max_bytes=0)
        q.enqueue(_make_telemetry("dev1", "ev-0"), "key-0")
        # With max_bytes=0, the event should be dropped immediately
        assert q.size() == 0


# ===================================================================
# 6. Protobuf Round-Trip Fidelity
# ===================================================================


class TestProtobufRoundTrip:
    """Protobuf data must survive serialize→SQLite→deserialize intact."""

    def test_all_fields_survive(self, queue):
        """Complex DeviceTelemetry round-trips with all fields intact."""
        original = pb.DeviceTelemetry(
            device_id="test-host-42",
            device_type="ENDPOINT",
            protocol="AGENT_TELEMETRY",
            collection_agent="kernel_audit_v2",
            agent_version="v2.1.0",
            timestamp_ns=1700000000000000000,
        )
        ev = original.events.add()
        ev.event_id = "evt-round-trip-001"
        ev.event_type = "protocol_threat"
        ev.severity = "HIGH"
        ev.event_timestamp_ns = 1700000000000000000
        ev.source_component = "ssh_brute_force"
        ev.confidence_score = 0.95
        ev.tags.extend(["ssh", "brute_force"])
        ev.attributes["src_ip"] = "192.168.1.42"
        ev.attributes["category"] = "SSH_BRUTE_FORCE"

        # Populate security_event
        sec = ev.security_event
        sec.event_category = "SSH_BRUTE_FORCE"
        sec.event_action = "DETECTED"
        sec.event_outcome = "UNKNOWN"
        sec.source_ip = "192.168.1.42"
        sec.risk_score = 0.95
        sec.mitre_techniques.extend(["T1110", "T1021.004"])
        sec.requires_investigation = True
        sec.analyst_notes = "5 failed SSH logins from 192.168.1.42"

        queue.enqueue(original, "round-trip-key")

        # Drain and compare
        recovered = []

        def capture(t):
            recovered.append(t)
            return type("A", (), {"status": 0})()

        queue.drain(capture, limit=1)
        assert len(recovered) == 1

        r = recovered[0]
        assert r.device_id == "test-host-42"
        assert r.device_type == "ENDPOINT"
        assert r.collection_agent == "kernel_audit_v2"
        assert r.agent_version == "v2.1.0"
        assert r.timestamp_ns == 1700000000000000000

        rev = r.events[0]
        assert rev.event_id == "evt-round-trip-001"
        assert rev.event_type == "protocol_threat"
        assert rev.severity == "HIGH"
        assert rev.source_component == "ssh_brute_force"
        assert abs(rev.confidence_score - 0.95) < 0.001
        assert list(rev.tags) == ["ssh", "brute_force"]
        assert rev.attributes["src_ip"] == "192.168.1.42"

        rsec = rev.security_event
        assert rsec.event_category == "SSH_BRUTE_FORCE"
        assert rsec.event_action == "DETECTED"
        assert rsec.source_ip == "192.168.1.42"
        assert abs(rsec.risk_score - 0.95) < 0.001
        assert list(rsec.mitre_techniques) == ["T1110", "T1021.004"]
        assert rsec.requires_investigation is True
        assert "5 failed SSH" in rsec.analyst_notes

    def test_empty_telemetry_round_trip(self, queue):
        """Minimal DeviceTelemetry survives round-trip."""
        original = pb.DeviceTelemetry(device_id="empty-host")
        queue.enqueue(original, "empty-key")

        recovered = []

        def capture(t):
            recovered.append(t)
            return type("A", (), {"status": 0})()

        queue.drain(capture, limit=1)
        assert recovered[0].device_id == "empty-host"

    def test_adapter_dict_round_trip(self, adapter):
        """Dict event → adapter.enqueue → drain → verify SecurityEvent.

        drain() now wraps in UniversalEnvelope; unwrap via .device_telemetry.
        """
        event = {
            "event_type": "protocol_threat",
            "severity": "HIGH",
            "probe_name": "dns_tunneling",
            "confidence": 0.88,
            "mitre_techniques": ["T1048.003"],
            "tags": ["dns", "exfil"],
            "data": {
                "category": "DNS_TUNNELING",
                "description": "High entropy DNS queries to suspicious TLD",
                "src_ip": "10.0.0.50",
                "dst_ip": "8.8.8.8",
            },
        }
        adapter.enqueue(event)

        captured = []

        def capture_fn(events):
            captured.extend(events)

        adapter.drain(capture_fn, limit=1)
        assert len(captured) == 1

        envelope = captured[0]
        t = envelope.device_telemetry
        assert t.collection_agent == "test_agent"
        assert t.device_id == "host-test-001"

        ev = t.events[0]
        assert ev.event_type == "protocol_threat"
        assert ev.HasField("security_event")

        sec = ev.security_event
        assert sec.event_category == "DNS_TUNNELING"
        assert list(sec.mitre_techniques) == ["T1048.003"]
        assert sec.source_ip == "10.0.0.50"
        assert sec.event_action == "DETECTED"
        assert "High entropy" in sec.analyst_notes


# ===================================================================
# 7. Schema Invariants
# ===================================================================


class TestSchemaInvariants:
    """Queue DB schema must enforce required constraints."""

    def test_unique_idem_index_exists(self, queue):
        """UNIQUE INDEX queue_idem must exist."""
        rows = queue.db.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name='queue_idem'"
        ).fetchall()
        assert len(rows) == 1

    def test_ts_index_exists(self, queue):
        """INDEX queue_ts must exist for ordered drain."""
        rows = queue.db.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name='queue_ts'"
        ).fetchall()
        assert len(rows) == 1

    def test_queue_table_columns(self, queue):
        """queue table must have core + signing columns."""
        rows = queue.db.execute("PRAGMA table_info(queue)").fetchall()
        col_names = {r[1] for r in rows}
        assert col_names == {
            "id", "idem", "ts_ns", "bytes", "retries",
            "content_hash", "sig", "prev_sig",
        }

    def test_synchronous_normal(self, queue):
        """PRAGMA synchronous must be NORMAL for WAL performance."""
        row = queue.db.execute("PRAGMA synchronous").fetchone()
        # 1 = NORMAL
        assert row[0] == 1
