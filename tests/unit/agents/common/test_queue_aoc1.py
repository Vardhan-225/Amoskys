"""Tests for AOC-1 queue pipeline visibility (Phase 2).

Validates:
    - P0-10: Backpressure drops fire callback and increment metrics
    - P0-11: Drain success/failure fire callbacks and increment metrics
    - P0-12: Max-retry drops fire callback and increment metrics
    - P0-13: Signing key load failures logged at WARNING
    - P0-14: verify_hash_chain() detects intact/broken/unsigned chains
    - Callback wiring: LocalQueueAdapter wires LocalQueue callbacks
"""

import logging
import time

import pytest

from amoskys.agents.common.local_queue import LocalQueue
from amoskys.agents.common.metrics import AgentMetrics
from amoskys.agents.common.queue_adapter import LocalQueueAdapter, _load_signing_key
from amoskys.proto import universal_telemetry_pb2 as pb

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_queue_path(tmp_path):
    """Provide temporary queue database path."""
    return str(tmp_path / "aoc1_queue.db")


@pytest.fixture
def queue(tmp_queue_path):
    """Create a fresh LocalQueue."""
    return LocalQueue(path=tmp_queue_path, max_bytes=50 * 1024 * 1024)


@pytest.fixture
def adapter(tmp_queue_path):
    """Create a LocalQueueAdapter with metrics wired."""
    a = LocalQueueAdapter(
        queue_path=tmp_queue_path,
        agent_name="test_agent",
        device_id="device-001",
    )
    a._metrics = AgentMetrics()
    return a


def _make_telemetry(device_id="dev-1"):
    return pb.DeviceTelemetry(
        device_id=device_id,
        device_type="HOST",
        timestamp_ns=int(time.time() * 1e9),
        collection_agent="test_agent",
    )


# ---------------------------------------------------------------------------
# P0-10: Backpressure callback fires + metrics
# ---------------------------------------------------------------------------


class TestBackpressureCallbacks:
    def test_callback_wired_on_construction(self, adapter):
        """LocalQueue._on_backpressure_drop should be wired to adapter."""
        assert adapter.queue._on_backpressure_drop is not None

    def test_backpressure_increments_metrics(self, tmp_path):
        """Backpressure drops should increment metrics counter."""
        adapter = LocalQueueAdapter(
            queue_path=str(tmp_path / "bp.db"),
            agent_name="bp_agent",
            device_id="dev-bp",
            max_bytes=500,  # tiny limit to trigger backpressure
        )
        metrics = AgentMetrics()
        adapter._metrics = metrics

        # Enqueue enough to trigger backpressure
        for i in range(30):
            adapter.enqueue(_make_telemetry(f"dev-{i}"))

        assert metrics.queue_backpressure_drops > 0

    def test_backpressure_without_metrics_no_crash(self, tmp_path):
        """Backpressure with _metrics=None should not crash."""
        adapter = LocalQueueAdapter(
            queue_path=str(tmp_path / "bp2.db"),
            agent_name="bp_agent",
            device_id="dev-bp",
            max_bytes=500,
        )
        # _metrics is None by default
        adapter._metrics = None

        # Should not raise
        for i in range(30):
            adapter.enqueue(_make_telemetry(f"dev-{i}"))


# ---------------------------------------------------------------------------
# P0-11: Drain success/failure callbacks + metrics
# ---------------------------------------------------------------------------


class TestDrainCallbacks:
    def test_drain_success_callback_wired(self, adapter):
        """LocalQueue._on_drain_success should be wired."""
        assert adapter.queue._on_drain_success is not None

    def test_drain_failure_callback_wired(self, adapter):
        """LocalQueue._on_drain_failure should be wired."""
        assert adapter.queue._on_drain_failure is not None

    def test_drain_success_increments_metrics(self, adapter):
        """Successful drain should increment drain_successes."""
        for i in range(3):
            adapter.enqueue({"event_type": "METRIC", "severity": "INFO"})

        def publish_ok(envelopes):
            pass  # adapter.drain wraps in envelope, status=0 on success

        adapter.drain(publish_ok, limit=10)

        assert adapter._metrics.queue_drain_successes == 3

    def test_drain_failure_increments_metrics(self, adapter):
        """Failed drain should increment drain_failures.

        Note: adapter.drain() wraps publish exceptions as status=2 (permanent
        error), so to test the raw _on_drain_failure callback we use the
        underlying queue.drain() directly.
        """
        adapter.enqueue({"event_type": "METRIC", "severity": "INFO"})

        def publish_fail(telemetry):
            raise ConnectionError("EventBus down")

        adapter.queue.drain(publish_fail, limit=1)

        assert adapter._metrics.queue_drain_failures == 1


# ---------------------------------------------------------------------------
# P0-12: Max-retry drops callback + metrics
# ---------------------------------------------------------------------------


class TestMaxRetryDropCallbacks:
    def test_max_retry_callback_wired(self, adapter):
        """LocalQueue._on_max_retry_drop should be wired."""
        assert adapter.queue._on_max_retry_drop is not None

    def test_max_retry_drop_increments_metrics(self, tmp_path):
        """Exceeding max_retries should increment max_retry_drops.

        Uses raw queue.drain() to bypass adapter's exception wrapping,
        so the retry/drop logic in _drain_impl actually engages.
        """
        adapter = LocalQueueAdapter(
            queue_path=str(tmp_path / "retry.db"),
            agent_name="retry_agent",
            device_id="dev-retry",
            max_retries=1,  # fail after 1 retry
        )
        metrics = AgentMetrics()
        adapter._metrics = metrics

        adapter.enqueue({"event_type": "METRIC", "severity": "INFO"})

        def publish_fail(_telemetry):
            raise ConnectionError("Permanent failure")

        # First drain: retries=0 → increment to 1, no drop yet
        adapter.queue.drain(publish_fail, limit=1)
        assert adapter.size() == 1  # still in queue

        # Second drain: retries=1 → exceeds max_retries=1 → drop
        adapter.queue.drain(publish_fail, limit=1)
        assert adapter.size() == 0  # dropped
        assert metrics.queue_max_retry_drops >= 1


# ---------------------------------------------------------------------------
# P0-13: Signing key load failure logging
# ---------------------------------------------------------------------------


class TestSigningKeyFailureLogging:
    def test_missing_key_logs_warning(self, caplog):
        """Missing signing key should log SIGNING_KEY_MISSING at WARNING."""
        with caplog.at_level(logging.WARNING):
            result = _load_signing_key("/nonexistent/path/key.ed25519")

        assert result is None
        assert "SIGNING_KEY_MISSING" in caplog.text

    def test_corrupt_key_logs_warning(self, tmp_path, caplog):
        """Corrupt signing key should log SIGNING_KEY_LOAD_FAILURE."""
        key_path = tmp_path / "bad.ed25519"
        key_path.write_bytes(b"not a valid key")

        with caplog.at_level(logging.WARNING):
            result = _load_signing_key(str(key_path))

        assert result is None
        assert "SIGNING_KEY_LOAD_FAILURE" in caplog.text


# ---------------------------------------------------------------------------
# P0-14: Hash chain verification
# ---------------------------------------------------------------------------


class TestHashChainVerification:
    def test_empty_queue_valid(self, adapter):
        """Empty queue should report valid chain."""
        result = adapter.verify_hash_chain()
        assert result["chain_valid"] is True
        assert result["total_rows"] == 0
        assert result["broken_at"] is None
        assert result["unsigned_count"] == 0

    def test_unsigned_events_counted(self, adapter):
        """Events without signing key should be counted as unsigned."""
        for i in range(3):
            adapter.enqueue({"event_type": "METRIC", "severity": "INFO"})

        result = adapter.verify_hash_chain()
        assert result["chain_valid"] is True
        assert result["total_rows"] == 3
        assert result["unsigned_count"] == 3

    def test_signed_chain_valid(self, tmp_path):
        """Properly signed chain should verify as valid."""
        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519 as ed_mod

            sk = ed_mod.Ed25519PrivateKey.generate()
            key_path = str(tmp_path / "agent.ed25519")
            with open(key_path, "wb") as f:
                f.write(sk.private_bytes_raw())
        except ImportError:
            pytest.skip("cryptography package not available")

        adapter = LocalQueueAdapter(
            queue_path=str(tmp_path / "signed.db"),
            agent_name="signed_agent",
            device_id="dev-signed",
            signing_key_path=key_path,
        )

        for i in range(5):
            adapter.enqueue({"event_type": "METRIC", "severity": "INFO"})

        result = adapter.verify_hash_chain()
        assert result["chain_valid"] is True
        assert result["total_rows"] == 5
        assert result["unsigned_count"] == 0
        assert result["broken_at"] is None

    def test_broken_chain_detected(self, tmp_path):
        """Tampered prev_sig should be detected as broken chain."""
        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519 as ed_mod

            sk = ed_mod.Ed25519PrivateKey.generate()
            key_path = str(tmp_path / "agent.ed25519")
            with open(key_path, "wb") as f:
                f.write(sk.private_bytes_raw())
        except ImportError:
            pytest.skip("cryptography package not available")

        adapter = LocalQueueAdapter(
            queue_path=str(tmp_path / "tampered.db"),
            agent_name="tampered_agent",
            device_id="dev-tampered",
            signing_key_path=key_path,
        )

        for i in range(5):
            adapter.enqueue({"event_type": "METRIC", "severity": "INFO"})

        # Tamper with prev_sig of row 3
        adapter.queue.db.execute("UPDATE queue SET prev_sig = X'DEADBEEF' WHERE id = 3")

        result = adapter.verify_hash_chain()
        assert result["chain_valid"] is False
        assert result["broken_at"] == 3


# ---------------------------------------------------------------------------
# Callback wiring integration
# ---------------------------------------------------------------------------


class TestCallbackWiringIntegration:
    def test_all_four_callbacks_wired(self, adapter):
        """All four LocalQueue callbacks should be wired by adapter."""
        # Bound methods create new objects on each access, so compare __func__
        assert (
            adapter.queue._on_backpressure_drop.__func__
            is LocalQueueAdapter._on_backpressure_drop
        )
        assert (
            adapter.queue._on_max_retry_drop.__func__
            is LocalQueueAdapter._on_max_retry_drop
        )
        assert (
            adapter.queue._on_drain_success.__func__
            is LocalQueueAdapter._on_drain_success
        )
        assert (
            adapter.queue._on_drain_failure.__func__
            is LocalQueueAdapter._on_drain_failure
        )

    def test_metrics_set_after_construction(self, tmp_path):
        """Adapter should accept _metrics being set after construction."""
        adapter = LocalQueueAdapter(
            queue_path=str(tmp_path / "late.db"),
            agent_name="late_agent",
            device_id="dev-late",
        )
        assert adapter._metrics is None

        metrics = AgentMetrics()
        adapter._metrics = metrics

        adapter.enqueue({"event_type": "METRIC", "severity": "INFO"})

        def publish_ok(envelopes):
            pass

        adapter.drain(publish_ok, limit=1)
        assert metrics.queue_drain_successes == 1

    def test_queue_depth_readable(self, adapter):
        """Queue depth should be readable for metrics snapshot."""
        for i in range(5):
            adapter.enqueue({"event_type": "METRIC", "severity": "INFO"})

        assert adapter.size() == 5
        assert adapter.size_bytes() > 0
