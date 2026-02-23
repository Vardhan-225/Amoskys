"""Tests for AMOSKYS Edge Optimization Engine.

Covers:
    - ResourceConstraints dataclass defaults and custom values
    - EdgeMetrics dataclass creation
    - CompressionEngine algorithm selection, compress/decompress round-trips,
      statistics tracking, and lz4 fallback behaviour
    - EdgeEventBuffer add/overflow/batch/flush logic and statistics
    - ResourceMonitor constraint checks, resource availability, recommendations
    - EdgeOptimizer initialization (ResourceConstraints, dict, invalid),
      telemetry batch processing, event buffering, transmission gating,
      batching helpers, optimization recommendations, optimize_data path,
      and the async optimization loop
    - EdgeAgentController instantiation, telemetry forwarding, and status
"""

import asyncio
import gzip
import json
import time
from collections import deque
from dataclasses import asdict
from datetime import datetime, timedelta
from typing import Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from amoskys.edge.edge_optimizer import (
    EDGE_CONFIGS,
    CompressionEngine,
    EdgeAgentController,
    EdgeEventBuffer,
    EdgeMetrics,
    EdgeOptimizer,
    ResourceConstraints,
    ResourceMonitor,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def default_constraints():
    """Return a ResourceConstraints with defaults."""
    return ResourceConstraints()


@pytest.fixture
def tight_constraints():
    """Return tightly constrained ResourceConstraints (small queue)."""
    return ResourceConstraints(
        max_cpu_percent=30.0,
        max_memory_mb=64,
        max_storage_mb=128,
        max_bandwidth_kbps=10,
        max_concurrent_connections=2,
        max_queue_size=5,
        max_batch_age_seconds=5,
    )


@pytest.fixture
def compression_engine():
    return CompressionEngine()


@pytest.fixture
def event_buffer(default_constraints):
    return EdgeEventBuffer(default_constraints)


@pytest.fixture
def small_buffer(tight_constraints):
    return EdgeEventBuffer(tight_constraints)


@pytest.fixture
def resource_monitor(default_constraints):
    return ResourceMonitor(default_constraints)


@pytest.fixture
def optimizer(default_constraints):
    return EdgeOptimizer(default_constraints)


@pytest.fixture
def dict_optimizer():
    return EdgeOptimizer({"max_queue_size": 500, "max_cpu_percent": 40.0})


def _make_event(event_id: str = "evt_1", event_type: str = "METRIC") -> Dict:
    return {
        "event_id": event_id,
        "device_id": "edge_001",
        "timestamp": datetime.now().isoformat(),
        "event_type": event_type,
        "data": {"temperature": 22.5},
    }


# ---------------------------------------------------------------------------
# ResourceConstraints
# ---------------------------------------------------------------------------


class TestResourceConstraints:
    """Validate dataclass defaults and custom values."""

    def test_defaults(self):
        rc = ResourceConstraints()
        assert rc.max_cpu_percent == 50.0
        assert rc.max_memory_mb == 256
        assert rc.max_storage_mb == 1024
        assert rc.max_bandwidth_kbps == 100
        assert rc.max_concurrent_connections == 10
        assert rc.max_queue_size == 1000
        assert rc.max_batch_age_seconds == 30

    def test_custom_values(self):
        rc = ResourceConstraints(max_cpu_percent=25.0, max_memory_mb=32)
        assert rc.max_cpu_percent == 25.0
        assert rc.max_memory_mb == 32
        # Others keep defaults
        assert rc.max_queue_size == 1000

    def test_asdict_round_trip(self):
        rc = ResourceConstraints()
        d = asdict(rc)
        rc2 = ResourceConstraints(**d)
        assert asdict(rc) == asdict(rc2)


# ---------------------------------------------------------------------------
# EdgeMetrics
# ---------------------------------------------------------------------------


class TestEdgeMetrics:
    """Validate EdgeMetrics dataclass creation."""

    def test_creation(self):
        now = datetime.now()
        m = EdgeMetrics(
            cpu_usage_percent=10.0,
            memory_usage_mb=100.0,
            storage_usage_mb=200.0,
            network_usage_kbps=5.0,
            queue_depth=42,
            events_processed=100,
            events_dropped=3,
            compression_ratio=0.6,
            uptime_seconds=300.0,
            last_update=now,
        )
        assert m.cpu_usage_percent == 10.0
        assert m.queue_depth == 42
        assert m.last_update == now

    def test_asdict(self):
        now = datetime.now()
        m = EdgeMetrics(
            cpu_usage_percent=1.0,
            memory_usage_mb=2.0,
            storage_usage_mb=3.0,
            network_usage_kbps=4.0,
            queue_depth=5,
            events_processed=6,
            events_dropped=7,
            compression_ratio=0.5,
            uptime_seconds=8.0,
            last_update=now,
        )
        d = asdict(m)
        assert d["cpu_usage_percent"] == 1.0
        assert d["events_dropped"] == 7


# ---------------------------------------------------------------------------
# CompressionEngine
# ---------------------------------------------------------------------------


class TestCompressionEngine:
    """Test compression algorithms, auto-selection, stats, and round-trips."""

    def test_gzip_round_trip(self, compression_engine):
        data = b"hello world " * 200
        compressed, algo, ratio = compression_engine.compress_data(
            data, algorithm="gzip"
        )
        assert algo == "gzip"
        assert len(compressed) < len(data)
        assert ratio < 1.0
        # Decompress
        decompressed = gzip.decompress(compressed)
        assert decompressed == data

    def test_none_compression(self, compression_engine):
        data = b"tiny"
        compressed, algo, ratio = compression_engine.compress_data(
            data, algorithm="none"
        )
        assert algo == "none"
        assert compressed == data
        assert ratio == 1.0

    def test_auto_selects_none_for_small_data(self, compression_engine):
        data = b"x" * 50  # < 100 bytes
        _, algo, _ = compression_engine.compress_data(data, algorithm="auto")
        assert algo == "none"

    def test_auto_selects_compression_for_medium_data(self, compression_engine):
        data = b"y" * 500  # 100 < size < 10000
        _, algo, _ = compression_engine.compress_data(data, algorithm="auto")
        assert algo in ("lz4", "gzip")

    def test_auto_selects_gzip_for_large_data(self, compression_engine):
        data = b"z" * 20000  # >= 10000
        _, algo, _ = compression_engine.compress_data(data, algorithm="auto")
        assert algo == "gzip"

    def test_compression_stats_tracking(self, compression_engine):
        data = b"a" * 5000
        compression_engine.compress_data(data, algorithm="gzip")
        compression_engine.compress_data(data, algorithm="gzip")

        stats = compression_engine.get_compression_stats()
        assert stats["overall_compression_ratio"] < 1.0
        assert stats["total_bytes_saved"] > 0
        assert stats["average_compression_time_ms"] >= 0
        assert "gzip" in stats["algorithm_performance"]
        assert stats["algorithm_performance"]["gzip"]["count"] == 2

    def test_compression_stats_no_data(self):
        engine = CompressionEngine()
        stats = engine.get_compression_stats()
        assert stats["overall_compression_ratio"] == 1.0
        assert stats["average_compression_time_ms"] == 0.0
        assert stats["total_bytes_saved"] == 0

    def test_empty_data_ratio_is_one(self, compression_engine):
        _, _, ratio = compression_engine.compress_data(b"", algorithm="none")
        assert ratio == 1.0

    def test_lz4_fallback_to_gzip_when_unavailable(self, compression_engine):
        """When lz4 is not available, _lz4_compress falls back to gzip."""
        data = b"test data for lz4 fallback " * 100
        with patch("amoskys.edge.edge_optimizer.HAS_LZ4", False):
            compressed = compression_engine._lz4_compress(data)
            decompressed = compression_engine._lz4_decompress(compressed)
            assert decompressed == data

    def test_no_decompression_identity(self, compression_engine):
        data = b"identity"
        assert compression_engine._no_decompression(data) == data

    def test_gzip_decompress(self, compression_engine):
        data = b"decompress me " * 50
        compressed = compression_engine._gzip_compress(data)
        result = compression_engine._gzip_decompress(compressed)
        assert result == data


# ---------------------------------------------------------------------------
# EdgeEventBuffer
# ---------------------------------------------------------------------------


class TestEdgeEventBuffer:
    """Test buffering, overflow, batching, flush decisions, and stats."""

    def test_add_event_success(self, event_buffer):
        evt = _make_event("e1")
        assert event_buffer.add_event(evt) is True
        assert event_buffer.total_events == 1
        assert event_buffer.dropped_events == 0

    def test_event_decorated_with_metadata(self, event_buffer):
        evt = _make_event("e1")
        event_buffer.add_event(evt)
        batch = event_buffer.get_batch(max_size=1)
        assert len(batch) == 1
        assert "buffered_at" in batch[0]
        assert "buffer_sequence" in batch[0]
        assert batch[0]["buffer_sequence"] == 0

    def test_overflow_drops_oldest(self, small_buffer):
        """Buffer with max_queue_size=5 drops oldest on overflow."""
        for i in range(7):
            small_buffer.add_event(_make_event(f"e{i}"))
        # 7 added, 2 dropped (6th and 7th push cause drops of 1st and 2nd)
        assert small_buffer.total_events == 7
        assert small_buffer.dropped_events == 2
        # Remaining events should be e2..e6
        batch = small_buffer.get_batch(max_size=10)
        ids = [e["event_id"] for e in batch]
        assert ids == ["e2", "e3", "e4", "e5", "e6"]

    def test_get_batch_default_size(self, event_buffer):
        for i in range(5):
            event_buffer.add_event(_make_event(f"e{i}"))
        batch = event_buffer.get_batch()
        assert len(batch) == 5

    def test_get_batch_respects_max_size(self, event_buffer):
        for i in range(10):
            event_buffer.add_event(_make_event(f"e{i}"))
        batch = event_buffer.get_batch(max_size=3)
        assert len(batch) == 3

    def test_get_batch_empty_buffer(self, event_buffer):
        batch = event_buffer.get_batch()
        assert batch == []

    def test_get_batch_updates_last_flush(self, event_buffer):
        event_buffer.add_event(_make_event("e1"))
        before = event_buffer.last_flush
        time.sleep(0.01)
        event_buffer.get_batch()
        assert event_buffer.last_flush >= before

    def test_should_flush_full_buffer(self, small_buffer):
        """Buffer at 80% capacity should flush."""
        # max_queue_size=5, 80% = 4
        for i in range(4):
            small_buffer.add_event(_make_event(f"e{i}"))
        assert small_buffer.should_flush() is True

    def test_should_flush_old_events(self, event_buffer):
        """Events older than max_batch_age_seconds trigger flush."""
        event_buffer.add_event(_make_event("e1"))
        # Simulate old last_flush
        event_buffer.last_flush = datetime.now() - timedelta(seconds=60)
        assert event_buffer.should_flush() is True

    def test_should_flush_minimum_batch(self, event_buffer):
        """10+ events trigger flush even if not full or old."""
        for i in range(10):
            event_buffer.add_event(_make_event(f"e{i}"))
        assert event_buffer.should_flush() is True

    def test_should_not_flush_small_recent(self, event_buffer):
        """A few recent events should not trigger flush."""
        for i in range(3):
            event_buffer.add_event(_make_event(f"e{i}"))
        event_buffer.last_flush = datetime.now()
        assert event_buffer.should_flush() is False

    def test_get_stats(self, event_buffer):
        for i in range(5):
            event_buffer.add_event(_make_event(f"e{i}"))
        stats = event_buffer.get_stats()
        assert stats["current_size"] == 5
        assert stats["max_size"] == 1000
        assert stats["total_events"] == 5
        assert stats["dropped_events"] == 0
        assert 0 < stats["fill_percentage"] < 100
        assert "last_flush" in stats


# ---------------------------------------------------------------------------
# ResourceMonitor
# ---------------------------------------------------------------------------


class TestResourceMonitor:
    """Test resource monitoring, constraint checks, and recommendations."""

    def _mock_psutil(self):
        """Return patchers for psutil calls used by collect_metrics."""
        cpu_patch = patch(
            "amoskys.edge.edge_optimizer.psutil.cpu_percent", return_value=25.0
        )
        mem_mock = MagicMock()
        mem_mock.used = 100 * 1024 * 1024  # 100 MB
        mem_patch = patch(
            "amoskys.edge.edge_optimizer.psutil.virtual_memory", return_value=mem_mock
        )
        disk_mock = MagicMock()
        disk_mock.used = 200 * 1024 * 1024  # 200 MB
        disk_patch = patch(
            "amoskys.edge.edge_optimizer.psutil.disk_usage", return_value=disk_mock
        )
        net_mock = MagicMock()
        net_mock.bytes_sent = 0
        net_mock.bytes_recv = 0
        net_patch = patch(
            "amoskys.edge.edge_optimizer.psutil.net_io_counters", return_value=net_mock
        )
        return cpu_patch, mem_patch, disk_patch, net_patch

    def test_collect_metrics(self, resource_monitor):
        cpu_p, mem_p, disk_p, net_p = self._mock_psutil()
        with cpu_p, mem_p, disk_p, net_p:
            metrics = resource_monitor.collect_metrics()
        assert metrics.cpu_usage_percent == 25.0
        assert metrics.memory_usage_mb == pytest.approx(100.0, abs=1)
        assert metrics.uptime_seconds >= 0
        assert len(resource_monitor.metrics_history) == 1

    def test_constraint_violation_generates_alert(self):
        constraints = ResourceConstraints(max_cpu_percent=10.0)
        monitor = ResourceMonitor(constraints)

        cpu_p = patch(
            "amoskys.edge.edge_optimizer.psutil.cpu_percent", return_value=50.0
        )
        mem_mock = MagicMock()
        mem_mock.used = 100 * 1024 * 1024
        mem_p = patch(
            "amoskys.edge.edge_optimizer.psutil.virtual_memory", return_value=mem_mock
        )
        disk_mock = MagicMock()
        disk_mock.used = 200 * 1024 * 1024
        disk_p = patch(
            "amoskys.edge.edge_optimizer.psutil.disk_usage", return_value=disk_mock
        )
        net_mock = MagicMock()
        net_p = patch(
            "amoskys.edge.edge_optimizer.psutil.net_io_counters", return_value=net_mock
        )

        with cpu_p, mem_p, disk_p, net_p:
            monitor.collect_metrics()

        assert len(monitor.alerts) == 1
        assert "CPU usage" in monitor.alerts[0]["violations"][0]

    def test_is_resource_available_no_history(self, resource_monitor):
        """With no history, resources are assumed available."""
        assert resource_monitor.is_resource_available("cpu", 10.0) is True
        assert resource_monitor.is_resource_available("memory", 10.0) is True
        assert resource_monitor.is_resource_available("storage", 10.0) is True

    def test_is_resource_available_with_history(self, resource_monitor):
        """After collecting metrics, availability checks use real data."""
        cpu_p, mem_p, disk_p, net_p = self._mock_psutil()
        with cpu_p, mem_p, disk_p, net_p:
            resource_monitor.collect_metrics()

        # CPU: used=25%, max=50%, available=25%
        assert resource_monitor.is_resource_available("cpu", 20.0) is True
        assert resource_monitor.is_resource_available("cpu", 30.0) is False

        # Memory: used=100MB, max=256MB, available=156MB
        assert resource_monitor.is_resource_available("memory", 100.0) is True
        assert resource_monitor.is_resource_available("memory", 200.0) is False

    def test_is_resource_available_unknown_type(self, resource_monitor):
        """Unknown resource types return True."""
        cpu_p, mem_p, disk_p, net_p = self._mock_psutil()
        with cpu_p, mem_p, disk_p, net_p:
            resource_monitor.collect_metrics()
        assert resource_monitor.is_resource_available("gpu", 999.0) is True

    def test_get_resource_recommendation_insufficient_data(self, resource_monitor):
        rec = resource_monitor.get_resource_recommendation()
        assert rec["status"] == "insufficient_data"

    def test_get_resource_recommendation_ok(self, resource_monitor):
        cpu_p, mem_p, disk_p, net_p = self._mock_psutil()
        with cpu_p, mem_p, disk_p, net_p:
            for _ in range(12):
                resource_monitor.collect_metrics()

        rec = resource_monitor.get_resource_recommendation()
        assert rec["status"] == "ok"
        assert "average_cpu" in rec
        assert "average_memory" in rec
        assert isinstance(rec["recommendations"], list)

    def test_get_resource_recommendation_high_cpu(self):
        constraints = ResourceConstraints(max_cpu_percent=30.0)
        monitor = ResourceMonitor(constraints)

        # CPU at 90% > 80% of 30% = 24%
        cpu_p = patch(
            "amoskys.edge.edge_optimizer.psutil.cpu_percent", return_value=90.0
        )
        mem_mock = MagicMock()
        mem_mock.used = 50 * 1024 * 1024
        mem_p = patch(
            "amoskys.edge.edge_optimizer.psutil.virtual_memory", return_value=mem_mock
        )
        disk_mock = MagicMock()
        disk_mock.used = 50 * 1024 * 1024
        disk_p = patch(
            "amoskys.edge.edge_optimizer.psutil.disk_usage", return_value=disk_mock
        )
        net_mock = MagicMock()
        net_p = patch(
            "amoskys.edge.edge_optimizer.psutil.net_io_counters", return_value=net_mock
        )

        with cpu_p, mem_p, disk_p, net_p:
            for _ in range(12):
                monitor.collect_metrics()

        rec = monitor.get_resource_recommendation()
        types = [r["type"] for r in rec["recommendations"]]
        assert "CPU_HIGH" in types

    def test_get_resource_recommendation_high_memory(self):
        constraints = ResourceConstraints(max_memory_mb=100)
        monitor = ResourceMonitor(constraints)

        cpu_p = patch(
            "amoskys.edge.edge_optimizer.psutil.cpu_percent", return_value=5.0
        )
        mem_mock = MagicMock()
        mem_mock.used = 90 * 1024 * 1024  # 90MB > 80% of 100MB
        mem_p = patch(
            "amoskys.edge.edge_optimizer.psutil.virtual_memory", return_value=mem_mock
        )
        disk_mock = MagicMock()
        disk_mock.used = 50 * 1024 * 1024
        disk_p = patch(
            "amoskys.edge.edge_optimizer.psutil.disk_usage", return_value=disk_mock
        )
        net_mock = MagicMock()
        net_p = patch(
            "amoskys.edge.edge_optimizer.psutil.net_io_counters", return_value=net_mock
        )

        with cpu_p, mem_p, disk_p, net_p:
            for _ in range(12):
                monitor.collect_metrics()

        rec = monitor.get_resource_recommendation()
        types = [r["type"] for r in rec["recommendations"]]
        assert "MEMORY_HIGH" in types


# ---------------------------------------------------------------------------
# EdgeOptimizer — Initialization
# ---------------------------------------------------------------------------


class TestEdgeOptimizerInit:
    """Test EdgeOptimizer construction from various config types."""

    def test_init_with_resource_constraints(self, default_constraints):
        opt = EdgeOptimizer(default_constraints)
        assert opt.constraints is default_constraints
        assert opt.optimization_enabled is True
        assert opt.adaptive_mode is True

    def test_init_with_dict(self):
        opt = EdgeOptimizer({"max_queue_size": 200, "max_cpu_percent": 20.0})
        assert opt.constraints.max_queue_size == 200
        assert opt.constraints.max_cpu_percent == 20.0
        # Defaults for unspecified fields
        assert opt.constraints.max_memory_mb == 256

    def test_init_with_empty_dict(self):
        opt = EdgeOptimizer({})
        assert opt.constraints.max_cpu_percent == 50.0

    def test_init_invalid_type_raises(self):
        with pytest.raises(
            TypeError, match="config must be ResourceConstraints or dict"
        ):
            EdgeOptimizer("bad_config")

    def test_init_invalid_type_int_raises(self):
        with pytest.raises(TypeError):
            EdgeOptimizer(42)

    def test_stores_original_config(self, default_constraints):
        opt = EdgeOptimizer(default_constraints)
        assert opt.config is default_constraints

    def test_performance_stats_initialized(self, optimizer):
        stats = optimizer.performance_stats
        assert stats["optimization_cycles"] == 0
        assert stats["bandwidth_saved_bytes"] == 0


# ---------------------------------------------------------------------------
# EdgeOptimizer — Telemetry batch processing
# ---------------------------------------------------------------------------


class TestEdgeOptimizerBatchProcessing:
    """Test process_telemetry_batch with various inputs."""

    def test_empty_events_returns_empty(self, optimizer):
        data, meta = optimizer.process_telemetry_batch([])
        assert data == b""
        assert meta == {}

    def test_single_event_batch(self, optimizer):
        events = [_make_event("e1")]
        data, meta = optimizer.process_telemetry_batch(events)
        assert len(data) > 0
        assert meta["events_processed"] == 1
        assert meta["original_size"] > 0
        assert "compression_algorithm" in meta
        assert "compression_ratio" in meta

    def test_large_batch_compressed(self, optimizer):
        events = [_make_event(f"e{i}") for i in range(200)]
        data, meta = optimizer.process_telemetry_batch(events)
        assert meta["compressed_size"] < meta["original_size"]
        assert meta["events_processed"] == 200

    def test_bandwidth_saved_tracked(self, optimizer):
        events = [_make_event(f"e{i}") for i in range(50)]
        optimizer.process_telemetry_batch(events)
        assert optimizer.performance_stats["bandwidth_saved_bytes"] > 0


# ---------------------------------------------------------------------------
# EdgeOptimizer — Event buffering
# ---------------------------------------------------------------------------


class TestEdgeOptimizerEventBuffering:
    """Test add_telemetry_event and buffer interactions."""

    def test_add_telemetry_event(self, optimizer):
        assert optimizer.add_telemetry_event(_make_event("e1")) is True

    def test_multiple_events_buffered(self, optimizer):
        for i in range(15):
            optimizer.add_telemetry_event(_make_event(f"e{i}"))
        stats = optimizer.event_buffer.get_stats()
        assert stats["current_size"] == 15


# ---------------------------------------------------------------------------
# EdgeOptimizer — Transmission decisions
# ---------------------------------------------------------------------------


class TestEdgeOptimizerTransmission:
    """Test should_transmit_batch and get_transmission_batch."""

    def test_should_transmit_when_buffer_full(self, optimizer):
        for i in range(15):
            optimizer.add_telemetry_event(_make_event(f"e{i}"))
        # 15 events >= 10 minimum batch
        cpu_p = patch(
            "amoskys.edge.edge_optimizer.psutil.cpu_percent", return_value=5.0
        )
        mem_mock = MagicMock()
        mem_mock.used = 50 * 1024 * 1024
        mem_p = patch(
            "amoskys.edge.edge_optimizer.psutil.virtual_memory", return_value=mem_mock
        )
        disk_mock = MagicMock()
        disk_mock.used = 50 * 1024 * 1024
        disk_p = patch(
            "amoskys.edge.edge_optimizer.psutil.disk_usage", return_value=disk_mock
        )
        net_mock = MagicMock()
        net_p = patch(
            "amoskys.edge.edge_optimizer.psutil.net_io_counters", return_value=net_mock
        )
        with cpu_p, mem_p, disk_p, net_p:
            assert optimizer.should_transmit_batch() is True

    def test_get_transmission_batch_empty(self, optimizer):
        data, meta = optimizer.get_transmission_batch()
        assert data == b""
        assert meta == {}

    def test_get_transmission_batch_with_events(self, optimizer):
        for i in range(5):
            optimizer.add_telemetry_event(_make_event(f"e{i}"))
        data, meta = optimizer.get_transmission_batch()
        assert len(data) > 0
        assert meta["events_processed"] == 5


# ---------------------------------------------------------------------------
# EdgeOptimizer — _create_batches helper
# ---------------------------------------------------------------------------


class TestEdgeOptimizerCreateBatches:
    """Test the _create_batches helper method."""

    def test_empty_list(self, optimizer):
        assert optimizer._create_batches([]) == []

    def test_single_batch(self, optimizer):
        events = list(range(5))
        batches = optimizer._create_batches(events, batch_size=10)
        assert len(batches) == 1
        assert batches[0] == [0, 1, 2, 3, 4]

    def test_multiple_batches(self, optimizer):
        events = list(range(10))
        batches = optimizer._create_batches(events, batch_size=3)
        assert len(batches) == 4
        assert batches[0] == [0, 1, 2]
        assert batches[1] == [3, 4, 5]
        assert batches[2] == [6, 7, 8]
        assert batches[3] == [9]

    def test_exact_batch_size(self, optimizer):
        events = list(range(6))
        batches = optimizer._create_batches(events, batch_size=3)
        assert len(batches) == 2
        assert all(len(b) == 3 for b in batches)

    def test_default_batch_size(self, optimizer):
        events = list(range(250))
        batches = optimizer._create_batches(events)
        assert len(batches) == 3  # 100 + 100 + 50


# ---------------------------------------------------------------------------
# EdgeOptimizer — _compress_data helper
# ---------------------------------------------------------------------------


class TestEdgeOptimizerCompressData:
    """Test the _compress_data convenience method."""

    def test_compress_and_decompress(self, optimizer):
        data = b"repeat this phrase many times " * 100
        compressed = optimizer._compress_data(data)
        assert len(compressed) < len(data)
        decompressed = gzip.decompress(compressed)
        assert decompressed == data

    def test_custom_compression_level(self, optimizer):
        data = b"some data " * 100
        c1 = optimizer._compress_data(data, compression_level=1)
        c9 = optimizer._compress_data(data, compression_level=9)
        # Both decompress back to original
        assert gzip.decompress(c1) == data
        assert gzip.decompress(c9) == data


# ---------------------------------------------------------------------------
# EdgeOptimizer — Optimization recommendations
# ---------------------------------------------------------------------------


class TestEdgeOptimizerRecommendations:
    """Test _generate_optimization_recommendations."""

    def test_normal_resources(self, optimizer):
        info = {"cpu_percent": 10.0, "memory_mb": 50.0}
        recs = optimizer._generate_optimization_recommendations(info)
        assert len(recs) == 1
        assert "normal limits" in recs[0]

    def test_high_cpu(self, optimizer):
        info = {"cpu_percent": 60.0, "memory_mb": 50.0, "constraint_cpu_percent": 50.0}
        recs = optimizer._generate_optimization_recommendations(info)
        assert any("High CPU" in r for r in recs)
        assert any("batch size" in r for r in recs)

    def test_high_memory(self, optimizer):
        info = {"cpu_percent": 5.0, "memory_mb": 300.0, "constraint_memory_mb": 200.0}
        recs = optimizer._generate_optimization_recommendations(info)
        assert any("High memory" in r for r in recs)

    def test_approaching_limits(self, optimizer):
        # 80% of default 50% CPU = 40%. Setting cpu at 42% triggers.
        info = {"cpu_percent": 42.0, "memory_mb": 50.0}
        recs = optimizer._generate_optimization_recommendations(info)
        assert any("Approaching" in r for r in recs)

    def test_both_high(self, optimizer):
        info = {
            "cpu_percent": 80.0,
            "memory_mb": 400.0,
            "constraint_cpu_percent": 50.0,
            "constraint_memory_mb": 256.0,
        }
        recs = optimizer._generate_optimization_recommendations(info)
        assert any("High CPU" in r for r in recs)
        assert any("High memory" in r for r in recs)
        assert any("Approaching" in r for r in recs)


# ---------------------------------------------------------------------------
# EdgeOptimizer — optimize_data
# ---------------------------------------------------------------------------


class TestEdgeOptimizerOptimizeData:
    """Test optimize_data with compression and constraint checks."""

    def _patch_low_resources(self):
        """Patch psutil to return low resource usage."""
        cpu_p = patch(
            "amoskys.edge.edge_optimizer.psutil.cpu_percent", return_value=5.0
        )
        mem_mock = MagicMock()
        mem_mock.used = 50 * 1024 * 1024  # 50 MB
        mem_p = patch(
            "amoskys.edge.edge_optimizer.psutil.virtual_memory", return_value=mem_mock
        )
        disk_mock = MagicMock()
        disk_mock.used = 100 * 1024 * 1024
        disk_p = patch(
            "amoskys.edge.edge_optimizer.psutil.disk_usage", return_value=disk_mock
        )
        net_mock = MagicMock()
        net_p = patch(
            "amoskys.edge.edge_optimizer.psutil.net_io_counters", return_value=net_mock
        )
        return cpu_p, mem_p, disk_p, net_p

    def test_small_data_not_compressed(self, optimizer):
        """Data <= 1024 bytes is returned as-is."""
        data = b"small"
        cpu_p, mem_p, disk_p, net_p = self._patch_low_resources()
        with cpu_p, mem_p, disk_p, net_p:
            result = optimizer.optimize_data(data)
        assert result == data

    def test_large_data_compressed(self, optimizer):
        """Data > 1024 bytes is compressed."""
        data = b"x" * 2000
        cpu_p, mem_p, disk_p, net_p = self._patch_low_resources()
        with cpu_p, mem_p, disk_p, net_p:
            result = optimizer.optimize_data(data)
        assert len(result) < len(data)
        assert gzip.decompress(result) == data

    def test_severe_memory_constraint_raises(self):
        """Exceeding 1.5x memory limit raises RuntimeError."""
        constraints = ResourceConstraints(max_memory_mb=10)
        opt = EdgeOptimizer(constraints)

        cpu_p = patch(
            "amoskys.edge.edge_optimizer.psutil.cpu_percent", return_value=5.0
        )
        mem_mock = MagicMock()
        # 20 MB > 1.5 * 10 MB = 15 MB
        mem_mock.used = 20 * 1024 * 1024
        mem_p = patch(
            "amoskys.edge.edge_optimizer.psutil.virtual_memory", return_value=mem_mock
        )
        disk_mock = MagicMock()
        disk_mock.used = 50 * 1024 * 1024
        disk_p = patch(
            "amoskys.edge.edge_optimizer.psutil.disk_usage", return_value=disk_mock
        )
        net_mock = MagicMock()
        net_p = patch(
            "amoskys.edge.edge_optimizer.psutil.net_io_counters", return_value=net_mock
        )

        with cpu_p, mem_p, disk_p, net_p:
            with pytest.raises(RuntimeError, match="memory usage"):
                opt.optimize_data(b"test")

    def test_severe_cpu_constraint_raises(self):
        """Exceeding 1.5x CPU limit raises RuntimeError."""
        constraints = ResourceConstraints(max_cpu_percent=10.0)
        opt = EdgeOptimizer(constraints)

        cpu_p = patch(
            "amoskys.edge.edge_optimizer.psutil.cpu_percent", return_value=20.0
        )
        mem_mock = MagicMock()
        mem_mock.used = 50 * 1024 * 1024
        mem_p = patch(
            "amoskys.edge.edge_optimizer.psutil.virtual_memory", return_value=mem_mock
        )
        disk_mock = MagicMock()
        disk_mock.used = 50 * 1024 * 1024
        disk_p = patch(
            "amoskys.edge.edge_optimizer.psutil.disk_usage", return_value=disk_mock
        )
        net_mock = MagicMock()
        net_p = patch(
            "amoskys.edge.edge_optimizer.psutil.net_io_counters", return_value=net_mock
        )

        with cpu_p, mem_p, disk_p, net_p:
            with pytest.raises(RuntimeError, match="CPU usage"):
                opt.optimize_data(b"test")


# ---------------------------------------------------------------------------
# EdgeOptimizer — get_resource_usage
# ---------------------------------------------------------------------------


class TestEdgeOptimizerGetResourceUsage:
    """Test the get_resource_usage convenience method."""

    def test_returns_expected_keys(self, optimizer):
        cpu_p = patch(
            "amoskys.edge.edge_optimizer.psutil.cpu_percent", return_value=10.0
        )
        mem_mock = MagicMock()
        mem_mock.used = 128 * 1024 * 1024
        mem_p = patch(
            "amoskys.edge.edge_optimizer.psutil.virtual_memory", return_value=mem_mock
        )
        disk_mock = MagicMock()
        disk_mock.used = 512 * 1024 * 1024
        disk_p = patch(
            "amoskys.edge.edge_optimizer.psutil.disk_usage", return_value=disk_mock
        )
        net_mock = MagicMock()
        net_p = patch(
            "amoskys.edge.edge_optimizer.psutil.net_io_counters", return_value=net_mock
        )

        with cpu_p, mem_p, disk_p, net_p:
            usage = optimizer.get_resource_usage()

        assert "cpu_percent" in usage
        assert "memory_mb" in usage
        assert "disk_usage_percent" in usage
        assert "memory_percent" in usage
        assert usage["cpu_percent"] == 10.0
        assert usage["memory_mb"] == pytest.approx(128.0, abs=1)


# ---------------------------------------------------------------------------
# EdgeOptimizer — get_optimization_stats
# ---------------------------------------------------------------------------


class TestEdgeOptimizerStats:
    """Test get_optimization_stats aggregation."""

    def test_stats_structure(self, optimizer):
        cpu_p = patch(
            "amoskys.edge.edge_optimizer.psutil.cpu_percent", return_value=5.0
        )
        mem_mock = MagicMock()
        mem_mock.used = 50 * 1024 * 1024
        mem_p = patch(
            "amoskys.edge.edge_optimizer.psutil.virtual_memory", return_value=mem_mock
        )
        disk_mock = MagicMock()
        disk_mock.used = 50 * 1024 * 1024
        disk_p = patch(
            "amoskys.edge.edge_optimizer.psutil.disk_usage", return_value=disk_mock
        )
        net_mock = MagicMock()
        net_p = patch(
            "amoskys.edge.edge_optimizer.psutil.net_io_counters", return_value=net_mock
        )

        with cpu_p, mem_p, disk_p, net_p:
            stats = optimizer.get_optimization_stats()

        assert "edge_optimization" in stats
        assert "compression" in stats
        assert "buffer" in stats
        assert "resources" in stats
        assert "alerts" in stats

        eo = stats["edge_optimization"]
        assert eo["optimization_cycles"] == 0
        assert eo["adaptive_mode"] is True
        assert "constraints" in eo


# ---------------------------------------------------------------------------
# EdgeOptimizer — async optimization loop
# ---------------------------------------------------------------------------


class TestEdgeOptimizerAsyncLoop:
    """Test the async start_optimization_loop."""

    @pytest.mark.asyncio
    async def test_optimization_loop_runs_and_stops(self, optimizer):
        """Loop increments optimization_cycles then stops."""
        cpu_p = patch(
            "amoskys.edge.edge_optimizer.psutil.cpu_percent", return_value=5.0
        )
        mem_mock = MagicMock()
        mem_mock.used = 50 * 1024 * 1024
        mem_p = patch(
            "amoskys.edge.edge_optimizer.psutil.virtual_memory", return_value=mem_mock
        )
        disk_mock = MagicMock()
        disk_mock.used = 50 * 1024 * 1024
        disk_p = patch(
            "amoskys.edge.edge_optimizer.psutil.disk_usage", return_value=disk_mock
        )
        net_mock = MagicMock()
        net_p = patch(
            "amoskys.edge.edge_optimizer.psutil.net_io_counters", return_value=net_mock
        )

        with cpu_p, mem_p, disk_p, net_p:
            # Run the loop for a short time then cancel
            async def stop_after_delay():
                await asyncio.sleep(0.15)
                optimizer.optimization_enabled = False

            await asyncio.gather(
                optimizer.start_optimization_loop(),
                stop_after_delay(),
            )

        assert optimizer.performance_stats["optimization_cycles"] >= 1

    @pytest.mark.asyncio
    async def test_optimization_loop_handles_error(self, optimizer):
        """Loop survives exceptions and continues."""
        call_count = 0

        original_collect = optimizer.resource_monitor.collect_metrics

        def flaky_collect():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RuntimeError("simulated failure")
            return original_collect()

        optimizer.resource_monitor.collect_metrics = flaky_collect

        cpu_p = patch(
            "amoskys.edge.edge_optimizer.psutil.cpu_percent", return_value=5.0
        )
        mem_mock = MagicMock()
        mem_mock.used = 50 * 1024 * 1024
        mem_p = patch(
            "amoskys.edge.edge_optimizer.psutil.virtual_memory", return_value=mem_mock
        )
        disk_mock = MagicMock()
        disk_mock.used = 50 * 1024 * 1024
        disk_p = patch(
            "amoskys.edge.edge_optimizer.psutil.disk_usage", return_value=disk_mock
        )
        net_mock = MagicMock()
        net_p = patch(
            "amoskys.edge.edge_optimizer.psutil.net_io_counters", return_value=net_mock
        )

        with cpu_p, mem_p, disk_p, net_p:

            async def stop_after_delay():
                await asyncio.sleep(
                    6.5
                )  # Allow error recovery (5s delay) + one good cycle
                optimizer.optimization_enabled = False

            await asyncio.gather(
                optimizer.start_optimization_loop(),
                stop_after_delay(),
            )

        # Should have survived the error and done at least one successful cycle
        assert call_count >= 2

    @pytest.mark.asyncio
    async def test_adaptive_optimizations_cpu_high(self, optimizer):
        """When CPU is high, _reduce_processing_load is called."""
        metrics = EdgeMetrics(
            cpu_usage_percent=48.0,  # > 0.9 * 50 = 45
            memory_usage_mb=50.0,
            storage_usage_mb=50.0,
            network_usage_kbps=5.0,
            queue_depth=0,
            events_processed=0,
            events_dropped=0,
            compression_ratio=1.0,
            uptime_seconds=10.0,
            last_update=datetime.now(),
        )
        with patch.object(
            optimizer, "_reduce_processing_load", new_callable=AsyncMock
        ) as mock_reduce:
            await optimizer._apply_adaptive_optimizations(metrics)
            mock_reduce.assert_called_once()

    @pytest.mark.asyncio
    async def test_adaptive_optimizations_memory_high(self, optimizer):
        """When memory is high, _emergency_buffer_flush is called."""
        metrics = EdgeMetrics(
            cpu_usage_percent=5.0,
            memory_usage_mb=240.0,  # > 0.9 * 256 = 230.4
            storage_usage_mb=50.0,
            network_usage_kbps=5.0,
            queue_depth=0,
            events_processed=0,
            events_dropped=0,
            compression_ratio=1.0,
            uptime_seconds=10.0,
            last_update=datetime.now(),
        )
        with patch.object(
            optimizer, "_emergency_buffer_flush", new_callable=AsyncMock
        ) as mock_flush:
            await optimizer._apply_adaptive_optimizations(metrics)
            mock_flush.assert_called_once()

    @pytest.mark.asyncio
    async def test_adaptive_optimizations_bandwidth_high(self, optimizer):
        """When bandwidth is high, _increase_compression is called."""
        metrics = EdgeMetrics(
            cpu_usage_percent=5.0,
            memory_usage_mb=50.0,
            storage_usage_mb=50.0,
            network_usage_kbps=85.0,  # > 0.8 * 100 = 80
            queue_depth=0,
            events_processed=0,
            events_dropped=0,
            compression_ratio=1.0,
            uptime_seconds=10.0,
            last_update=datetime.now(),
        )
        with patch.object(
            optimizer, "_increase_compression", new_callable=AsyncMock
        ) as mock_comp:
            await optimizer._apply_adaptive_optimizations(metrics)
            mock_comp.assert_called_once()

    @pytest.mark.asyncio
    async def test_adaptive_optimizations_none_needed(self, optimizer):
        """When all resources are low, no optimizations fire."""
        metrics = EdgeMetrics(
            cpu_usage_percent=5.0,
            memory_usage_mb=50.0,
            storage_usage_mb=50.0,
            network_usage_kbps=5.0,
            queue_depth=0,
            events_processed=0,
            events_dropped=0,
            compression_ratio=1.0,
            uptime_seconds=10.0,
            last_update=datetime.now(),
        )
        with (
            patch.object(
                optimizer, "_reduce_processing_load", new_callable=AsyncMock
            ) as mock_r,
            patch.object(
                optimizer, "_emergency_buffer_flush", new_callable=AsyncMock
            ) as mock_f,
            patch.object(
                optimizer, "_increase_compression", new_callable=AsyncMock
            ) as mock_c,
        ):
            await optimizer._apply_adaptive_optimizations(metrics)
            mock_r.assert_not_called()
            mock_f.assert_not_called()
            mock_c.assert_not_called()

    @pytest.mark.asyncio
    async def test_emergency_buffer_flush(self, optimizer):
        """_emergency_buffer_flush drains events from the buffer."""
        for i in range(20):
            optimizer.add_telemetry_event(_make_event(f"e{i}"))
        stats_before = optimizer.event_buffer.get_stats()
        assert stats_before["current_size"] == 20

        await optimizer._emergency_buffer_flush()
        stats_after = optimizer.event_buffer.get_stats()
        # Should have flushed up to 50, so 20 -> 0
        assert stats_after["current_size"] == 0


# ---------------------------------------------------------------------------
# EdgeOptimizer — _log_performance_summary
# ---------------------------------------------------------------------------


class TestEdgeOptimizerLogPerformance:
    """Test _log_performance_summary runs without error."""

    def test_log_performance_summary(self, optimizer):
        metrics = EdgeMetrics(
            cpu_usage_percent=10.0,
            memory_usage_mb=100.0,
            storage_usage_mb=200.0,
            network_usage_kbps=5.0,
            queue_depth=42,
            events_processed=100,
            events_dropped=3,
            compression_ratio=0.6,
            uptime_seconds=300.0,
            last_update=datetime.now(),
        )
        cpu_p = patch(
            "amoskys.edge.edge_optimizer.psutil.cpu_percent", return_value=10.0
        )
        mem_mock = MagicMock()
        mem_mock.used = 100 * 1024 * 1024
        mem_p = patch(
            "amoskys.edge.edge_optimizer.psutil.virtual_memory", return_value=mem_mock
        )
        disk_mock = MagicMock()
        disk_mock.used = 200 * 1024 * 1024
        disk_p = patch(
            "amoskys.edge.edge_optimizer.psutil.disk_usage", return_value=disk_mock
        )
        net_mock = MagicMock()
        net_p = patch(
            "amoskys.edge.edge_optimizer.psutil.net_io_counters", return_value=net_mock
        )

        with cpu_p, mem_p, disk_p, net_p:
            # Should not raise
            optimizer._log_performance_summary(metrics)


# ---------------------------------------------------------------------------
# EdgeAgentController
# ---------------------------------------------------------------------------


class TestEdgeAgentController:
    """Test EdgeAgentController instantiation and interface."""

    def test_init_from_config(self):
        config = EDGE_CONFIGS["raspberry_pi"]
        ctrl = EdgeAgentController(config)
        assert ctrl.is_running is False
        assert ctrl.constraints.max_cpu_percent == 60.0
        assert ctrl.constraints.max_memory_mb == 200

    def test_init_empty_constraints(self):
        ctrl = EdgeAgentController({})
        assert ctrl.constraints.max_cpu_percent == 50.0

    def test_add_telemetry(self):
        ctrl = EdgeAgentController(EDGE_CONFIGS["industrial_gateway"])
        result = ctrl.add_telemetry(_make_event("e1"))
        assert result is True

    def test_get_status(self):
        ctrl = EdgeAgentController(EDGE_CONFIGS["medical_device_hub"])

        cpu_p = patch(
            "amoskys.edge.edge_optimizer.psutil.cpu_percent", return_value=5.0
        )
        mem_mock = MagicMock()
        mem_mock.used = 50 * 1024 * 1024
        mem_p = patch(
            "amoskys.edge.edge_optimizer.psutil.virtual_memory", return_value=mem_mock
        )
        disk_mock = MagicMock()
        disk_mock.used = 50 * 1024 * 1024
        disk_p = patch(
            "amoskys.edge.edge_optimizer.psutil.disk_usage", return_value=disk_mock
        )
        net_mock = MagicMock()
        net_p = patch(
            "amoskys.edge.edge_optimizer.psutil.net_io_counters", return_value=net_mock
        )

        with cpu_p, mem_p, disk_p, net_p:
            status = ctrl.get_status()

        assert status["is_running"] is False
        assert "constraints" in status
        assert "optimization_stats" in status


# ---------------------------------------------------------------------------
# EDGE_CONFIGS
# ---------------------------------------------------------------------------


class TestEdgeConfigs:
    """Validate the bundled deployment scenario configurations."""

    def test_all_configs_present(self):
        assert "raspberry_pi" in EDGE_CONFIGS
        assert "industrial_gateway" in EDGE_CONFIGS
        assert "medical_device_hub" in EDGE_CONFIGS

    @pytest.mark.parametrize(
        "profile", ["raspberry_pi", "industrial_gateway", "medical_device_hub"]
    )
    def test_config_creates_valid_controller(self, profile):
        ctrl = EdgeAgentController(EDGE_CONFIGS[profile])
        assert ctrl.constraints.max_queue_size > 0
        assert ctrl.constraints.max_cpu_percent > 0
