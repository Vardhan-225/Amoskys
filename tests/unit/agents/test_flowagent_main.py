"""
Unit tests for FlowAgent main module (src/amoskys/agents/flowagent/main.py).

Covers:
- idem_key() deterministic hashing
- make_envelope() envelope construction with mocked crypto
- grpc_channel() TLS channel creation (mutual and one-way)
- sleep_with_jitter() timing behaviour
- _size_ok() envelope size checking
- _rate_limit() send rate enforcement
- _backoff_delay() exponential backoff calculation
- publish_with_safety() retry logic and error paths
- publish_with_wal() WAL-backed publishing (OK, RETRY, FAIL, oversize)
- drain_once() WAL drain
- start_health() HTTP health/readiness endpoints
- main() lifecycle loop (SIGHUP, stop, drain, rate limiting)
- Signal handlers _on_hup() and _graceful()
"""

import hashlib
import http.client

# We import the actual module (not the function) using importlib because
# the flowagent __init__.py re-exports main() as a function, masking
# the module. Using importlib.import_module gets the real module object.
import importlib
import os
import threading
import time
from types import SimpleNamespace
from unittest.mock import MagicMock, PropertyMock, mock_open, patch

import pytest

flowagent_main = importlib.import_module("amoskys.agents.flowagent.main")
from amoskys.proto import messaging_schema_pb2 as pb

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_flow(**kw):
    """Create a minimal FlowEvent for testing."""
    defaults = dict(
        src_ip="10.0.0.1",
        dst_ip="8.8.8.8",
        src_port=12345,
        dst_port=53,
        protocol="UDP",
        bytes_sent=100,
        bytes_recv=200,
        flags=0,
        start_time=1,
        end_time=2,
        bytes_tx=100,
        bytes_rx=200,
        proto="UDP",
        duration_ms=50,
    )
    defaults.update(kw)
    return pb.FlowEvent(**defaults)


def _make_envelope(flow=None):
    """Build a lightweight Envelope for testing."""
    if flow is None:
        flow = _make_flow()
    ts_ns = 1_000_000_000
    idem = flowagent_main.idem_key(flow, ts_ns)
    return pb.Envelope(
        version="v1",
        ts_ns=ts_ns,
        idempotency_key=idem,
        flow=flow,
        sig=b"\x00" * 64,
        prev_sig=b"",
    )


# ===========================================================================
# idem_key tests
# ===========================================================================


class TestIdemKey:
    """Test idempotency key generation."""

    def test_returns_sha256_hex(self):
        flow = _make_flow()
        key = flowagent_main.idem_key(flow, 1000)
        assert isinstance(key, str)
        assert len(key) == 64  # SHA256 hex digest

    def test_deterministic(self):
        flow = _make_flow()
        k1 = flowagent_main.idem_key(flow, 1000)
        k2 = flowagent_main.idem_key(flow, 1000)
        assert k1 == k2

    def test_different_timestamps_different_keys(self):
        flow = _make_flow()
        k1 = flowagent_main.idem_key(flow, 1000)
        k2 = flowagent_main.idem_key(flow, 2000)
        assert k1 != k2

    def test_different_flows_different_keys(self):
        f1 = _make_flow(src_ip="1.1.1.1")
        f2 = _make_flow(src_ip="2.2.2.2")
        k1 = flowagent_main.idem_key(f1, 1000)
        k2 = flowagent_main.idem_key(f2, 1000)
        assert k1 != k2

    def test_all_5tuple_fields_affect_key(self):
        """Changing any one of the 5 tuple fields changes the key."""
        base = _make_flow()
        base_key = flowagent_main.idem_key(base, 1000)

        variants = [
            _make_flow(src_ip="9.9.9.9"),
            _make_flow(dst_ip="9.9.9.9"),
            _make_flow(src_port=99999),
            _make_flow(dst_port=99999),
            _make_flow(protocol="TCP"),
        ]
        for v in variants:
            assert flowagent_main.idem_key(v, 1000) != base_key


# ===========================================================================
# make_envelope tests
# ===========================================================================


class TestMakeEnvelope:
    """Test envelope construction (with mocked crypto)."""

    @patch("amoskys.agents.flowagent.main.sign", return_value=b"\x00" * 64)
    @patch("amoskys.agents.flowagent.main.load_private_key", return_value=MagicMock())
    @patch("amoskys.agents.flowagent.main.canonical_bytes", return_value=b"canonical")
    def test_returns_envelope(self, mock_canon, mock_load, mock_sign):
        flow = _make_flow()
        env = flowagent_main.make_envelope(flow)
        assert isinstance(env, pb.Envelope)
        assert env.version == "v1"
        assert env.ts_ns > 0
        assert len(env.idempotency_key) == 64
        assert env.sig == b"\x00" * 64

    @patch("amoskys.agents.flowagent.main.sign", return_value=b"sig")
    @patch("amoskys.agents.flowagent.main.load_private_key", return_value=MagicMock())
    @patch("amoskys.agents.flowagent.main.canonical_bytes", return_value=b"canonical")
    def test_flow_attached(self, mock_canon, mock_load, mock_sign):
        flow = _make_flow(src_ip="192.168.1.1")
        env = flowagent_main.make_envelope(flow)
        assert env.flow.src_ip == "192.168.1.1"


# ===========================================================================
# _size_ok tests
# ===========================================================================


class TestSizeOk:
    """Test envelope size checking."""

    def test_small_envelope_passes(self):
        env = _make_envelope()
        # Override the module-level MAX_ENV_BYTES for the test
        with patch.object(flowagent_main, "MAX_ENV_BYTES", 1_000_000):
            assert flowagent_main._size_ok(env) is True

    def test_oversize_envelope_rejected(self):
        env = _make_envelope()
        with patch.object(flowagent_main, "MAX_ENV_BYTES", 1):
            assert flowagent_main._size_ok(env) is False

    def test_serialize_error_returns_false(self):
        """If SerializeToString raises, return False."""
        bad = MagicMock()
        bad.SerializeToString.side_effect = RuntimeError("boom")
        assert flowagent_main._size_ok(bad) is False


# ===========================================================================
# _rate_limit tests
# ===========================================================================


class TestRateLimit:
    """Test send rate limit enforcement."""

    def test_no_rate_limit_when_zero(self):
        """SEND_RATE <= 0 means no rate limiting."""
        with patch.object(flowagent_main, "SEND_RATE", 0):
            flowagent_main._rate_limit()
            # Should return immediately with no sleep

    def test_rate_limit_when_positive(self):
        """When SEND_RATE is positive, should enforce delay."""
        with patch.object(flowagent_main, "SEND_RATE", 10):
            flowagent_main._last_send_ts = time.time()  # just sent
            with patch("amoskys.agents.flowagent.main.time") as mock_time:
                mock_time.time.return_value = flowagent_main._last_send_ts + 0.001
                flowagent_main._rate_limit()
                # Should have called time.sleep
                mock_time.sleep.assert_called()


# ===========================================================================
# _backoff_delay tests
# ===========================================================================


class TestBackoffDelay:
    """Test exponential backoff with jitter."""

    def test_attempt_zero_bounded(self):
        """Attempt 0 should produce small delay."""
        for _ in range(20):
            d = flowagent_main._backoff_delay(0)
            assert 0 < d < 0.15  # 50ms * (0.5 to 1.5)

    def test_capped_at_2_seconds_base(self):
        """Even high attempt numbers cap at 2s base."""
        for _ in range(20):
            d = flowagent_main._backoff_delay(100)
            assert d <= 4.0  # 2.0 * ~2.0 max jitter

    def test_increases_with_attempt(self):
        """Higher attempts should generally produce larger delays."""
        # Average over many samples to handle randomness
        low_avg = sum(flowagent_main._backoff_delay(0) for _ in range(100)) / 100
        high_avg = sum(flowagent_main._backoff_delay(5) for _ in range(100)) / 100
        assert high_avg > low_avg


# ===========================================================================
# sleep_with_jitter tests
# ===========================================================================


class TestSleepWithJitter:
    """Test jittered sleep."""

    @patch("amoskys.agents.flowagent.main.time")
    def test_minimum_50ms(self, mock_time):
        mock_time.sleep = MagicMock()
        # Force specific random value for reproducibility
        with patch("amoskys.agents.flowagent.main.random") as mock_random:
            mock_random.uniform.return_value = 0.2
            flowagent_main.sleep_with_jitter(10)
            args = mock_time.sleep.call_args[0]
            assert args[0] >= 0.05  # At least 50ms base

    @patch("amoskys.agents.flowagent.main.time")
    def test_jitter_adds_to_base(self, mock_time):
        mock_time.sleep = MagicMock()
        with patch("amoskys.agents.flowagent.main.random") as mock_random:
            mock_random.uniform.return_value = 0.5
            flowagent_main.sleep_with_jitter(1000)
            args = mock_time.sleep.call_args[0]
            # base = 1.0, jitter = 1.0 * 0.5 = 0.5, total = 1.5
            assert args[0] == pytest.approx(1.5, abs=0.01)


# ===========================================================================
# publish_with_safety tests
# ===========================================================================


class TestPublishWithSafety:
    """Test publish_with_safety retry loop."""

    def test_oversize_envelope_drops(self):
        stub = MagicMock()
        env = _make_envelope()
        with patch.object(flowagent_main, "MAX_ENV_BYTES", 1):
            ok, reason = flowagent_main.publish_with_safety(stub, env)
        assert ok is False
        assert reason == "dropped-oversize"
        stub.Publish.assert_not_called()

    def test_ok_response_returns_success(self):
        stub = MagicMock()
        ack = pb.PublishAck(status=pb.PublishAck.OK)
        stub.Publish.return_value = ack

        env = _make_envelope()
        with patch.object(flowagent_main, "MAX_ENV_BYTES", 1_000_000):
            with patch.object(flowagent_main, "SEND_RATE", 0):
                ok, reason = flowagent_main.publish_with_safety(stub, env)
        assert ok is True
        assert reason == "ok"

    def test_retry_response_retries_then_fails(self):
        stub = MagicMock()
        ack = pb.PublishAck(status=pb.PublishAck.RETRY, reason="busy")
        stub.Publish.return_value = ack

        env = _make_envelope()
        with patch.object(flowagent_main, "MAX_ENV_BYTES", 1_000_000):
            with patch.object(flowagent_main, "SEND_RATE", 0):
                with patch.object(flowagent_main, "RETRY_MAX", 2):
                    with patch("amoskys.agents.flowagent.main.time") as mock_time:
                        mock_time.time.return_value = 1.0
                        mock_time.sleep = MagicMock()
                        ok, reason = flowagent_main.publish_with_safety(stub, env)
        assert ok is False
        # Should have been called RETRY_MAX + 1 times (initial + retries)
        assert stub.Publish.call_count == 3

    def test_invalid_response_returns_fail(self):
        stub = MagicMock()
        ack = pb.PublishAck(status=pb.PublishAck.INVALID, reason="bad-data")
        stub.Publish.return_value = ack

        env = _make_envelope()
        with patch.object(flowagent_main, "MAX_ENV_BYTES", 1_000_000):
            with patch.object(flowagent_main, "SEND_RATE", 0):
                ok, reason = flowagent_main.publish_with_safety(stub, env)
        assert ok is False


# ===========================================================================
# publish_with_wal tests
# ===========================================================================


class TestPublishWithWal:
    """Test publish_with_wal with WAL-backed reliability."""

    def test_oversize_envelope_dropped(self):
        wal = MagicMock()
        env = _make_envelope()
        with patch.object(flowagent_main, "MAX_ENV_BYTES", 1):
            flowagent_main.publish_with_wal(env, wal)
        wal.append.assert_not_called()

    @patch("amoskys.agents.flowagent.main.grpc_channel")
    def test_ok_response_no_wal_write(self, mock_channel):
        wal = MagicMock()
        wal.backlog_bytes.return_value = 0

        mock_stub_instance = MagicMock()
        ack = pb.PublishAck(status=pb.PublishAck.OK)
        mock_stub_instance.Publish.return_value = ack

        mock_ch = MagicMock()
        mock_ch.__enter__ = MagicMock(return_value=mock_ch)
        mock_ch.__exit__ = MagicMock(return_value=False)
        mock_channel.return_value = mock_ch

        with patch(
            "amoskys.agents.flowagent.main.pbrpc.EventBusStub",
            return_value=mock_stub_instance,
        ):
            with patch.object(flowagent_main, "MAX_ENV_BYTES", 1_000_000):
                flowagent_main.publish_with_wal(_make_envelope(), wal)

        wal.append.assert_not_called()

    @patch("amoskys.agents.flowagent.main.grpc_channel")
    def test_retry_response_appends_to_wal(self, mock_channel):
        wal = MagicMock()
        wal.backlog_bytes.return_value = 100

        mock_stub = MagicMock()
        ack = pb.PublishAck(status=pb.PublishAck.RETRY, backoff_hint_ms=200)
        mock_stub.Publish.return_value = ack

        mock_ch = MagicMock()
        mock_ch.__enter__ = MagicMock(return_value=mock_ch)
        mock_ch.__exit__ = MagicMock(return_value=False)
        mock_channel.return_value = mock_ch

        with patch(
            "amoskys.agents.flowagent.main.pbrpc.EventBusStub", return_value=mock_stub
        ):
            with patch.object(flowagent_main, "MAX_ENV_BYTES", 1_000_000):
                with patch("amoskys.agents.flowagent.main.sleep_with_jitter"):
                    flowagent_main.publish_with_wal(_make_envelope(), wal)

        wal.append.assert_called_once()

    @patch("amoskys.agents.flowagent.main.grpc_channel")
    def test_rpc_error_appends_to_wal(self, mock_channel):
        import grpc

        wal = MagicMock()
        wal.backlog_bytes.return_value = 50

        mock_ch = MagicMock()
        mock_ch.__enter__ = MagicMock(return_value=mock_ch)
        mock_ch.__exit__ = MagicMock(return_value=False)
        mock_channel.return_value = mock_ch

        rpc_error = grpc.RpcError()
        rpc_error.code = MagicMock(return_value=grpc.StatusCode.UNAVAILABLE)

        mock_stub = MagicMock()
        mock_stub.Publish.side_effect = rpc_error

        with patch(
            "amoskys.agents.flowagent.main.pbrpc.EventBusStub", return_value=mock_stub
        ):
            with patch.object(flowagent_main, "MAX_ENV_BYTES", 1_000_000):
                with patch("amoskys.agents.flowagent.main.sleep_with_jitter"):
                    flowagent_main.publish_with_wal(_make_envelope(), wal)

        wal.append.assert_called_once()

    @patch("amoskys.agents.flowagent.main.grpc_channel")
    def test_fail_response_increments_fail_counter(self, mock_channel):
        wal = MagicMock()
        wal.backlog_bytes.return_value = 0

        mock_stub = MagicMock()
        ack = pb.PublishAck(status=pb.PublishAck.UNAUTHORIZED, reason="bad-sig")
        mock_stub.Publish.return_value = ack

        mock_ch = MagicMock()
        mock_ch.__enter__ = MagicMock(return_value=mock_ch)
        mock_ch.__exit__ = MagicMock(return_value=False)
        mock_channel.return_value = mock_ch

        with patch(
            "amoskys.agents.flowagent.main.pbrpc.EventBusStub", return_value=mock_stub
        ):
            with patch.object(flowagent_main, "MAX_ENV_BYTES", 1_000_000):
                # Should not raise
                flowagent_main.publish_with_wal(_make_envelope(), wal)

        # WAL append should NOT be called for UNAUTHORIZED (non-RETRY)
        wal.append.assert_not_called()


# ===========================================================================
# drain_once tests
# ===========================================================================


class TestDrainOnce:
    """Test WAL drain function."""

    @patch("amoskys.agents.flowagent.main.grpc_channel")
    def test_drain_calls_wal_drain(self, mock_channel):
        wal = MagicMock()
        wal.drain.return_value = 5

        result = flowagent_main.drain_once(wal)
        assert result == 5
        wal.drain.assert_called_once()
        # The limit parameter should be 500
        _, kwargs = wal.drain.call_args
        assert kwargs.get("limit") == 500


# ===========================================================================
# grpc_channel tests
# ===========================================================================


class TestGrpcChannel:
    """Test gRPC channel construction."""

    @patch("amoskys.agents.flowagent.main.grpc.secure_channel")
    @patch("amoskys.agents.flowagent.main.grpc.ssl_channel_credentials")
    def test_mutual_tls_when_certs_exist(self, mock_creds, mock_channel):
        """When client.crt and client.key exist, use mutual TLS."""
        ca_data = b"CA_CERT"
        crt_data = b"CLIENT_CERT"
        key_data = b"CLIENT_KEY"

        def mock_open_fn(path, mode="r"):
            if "ca.crt" in path:
                return MagicMock(
                    __enter__=MagicMock(
                        return_value=MagicMock(read=MagicMock(return_value=ca_data))
                    ),
                    __exit__=MagicMock(return_value=False),
                )
            elif "client.crt" in path:
                return MagicMock(
                    __enter__=MagicMock(
                        return_value=MagicMock(read=MagicMock(return_value=crt_data))
                    ),
                    __exit__=MagicMock(return_value=False),
                )
            elif "client.key" in path:
                return MagicMock(
                    __enter__=MagicMock(
                        return_value=MagicMock(read=MagicMock(return_value=key_data))
                    ),
                    __exit__=MagicMock(return_value=False),
                )

        with patch("builtins.open", side_effect=mock_open_fn):
            with patch("os.path.exists", return_value=True):
                flowagent_main.grpc_channel()

        mock_creds.assert_called_once_with(
            root_certificates=ca_data, private_key=key_data, certificate_chain=crt_data
        )

    @patch("amoskys.agents.flowagent.main.grpc.secure_channel")
    @patch("amoskys.agents.flowagent.main.grpc.ssl_channel_credentials")
    def test_one_way_tls_when_certs_missing(self, mock_creds, mock_channel):
        """When client certs are missing, use one-way TLS."""
        ca_data = b"CA_CERT"

        def mock_open_fn(path, mode="r"):
            if "ca.crt" in path:
                return MagicMock(
                    __enter__=MagicMock(
                        return_value=MagicMock(read=MagicMock(return_value=ca_data))
                    ),
                    __exit__=MagicMock(return_value=False),
                )
            raise FileNotFoundError(path)

        with patch("builtins.open", side_effect=mock_open_fn):
            with patch("os.path.exists", return_value=False):
                flowagent_main.grpc_channel()

        mock_creds.assert_called_once_with(root_certificates=ca_data)


# ===========================================================================
# Signal handler tests
# ===========================================================================


class TestSignalHandlers:
    """Test signal handler functions directly."""

    def test_on_hup_sets_exit_flag(self):
        original = flowagent_main._SHOULD_EXIT
        try:
            flowagent_main._SHOULD_EXIT = False
            flowagent_main._on_hup(1, None)
            assert flowagent_main._SHOULD_EXIT is True
        finally:
            flowagent_main._SHOULD_EXIT = original

    def test_graceful_sets_stop_and_not_ready(self):
        original_stop = flowagent_main.stop
        original_ready = flowagent_main.READY
        try:
            flowagent_main.stop = False
            flowagent_main.READY = True
            flowagent_main._graceful(2, None)
            assert flowagent_main.stop is True
            assert flowagent_main.READY is False
        finally:
            flowagent_main.stop = original_stop
            flowagent_main.READY = original_ready


# ===========================================================================
# start_health tests
# ===========================================================================


class TestStartHealth:
    """Test HTTP health server startup."""

    def test_health_server_starts(self):
        """Health server starts on a thread and responds to /healthz."""
        # Use a random high port to avoid conflicts
        import socket

        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()

        with patch.object(flowagent_main.config.agent, "health_port", port):
            flowagent_main.start_health()
            # Give the thread a moment to start
            time.sleep(0.3)

            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
            try:
                conn.request("GET", "/healthz")
                resp = conn.getresponse()
                assert resp.status == 200
                body = resp.read()
                assert b"ok" in body
            finally:
                conn.close()

    def test_health_server_404_for_unknown_path(self):
        """Unknown paths return 404."""
        import socket

        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()

        with patch.object(flowagent_main.config.agent, "health_port", port):
            flowagent_main.start_health()
            time.sleep(0.3)

            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
            try:
                conn.request("GET", "/nonexistent")
                resp = conn.getresponse()
                assert resp.status == 404
            finally:
                conn.close()

    def test_ready_endpoint_not_ready(self):
        """When READY=False, /ready returns 503."""
        import socket

        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()

        original = flowagent_main.READY
        try:
            flowagent_main.READY = False
            with patch.object(flowagent_main.config.agent, "health_port", port):
                flowagent_main.start_health()
                time.sleep(0.3)

                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
                try:
                    conn.request("GET", "/ready")
                    resp = conn.getresponse()
                    assert resp.status == 503
                    body = resp.read()
                    assert b"not-ready" in body
                finally:
                    conn.close()
        finally:
            flowagent_main.READY = original

    def test_ready_endpoint_ready(self):
        """When READY=True, /ready returns 200."""
        import socket

        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()

        original = flowagent_main.READY
        try:
            flowagent_main.READY = True
            with patch.object(flowagent_main.config.agent, "health_port", port):
                flowagent_main.start_health()
                time.sleep(0.3)

                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
                try:
                    conn.request("GET", "/ready")
                    resp = conn.getresponse()
                    assert resp.status == 200
                    body = resp.read()
                    assert b"ready" in body
                finally:
                    conn.close()
        finally:
            flowagent_main.READY = original


# ===========================================================================
# main() lifecycle tests
# ===========================================================================


class TestMainLifecycle:
    """Test main() loop with mocked dependencies."""

    @patch("amoskys.agents.flowagent.main.drain_once", return_value=0)
    @patch("amoskys.agents.flowagent.main.start_health")
    @patch("amoskys.agents.flowagent.main.SQLiteWAL")
    def test_main_exits_on_stop(self, mock_wal_cls, mock_health, mock_drain):
        """main() exits when stop is set."""
        original_stop = flowagent_main.stop
        original_ready = flowagent_main.READY
        original_exit = flowagent_main._SHOULD_EXIT
        try:
            flowagent_main.stop = False
            flowagent_main._SHOULD_EXIT = False

            # Set stop flag after one iteration
            call_count = [0]

            def drain_side_effect(wal):
                call_count[0] += 1
                if call_count[0] >= 1:
                    flowagent_main.stop = True
                return 0

            mock_drain.side_effect = drain_side_effect

            with patch.object(flowagent_main, "SEND_RATE", 0):
                with patch("amoskys.agents.flowagent.main.time") as mock_time:
                    mock_time.sleep = MagicMock()
                    mock_time.time.return_value = 1.0
                    flowagent_main.main()

            assert flowagent_main.READY is True  # Set to True during init
            mock_health.assert_called_once()
        finally:
            flowagent_main.stop = original_stop
            flowagent_main.READY = original_ready
            flowagent_main._SHOULD_EXIT = original_exit

    @patch("amoskys.agents.flowagent.main.drain_once", return_value=0)
    @patch("amoskys.agents.flowagent.main.start_health")
    @patch("amoskys.agents.flowagent.main.SQLiteWAL")
    def test_main_exits_on_sighup(self, mock_wal_cls, mock_health, mock_drain):
        """main() exits with sys.exit(0) on SIGHUP."""
        original_stop = flowagent_main.stop
        original_exit = flowagent_main._SHOULD_EXIT
        try:
            flowagent_main.stop = False
            flowagent_main._SHOULD_EXIT = True

            with pytest.raises(SystemExit) as exc:
                flowagent_main.main()

            assert exc.value.code == 0
        finally:
            flowagent_main.stop = original_stop
            flowagent_main._SHOULD_EXIT = original_exit

    @patch("amoskys.agents.flowagent.main.drain_once", return_value=5)
    @patch("amoskys.agents.flowagent.main.start_health")
    @patch("amoskys.agents.flowagent.main.SQLiteWAL")
    def test_main_with_send_rate(self, mock_wal_cls, mock_health, mock_drain):
        """main() applies rate limiting when SEND_RATE > 0."""
        original_stop = flowagent_main.stop
        original_exit = flowagent_main._SHOULD_EXIT
        try:
            flowagent_main.stop = False
            flowagent_main._SHOULD_EXIT = False

            call_count = [0]

            def drain_effect(wal):
                call_count[0] += 1
                if call_count[0] >= 1:
                    flowagent_main.stop = True
                return 5

            mock_drain.side_effect = drain_effect

            with patch.object(flowagent_main, "SEND_RATE", 10):
                with patch("amoskys.agents.flowagent.main.time") as mock_time:
                    mock_time.time.return_value = 1.0
                    mock_time.sleep = MagicMock()
                    flowagent_main.main()

            # time.sleep should have been called for rate limiting
            assert mock_time.sleep.called
        finally:
            flowagent_main.stop = original_stop
            flowagent_main._SHOULD_EXIT = original_exit

    @patch("amoskys.agents.flowagent.main.drain_once", return_value=0)
    @patch("amoskys.agents.flowagent.main.start_health")
    @patch("amoskys.agents.flowagent.main.SQLiteWAL")
    def test_main_sleeps_when_no_events(self, mock_wal_cls, mock_health, mock_drain):
        """main() sleeps 2s when no events drained and SEND_RATE=0."""
        original_stop = flowagent_main.stop
        original_exit = flowagent_main._SHOULD_EXIT
        try:
            flowagent_main.stop = False
            flowagent_main._SHOULD_EXIT = False

            call_count = [0]

            def drain_effect(wal):
                call_count[0] += 1
                if call_count[0] >= 1:
                    flowagent_main.stop = True
                return 0

            mock_drain.side_effect = drain_effect

            with patch.object(flowagent_main, "SEND_RATE", 0):
                with patch("amoskys.agents.flowagent.main.time") as mock_time:
                    mock_time.time.return_value = 1.0
                    mock_time.sleep = MagicMock()
                    flowagent_main.main()

            # Should have slept at 2 seconds (idle drain) + 0.2 (loop delay)
            sleep_calls = [c[0][0] for c in mock_time.sleep.call_args_list]
            assert 2 in sleep_calls
        finally:
            flowagent_main.stop = original_stop
            flowagent_main._SHOULD_EXIT = original_exit
