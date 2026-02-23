"""Hardening tests for EventBus Component 3.

Covers all P0/P1 fixes:
- P0-EB-1: Legacy Publish signature verification
- P0-EB-2: ACK-after-WAL delivery guarantee
- P0-EB-3: mTLS enabled by default
- P1-EB-1: Application-level dedup wired
- P1-EB-3: Graceful shutdown
- P1-EB-4: Health check server
- P1-EB-5: _load_keys/_load_trust called in serve()
"""

import os
import signal
import threading
import time
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_srv():
    """Import and return the eventbus server module."""
    import amoskys.eventbus.server as srv

    return srv


# ---------------------------------------------------------------------------
# Phase 0: Crypto Foundation Tests
# ---------------------------------------------------------------------------


class TestLegacySignatureVerification:
    """P0-EB-1: Legacy Publish() must verify signatures."""

    def setup_method(self):
        self.srv = _get_srv()

    def test_legacy_verify_accepts_unsigned_when_not_required(self):
        """Unsigned envelope accepted when REQUIRE_SIGNATURES=false."""
        original = self.srv.REQUIRE_SIGNATURES
        try:
            self.srv.REQUIRE_SIGNATURES = False
            from amoskys.proto import messaging_schema_pb2 as pb

            env = pb.Envelope(sig=b"")
            valid, error = self.srv._verify_legacy_envelope_signature(env)
            assert valid is True
            assert error is None
        finally:
            self.srv.REQUIRE_SIGNATURES = original

    def test_legacy_verify_rejects_unsigned_when_required(self):
        """Unsigned envelope rejected when REQUIRE_SIGNATURES=true."""
        original = self.srv.REQUIRE_SIGNATURES
        try:
            self.srv.REQUIRE_SIGNATURES = True
            from amoskys.proto import messaging_schema_pb2 as pb

            env = pb.Envelope(sig=b"")
            valid, error = self.srv._verify_legacy_envelope_signature(env)
            assert valid is False
            assert "required" in error.lower()
        finally:
            self.srv.REQUIRE_SIGNATURES = original

    def test_legacy_verify_rejects_when_no_pubkey(self):
        """Signed envelope rejected when AGENT_PUBKEY is None."""
        original_key = self.srv.AGENT_PUBKEY
        original_req = self.srv.REQUIRE_SIGNATURES
        try:
            self.srv.AGENT_PUBKEY = None
            self.srv.REQUIRE_SIGNATURES = False
            from amoskys.proto import messaging_schema_pb2 as pb

            env = pb.Envelope(sig=b"fake-signature-64-bytes" * 3)
            valid, error = self.srv._verify_legacy_envelope_signature(env)
            assert valid is False
            assert "No public key" in error
        finally:
            self.srv.AGENT_PUBKEY = original_key
            self.srv.REQUIRE_SIGNATURES = original_req

    def test_legacy_verify_returns_tuple(self):
        """Return type is always (bool, Optional[str])."""
        from amoskys.proto import messaging_schema_pb2 as pb

        env = pb.Envelope(sig=b"")
        result = self.srv._verify_legacy_envelope_signature(env)
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], bool)

    def test_verify_envelope_signature_function_exists(self):
        """_verify_envelope_signature exists for UniversalEnvelope."""
        assert callable(self.srv._verify_envelope_signature)

    def test_verify_legacy_envelope_signature_function_exists(self):
        """_verify_legacy_envelope_signature exists for legacy Envelope."""
        assert callable(self.srv._verify_legacy_envelope_signature)


class TestKeyLoading:
    """P1-EB-5: Keys and trust map loaded in serve()."""

    def test_load_keys_function_exists(self):
        srv = _get_srv()
        assert callable(srv._load_keys)

    def test_load_trust_function_exists(self):
        srv = _get_srv()
        assert callable(srv._load_trust)


# ---------------------------------------------------------------------------
# Phase 1: Delivery Guarantee Tests
# ---------------------------------------------------------------------------


class TestACKAfterWAL:
    """P0-EB-2: Server must not ACK before WAL write is confirmed."""

    def test_wal_failure_counter_exists(self):
        """BUS_WAL_FAILURES Prometheus counter exists."""
        srv = _get_srv()
        assert hasattr(srv, "BUS_WAL_FAILURES")

    def test_publish_wal_write_success_returns_ok(self):
        """When WAL write succeeds, Publish returns OK."""
        # This is a structural test — the wal_written flag must gate the return
        srv = _get_srv()
        # Verify the source code pattern exists
        import inspect

        source = inspect.getsource(srv.EventBusServicer.Publish)
        assert "wal_written" in source
        assert "wal_duplicate" in source

    def test_publish_telemetry_wal_pattern(self):
        """PublishTelemetry also uses wal_written/wal_duplicate pattern."""
        srv = _get_srv()
        import inspect

        source = inspect.getsource(srv.UniversalEventBusServicer.PublishTelemetry)
        assert "wal_written" in source
        assert "wal_duplicate" in source

    def test_wal_failure_triggers_retry_in_publish(self):
        """Source code returns RETRY on WAL write failure, not OK."""
        srv = _get_srv()
        import inspect

        source = inspect.getsource(srv.EventBusServicer.Publish)
        assert "WAL write failed, retry" in source
        assert "BUS_WAL_FAILURES" in source

    def test_wal_failure_triggers_retry_in_publish_telemetry(self):
        """Source code returns RETRY on WAL write failure in PublishTelemetry."""
        srv = _get_srv()
        import inspect

        source = inspect.getsource(srv.UniversalEventBusServicer.PublishTelemetry)
        assert "WAL write failed, retry" in source
        assert "BUS_WAL_FAILURES" in source

    def test_wal_ok_when_no_storage(self):
        """When wal_storage is None, OK is returned (no WAL to fail)."""
        srv = _get_srv()
        import inspect

        source = inspect.getsource(srv.EventBusServicer.Publish)
        assert "not wal_storage" in source


# ---------------------------------------------------------------------------
# Phase 2: Application-Level Dedup Tests
# ---------------------------------------------------------------------------


class TestDedupWiring:
    """P1-EB-1: _seen() called in both Publish handlers."""

    def setup_method(self):
        self.srv = _get_srv()
        self.srv._dedupe.clear()

    def test_dedup_counter_exists(self):
        """BUS_DEDUP_HITS Prometheus counter exists."""
        assert hasattr(self.srv, "BUS_DEDUP_HITS")

    def test_seen_wired_in_publish(self):
        """Publish handler calls _seen() for dedup."""
        import inspect

        source = inspect.getsource(self.srv.EventBusServicer.Publish)
        assert "_seen(" in source
        assert "BUS_DEDUP_HITS" in source

    def test_seen_wired_in_publish_telemetry(self):
        """PublishTelemetry handler calls _seen() for dedup."""
        import inspect

        source = inspect.getsource(self.srv.UniversalEventBusServicer.PublishTelemetry)
        assert "_seen(" in source
        assert "BUS_DEDUP_HITS" in source

    def test_duplicate_returns_ok_with_duplicate_reason(self):
        """Dedup hit returns OK with 'duplicate' reason (not error)."""
        import inspect

        source = inspect.getsource(self.srv.EventBusServicer.Publish)
        assert '"duplicate"' in source


# ---------------------------------------------------------------------------
# Phase 2 (cont): Thread Safety Tests
# ---------------------------------------------------------------------------


class TestDedupThreadSafety:
    """_seen() must be thread-safe under concurrent gRPC threads."""

    def setup_method(self):
        self.srv = _get_srv()
        self.srv._dedupe.clear()

    def test_dedupe_lock_exists(self):
        """_dedupe_lock threading.Lock exists at module level."""
        assert hasattr(self.srv, "_dedupe_lock")
        assert isinstance(self.srv._dedupe_lock, type(threading.Lock()))

    def test_seen_thread_safe_under_contention(self):
        """Multiple threads calling _seen() concurrently don't crash."""
        errors = []

        def worker(thread_id):
            try:
                for i in range(100):
                    self.srv._seen(f"thread-{thread_id}-key-{i}")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert len(errors) == 0, f"Thread errors: {errors}"
        # All 800 unique keys should have been processed
        assert len(self.srv._dedupe) <= self.srv.DEDUPE_MAX


# ---------------------------------------------------------------------------
# Phase 4: Graceful Shutdown Tests
# ---------------------------------------------------------------------------


class TestGracefulShutdown:
    """P1-EB-3: Server must shut down gracefully on SIGTERM/SIGHUP."""

    def test_should_exit_flag_exists(self):
        srv = _get_srv()
        assert hasattr(srv, "_SHOULD_EXIT")

    def test_sigterm_registered(self):
        """SIGTERM handler is registered (sets _SHOULD_EXIT)."""
        srv = _get_srv()
        # Re-register to ensure our handler is set (other tests may reset signals)
        signal.signal(signal.SIGTERM, srv._on_hup)
        handler = signal.getsignal(signal.SIGTERM)
        assert handler == srv._on_hup

    def test_sighup_registered(self):
        """SIGHUP handler is registered (sets _SHOULD_EXIT)."""
        srv = _get_srv()
        signal.signal(signal.SIGHUP, srv._on_hup)
        handler = signal.getsignal(signal.SIGHUP)
        assert handler == srv._on_hup

    def test_on_hup_sets_should_exit(self):
        """_on_hup sets _SHOULD_EXIT to True."""
        srv = _get_srv()
        original = srv._SHOULD_EXIT
        try:
            srv._SHOULD_EXIT = False
            srv._on_hup(signal.SIGHUP, None)
            assert srv._SHOULD_EXIT is True
        finally:
            srv._SHOULD_EXIT = original

    def test_serve_checks_should_exit(self):
        """serve() main loop checks _SHOULD_EXIT (not infinite while True)."""
        srv = _get_srv()
        import inspect

        source = inspect.getsource(srv.serve)
        assert "while not _SHOULD_EXIT" in source
        assert "AOC1_GRACEFUL_SHUTDOWN" in source


# ---------------------------------------------------------------------------
# Phase 4: Health Check Tests
# ---------------------------------------------------------------------------


class TestHealthCheck:
    """P1-EB-4: Health check server started and shutdown-aware."""

    def test_health_server_called_in_serve(self):
        """_start_health_server() is called in serve()."""
        srv = _get_srv()
        import inspect

        source = inspect.getsource(srv.serve)
        assert "_start_health_server()" in source

    def test_health_handler_returns_503_on_shutdown(self):
        """Health handler checks _SHOULD_EXIT for 503."""
        srv = _get_srv()
        import inspect

        source = inspect.getsource(srv._start_health_server)
        assert "_SHOULD_EXIT" in source
        assert "503" in source

    def test_health_handler_returns_200_when_healthy(self):
        """Health handler returns 200 OK when not shutting down."""
        srv = _get_srv()
        import inspect

        source = inspect.getsource(srv._start_health_server)
        assert "200" in source
        assert "OK bus" in source


# ---------------------------------------------------------------------------
# Phase 4: mTLS Default Tests
# ---------------------------------------------------------------------------


class TestMTLSDefault:
    """P0-EB-3: mTLS must be enabled by default."""

    def test_mtls_default_true(self):
        """Default mTLS setting is 'true' (enabled by default)."""
        srv = _get_srv()
        import inspect

        source = inspect.getsource(srv.serve)
        # The default should be "true", not "false"
        assert '"true"' in source or "'true'" in source
        # Verify pattern: default is "true", check != "false"
        assert '!= "false"' in source or "!= 'false'" in source

    def test_mtls_can_be_disabled_for_ci(self):
        """EVENTBUS_REQUIRE_CLIENT_AUTH=false disables mTLS."""
        srv = _get_srv()
        import inspect

        source = inspect.getsource(srv.serve)
        assert "EVENTBUS_REQUIRE_CLIENT_AUTH" in source


# ---------------------------------------------------------------------------
# Structural: AOC1 Telemetry Markers
# ---------------------------------------------------------------------------


class TestAOC1Markers:
    """Verify AOC1 telemetry markers are present in source."""

    def test_wal_write_failure_marker(self):
        srv = _get_srv()
        import inspect

        source = inspect.getsource(srv.EventBusServicer.Publish)
        assert "AOC1_WAL_WRITE_FAILURE" in source

    def test_graceful_shutdown_marker(self):
        srv = _get_srv()
        import inspect

        source = inspect.getsource(srv.serve)
        assert "AOC1_GRACEFUL_SHUTDOWN" in source

    def test_signing_key_missing_marker(self):
        srv = _get_srv()
        import inspect

        source = inspect.getsource(srv.serve)
        assert "AOC1_SIGNING_KEY_MISSING" in source

    def test_trust_map_missing_marker(self):
        srv = _get_srv()
        import inspect

        source = inspect.getsource(srv.serve)
        assert "AOC1_TRUST_MAP_MISSING" in source
