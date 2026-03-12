"""Comprehensive unit tests for EventBus server business logic.

Targets the UNTESTED methods and error paths in amoskys/eventbus/server.py
to significantly increase coverage beyond the existing test_eventbus_core.py
and test_eventbus_hardened.py suites.

Covers:
    - _seen() dedup cache: TTL expiry edge cases, max-size eviction ordering
    - _verify_envelope_signature() for UniversalEnvelope: all branches
    - _verify_legacy_envelope_signature() for legacy Envelope: all branches
    - _flow_from_envelope(): flow field, payload fallback, empty envelope
    - _ack_with_status / _ack_ok / _ack_retry / _ack_invalid / _ack_err builders
    - _sizeof_env: valid/invalid/exception paths
    - _peer_cn_from_context: CN extraction, SAN fallback, missing auth
    - _inc_inflight / _dec_inflight: counter management, floor-at-zero
    - set_overload_setting / is_overloaded: all mode branches
    - _on_hup signal handler
    - EventBusServicer.Publish: overload, size limit, dedup, inflight cap,
      flow extraction, WAL paths, ValueError, general exception
    - EventBusServicer.Subscribe: UNIMPLEMENTED abort
    - UniversalEventBusServicer.PublishTelemetry: overload, size, sig, dedup,
      inflight, device_telemetry/process/flow/empty, WAL, exceptions
    - UniversalEventBusServicer unimplemented RPCs

All gRPC infrastructure is mocked. No real server or network needed.
"""

import sqlite3
import threading
import time
from collections import OrderedDict
from unittest.mock import MagicMock, PropertyMock, patch

import grpc
import pytest

import amoskys.eventbus.server as srv
from amoskys.proto import messaging_schema_pb2 as pb
from amoskys.proto import universal_telemetry_pb2 as tpb

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _reset_server_state():
    """Reset all mutable module-level state in the server module."""
    srv._dedupe.clear()
    srv._inflight = 0
    srv._SHOULD_EXIT = False
    srv._OVERLOAD = None


def _mock_context():
    """Return a MagicMock gRPC context suitable for servicer methods."""
    ctx = MagicMock(spec=["abort", "auth_context", "set_code", "set_details"])
    ctx.auth_context.return_value = {}
    # Make abort raise an exception so Subscribe tests can catch it
    ctx.abort.side_effect = grpc.RpcError()
    return ctx


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def clean_state():
    """Ensure clean module state before and after every test."""
    saved = {
        "OVERLOAD": srv._OVERLOAD,
        "SHOULD_EXIT": srv._SHOULD_EXIT,
        "inflight": srv._inflight,
        "REQUIRE_SIGNATURES": srv.REQUIRE_SIGNATURES,
        "AGENT_PUBKEY": srv.AGENT_PUBKEY,
        "MAX_ENV_BYTES": srv.MAX_ENV_BYTES,
        "BUS_MAX_INFLIGHT": srv.BUS_MAX_INFLIGHT,
        "DEDUPE_TTL_SEC": srv.DEDUPE_TTL_SEC,
        "DEDUPE_MAX": srv.DEDUPE_MAX,
        "wal_storage": srv.wal_storage,
    }
    _reset_server_state()
    yield
    # Restore all saved state
    srv._OVERLOAD = saved["OVERLOAD"]
    srv._SHOULD_EXIT = saved["SHOULD_EXIT"]
    srv._inflight = saved["inflight"]
    srv.REQUIRE_SIGNATURES = saved["REQUIRE_SIGNATURES"]
    srv.AGENT_PUBKEY = saved["AGENT_PUBKEY"]
    srv.MAX_ENV_BYTES = saved["MAX_ENV_BYTES"]
    srv.BUS_MAX_INFLIGHT = saved["BUS_MAX_INFLIGHT"]
    srv.DEDUPE_TTL_SEC = saved["DEDUPE_TTL_SEC"]
    srv.DEDUPE_MAX = saved["DEDUPE_MAX"]
    srv.wal_storage = saved["wal_storage"]
    srv._dedupe.clear()


# ===================================================================
# 1. _seen() dedup cache -- additional edge-case coverage
# ===================================================================


class TestSeenDedupExtended:
    """Edge cases beyond what test_eventbus_core.py covers."""

    def test_seen_returns_false_for_new_key(self):
        assert srv._seen("brand-new") is False

    def test_seen_returns_true_for_duplicate(self):
        srv._seen("dup-key")
        assert srv._seen("dup-key") is True

    def test_ttl_zero_expires_immediately(self):
        srv.DEDUPE_TTL_SEC = 0
        srv._seen("old")
        time.sleep(0.02)
        # Next insertion should evict "old" because TTL expired
        assert srv._seen("fresh") is False
        assert "old" not in srv._dedupe

    def test_max_one_entry_evicts_on_every_insert(self):
        srv.DEDUPE_MAX = 1
        srv._seen("first")
        srv._seen("second")
        assert len(srv._dedupe) == 1
        assert "second" in srv._dedupe
        assert "first" not in srv._dedupe

    def test_move_to_end_on_duplicate_hit(self):
        srv._seen("x")
        srv._seen("y")
        srv._seen("z")
        # Re-access "x" -- it should move to the end
        srv._seen("x")
        keys = list(srv._dedupe.keys())
        assert keys[-1] == "x"
        assert keys[0] == "y"

    def test_concurrent_inserts_no_crash(self):
        """Many threads inserting concurrently must not corrupt the cache."""
        errors = []

        def worker(tid):
            try:
                for i in range(200):
                    srv._seen(f"t{tid}-{i}")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert errors == [], f"Thread errors: {errors}"

    def test_empty_string_key(self):
        assert srv._seen("") is False
        assert srv._seen("") is True


# ===================================================================
# 2. _verify_envelope_signature (UniversalEnvelope)
# ===================================================================


class TestVerifyEnvelopeSignature:
    """All branches of _verify_envelope_signature()."""

    def test_no_sig_no_algorithm_not_required(self):
        srv.REQUIRE_SIGNATURES = False
        env = tpb.UniversalEnvelope()
        valid, err = srv._verify_envelope_signature(env)
        assert valid is True
        assert err is None

    def test_no_sig_no_algorithm_required(self):
        srv.REQUIRE_SIGNATURES = True
        env = tpb.UniversalEnvelope()
        valid, err = srv._verify_envelope_signature(env)
        assert valid is False
        assert "required" in err.lower()

    def test_sig_present_no_algorithm_incomplete(self):
        srv.REQUIRE_SIGNATURES = False
        env = tpb.UniversalEnvelope(sig=b"some-bytes")
        # signing_algorithm not set -> incomplete
        valid, err = srv._verify_envelope_signature(env)
        assert valid is False
        assert "incomplete" in err.lower()

    def test_algorithm_present_no_sig_incomplete(self):
        srv.REQUIRE_SIGNATURES = False
        env = tpb.UniversalEnvelope(signing_algorithm="Ed25519")
        # sig not set -> incomplete
        valid, err = srv._verify_envelope_signature(env)
        assert valid is False
        assert "incomplete" in err.lower()

    def test_unsupported_algorithm(self):
        srv.REQUIRE_SIGNATURES = False
        env = tpb.UniversalEnvelope(sig=b"data", signing_algorithm="RSA-2048")
        valid, err = srv._verify_envelope_signature(env)
        assert valid is False
        assert "Unsupported" in err

    def test_no_pubkey_configured(self):
        srv.AGENT_PUBKEY = None
        env = tpb.UniversalEnvelope(sig=b"data", signing_algorithm="Ed25519")
        valid, err = srv._verify_envelope_signature(env)
        assert valid is False
        assert "No public key" in err

    def test_invalid_signature_rejected(self):
        """Signature that fails verify() returns False."""
        mock_key = MagicMock()
        srv.AGENT_PUBKEY = mock_key
        with patch("amoskys.eventbus.server.verify", return_value=False):
            env = tpb.UniversalEnvelope(sig=b"bad-sig", signing_algorithm="Ed25519")
            valid, err = srv._verify_envelope_signature(env)
            assert valid is False
            assert "failed" in err.lower()

    def test_valid_signature_accepted(self):
        """Signature that passes verify() returns True."""
        mock_key = MagicMock()
        srv.AGENT_PUBKEY = mock_key
        with patch("amoskys.eventbus.server.verify", return_value=True):
            env = tpb.UniversalEnvelope(sig=b"good-sig", signing_algorithm="Ed25519")
            valid, err = srv._verify_envelope_signature(env)
            assert valid is True
            assert err is None


# ===================================================================
# 3. _verify_legacy_envelope_signature (legacy Envelope)
# ===================================================================


class TestVerifyLegacyEnvelopeSignature:
    """All branches of _verify_legacy_envelope_signature()."""

    def test_no_sig_not_required(self):
        srv.REQUIRE_SIGNATURES = False
        env = pb.Envelope()
        valid, err = srv._verify_legacy_envelope_signature(env)
        assert valid is True
        assert err is None

    def test_no_sig_required(self):
        srv.REQUIRE_SIGNATURES = True
        env = pb.Envelope()
        valid, err = srv._verify_legacy_envelope_signature(env)
        assert valid is False
        assert "required" in err.lower()

    def test_sig_but_no_pubkey(self):
        srv.AGENT_PUBKEY = None
        srv.REQUIRE_SIGNATURES = False
        env = pb.Envelope(sig=b"signature-data-here")
        valid, err = srv._verify_legacy_envelope_signature(env)
        assert valid is False
        assert "No public key" in err

    def test_sig_verify_fails(self):
        mock_key = MagicMock()
        srv.AGENT_PUBKEY = mock_key
        with patch("amoskys.eventbus.server.verify", return_value=False):
            env = pb.Envelope(sig=b"bad-sig")
            valid, err = srv._verify_legacy_envelope_signature(env)
            assert valid is False
            assert "failed" in err.lower()

    def test_sig_verify_succeeds(self):
        mock_key = MagicMock()
        srv.AGENT_PUBKEY = mock_key
        with patch("amoskys.eventbus.server.verify", return_value=True):
            env = pb.Envelope(sig=b"good-sig")
            valid, err = srv._verify_legacy_envelope_signature(env)
            assert valid is True
            assert err is None

    def test_return_type_is_tuple(self):
        env = pb.Envelope()
        result = srv._verify_legacy_envelope_signature(env)
        assert isinstance(result, tuple)
        assert len(result) == 2


# ===================================================================
# 4. _flow_from_envelope
# ===================================================================


class TestFlowFromEnvelope:
    """Test extraction of FlowEvent from Envelope."""

    def test_flow_field_populated(self):
        env = pb.Envelope()
        env.flow.src_ip = "1.2.3.4"
        env.flow.dst_ip = "5.6.7.8"
        flow = srv._flow_from_envelope(env)
        assert flow.src_ip == "1.2.3.4"
        assert flow.dst_ip == "5.6.7.8"

    def test_payload_fallback(self):
        flow_msg = pb.FlowEvent(src_ip="10.0.0.1", dst_ip="10.0.0.2")
        env = pb.Envelope(payload=flow_msg.SerializeToString())
        flow = srv._flow_from_envelope(env)
        assert flow.src_ip == "10.0.0.1"
        assert flow.dst_ip == "10.0.0.2"

    def test_empty_envelope_raises_value_error(self):
        env = pb.Envelope()
        with pytest.raises(ValueError, match="Envelope missing flow/payload"):
            srv._flow_from_envelope(env)

    def test_flow_with_bytes_tx(self):
        env = pb.Envelope()
        env.flow.src_ip = "a"
        env.flow.dst_ip = "b"
        env.flow.bytes_tx = 42
        flow = srv._flow_from_envelope(env)
        assert flow.bytes_tx == 42


# ===================================================================
# 5. Ack Builders
# ===================================================================


class TestAckBuilders:
    """Test all PublishAck builder functions."""

    def test_ack_with_status_ok(self):
        ack = srv._ack_with_status("OK", "success")
        assert ack.status == pb.PublishAck.Status.OK
        assert ack.reason == "success"

    def test_ack_with_status_retry(self):
        ack = srv._ack_with_status("RETRY", "please wait")
        assert ack.status == pb.PublishAck.Status.RETRY
        assert ack.reason == "please wait"

    def test_ack_with_status_invalid(self):
        ack = srv._ack_with_status("INVALID", "bad data")
        assert ack.status == pb.PublishAck.Status.INVALID
        assert ack.reason == "bad data"

    def test_ack_with_status_unauthorized(self):
        ack = srv._ack_with_status("UNAUTHORIZED", "denied")
        assert ack.status == pb.PublishAck.Status.UNAUTHORIZED
        assert ack.reason == "denied"

    def test_ack_with_status_unknown_defaults_invalid(self):
        ack = srv._ack_with_status("FOOBAR", "unknown status")
        assert ack.status == pb.PublishAck.Status.INVALID
        assert ack.reason == "unknown status"

    def test_ack_with_status_empty_reason(self):
        ack = srv._ack_with_status("OK")
        assert ack.reason == ""

    def test_ack_ok_default(self):
        ack = srv._ack_ok()
        assert ack.status == pb.PublishAck.Status.OK
        assert ack.reason == "OK"

    def test_ack_ok_custom(self):
        ack = srv._ack_ok("accepted")
        assert ack.reason == "accepted"

    def test_ack_retry_default(self):
        ack = srv._ack_retry()
        assert ack.status == pb.PublishAck.Status.RETRY
        assert ack.reason == "RETRY"
        assert ack.backoff_hint_ms == 1000

    def test_ack_retry_custom(self):
        ack = srv._ack_retry("overloaded", 5000)
        assert ack.reason == "overloaded"
        assert ack.backoff_hint_ms == 5000

    def test_ack_invalid_default(self):
        ack = srv._ack_invalid()
        assert ack.status == pb.PublishAck.Status.INVALID
        assert ack.reason == "INVALID"

    def test_ack_invalid_custom(self):
        ack = srv._ack_invalid("too big")
        assert ack.reason == "too big"

    def test_ack_err_default(self):
        ack = srv._ack_err()
        assert ack.reason == "ERROR"

    def test_ack_err_custom(self):
        ack = srv._ack_err("internal failure")
        assert ack.reason == "internal failure"


# ===================================================================
# 6. _sizeof_env
# ===================================================================


class TestSizeofEnv:
    """Test envelope size measurement."""

    def test_valid_envelope_size(self):
        env = pb.Envelope(version="1.0", idempotency_key="key-123")
        size = srv._sizeof_env(env)
        assert size > 0

    def test_empty_envelope_size_zero(self):
        env = pb.Envelope()
        size = srv._sizeof_env(env)
        assert size == 0  # all defaults -> 0 bytes

    def test_bad_object_returns_zero(self):
        assert srv._sizeof_env("not-a-protobuf") == 0

    def test_none_returns_zero(self):
        assert srv._sizeof_env(None) == 0

    def test_envelope_with_flow_has_positive_size(self):
        env = pb.Envelope()
        env.flow.src_ip = "192.168.1.1"
        env.flow.dst_ip = "10.0.0.1"
        size = srv._sizeof_env(env)
        assert size > 0


# ===================================================================
# 7. _peer_cn_from_context
# ===================================================================


class TestPeerCnFromContext:
    """Test CN extraction from gRPC auth context."""

    def test_x509_common_name(self):
        ctx = MagicMock()
        ctx.auth_context.return_value = {
            "x509_common_name": [b"agent-1.example.com"],
        }
        cn = srv._peer_cn_from_context(ctx)
        assert cn == "agent-1.example.com"

    def test_san_fallback(self):
        ctx = MagicMock()
        ctx.auth_context.return_value = {
            "x509_subject_alternative_name": [b"agent-san.example.com"],
        }
        cn = srv._peer_cn_from_context(ctx)
        assert cn == "agent-san.example.com"

    def test_cn_preferred_over_san(self):
        ctx = MagicMock()
        # Items order matters: auth_context is a dict so we iterate it;
        # the code checks x509_common_name first in a separate loop.
        ctx.auth_context.return_value = {
            "x509_common_name": [b"cn-value"],
            "x509_subject_alternative_name": [b"san-value"],
        }
        cn = srv._peer_cn_from_context(ctx)
        assert cn == "cn-value"

    def test_empty_auth_context(self):
        ctx = MagicMock()
        ctx.auth_context.return_value = {}
        cn = srv._peer_cn_from_context(ctx)
        assert cn is None

    def test_empty_cn_value(self):
        ctx = MagicMock()
        ctx.auth_context.return_value = {"x509_common_name": [b""]}
        cn = srv._peer_cn_from_context(ctx)
        # Empty bytes -> falsy, so falls through
        assert cn is None

    def test_cn_list_empty(self):
        ctx = MagicMock()
        ctx.auth_context.return_value = {"x509_common_name": []}
        cn = srv._peer_cn_from_context(ctx)
        assert cn is None

    def test_cn_none_value(self):
        ctx = MagicMock()
        ctx.auth_context.return_value = {"x509_common_name": [None]}
        cn = srv._peer_cn_from_context(ctx)
        # None is falsy
        assert cn is None


# ===================================================================
# 8. _inc_inflight / _dec_inflight
# ===================================================================


class TestInflightCounter:
    """Test atomic in-flight request counter."""

    def test_inc_returns_incremented_value(self):
        srv._inflight = 0
        assert srv._inc_inflight() == 1
        assert srv._inc_inflight() == 2
        assert srv._inc_inflight() == 3

    def test_dec_decrements(self):
        srv._inflight = 5
        srv._dec_inflight()
        assert srv._inflight == 4

    def test_dec_floors_at_zero(self):
        srv._inflight = 0
        srv._dec_inflight()
        assert srv._inflight == 0

    def test_dec_from_one_goes_to_zero(self):
        srv._inflight = 1
        srv._dec_inflight()
        assert srv._inflight == 0

    def test_inc_dec_pair_returns_to_original(self):
        srv._inflight = 10
        srv._inc_inflight()
        srv._dec_inflight()
        assert srv._inflight == 10


# ===================================================================
# 9. Overload control (extended)
# ===================================================================


class TestOverloadControlExtended:
    """Extended overload setting/checking tests."""

    def test_is_overloaded_none_is_false(self):
        srv._OVERLOAD = None
        assert srv.is_overloaded() is False

    def test_is_overloaded_true(self):
        srv._OVERLOAD = True
        assert srv.is_overloaded() is True

    def test_is_overloaded_false(self):
        srv._OVERLOAD = False
        assert srv.is_overloaded() is False

    def test_set_overload_on(self):
        srv.set_overload_setting("on")
        assert srv.BUS_OVERLOAD_SETTING == "on"
        assert srv.BUS_OVERLOAD_SOURCE == "cli"

    def test_set_overload_off(self):
        srv.set_overload_setting("off")
        assert srv.BUS_OVERLOAD_SETTING == "off"
        assert srv.BUS_OVERLOAD_SOURCE == "cli"

    def test_set_overload_auto(self):
        srv.set_overload_setting("auto")
        assert srv.BUS_OVERLOAD_SETTING == "auto"

    def test_set_overload_none_resets_to_auto_env(self):
        srv.set_overload_setting(None)
        assert srv.BUS_OVERLOAD_SETTING == "auto"
        assert srv.BUS_OVERLOAD_SOURCE == "env"

    def test_set_overload_invalid_string(self):
        srv.set_overload_setting("banana")
        assert srv.BUS_OVERLOAD_SETTING == "auto"
        assert srv.BUS_OVERLOAD_SOURCE == "cli"


# ===================================================================
# 10. _on_hup signal handler
# ===================================================================


class TestOnHup:
    def test_sets_should_exit(self):
        srv._SHOULD_EXIT = False
        srv._on_hup(None, None)
        assert srv._SHOULD_EXIT is True

    def test_idempotent(self):
        srv._SHOULD_EXIT = True
        srv._on_hup(None, None)
        assert srv._SHOULD_EXIT is True


# ===================================================================
# 11. EventBusServicer.Publish -- full path coverage
# ===================================================================


class TestEventBusServicerPublish:
    """Test the legacy Publish RPC handler with mocked context."""

    def setup_method(self):
        self.servicer = srv.EventBusServicer()
        self.ctx = _mock_context()
        srv._OVERLOAD = False
        srv.REQUIRE_SIGNATURES = False
        srv.AGENT_PUBKEY = None
        srv.wal_storage = None  # No WAL -> OK path

    # -- Overload path --
    def test_overloaded_returns_retry(self):
        srv._OVERLOAD = True
        env = pb.Envelope()
        env.flow.src_ip = "1.1.1.1"
        env.flow.dst_ip = "2.2.2.2"
        ack = self.servicer.Publish(env, self.ctx)
        assert ack.status == pb.PublishAck.Status.RETRY
        assert "overloaded" in ack.reason.lower()
        assert ack.backoff_hint_ms == 2000

    # -- Size check --
    def test_oversized_envelope_returns_invalid(self):
        srv.MAX_ENV_BYTES = 10  # Very small limit
        env = pb.Envelope(
            version="1.0",
            idempotency_key="test-key-long-enough-to-exceed-10-bytes",
        )
        env.flow.src_ip = "very-long-source-ip-address"
        ack = self.servicer.Publish(env, self.ctx)
        assert ack.status == pb.PublishAck.Status.INVALID
        assert "too large" in ack.reason.lower()

    # -- Dedup path --
    def test_duplicate_idempotency_key_returns_ok_duplicate(self):
        env = pb.Envelope(idempotency_key="dup-1")
        env.flow.src_ip = "a"
        env.flow.dst_ip = "b"
        ack1 = self.servicer.Publish(env, self.ctx)
        assert ack1.status == pb.PublishAck.Status.OK

        ack2 = self.servicer.Publish(env, self.ctx)
        assert ack2.status == pb.PublishAck.Status.OK
        assert ack2.reason == "duplicate"

    # -- Inflight limit --
    def test_inflight_limit_returns_retry(self):
        srv.BUS_MAX_INFLIGHT = 0  # Any request exceeds limit
        env = pb.Envelope(idempotency_key="inflight-test")
        env.flow.src_ip = "x"
        env.flow.dst_ip = "y"
        ack = self.servicer.Publish(env, self.ctx)
        assert ack.status == pb.PublishAck.Status.RETRY
        assert "capacity" in ack.reason.lower()

    # -- Happy path (no WAL) --
    def test_valid_envelope_returns_ok(self):
        env = pb.Envelope(idempotency_key="happy-path")
        env.flow.src_ip = "10.0.0.1"
        env.flow.dst_ip = "10.0.0.2"
        env.flow.bytes_tx = 100
        ack = self.servicer.Publish(env, self.ctx)
        assert ack.status == pb.PublishAck.Status.OK
        assert ack.reason == "accepted"

    # -- Missing flow/payload raises ValueError -> INVALID --
    def test_missing_flow_returns_invalid(self):
        env = pb.Envelope(idempotency_key="no-flow")
        ack = self.servicer.Publish(env, self.ctx)
        assert ack.status == pb.PublishAck.Status.INVALID
        assert "missing" in ack.reason.lower() or "flow" in ack.reason.lower()

    # -- Signature verification failure path --
    def test_sig_verification_failure_returns_invalid(self):
        srv.AGENT_PUBKEY = None
        env = pb.Envelope(idempotency_key="sig-fail", sig=b"fake-sig")
        env.flow.src_ip = "a"
        env.flow.dst_ip = "b"
        ack = self.servicer.Publish(env, self.ctx)
        assert ack.status == pb.PublishAck.Status.INVALID
        assert "signature" in ack.reason.lower()

    # -- General exception -> ERROR --
    def test_general_exception_returns_error(self):
        env = pb.Envelope(idempotency_key="exception-test")
        env.flow.src_ip = "a"
        env.flow.dst_ip = "b"
        # Patch _flow_from_envelope to raise a general Exception
        with patch.object(srv, "_flow_from_envelope", side_effect=RuntimeError("boom")):
            ack = self.servicer.Publish(env, self.ctx)
            # _ack_err defaults to INVALID status since ERROR is not a valid enum
            assert ack.reason == "boom"

    # -- Inflight counter always decremented --
    def test_inflight_decremented_after_success(self):
        srv._inflight = 0
        env = pb.Envelope(idempotency_key="dec-test")
        env.flow.src_ip = "a"
        env.flow.dst_ip = "b"
        self.servicer.Publish(env, self.ctx)
        assert srv._inflight == 0

    # -- Payload fallback path --
    def test_payload_fallback_works(self):
        flow = pb.FlowEvent(src_ip="10.1.1.1", dst_ip="10.2.2.2", bytes_tx=50)
        env = pb.Envelope(
            idempotency_key="payload-test",
            payload=flow.SerializeToString(),
        )
        ack = self.servicer.Publish(env, self.ctx)
        assert ack.status == pb.PublishAck.Status.OK

    # -- idem field fallback --
    def test_fallback_idem_field(self):
        """When neither idempotency_key nor idem, uses ts_ns fallback."""
        env = pb.Envelope()
        env.flow.src_ip = "a"
        env.flow.dst_ip = "b"
        env.ts_ns = 12345
        # No idempotency_key set -- falls to "unknown_{ts_ns}"
        ack = self.servicer.Publish(env, self.ctx)
        assert ack.status == pb.PublishAck.Status.OK


# ===================================================================
# 12. EventBusServicer.Subscribe
# ===================================================================


class TestEventBusServicerSubscribe:
    def test_subscribe_aborts_unimplemented(self):
        servicer = srv.EventBusServicer()
        ctx = _mock_context()
        with pytest.raises(grpc.RpcError):
            servicer.Subscribe(MagicMock(), ctx)
        ctx.abort.assert_called_once_with(
            grpc.StatusCode.UNIMPLEMENTED, "Subscribe not supported"
        )


# ===================================================================
# 13. UniversalEventBusServicer.PublishTelemetry
# ===================================================================


class TestUniversalPublishTelemetry:
    """Test the universal PublishTelemetry RPC handler."""

    def setup_method(self):
        self.servicer = srv.UniversalEventBusServicer()
        self.ctx = _mock_context()
        srv._OVERLOAD = False
        srv.REQUIRE_SIGNATURES = False
        srv.AGENT_PUBKEY = None
        srv.wal_storage = None

    # -- Overload --
    def test_overloaded_returns_retry(self):
        srv._OVERLOAD = True
        env = tpb.UniversalEnvelope()
        ack = self.servicer.PublishTelemetry(env, self.ctx)
        assert ack.status == tpb.UniversalAck.Status.RETRY
        assert "overloaded" in ack.reason.lower()
        assert ack.backoff_hint_ms == 2000

    # -- Size check --
    def test_oversized_returns_invalid(self):
        srv.MAX_ENV_BYTES = 1
        env = tpb.UniversalEnvelope(idempotency_key="big-envelope-key-exceeds-1-byte")
        ack = self.servicer.PublishTelemetry(env, self.ctx)
        assert ack.status == tpb.UniversalAck.Status.INVALID
        assert "too large" in ack.reason.lower()

    # -- Signature failure --
    def test_sig_failure_returns_security_violation(self):
        srv.REQUIRE_SIGNATURES = True
        env = tpb.UniversalEnvelope(idempotency_key="sig-test")
        ack = self.servicer.PublishTelemetry(env, self.ctx)
        assert ack.status == tpb.UniversalAck.Status.SECURITY_VIOLATION
        assert "signature" in ack.reason.lower()

    # -- Dedup --
    def test_duplicate_returns_ok_duplicate(self):
        env = tpb.UniversalEnvelope(idempotency_key="telemetry-dup")
        env.device_telemetry.device_id = "dev-1"
        ack1 = self.servicer.PublishTelemetry(env, self.ctx)
        assert ack1.status == tpb.UniversalAck.Status.OK

        ack2 = self.servicer.PublishTelemetry(env, self.ctx)
        assert ack2.status == tpb.UniversalAck.Status.OK
        assert ack2.reason == "duplicate"

    # -- Inflight limit --
    def test_inflight_limit_returns_retry(self):
        srv.BUS_MAX_INFLIGHT = 0
        env = tpb.UniversalEnvelope(idempotency_key="inflight-tel")
        env.device_telemetry.device_id = "dev-1"
        ack = self.servicer.PublishTelemetry(env, self.ctx)
        assert ack.status == tpb.UniversalAck.Status.RETRY
        assert "capacity" in ack.reason.lower()

    # -- device_telemetry processing --
    def test_device_telemetry_accepted(self):
        env = tpb.UniversalEnvelope(idempotency_key="dev-tel")
        env.device_telemetry.device_id = "switch-01"
        env.device_telemetry.device_type = "NETWORK"
        ack = self.servicer.PublishTelemetry(env, self.ctx)
        assert ack.status == tpb.UniversalAck.Status.OK
        assert ack.reason == "accepted"

    # -- process event processing --
    def test_process_event_accepted(self):
        env = tpb.UniversalEnvelope(idempotency_key="proc-ev")
        env.process.pid = 1234
        env.process.exe = "/usr/bin/test"
        ack = self.servicer.PublishTelemetry(env, self.ctx)
        assert ack.status == tpb.UniversalAck.Status.OK

    # -- flow event processing --
    def test_flow_event_accepted(self):
        env = tpb.UniversalEnvelope(idempotency_key="flow-ev")
        env.flow.src_ip = "1.2.3.4"
        env.flow.dst_ip = "5.6.7.8"
        ack = self.servicer.PublishTelemetry(env, self.ctx)
        assert ack.status == tpb.UniversalAck.Status.OK

    # -- empty envelope (contract rejects — no payload_kind or event_type) --
    def test_empty_envelope_rejected_by_contract(self):
        env = tpb.UniversalEnvelope(idempotency_key="empty-ev")
        ack = self.servicer.PublishTelemetry(env, self.ctx)
        assert ack.status == tpb.UniversalAck.Status.INVALID
        assert "Contract violation" in ack.reason

    # -- General exception --
    def test_exception_returns_processing_error(self):
        env = tpb.UniversalEnvelope(idempotency_key="exc-test")
        env.device_telemetry.device_id = "dev-1"
        # Patch ByteSize to raise after size check passes
        with patch.object(srv, "_inc_inflight", side_effect=RuntimeError("crash")):
            ack = self.servicer.PublishTelemetry(env, self.ctx)
            assert ack.status == tpb.UniversalAck.Status.PROCESSING_ERROR
            assert "crash" in ack.reason

    # -- Idempotency key fallback --
    def test_no_idempotency_key_uses_ts_ns(self):
        env = tpb.UniversalEnvelope(ts_ns=999999)
        env.device_telemetry.device_id = "d"
        ack = self.servicer.PublishTelemetry(env, self.ctx)
        assert ack.status == tpb.UniversalAck.Status.OK
        # The dedup key should be "unknown_999999"
        assert "unknown_999999" in srv._dedupe

    # -- processed_timestamp_ns is set --
    def test_response_has_processed_timestamp(self):
        env = tpb.UniversalEnvelope(idempotency_key="ts-test")
        env.device_telemetry.device_id = "d"
        ack = self.servicer.PublishTelemetry(env, self.ctx)
        assert ack.processed_timestamp_ns > 0

    # -- events_accepted count --
    def test_events_accepted_is_one(self):
        env = tpb.UniversalEnvelope(idempotency_key="count-test")
        env.device_telemetry.device_id = "d"
        ack = self.servicer.PublishTelemetry(env, self.ctx)
        assert ack.events_accepted == 1


# ===================================================================
# 14. UniversalEventBusServicer unimplemented RPCs
# ===================================================================


class TestUniversalUnimplementedRPCs:
    """All unimplemented RPCs must abort with UNIMPLEMENTED."""

    def setup_method(self):
        self.servicer = srv.UniversalEventBusServicer()

    def _check_unimplemented(self, method_name, expected_msg):
        ctx = _mock_context()
        method = getattr(self.servicer, method_name)
        with pytest.raises(grpc.RpcError):
            method(MagicMock(), ctx)
        ctx.abort.assert_called_once_with(grpc.StatusCode.UNIMPLEMENTED, expected_msg)

    def test_publish_batch(self):
        self._check_unimplemented("PublishBatch", "PublishBatch not supported")

    def test_register_device(self):
        self._check_unimplemented("RegisterDevice", "RegisterDevice not supported")

    def test_update_device(self):
        self._check_unimplemented("UpdateDevice", "UpdateDevice not supported")

    def test_deregister_device(self):
        self._check_unimplemented("DeregisterDevice", "DeregisterDevice not supported")

    def test_get_health(self):
        self._check_unimplemented("GetHealth", "GetHealth not supported")

    def test_get_status(self):
        self._check_unimplemented("GetStatus", "GetStatus not supported")

    def test_get_metrics(self):
        self._check_unimplemented("GetMetrics", "GetMetrics not supported")


# ===================================================================
# 15. WAL integration paths in Publish
# ===================================================================


class TestPublishWALPaths:
    """Test WAL write success / failure / duplicate paths in Publish."""

    def setup_method(self):
        self.servicer = srv.EventBusServicer()
        self.ctx = _mock_context()
        srv._OVERLOAD = False
        srv.REQUIRE_SIGNATURES = False
        srv.AGENT_PUBKEY = None

    def test_wal_write_success(self):
        """When WAL write_raw succeeds, Publish returns OK."""
        mock_wal = MagicMock()
        mock_wal.write_raw.return_value = True
        srv.wal_storage = mock_wal

        env = pb.Envelope(idempotency_key="wal-ok", ts_ns=100)
        env.flow.src_ip = "a"
        env.flow.dst_ip = "b"
        ack = self.servicer.Publish(env, self.ctx)
        assert ack.status == pb.PublishAck.Status.OK
        assert ack.reason == "accepted"
        mock_wal.write_raw.assert_called_once()

    def test_wal_duplicate_returns_ok(self):
        """When WAL write_raw returns False (duplicate), returns OK."""
        mock_wal = MagicMock()
        mock_wal.write_raw.return_value = False
        srv.wal_storage = mock_wal

        env = pb.Envelope(idempotency_key="wal-dup", ts_ns=200)
        env.flow.src_ip = "a"
        env.flow.dst_ip = "b"
        ack = self.servicer.Publish(env, self.ctx)
        assert ack.status == pb.PublishAck.Status.OK

    def test_wal_general_failure_returns_retry(self):
        """When WAL write_raw raises an exception, returns RETRY."""
        mock_wal = MagicMock()
        mock_wal.write_raw.side_effect = RuntimeError("disk full")
        srv.wal_storage = mock_wal

        env = pb.Envelope(idempotency_key="wal-fail", ts_ns=300)
        env.flow.src_ip = "a"
        env.flow.dst_ip = "b"
        ack = self.servicer.Publish(env, self.ctx)
        assert ack.status == pb.PublishAck.Status.RETRY
        assert "WAL write failed" in ack.reason

    def test_no_wal_returns_ok(self):
        """When wal_storage is None, Publish returns OK without WAL."""
        srv.wal_storage = None
        env = pb.Envelope(idempotency_key="no-wal", ts_ns=400)
        env.flow.src_ip = "a"
        env.flow.dst_ip = "b"
        ack = self.servicer.Publish(env, self.ctx)
        assert ack.status == pb.PublishAck.Status.OK
        assert ack.reason == "accepted"


# ===================================================================
# 16. WAL integration paths in PublishTelemetry
# ===================================================================


class TestPublishTelemetryWALPaths:
    """Test WAL write success / failure / duplicate paths in PublishTelemetry."""

    def setup_method(self):
        self.servicer = srv.UniversalEventBusServicer()
        self.ctx = _mock_context()
        srv._OVERLOAD = False
        srv.REQUIRE_SIGNATURES = False
        srv.AGENT_PUBKEY = None

    def test_wal_write_success(self):
        mock_wal = MagicMock()
        mock_wal.write_raw.return_value = True
        srv.wal_storage = mock_wal

        env = tpb.UniversalEnvelope(idempotency_key="uwal-ok", ts_ns=100)
        env.device_telemetry.device_id = "d"
        ack = self.servicer.PublishTelemetry(env, self.ctx)
        assert ack.status == tpb.UniversalAck.Status.OK
        assert ack.reason == "accepted"
        mock_wal.write_raw.assert_called_once()

    def test_wal_duplicate_returns_ok(self):
        mock_wal = MagicMock()
        mock_wal.write_raw.return_value = False
        srv.wal_storage = mock_wal

        env = tpb.UniversalEnvelope(idempotency_key="uwal-dup", ts_ns=200)
        env.device_telemetry.device_id = "d"
        ack = self.servicer.PublishTelemetry(env, self.ctx)
        assert ack.status == tpb.UniversalAck.Status.OK

    def test_wal_failure_returns_retry(self):
        mock_wal = MagicMock()
        mock_wal.write_raw.side_effect = RuntimeError("disk error")
        srv.wal_storage = mock_wal

        env = tpb.UniversalEnvelope(idempotency_key="uwal-fail", ts_ns=300)
        env.device_telemetry.device_id = "d"
        ack = self.servicer.PublishTelemetry(env, self.ctx)
        assert ack.status == tpb.UniversalAck.Status.RETRY
        assert "WAL write failed" in ack.reason

    def test_no_wal_returns_ok(self):
        srv.wal_storage = None
        env = tpb.UniversalEnvelope(idempotency_key="uno-wal", ts_ns=400)
        env.device_telemetry.device_id = "d"
        ack = self.servicer.PublishTelemetry(env, self.ctx)
        assert ack.status == tpb.UniversalAck.Status.OK


# ===================================================================
# 17. Verify envelope signature with mock verify()
# ===================================================================


class TestVerifySignatureWithMockCrypto:
    """Integration-level tests using mock verify() for both envelope types."""

    def test_universal_valid_sig_passes(self):
        mock_key = MagicMock()
        srv.AGENT_PUBKEY = mock_key
        with patch("amoskys.eventbus.server.verify", return_value=True):
            env = tpb.UniversalEnvelope(
                sig=b"valid",
                signing_algorithm="Ed25519",
                idempotency_key="crypto-ok",
            )
            valid, err = srv._verify_envelope_signature(env)
            assert valid is True

    def test_universal_invalid_sig_fails(self):
        mock_key = MagicMock()
        srv.AGENT_PUBKEY = mock_key
        with patch("amoskys.eventbus.server.verify", return_value=False):
            env = tpb.UniversalEnvelope(
                sig=b"invalid",
                signing_algorithm="Ed25519",
            )
            valid, err = srv._verify_envelope_signature(env)
            assert valid is False

    def test_legacy_valid_sig_passes(self):
        mock_key = MagicMock()
        srv.AGENT_PUBKEY = mock_key
        with patch("amoskys.eventbus.server.verify", return_value=True):
            env = pb.Envelope(sig=b"valid")
            valid, err = srv._verify_legacy_envelope_signature(env)
            assert valid is True

    def test_legacy_invalid_sig_fails(self):
        mock_key = MagicMock()
        srv.AGENT_PUBKEY = mock_key
        with patch("amoskys.eventbus.server.verify", return_value=False):
            env = pb.Envelope(sig=b"invalid")
            valid, err = srv._verify_legacy_envelope_signature(env)
            assert valid is False


# ===================================================================
# 18. Publish end-to-end with signature verification enabled
# ===================================================================


class TestPublishWithSignatureVerification:
    """Test Publish when REQUIRE_SIGNATURES is True."""

    def setup_method(self):
        self.servicer = srv.EventBusServicer()
        self.ctx = _mock_context()
        srv._OVERLOAD = False
        srv.wal_storage = None

    def test_require_sig_unsigned_rejected(self):
        srv.REQUIRE_SIGNATURES = True
        env = pb.Envelope(idempotency_key="unsigned")
        env.flow.src_ip = "a"
        env.flow.dst_ip = "b"
        ack = self.servicer.Publish(env, self.ctx)
        assert ack.status == pb.PublishAck.Status.INVALID
        assert "signature" in ack.reason.lower()

    def test_require_sig_signed_no_key_rejected(self):
        srv.REQUIRE_SIGNATURES = False
        srv.AGENT_PUBKEY = None
        env = pb.Envelope(idempotency_key="signed-no-key", sig=b"sig-data")
        env.flow.src_ip = "a"
        env.flow.dst_ip = "b"
        ack = self.servicer.Publish(env, self.ctx)
        assert ack.status == pb.PublishAck.Status.INVALID

    def test_require_sig_valid_sig_accepted(self):
        srv.REQUIRE_SIGNATURES = False
        mock_key = MagicMock()
        srv.AGENT_PUBKEY = mock_key
        with patch("amoskys.eventbus.server.verify", return_value=True):
            env = pb.Envelope(idempotency_key="valid-sig", sig=b"good-sig")
            env.flow.src_ip = "a"
            env.flow.dst_ip = "b"
            ack = self.servicer.Publish(env, self.ctx)
            assert ack.status == pb.PublishAck.Status.OK


# ===================================================================
# 19. PublishTelemetry end-to-end with signature verification
# ===================================================================


class TestPublishTelemetryWithSignature:
    """Test PublishTelemetry when REQUIRE_SIGNATURES is True."""

    def setup_method(self):
        self.servicer = srv.UniversalEventBusServicer()
        self.ctx = _mock_context()
        srv._OVERLOAD = False
        srv.wal_storage = None

    def test_require_sig_unsigned_rejected(self):
        srv.REQUIRE_SIGNATURES = True
        env = tpb.UniversalEnvelope(idempotency_key="unsigned-tel")
        env.device_telemetry.device_id = "d"
        ack = self.servicer.PublishTelemetry(env, self.ctx)
        assert ack.status == tpb.UniversalAck.Status.SECURITY_VIOLATION

    def test_valid_sig_accepted(self):
        srv.REQUIRE_SIGNATURES = False
        mock_key = MagicMock()
        srv.AGENT_PUBKEY = mock_key
        with patch("amoskys.eventbus.server.verify", return_value=True):
            env = tpb.UniversalEnvelope(
                idempotency_key="valid-sig-tel",
                sig=b"good",
                signing_algorithm="Ed25519",
            )
            env.device_telemetry.device_id = "d"
            ack = self.servicer.PublishTelemetry(env, self.ctx)
            assert ack.status == tpb.UniversalAck.Status.OK

    def test_invalid_sig_rejected(self):
        srv.REQUIRE_SIGNATURES = False
        mock_key = MagicMock()
        srv.AGENT_PUBKEY = mock_key
        with patch("amoskys.eventbus.server.verify", return_value=False):
            env = tpb.UniversalEnvelope(
                idempotency_key="bad-sig-tel",
                sig=b"bad",
                signing_algorithm="Ed25519",
            )
            env.device_telemetry.device_id = "d"
            ack = self.servicer.PublishTelemetry(env, self.ctx)
            assert ack.status == tpb.UniversalAck.Status.SECURITY_VIOLATION


# ===================================================================
# 20. Module-level constants and configuration
# ===================================================================


class TestModuleConstants:
    """Verify key module-level constants are properly defined."""

    def test_overload_reason_constant(self):
        assert srv.OVERLOAD_REASON == "Server is overloaded"

    def test_overload_log_constant(self):
        assert srv.OVERLOAD_LOG == "[Publish] Server is overloaded"

    def test_dedupe_max_default(self):
        # From env or defaults; just verify it's a positive int
        assert isinstance(srv.DEDUPE_MAX, int)
        assert srv.DEDUPE_MAX > 0

    def test_dedupe_ttl_default(self):
        assert isinstance(srv.DEDUPE_TTL_SEC, int)
        assert srv.DEDUPE_TTL_SEC > 0

    def test_max_env_bytes_default(self):
        assert isinstance(srv.MAX_ENV_BYTES, int)
        assert srv.MAX_ENV_BYTES > 0

    def test_bus_max_inflight_positive(self):
        assert isinstance(srv.BUS_MAX_INFLIGHT, int)
        assert srv.BUS_MAX_INFLIGHT > 0

    def test_dedupe_is_ordered_dict(self):
        assert isinstance(srv._dedupe, OrderedDict)

    def test_inflight_lock_is_lock(self):
        assert isinstance(srv._inflight_lock, type(threading.Lock()))

    def test_dedupe_lock_is_lock(self):
        assert isinstance(srv._dedupe_lock, type(threading.Lock()))
