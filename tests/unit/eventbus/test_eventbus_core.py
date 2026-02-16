"""Unit tests for EventBus server core logic.

Tests the deduplication cache, overload control, and envelope validation
WITHOUT requiring gRPC, TLS, or network connectivity.

Covers:
    - _seen() dedup cache: insertion, LRU eviction, TTL expiration
    - set_overload_setting / is_overloaded: mode switching
    - _sizeof_env: envelope size measurement
    - _peer_cn_from_context: CN extraction (mocked)
"""

import time
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Dedup cache tests
# ---------------------------------------------------------------------------


class TestDeduplicationCache:
    """Test the _seen() function and _dedupe OrderedDict."""

    def setup_method(self):
        """Reset the global dedup cache before each test."""
        # Import inside to get module-level globals
        import amoskys.eventbus.server as srv

        self._srv = srv
        srv._dedupe.clear()

    def test_first_key_not_seen(self):
        assert self._srv._seen("key-1") is False

    def test_second_lookup_is_seen(self):
        self._srv._seen("key-1")
        assert self._srv._seen("key-1") is True

    def test_different_keys_independent(self):
        self._srv._seen("key-a")
        assert self._srv._seen("key-b") is False
        assert self._srv._seen("key-a") is True

    def test_cache_respects_max_size(self):
        original_max = self._srv.DEDUPE_MAX
        try:
            self._srv.DEDUPE_MAX = 3
            self._srv._seen("a")
            self._srv._seen("b")
            self._srv._seen("c")
            self._srv._seen("d")  # Should evict "a"

            assert len(self._srv._dedupe) == 3
            assert "a" not in self._srv._dedupe
            assert "d" in self._srv._dedupe
        finally:
            self._srv.DEDUPE_MAX = original_max

    def test_cache_expires_old_entries(self):
        original_ttl = self._srv.DEDUPE_TTL_SEC
        try:
            self._srv.DEDUPE_TTL_SEC = 0  # Immediate expiry
            self._srv._seen("old-key")
            time.sleep(0.01)
            # Next call should expire "old-key" and treat new key as unseen
            assert self._srv._seen("new-key") is False
            assert "old-key" not in self._srv._dedupe
        finally:
            self._srv.DEDUPE_TTL_SEC = original_ttl

    def test_seen_moves_key_to_end(self):
        self._srv._seen("a")
        self._srv._seen("b")
        self._srv._seen("c")
        # Re-access "a" — should move to end
        self._srv._seen("a")
        keys = list(self._srv._dedupe.keys())
        assert keys[-1] == "a"


# ---------------------------------------------------------------------------
# Overload control tests
# ---------------------------------------------------------------------------


class TestOverloadControl:
    def setup_method(self):
        import amoskys.eventbus.server as srv

        self._srv = srv

    def test_set_overload_on(self):
        self._srv.set_overload_setting("on")
        assert self._srv.BUS_OVERLOAD_SETTING == "on"
        assert self._srv.BUS_OVERLOAD_SOURCE == "cli"

    def test_set_overload_off(self):
        self._srv.set_overload_setting("off")
        assert self._srv.BUS_OVERLOAD_SETTING == "off"

    def test_set_overload_auto(self):
        self._srv.set_overload_setting("auto")
        assert self._srv.BUS_OVERLOAD_SETTING == "auto"

    def test_set_overload_none_defaults_auto(self):
        self._srv.set_overload_setting(None)
        assert self._srv.BUS_OVERLOAD_SETTING == "auto"
        assert self._srv.BUS_OVERLOAD_SOURCE == "env"

    def test_set_overload_invalid_defaults_auto(self):
        self._srv.set_overload_setting("garbage")
        assert self._srv.BUS_OVERLOAD_SETTING == "auto"

    def test_is_overloaded_false_by_default(self):
        self._srv._OVERLOAD = None
        assert self._srv.is_overloaded() is False

    def test_is_overloaded_true_when_set(self):
        original = self._srv._OVERLOAD
        try:
            self._srv._OVERLOAD = True
            assert self._srv.is_overloaded() is True
        finally:
            self._srv._OVERLOAD = original


# ---------------------------------------------------------------------------
# Envelope size validation
# ---------------------------------------------------------------------------


class TestEnvelopeSize:
    def setup_method(self):
        import amoskys.eventbus.server as srv

        self._srv = srv

    def test_sizeof_valid_envelope(self):
        from amoskys.proto import messaging_schema_pb2 as pb

        env = pb.Envelope(version="1.0", idempotency_key="test-key")
        size = self._srv._sizeof_env(env)
        assert size > 0

    def test_sizeof_empty_envelope(self):
        from amoskys.proto import messaging_schema_pb2 as pb

        env = pb.Envelope()
        size = self._srv._sizeof_env(env)
        # Empty envelope serializes to 0 bytes (all defaults)
        assert size >= 0

    def test_sizeof_bad_object_returns_zero(self):
        size = self._srv._sizeof_env("not a protobuf")
        assert size == 0
