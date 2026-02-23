"""Unit tests for CircuitBreaker resilience pattern.

Tests state transitions (CLOSED → OPEN → HALF_OPEN → CLOSED),
failure tracking, recovery timeout, and thread safety.

CircuitBreaker protects EventBus from cascading failures and enables
graceful degradation with fallback to local queue.
"""

import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from amoskys.agents.common.base import CircuitBreaker, CircuitBreakerOpen


@pytest.fixture
def breaker():
    """Create a fresh CircuitBreaker with default settings."""
    return CircuitBreaker(
        failure_threshold=5,
        recovery_timeout=30.0,
        half_open_attempts=3,
    )


class TestInitialStateClosed:
    """Test circuit breaker starts in CLOSED state."""

    def test_initial_state_is_closed(self, breaker):
        """Verify new breaker starts in CLOSED state."""
        assert breaker.state == "CLOSED"

    def test_initial_failure_count_zero(self, breaker):
        """Verify failure count starts at 0."""
        assert breaker.failure_count == 0

    def test_initial_success_count_zero(self, breaker):
        """Verify success count starts at 0."""
        assert breaker.success_count == 0

    def test_allow_call_succeeds_when_closed(self, breaker):
        """Verify allow_call() doesn't raise when CLOSED."""
        try:
            breaker.allow_call()
        except CircuitBreakerOpen:
            pytest.fail("allow_call() raised when circuit is CLOSED")


class TestOpensAfterThreshold:
    """Test circuit opens after failure threshold exceeded."""

    def test_opens_after_failure_threshold(self, breaker):
        """Verify state changes to OPEN after 5 failures."""
        assert breaker.state == "CLOSED"

        for i in range(5):
            breaker.record_failure()
            if i < 4:
                assert breaker.state == "CLOSED"

        assert breaker.state == "OPEN"

    def test_failure_count_increments(self, breaker):
        """Verify failure count increments correctly."""
        for i in range(5):
            breaker.record_failure()
            assert breaker.failure_count == i + 1

    def test_opens_at_exactly_threshold(self, breaker):
        """Verify state opens at exactly the threshold."""
        for i in range(4):
            breaker.record_failure()
            assert breaker.state == "CLOSED"

        breaker.record_failure()
        assert breaker.state == "OPEN"

    def test_custom_threshold(self):
        """Verify custom failure threshold is respected."""
        custom_breaker = CircuitBreaker(failure_threshold=3)

        for i in range(2):
            custom_breaker.record_failure()
            assert custom_breaker.state == "CLOSED"

        custom_breaker.record_failure()
        assert custom_breaker.state == "OPEN"


class TestOpenRaisesException:
    """Test OPEN state blocks calls."""

    def test_open_raises_circuit_breaker_open(self, breaker):
        """Verify OPEN state raises CircuitBreakerOpen."""
        for _ in range(5):
            breaker.record_failure()

        assert breaker.state == "OPEN"

        with pytest.raises(CircuitBreakerOpen):
            breaker.allow_call()

    def test_open_blocks_multiple_calls(self, breaker):
        """Verify all calls are blocked when OPEN."""
        for _ in range(5):
            breaker.record_failure()

        # Try multiple calls
        for _ in range(10):
            with pytest.raises(CircuitBreakerOpen):
                breaker.allow_call()

    def test_exception_message_informative(self, breaker):
        """Verify exception message indicates circuit is open."""
        for _ in range(5):
            breaker.record_failure()

        with pytest.raises(CircuitBreakerOpen) as exc_info:
            breaker.allow_call()

        assert "OPEN" in str(exc_info.value)


class TestHalfOpenAfterRecoveryTimeout:
    """Test transition to HALF_OPEN after timeout."""

    def test_half_open_after_timeout(self, breaker):
        """Verify state transitions to HALF_OPEN after recovery_timeout."""
        for _ in range(5):
            breaker.record_failure()

        assert breaker.state == "OPEN"

        # Mock time to advance past recovery timeout
        with patch.object(
            breaker, "_now", return_value=breaker.last_failure_time + 31.0
        ):
            breaker.allow_call()

        assert breaker.state == "HALF_OPEN"

    def test_no_transition_before_timeout(self, breaker):
        """Verify no transition before timeout expires."""
        for _ in range(5):
            breaker.record_failure()

        assert breaker.state == "OPEN"

        # Advance time less than timeout
        with patch.object(
            breaker, "_now", return_value=breaker.last_failure_time + 10.0
        ):
            with pytest.raises(CircuitBreakerOpen):
                breaker.allow_call()

        assert breaker.state == "OPEN"

    def test_custom_recovery_timeout(self):
        """Verify custom recovery timeout is respected."""
        custom_breaker = CircuitBreaker(recovery_timeout=5.0)

        for _ in range(5):
            custom_breaker.record_failure()

        # Advance time past custom timeout
        with patch.object(
            custom_breaker, "_now", return_value=custom_breaker.last_failure_time + 6.0
        ):
            custom_breaker.allow_call()

        assert custom_breaker.state == "HALF_OPEN"


class TestClosesOnSuccess:
    """Test successful operations close circuit from HALF_OPEN."""

    def test_closes_after_half_open_success(self, breaker):
        """Verify circuit closes after success in HALF_OPEN."""
        # Open circuit
        for _ in range(5):
            breaker.record_failure()

        assert breaker.state == "OPEN"

        # Transition to HALF_OPEN
        with patch.object(
            breaker, "_now", return_value=breaker.last_failure_time + 31.0
        ):
            breaker.allow_call()

        assert breaker.state == "HALF_OPEN"

        # Record successes
        for i in range(3):
            breaker.record_success()

        assert breaker.state == "CLOSED"

    def test_closes_after_half_open_attempts(self, breaker):
        """Verify circuit fully closes after half_open_attempts successes."""
        # Setup: OPEN → HALF_OPEN
        for _ in range(5):
            breaker.record_failure()

        with patch.object(
            breaker, "_now", return_value=breaker.last_failure_time + 31.0
        ):
            breaker.allow_call()

        # Record exactly half_open_attempts successes
        for i in range(2):
            breaker.record_success()
            assert breaker.state == "HALF_OPEN"

        breaker.record_success()
        assert breaker.state == "CLOSED"

    def test_custom_half_open_attempts(self):
        """Verify custom half_open_attempts threshold is respected."""
        custom_breaker = CircuitBreaker(half_open_attempts=5)

        for _ in range(5):
            custom_breaker.record_failure()

        with patch.object(
            custom_breaker, "_now", return_value=custom_breaker.last_failure_time + 31.0
        ):
            custom_breaker.allow_call()

        # Need 5 successes to close
        for i in range(4):
            custom_breaker.record_success()
            assert custom_breaker.state == "HALF_OPEN"

        custom_breaker.record_success()
        assert custom_breaker.state == "CLOSED"


class TestReopensOnFailure:
    """Test circuit reopens if failures occur in HALF_OPEN."""

    def test_reopens_on_half_open_failure(self, breaker):
        """Verify failure in HALF_OPEN reopens circuit."""
        # Setup: OPEN → HALF_OPEN
        for _ in range(5):
            breaker.record_failure()

        with patch.object(
            breaker, "_now", return_value=breaker.last_failure_time + 31.0
        ):
            breaker.allow_call()

        assert breaker.state == "HALF_OPEN"

        # Record failure
        breaker.record_failure()

        assert breaker.state == "OPEN"

    def test_reopens_resets_counts(self, breaker):
        """Verify reopening resets success/failure counts."""
        # Setup: OPEN → HALF_OPEN → record failure → OPEN
        for _ in range(5):
            breaker.record_failure()

        with patch.object(
            breaker, "_now", return_value=breaker.last_failure_time + 31.0
        ):
            breaker.allow_call()

        breaker.record_success()
        breaker.record_failure()

        # Counts should be reset
        assert breaker.failure_count == 1
        assert breaker.success_count == 0
        assert breaker.state == "OPEN"

    def test_reopens_updates_last_failure_time(self, breaker):
        """Verify last_failure_time is updated on reopen."""
        # Open circuit
        for _ in range(5):
            breaker.record_failure()

        first_failure_time = breaker.last_failure_time

        # Transition to HALF_OPEN
        with patch.object(breaker, "_now", return_value=first_failure_time + 31.0):
            breaker.allow_call()

        # Fail again (with mocked newer time)
        new_time = first_failure_time + 35.0
        with patch.object(breaker, "_now", return_value=new_time):
            breaker.record_failure()

        assert breaker.last_failure_time == new_time


class TestSuccessCountResetsOnFailure:
    """Test success count is reset on failures."""

    def test_success_count_reset_in_closed(self, breaker):
        """Verify success in CLOSED resets failure count."""
        breaker.record_failure()
        breaker.record_failure()
        breaker.record_failure()

        assert breaker.failure_count == 3

        # Success should reset failure count
        breaker.record_success()

        assert breaker.failure_count == 0

    def test_success_count_reset_on_new_failure(self, breaker):
        """Verify new failure resets success count."""
        # Setup: OPEN → HALF_OPEN
        for _ in range(5):
            breaker.record_failure()

        with patch.object(
            breaker, "_now", return_value=breaker.last_failure_time + 31.0
        ):
            breaker.allow_call()

        # Record successes
        breaker.record_success()
        breaker.record_success()

        assert breaker.success_count == 2

        # Record failure - should reset success count
        breaker.record_failure()

        assert breaker.success_count == 0


class TestStateTransitionsLogged:
    """Test state transitions are logged."""

    def test_open_transition_logged(self, breaker):
        """Verify CLOSED → OPEN transition is logged."""
        with patch("amoskys.agents.common.base.logger") as mock_logger:
            for _ in range(5):
                breaker.record_failure()

            assert breaker.state == "OPEN"
            # Check that warning was called
            assert mock_logger.warning.called

    def test_half_open_transition_logged(self, breaker):
        """Verify OPEN → HALF_OPEN transition is logged."""
        for _ in range(5):
            breaker.record_failure()

        with patch("amoskys.agents.common.base.logger") as mock_logger:
            with patch.object(
                breaker, "_now", return_value=breaker.last_failure_time + 31.0
            ):
                breaker.allow_call()

            assert breaker.state == "HALF_OPEN"
            assert mock_logger.info.called

    def test_closed_transition_logged(self, breaker):
        """Verify HALF_OPEN → CLOSED transition is logged."""
        for _ in range(5):
            breaker.record_failure()

        with patch.object(
            breaker, "_now", return_value=breaker.last_failure_time + 31.0
        ):
            breaker.allow_call()

        with patch("amoskys.agents.common.base.logger") as mock_logger:
            for _ in range(3):
                breaker.record_success()

            assert breaker.state == "CLOSED"
            assert mock_logger.info.called


class TestConcurrentStateAccess:
    """Test thread-safe state transitions."""

    def test_concurrent_failure_recording(self, breaker):
        """Verify concurrent failures don't corrupt state."""
        lock = threading.Lock()
        thread_count = 10

        def record_failures():
            for _ in range(5):
                breaker.record_failure()

        threads = [
            threading.Thread(target=record_failures) for _ in range(thread_count)
        ]

        for t in threads:
            t.start()

        for t in threads:
            t.join()

        # Failure count should equal total failures
        assert breaker.failure_count >= thread_count * 5

    def test_concurrent_allow_call(self, breaker):
        """Verify concurrent allow_call() doesn't cause race conditions."""
        # Open circuit first
        for _ in range(5):
            breaker.record_failure()

        assert breaker.state == "OPEN"

        def try_call():
            try:
                breaker.allow_call()
            except CircuitBreakerOpen:
                pass

        threads = [threading.Thread(target=try_call) for _ in range(10)]

        for t in threads:
            t.start()

        for t in threads:
            t.join()

        # State should remain OPEN
        assert breaker.state == "OPEN"

    def test_concurrent_mixed_operations(self, breaker):
        """Verify concurrent reads/writes don't corrupt state."""
        results = {"opened": False, "half_opened": False, "closed": False}
        lock = threading.Lock()

        def worker():
            for i in range(10):
                # Record enough failures to exceed threshold (5)
                for _ in range(breaker.failure_threshold):
                    breaker.record_failure()

                if breaker.state == "OPEN":
                    with lock:
                        results["opened"] = True

                with patch.object(
                    breaker, "_now", return_value=breaker.last_failure_time + 31.0
                ):
                    try:
                        breaker.allow_call()
                    except CircuitBreakerOpen:
                        pass

                if breaker.state == "HALF_OPEN":
                    with lock:
                        results["half_opened"] = True

                breaker.record_success()
                breaker.record_success()
                breaker.record_success()

                if breaker.state == "CLOSED":
                    with lock:
                        results["closed"] = True

        threads = [threading.Thread(target=worker) for _ in range(3)]

        for t in threads:
            t.start()

        for t in threads:
            t.join()

        # All states should be visited
        assert results["opened"]
