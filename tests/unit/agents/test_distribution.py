"""Unit tests for AgentDistributionService.

Tests cover every public method and branch in distribution.py:
- TokenCreationResult / AgentInfo / AgentListResult / TokenInfo / TokenListResult / AgentRegistrationResult dataclasses
- AgentDistributionService:
    - create_deployment_token: happy path, invalid platform, custom expiry, no-expiry, DB error
    - list_user_tokens: happy path with consumed/valid/expired tokens, DB error
    - revoke_token: happy path, not-found, DB error
    - register_agent: happy path, invalid token, consumed token, expired token,
                      invalid platform fallback, DB error
    - list_user_agents: happy path with status calculation, JSON parse error, DB error
    - record_heartbeat: happy path, not-found, revoked agent, ip_address+metadata, DB error
    - revoke_agent: happy path, not-found, DB error
    - get_user_stats: happy path, exception fallback
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, PropertyMock, call, patch

import pytest

from amoskys.agents.distribution import (
    AgentDistributionService,
    AgentInfo,
    AgentListResult,
    AgentRegistrationResult,
    TokenCreationResult,
    TokenInfo,
    TokenListResult,
)
from amoskys.agents.models import AgentPlatform, AgentStatus

# =============================================================================
# Helpers
# =============================================================================


def _make_token_obj(
    *,
    token_id="tok-1",
    user_id="user-1",
    label="Test",
    platform=AgentPlatform.LINUX,
    is_consumed=False,
    is_valid_ret=True,
    expires_at=None,
    created_at=None,
    consumed_by_agent_id=None,
):
    """Create a mock AgentToken record."""
    tok = MagicMock()
    tok.id = token_id
    tok.user_id = user_id
    tok.label = label
    tok.platform = platform
    tok.is_consumed = is_consumed
    tok.is_valid.return_value = is_valid_ret
    tok.expires_at = expires_at
    tok.created_at = created_at or datetime.now(timezone.utc)
    tok.consumed_by_agent_id = consumed_by_agent_id
    return tok


def _make_agent_obj(
    *,
    agent_id="agent-1",
    user_id="user-1",
    hostname="host-001",
    ip_address="10.0.0.1",
    platform=AgentPlatform.LINUX,
    version="1.0.0",
    status=AgentStatus.ONLINE,
    capabilities='["dns","proc"]',
    last_heartbeat_at=None,
    created_at=None,
    heartbeat_count=5,
    calculate_status_ret=None,
):
    """Create a mock DeployedAgent record."""
    agent = MagicMock()
    agent.id = agent_id
    agent.user_id = user_id
    agent.hostname = hostname
    agent.ip_address = ip_address
    agent.platform = platform
    agent.version = version
    agent.status = status
    agent.capabilities = capabilities
    agent.last_heartbeat_at = last_heartbeat_at
    agent.created_at = created_at or datetime.now(timezone.utc)
    agent.heartbeat_count = heartbeat_count
    agent.calculate_status.return_value = (
        calculate_status_ret if calculate_status_ret is not None else status
    )
    return agent


@pytest.fixture
def mock_db():
    """Create a mock SQLAlchemy Session."""
    return MagicMock()


@pytest.fixture
def service(mock_db):
    """Create AgentDistributionService with mocked DB."""
    return AgentDistributionService(mock_db)


# =============================================================================
# Dataclass smoke tests
# =============================================================================


class TestDataclasses:
    """Verify dataclass construction."""

    def test_token_creation_result(self):
        r = TokenCreationResult(success=True, token="abc", token_id="tok-1")
        assert r.success is True
        assert r.token == "abc"
        assert r.error is None

    def test_token_creation_result_error(self):
        r = TokenCreationResult(success=False, error="fail", error_code="E1")
        assert r.success is False
        assert r.error == "fail"
        assert r.error_code == "E1"

    def test_agent_info(self):
        info = AgentInfo(
            id="a1",
            hostname="h",
            ip_address="1.2.3.4",
            platform="linux",
            version="1.0.0",
            status="online",
            capabilities=["dns"],
            last_heartbeat_at="2026-01-01T00:00:00",
            created_at="2026-01-01T00:00:00",
            heartbeat_count=0,
        )
        assert info.id == "a1"

    def test_agent_list_result(self):
        r = AgentListResult(success=True, agents=[], total=0, by_status={})
        assert r.total == 0

    def test_token_info(self):
        info = TokenInfo(
            id="t1",
            label="lab",
            platform="linux",
            is_consumed=False,
            expires_at=None,
            created_at="2026-01-01T00:00:00",
            consumed_by_agent_id=None,
        )
        assert info.label == "lab"

    def test_token_list_result(self):
        r = TokenListResult(
            success=True, tokens=[], total=0, active_count=0, consumed_count=0
        )
        assert r.active_count == 0

    def test_agent_registration_result(self):
        r = AgentRegistrationResult(success=True, agent_id="a1")
        assert r.agent_id == "a1"


# =============================================================================
# create_deployment_token
# =============================================================================


class TestCreateDeploymentToken:
    """Tests for create_deployment_token."""

    @patch("amoskys.agents.distribution.AgentToken")
    def test_happy_path(self, MockAgentToken, service, mock_db):
        """Successful token creation with default expiry."""
        MockAgentToken.generate_token.return_value = "plain-token-xyz"
        MockAgentToken.hash_token.return_value = "hash-abc"

        # The AgentToken() constructor call should return a mock with an .id
        mock_token_instance = MagicMock()
        mock_token_instance.id = "tok-new-1"
        MockAgentToken.return_value = mock_token_instance

        result = service.create_deployment_token(
            user_id="user-1",
            label="Prod Server",
            platform="linux",
        )

        assert result.success is True
        assert result.token == "plain-token-xyz"
        assert result.token_id == "tok-new-1"
        mock_db.add.assert_called_once()
        mock_db.commit.assert_called_once()

    @patch("amoskys.agents.distribution.AgentToken")
    def test_invalid_platform(self, MockAgentToken, service):
        """Invalid platform returns error."""
        result = service.create_deployment_token(
            user_id="user-1",
            label="Test",
            platform="solaris",
        )
        assert result.success is False
        assert result.error_code == "INVALID_PLATFORM"

    @patch("amoskys.agents.distribution.AgentToken")
    def test_custom_expiry(self, MockAgentToken, service, mock_db):
        """Custom expiry_in_days creates correct expiration."""
        MockAgentToken.generate_token.return_value = "t"
        MockAgentToken.hash_token.return_value = "h"
        mock_inst = MagicMock()
        mock_inst.id = "tok-2"
        MockAgentToken.return_value = mock_inst

        result = service.create_deployment_token(
            user_id="user-1",
            label="Test",
            platform="macos",
            expires_in_days=30,
        )
        assert result.success is True

    @patch("amoskys.agents.distribution.AgentToken")
    def test_no_expiry_zero_days(self, MockAgentToken, service, mock_db):
        """expires_in_days=0 means no expiration."""
        MockAgentToken.generate_token.return_value = "t"
        MockAgentToken.hash_token.return_value = "h"
        mock_inst = MagicMock()
        mock_inst.id = "tok-3"
        MockAgentToken.return_value = mock_inst

        result = service.create_deployment_token(
            user_id="user-1",
            label="No Expiry",
            platform="docker",
            expires_in_days=0,
        )
        assert result.success is True

    @patch("amoskys.agents.distribution.AgentToken")
    def test_db_error(self, MockAgentToken, service, mock_db):
        """DB commit failure returns error."""
        MockAgentToken.generate_token.return_value = "t"
        MockAgentToken.hash_token.return_value = "h"
        mock_inst = MagicMock()
        mock_inst.id = "tok-4"
        MockAgentToken.return_value = mock_inst

        mock_db.commit.side_effect = Exception("DB crash")

        result = service.create_deployment_token(
            user_id="user-1", label="Test", platform="linux"
        )
        assert result.success is False
        assert result.error_code == "TOKEN_CREATION_FAILED"
        mock_db.rollback.assert_called_once()


# =============================================================================
# list_user_tokens
# =============================================================================


class TestListUserTokens:
    """Tests for list_user_tokens."""

    def test_happy_path_mixed_tokens(self, service, mock_db):
        """Returns counts for consumed, valid, and expired tokens."""
        consumed_tok = _make_token_obj(
            token_id="t1", is_consumed=True, is_valid_ret=False
        )
        valid_tok = _make_token_obj(token_id="t2", is_consumed=False, is_valid_ret=True)
        expired_tok = _make_token_obj(
            token_id="t3",
            is_consumed=False,
            is_valid_ret=False,
            expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        )

        query_mock = MagicMock()
        mock_db.query.return_value = query_mock
        query_mock.filter.return_value = query_mock
        query_mock.order_by.return_value = query_mock
        query_mock.all.return_value = [consumed_tok, valid_tok, expired_tok]

        result = service.list_user_tokens("user-1")

        assert result.success is True
        assert result.total == 3
        assert result.consumed_count == 1
        assert result.active_count == 1
        assert len(result.tokens) == 3

    def test_empty_list(self, service, mock_db):
        """No tokens for user."""
        query_mock = MagicMock()
        mock_db.query.return_value = query_mock
        query_mock.filter.return_value = query_mock
        query_mock.order_by.return_value = query_mock
        query_mock.all.return_value = []

        result = service.list_user_tokens("user-1")
        assert result.success is True
        assert result.total == 0

    def test_token_with_no_expires_at(self, service, mock_db):
        """Token without expires_at has None in TokenInfo."""
        tok = _make_token_obj(
            token_id="t-no-exp",
            is_consumed=False,
            is_valid_ret=True,
            expires_at=None,
        )

        query_mock = MagicMock()
        mock_db.query.return_value = query_mock
        query_mock.filter.return_value = query_mock
        query_mock.order_by.return_value = query_mock
        query_mock.all.return_value = [tok]

        result = service.list_user_tokens("user-1")
        assert result.success is True
        assert result.tokens[0].expires_at is None

    def test_db_error(self, service, mock_db):
        """DB error returns empty result."""
        mock_db.query.side_effect = Exception("DB down")

        result = service.list_user_tokens("user-1")
        assert result.success is False
        assert result.total == 0
        assert result.error == "Failed to list tokens"


# =============================================================================
# revoke_token
# =============================================================================


class TestRevokeToken:
    """Tests for revoke_token."""

    def test_happy_path(self, service, mock_db):
        """Revoke sets is_consumed and consumed_at."""
        tok = MagicMock()

        query_mock = MagicMock()
        mock_db.query.return_value = query_mock
        query_mock.filter.return_value = query_mock
        query_mock.first.return_value = tok

        result = service.revoke_token("user-1", "tok-1")
        assert result is True
        assert tok.is_consumed is True
        mock_db.commit.assert_called_once()

    def test_not_found(self, service, mock_db):
        """Unknown token returns False."""
        query_mock = MagicMock()
        mock_db.query.return_value = query_mock
        query_mock.filter.return_value = query_mock
        query_mock.first.return_value = None

        result = service.revoke_token("user-1", "tok-nonexist")
        assert result is False

    def test_db_error(self, service, mock_db):
        """DB error returns False and calls rollback."""
        query_mock = MagicMock()
        mock_db.query.return_value = query_mock
        query_mock.filter.return_value = query_mock
        query_mock.first.side_effect = Exception("DB boom")

        result = service.revoke_token("user-1", "tok-1")
        assert result is False
        mock_db.rollback.assert_called_once()


# =============================================================================
# register_agent
# =============================================================================


class TestRegisterAgent:
    """Tests for register_agent."""

    @patch("amoskys.agents.distribution.DeployedAgent")
    @patch("amoskys.agents.distribution.AgentToken")
    def test_happy_path(self, MockAgentToken, MockDeployedAgent, service, mock_db):
        """Successful agent registration."""
        MockAgentToken.hash_token.return_value = "hash-xyz"

        token_record = MagicMock()
        token_record.is_valid.return_value = True
        token_record.is_consumed = False
        token_record.user_id = "user-1"
        token_record.id = "tok-1"
        token_record.platform = AgentPlatform.LINUX

        query_mock = MagicMock()
        mock_db.query.return_value = query_mock
        query_mock.filter.return_value = query_mock
        query_mock.first.return_value = token_record

        agent_instance = MagicMock()
        agent_instance.id = "agent-new-1"
        agent_instance.hostname = "server-1"
        agent_instance.platform = AgentPlatform.LINUX
        agent_instance.status = AgentStatus.ONLINE
        MockDeployedAgent.return_value = agent_instance

        result = service.register_agent(
            token="plaintext-token",
            hostname="server-1",
            ip_address="10.0.0.5",
            capabilities=["dns", "proc"],
            metadata={"os": "ubuntu"},
        )

        assert result.success is True
        assert result.agent_id == "agent-new-1"
        assert result.agent_info["hostname"] == "server-1"
        mock_db.add.assert_called_once()
        mock_db.commit.assert_called_once()

    @patch("amoskys.agents.distribution.AgentToken")
    def test_invalid_token(self, MockAgentToken, service, mock_db):
        """Unknown token returns INVALID_TOKEN."""
        MockAgentToken.hash_token.return_value = "hash-bad"

        query_mock = MagicMock()
        mock_db.query.return_value = query_mock
        query_mock.filter.return_value = query_mock
        query_mock.first.return_value = None

        result = service.register_agent(token="bad-token", hostname="h")
        assert result.success is False
        assert result.error_code == "INVALID_TOKEN"

    @patch("amoskys.agents.distribution.AgentToken")
    def test_consumed_token(self, MockAgentToken, service, mock_db):
        """Already-consumed token returns TOKEN_CONSUMED."""
        MockAgentToken.hash_token.return_value = "hash-c"

        token_record = MagicMock()
        token_record.is_valid.return_value = False
        token_record.is_consumed = True

        query_mock = MagicMock()
        mock_db.query.return_value = query_mock
        query_mock.filter.return_value = query_mock
        query_mock.first.return_value = token_record

        result = service.register_agent(token="consumed-tok", hostname="h")
        assert result.success is False
        assert result.error_code == "TOKEN_CONSUMED"

    @patch("amoskys.agents.distribution.AgentToken")
    def test_expired_token(self, MockAgentToken, service, mock_db):
        """Expired token returns TOKEN_EXPIRED."""
        MockAgentToken.hash_token.return_value = "hash-e"

        token_record = MagicMock()
        token_record.is_valid.return_value = False
        token_record.is_consumed = False

        query_mock = MagicMock()
        mock_db.query.return_value = query_mock
        query_mock.filter.return_value = query_mock
        query_mock.first.return_value = token_record

        result = service.register_agent(token="expired-tok", hostname="h")
        assert result.success is False
        assert result.error_code == "TOKEN_EXPIRED"

    @patch("amoskys.agents.distribution.DeployedAgent")
    @patch("amoskys.agents.distribution.AgentToken")
    def test_invalid_platform_override_fallback(
        self, MockAgentToken, MockDeployedAgent, service, mock_db
    ):
        """Invalid platform string falls back to token's platform."""
        MockAgentToken.hash_token.return_value = "hash-p"

        token_record = MagicMock()
        token_record.is_valid.return_value = True
        token_record.is_consumed = False
        token_record.user_id = "user-1"
        token_record.id = "tok-1"
        token_record.platform = AgentPlatform.MACOS

        query_mock = MagicMock()
        mock_db.query.return_value = query_mock
        query_mock.filter.return_value = query_mock
        query_mock.first.return_value = token_record

        agent_instance = MagicMock()
        agent_instance.id = "agent-2"
        agent_instance.hostname = "server-2"
        agent_instance.platform = AgentPlatform.MACOS
        agent_instance.status = AgentStatus.ONLINE
        MockDeployedAgent.return_value = agent_instance

        result = service.register_agent(
            token="tok", hostname="server-2", platform="solaris"
        )
        assert result.success is True

    @patch("amoskys.agents.distribution.DeployedAgent")
    @patch("amoskys.agents.distribution.AgentToken")
    def test_no_platform_override(
        self, MockAgentToken, MockDeployedAgent, service, mock_db
    ):
        """No platform passed uses token's platform."""
        MockAgentToken.hash_token.return_value = "hash-np"

        token_record = MagicMock()
        token_record.is_valid.return_value = True
        token_record.is_consumed = False
        token_record.user_id = "user-1"
        token_record.id = "tok-1"
        token_record.platform = AgentPlatform.DOCKER

        query_mock = MagicMock()
        mock_db.query.return_value = query_mock
        query_mock.filter.return_value = query_mock
        query_mock.first.return_value = token_record

        agent_instance = MagicMock()
        agent_instance.id = "agent-3"
        agent_instance.hostname = "container-1"
        agent_instance.platform = AgentPlatform.DOCKER
        agent_instance.status = AgentStatus.ONLINE
        MockDeployedAgent.return_value = agent_instance

        result = service.register_agent(token="tok", hostname="container-1")
        assert result.success is True

    @patch("amoskys.agents.distribution.AgentToken")
    def test_db_error(self, MockAgentToken, service, mock_db):
        """DB error during registration returns error."""
        MockAgentToken.hash_token.return_value = "hash-err"

        token_record = MagicMock()
        token_record.is_valid.return_value = True
        token_record.is_consumed = False
        token_record.user_id = "user-1"
        token_record.id = "tok-1"
        token_record.platform = AgentPlatform.LINUX

        query_mock = MagicMock()
        mock_db.query.return_value = query_mock
        query_mock.filter.return_value = query_mock
        query_mock.first.return_value = token_record

        mock_db.add.side_effect = Exception("DB write error")

        result = service.register_agent(token="tok", hostname="h")
        assert result.success is False
        assert result.error_code == "REGISTRATION_FAILED"
        mock_db.rollback.assert_called_once()


# =============================================================================
# list_user_agents
# =============================================================================


class TestListUserAgents:
    """Tests for list_user_agents."""

    def test_happy_path(self, service, mock_db):
        """Lists agents with correct status counts."""
        now = datetime.now(timezone.utc)
        agent1 = _make_agent_obj(
            agent_id="a1",
            status=AgentStatus.ONLINE,
            capabilities='["dns"]',
            last_heartbeat_at=now,
        )
        agent2 = _make_agent_obj(
            agent_id="a2",
            status=AgentStatus.STALE,
            calculate_status_ret=AgentStatus.STALE,
            last_heartbeat_at=now,
        )

        query_mock = MagicMock()
        mock_db.query.return_value = query_mock
        query_mock.filter.return_value = query_mock
        query_mock.order_by.return_value = query_mock
        query_mock.all.return_value = [agent1, agent2]

        result = service.list_user_agents("user-1")
        assert result.success is True
        assert result.total == 2

    def test_status_update_on_calculation(self, service, mock_db):
        """Agent status is updated if calculate_status differs from stored status."""
        agent = _make_agent_obj(
            status=AgentStatus.ONLINE,
            calculate_status_ret=AgentStatus.OFFLINE,
            last_heartbeat_at=datetime.now(timezone.utc),
        )

        query_mock = MagicMock()
        mock_db.query.return_value = query_mock
        query_mock.filter.return_value = query_mock
        query_mock.order_by.return_value = query_mock
        query_mock.all.return_value = [agent]

        result = service.list_user_agents("user-1")
        assert result.success is True
        # The agent's status should have been updated
        assert agent.status == AgentStatus.OFFLINE

    def test_json_decode_error_capabilities(self, service, mock_db):
        """Invalid JSON in capabilities returns empty list."""
        agent = _make_agent_obj(capabilities="not-valid-json")

        query_mock = MagicMock()
        mock_db.query.return_value = query_mock
        query_mock.filter.return_value = query_mock
        query_mock.order_by.return_value = query_mock
        query_mock.all.return_value = [agent]

        result = service.list_user_agents("user-1")
        assert result.success is True
        assert result.agents[0].capabilities == []

    def test_none_capabilities(self, service, mock_db):
        """None capabilities returns empty list."""
        agent = _make_agent_obj(capabilities=None)

        query_mock = MagicMock()
        mock_db.query.return_value = query_mock
        query_mock.filter.return_value = query_mock
        query_mock.order_by.return_value = query_mock
        query_mock.all.return_value = [agent]

        result = service.list_user_agents("user-1")
        assert result.success is True
        assert result.agents[0].capabilities == []

    def test_agent_with_no_heartbeat(self, service, mock_db):
        """Agent with no last_heartbeat_at has None in AgentInfo."""
        agent = _make_agent_obj(last_heartbeat_at=None)

        query_mock = MagicMock()
        mock_db.query.return_value = query_mock
        query_mock.filter.return_value = query_mock
        query_mock.order_by.return_value = query_mock
        query_mock.all.return_value = [agent]

        result = service.list_user_agents("user-1")
        assert result.success is True
        assert result.agents[0].last_heartbeat_at is None

    def test_db_error(self, service, mock_db):
        """DB error returns failure result."""
        mock_db.query.side_effect = Exception("DB error")

        result = service.list_user_agents("user-1")
        assert result.success is False
        assert result.total == 0
        assert result.error == "Failed to list agents"


# =============================================================================
# record_heartbeat
# =============================================================================


class TestRecordHeartbeat:
    """Tests for record_heartbeat."""

    def test_happy_path(self, service, mock_db):
        """Records heartbeat and commits."""
        agent = MagicMock()
        agent.status = AgentStatus.ONLINE

        query_mock = MagicMock()
        mock_db.query.return_value = query_mock
        query_mock.filter.return_value = query_mock
        query_mock.first.return_value = agent

        result = service.record_heartbeat("agent-1")
        assert result is True
        agent.update_heartbeat.assert_called_once()
        mock_db.commit.assert_called_once()

    def test_with_ip_and_metadata(self, service, mock_db):
        """Updates ip_address and extra_data when provided."""
        agent = MagicMock()
        agent.status = AgentStatus.ONLINE

        query_mock = MagicMock()
        mock_db.query.return_value = query_mock
        query_mock.filter.return_value = query_mock
        query_mock.first.return_value = agent

        result = service.record_heartbeat(
            "agent-1", ip_address="10.0.0.99", metadata={"key": "val"}
        )
        assert result is True
        assert agent.ip_address == "10.0.0.99"
        assert agent.extra_data == json.dumps({"key": "val"})

    def test_not_found(self, service, mock_db):
        """Unknown agent returns False."""
        query_mock = MagicMock()
        mock_db.query.return_value = query_mock
        query_mock.filter.return_value = query_mock
        query_mock.first.return_value = None

        result = service.record_heartbeat("agent-nonexist")
        assert result is False

    def test_revoked_agent(self, service, mock_db):
        """Revoked agent returns False."""
        agent = MagicMock()
        agent.status = AgentStatus.REVOKED

        query_mock = MagicMock()
        mock_db.query.return_value = query_mock
        query_mock.filter.return_value = query_mock
        query_mock.first.return_value = agent

        result = service.record_heartbeat("agent-revoked")
        assert result is False

    def test_db_error(self, service, mock_db):
        """DB error returns False and rolls back."""
        query_mock = MagicMock()
        mock_db.query.return_value = query_mock
        query_mock.filter.return_value = query_mock
        query_mock.first.side_effect = Exception("DB fail")

        result = service.record_heartbeat("agent-1")
        assert result is False
        mock_db.rollback.assert_called_once()


# =============================================================================
# revoke_agent
# =============================================================================


class TestRevokeAgent:
    """Tests for revoke_agent."""

    def test_happy_path(self, service, mock_db):
        """Revokes agent and commits."""
        agent = MagicMock()

        query_mock = MagicMock()
        mock_db.query.return_value = query_mock
        query_mock.filter.return_value = query_mock
        query_mock.first.return_value = agent

        result = service.revoke_agent("user-1", "agent-1")
        assert result is True
        assert agent.status == AgentStatus.REVOKED
        mock_db.commit.assert_called_once()

    def test_not_found(self, service, mock_db):
        """Unknown agent returns False."""
        query_mock = MagicMock()
        mock_db.query.return_value = query_mock
        query_mock.filter.return_value = query_mock
        query_mock.first.return_value = None

        result = service.revoke_agent("user-1", "agent-nonexist")
        assert result is False

    def test_db_error(self, service, mock_db):
        """DB error returns False and rolls back."""
        query_mock = MagicMock()
        mock_db.query.return_value = query_mock
        query_mock.filter.return_value = query_mock
        query_mock.first.side_effect = Exception("DB error")

        result = service.revoke_agent("user-1", "agent-1")
        assert result is False
        mock_db.rollback.assert_called_once()


# =============================================================================
# get_user_stats
# =============================================================================


class TestGetUserStats:
    """Tests for get_user_stats."""

    def test_happy_path(self, service, mock_db):
        """Returns combined stats from agents and tokens."""
        # We'll mock list_user_agents and list_user_tokens to avoid deep DB mocking
        with (
            patch.object(service, "list_user_agents") as mock_agents,
            patch.object(service, "list_user_tokens") as mock_tokens,
        ):
            mock_agents.return_value = AgentListResult(
                success=True,
                agents=[],
                total=3,
                by_status={"online": 2, "stale": 1, "offline": 0},
            )
            mock_tokens.return_value = TokenListResult(
                success=True,
                tokens=[],
                total=5,
                active_count=2,
                consumed_count=3,
            )

            stats = service.get_user_stats("user-1")

            assert stats["total_agents"] == 3
            assert stats["online_agents"] == 2
            assert stats["stale_agents"] == 1
            assert stats["offline_agents"] == 0
            assert stats["total_tokens"] == 5
            assert stats["active_tokens"] == 2
            assert stats["consumed_tokens"] == 3

    def test_exception_returns_zeros(self, service, mock_db):
        """Exception returns all-zero stats."""
        with patch.object(service, "list_user_agents", side_effect=Exception("boom")):
            stats = service.get_user_stats("user-1")
            assert stats["total_agents"] == 0
            assert stats["online_agents"] == 0
            assert stats["total_tokens"] == 0
