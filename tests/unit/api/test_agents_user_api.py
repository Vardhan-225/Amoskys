"""
Tests for amoskys.api.agents_user — Agent User Management Flask Blueprint.

Covers:
  - GET    /api/user/agents              (list_agents)
  - GET    /api/user/agents/tokens       (list_tokens)
  - POST   /api/user/agents/token        (create_token)
  - DELETE /api/user/agents/token/<id>   (revoke_token)
  - DELETE /api/user/agents/<id>         (revoke_agent)
  - GET    /api/user/agents/stats        (get_stats)
  - POST   /api/agents/register          (agent_register)
  - POST   /api/agents/heartbeat         (agent_heartbeat)
  - GET    /api/user/agents/package-info (get_package_info)
  - require_user_auth decorator

Note: require_user_auth captures AuthService at *decorator-application* time
via ``from amoskys.auth import AuthService`` in the decorator body (not inside
the wrapped function).  Therefore we cannot patch the module attribute; we must
use ``patch.object(AuthService, 'validate_and_refresh_session')`` to intercept
calls on already-bound class instances.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask

from amoskys.auth.service import AuthService

# ---------------------------------------------------------------------------
# Fake result types mirroring amoskys.agents.distribution
# ---------------------------------------------------------------------------


@dataclass
class _FakeAgentListResult:
    success: bool
    agents: list = None
    total: int = 0
    by_status: dict = None
    error: Optional[str] = None

    def __post_init__(self):
        if self.agents is None:
            self.agents = []
        if self.by_status is None:
            self.by_status = {}


@dataclass
class _FakeTokenListResult:
    success: bool
    tokens: list = None
    total: int = 0
    active_count: int = 0
    consumed_count: int = 0
    error: Optional[str] = None

    def __post_init__(self):
        if self.tokens is None:
            self.tokens = []


@dataclass
class _FakeTokenCreationResult:
    success: bool
    token: Optional[str] = None
    token_id: Optional[str] = None
    error: Optional[str] = None
    error_code: Optional[str] = None


@dataclass
class _FakeRegistrationResult:
    success: bool
    agent_id: Optional[str] = None
    agent_info: Optional[dict] = None
    error: Optional[str] = None
    error_code: Optional[str] = None


@dataclass
class _FakeSessionValidation:
    is_valid: bool
    user: Optional[object] = None
    session: Optional[object] = None
    error: Optional[str] = None
    error_code: Optional[str] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Session tokens must be >= 20 chars to pass AuthService.validate_session
_VALID_TOKEN = "test-session-token-at-least-twenty-chars"


def _make_user():
    user = MagicMock()
    user.id = "user-42"
    user.email = "agent@amoskys.com"
    return user


def _create_app():
    """Create a minimal Flask app with the agents_user blueprint."""
    with patch("amoskys.api.agents_user.rate_limit_auth", return_value=lambda f: f):
        from amoskys.api.agents_user import agents_user_bp

        app = Flask(__name__)
        app.config["TESTING"] = True
        app.register_blueprint(agents_user_bp)
        return app


_app = None


def _get_app():
    global _app
    if _app is None:
        _app = _create_app()
    return _app


@pytest.fixture()
def client():
    app = _get_app()
    with app.test_client() as c:
        yield c


@contextmanager
def _fake_session_ctx():
    """A real context manager that yields a MagicMock DB session."""
    yield MagicMock()


def _auth_ok_validation():
    """Build a successful SessionValidationResult for the auth decorator."""
    user = _make_user()
    return _FakeSessionValidation(is_valid=True, user=user, session=MagicMock())


def _auth_patches():
    """Return the two patches needed to bypass require_user_auth.

    Usage::

        with _auth_patches():
            client.set_cookie(...)
            resp = client.get(...)
    """
    return (
        patch.object(
            AuthService,
            "validate_and_refresh_session",
            return_value=_auth_ok_validation(),
        ),
        patch(
            "amoskys.api.agents_user.get_session_context",
            side_effect=_fake_session_ctx,
        ),
    )


# ---------------------------------------------------------------------------
# Tests: require_user_auth
# ---------------------------------------------------------------------------


class TestRequireUserAuth:
    def test_no_cookie_returns_401(self, client):
        resp = client.get("/api/user/agents")
        assert resp.status_code == 401
        assert resp.get_json()["error_code"] == "NO_SESSION"

    def test_invalid_session_returns_401(self, client):
        fake_val = _FakeSessionValidation(
            is_valid=False, error="expired", error_code="SESSION_EXPIRED"
        )
        with (
            patch.object(
                AuthService, "validate_and_refresh_session", return_value=fake_val
            ),
            patch(
                "amoskys.api.agents_user.get_session_context",
                side_effect=_fake_session_ctx,
            ),
        ):
            client.set_cookie("amoskys_session", _VALID_TOKEN, domain="localhost")
            resp = client.get("/api/user/agents")
            assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Tests: GET /api/user/agents
# ---------------------------------------------------------------------------


class TestListAgents:
    @patch("amoskys.api.agents_user.get_distribution_service")
    def test_list_agents_success(self, mock_svc_fn, client):
        mock_svc = MagicMock()
        mock_svc.list_user_agents.return_value = _FakeAgentListResult(
            success=True, agents=[], total=0, by_status={"online": 0}
        )
        mock_svc_fn.return_value = mock_svc

        p1, p2 = _auth_patches()
        with p1, p2:
            client.set_cookie("amoskys_session", _VALID_TOKEN, domain="localhost")
            resp = client.get("/api/user/agents")
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["success"] is True
            assert data["total"] == 0

    @patch("amoskys.api.agents_user.get_distribution_service")
    def test_list_agents_error_returns_500(self, mock_svc_fn, client):
        mock_svc = MagicMock()
        mock_svc.list_user_agents.return_value = _FakeAgentListResult(
            success=False, error="DB error"
        )
        mock_svc_fn.return_value = mock_svc

        p1, p2 = _auth_patches()
        with p1, p2:
            client.set_cookie("amoskys_session", _VALID_TOKEN, domain="localhost")
            resp = client.get("/api/user/agents")
            assert resp.status_code == 500


# ---------------------------------------------------------------------------
# Tests: GET /api/user/agents/tokens
# ---------------------------------------------------------------------------


class TestListTokens:
    @patch("amoskys.api.agents_user.get_distribution_service")
    def test_list_tokens_success(self, mock_svc_fn, client):
        mock_svc = MagicMock()
        mock_svc.list_user_tokens.return_value = _FakeTokenListResult(
            success=True, total=2, active_count=1, consumed_count=1
        )
        mock_svc_fn.return_value = mock_svc

        p1, p2 = _auth_patches()
        with p1, p2:
            client.set_cookie("amoskys_session", _VALID_TOKEN, domain="localhost")
            resp = client.get("/api/user/agents/tokens")
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["total"] == 2

    @patch("amoskys.api.agents_user.get_distribution_service")
    def test_list_tokens_error_returns_500(self, mock_svc_fn, client):
        mock_svc = MagicMock()
        mock_svc.list_user_tokens.return_value = _FakeTokenListResult(
            success=False, error="DB fail"
        )
        mock_svc_fn.return_value = mock_svc

        p1, p2 = _auth_patches()
        with p1, p2:
            client.set_cookie("amoskys_session", _VALID_TOKEN, domain="localhost")
            resp = client.get("/api/user/agents/tokens")
            assert resp.status_code == 500


# ---------------------------------------------------------------------------
# Tests: POST /api/user/agents/token
# ---------------------------------------------------------------------------


class TestCreateToken:
    @patch("amoskys.api.agents_user.get_distribution_service")
    def test_create_token_no_body_returns_400(self, mock_svc_fn, client):
        p1, p2 = _auth_patches()
        with p1, p2:
            client.set_cookie("amoskys_session", _VALID_TOKEN, domain="localhost")
            resp = client.post(
                "/api/user/agents/token",
                data=json.dumps(None),
                content_type="application/json",
            )
            assert resp.status_code == 400

    @patch("amoskys.api.agents_user.get_distribution_service")
    def test_create_token_missing_label_returns_400(self, mock_svc_fn, client):
        p1, p2 = _auth_patches()
        with p1, p2:
            client.set_cookie("amoskys_session", _VALID_TOKEN, domain="localhost")
            resp = client.post(
                "/api/user/agents/token",
                data=json.dumps({"platform": "linux"}),
                content_type="application/json",
            )
            assert resp.status_code == 400
            assert resp.get_json()["error_code"] == "MISSING_LABEL"

    @patch("amoskys.api.agents_user.get_distribution_service")
    def test_create_token_missing_platform_returns_400(self, mock_svc_fn, client):
        p1, p2 = _auth_patches()
        with p1, p2:
            client.set_cookie("amoskys_session", _VALID_TOKEN, domain="localhost")
            resp = client.post(
                "/api/user/agents/token",
                data=json.dumps({"label": "My Server"}),
                content_type="application/json",
            )
            assert resp.status_code == 400
            assert resp.get_json()["error_code"] == "MISSING_PLATFORM"

    @patch("amoskys.api.agents_user.get_distribution_service")
    def test_create_token_success_returns_201(self, mock_svc_fn, client):
        mock_svc = MagicMock()
        mock_svc.create_deployment_token.return_value = _FakeTokenCreationResult(
            success=True, token="plaintext-tok", token_id="tid-1"
        )
        mock_svc_fn.return_value = mock_svc

        p1, p2 = _auth_patches()
        with p1, p2:
            client.set_cookie("amoskys_session", _VALID_TOKEN, domain="localhost")
            resp = client.post(
                "/api/user/agents/token",
                data=json.dumps({"label": "Server1", "platform": "linux"}),
                content_type="application/json",
            )
            assert resp.status_code == 201
            data = resp.get_json()
            assert data["success"] is True
            assert data["token"] == "plaintext-tok"

    @patch("amoskys.api.agents_user.get_distribution_service")
    def test_create_token_failure_returns_400(self, mock_svc_fn, client):
        mock_svc = MagicMock()
        mock_svc.create_deployment_token.return_value = _FakeTokenCreationResult(
            success=False, error="Limit reached", error_code="TOKEN_LIMIT"
        )
        mock_svc_fn.return_value = mock_svc

        p1, p2 = _auth_patches()
        with p1, p2:
            client.set_cookie("amoskys_session", _VALID_TOKEN, domain="localhost")
            resp = client.post(
                "/api/user/agents/token",
                data=json.dumps({"label": "Server1", "platform": "linux"}),
                content_type="application/json",
            )
            assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Tests: DELETE /api/user/agents/token/<token_id>
# ---------------------------------------------------------------------------


class TestRevokeToken:
    @patch("amoskys.api.agents_user.get_distribution_service")
    def test_revoke_token_success(self, mock_svc_fn, client):
        mock_svc = MagicMock()
        mock_svc.revoke_token.return_value = True
        mock_svc_fn.return_value = mock_svc

        p1, p2 = _auth_patches()
        with p1, p2:
            client.set_cookie("amoskys_session", _VALID_TOKEN, domain="localhost")
            resp = client.delete("/api/user/agents/token/tid-1")
            assert resp.status_code == 200
            assert resp.get_json()["success"] is True

    @patch("amoskys.api.agents_user.get_distribution_service")
    def test_revoke_token_not_found_returns_404(self, mock_svc_fn, client):
        mock_svc = MagicMock()
        mock_svc.revoke_token.return_value = False
        mock_svc_fn.return_value = mock_svc

        p1, p2 = _auth_patches()
        with p1, p2:
            client.set_cookie("amoskys_session", _VALID_TOKEN, domain="localhost")
            resp = client.delete("/api/user/agents/token/bad-id")
            assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Tests: DELETE /api/user/agents/<agent_id>
# ---------------------------------------------------------------------------


class TestRevokeAgent:
    @patch("amoskys.api.agents_user.get_distribution_service")
    def test_revoke_agent_success(self, mock_svc_fn, client):
        mock_svc = MagicMock()
        mock_svc.revoke_agent.return_value = True
        mock_svc_fn.return_value = mock_svc

        p1, p2 = _auth_patches()
        with p1, p2:
            client.set_cookie("amoskys_session", _VALID_TOKEN, domain="localhost")
            resp = client.delete("/api/user/agents/agent-42")
            assert resp.status_code == 200

    @patch("amoskys.api.agents_user.get_distribution_service")
    def test_revoke_agent_not_found_returns_404(self, mock_svc_fn, client):
        mock_svc = MagicMock()
        mock_svc.revoke_agent.return_value = False
        mock_svc_fn.return_value = mock_svc

        p1, p2 = _auth_patches()
        with p1, p2:
            client.set_cookie("amoskys_session", _VALID_TOKEN, domain="localhost")
            resp = client.delete("/api/user/agents/nope")
            assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Tests: GET /api/user/agents/stats
# ---------------------------------------------------------------------------


class TestGetStats:
    @patch("amoskys.api.agents_user.get_distribution_service")
    def test_get_stats_success(self, mock_svc_fn, client):
        mock_svc = MagicMock()
        mock_svc.get_user_stats.return_value = {"total_agents": 5, "online": 3}
        mock_svc_fn.return_value = mock_svc

        p1, p2 = _auth_patches()
        with p1, p2:
            client.set_cookie("amoskys_session", _VALID_TOKEN, domain="localhost")
            resp = client.get("/api/user/agents/stats")
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["success"] is True
            assert data["total_agents"] == 5


# ---------------------------------------------------------------------------
# Tests: POST /api/agents/register (token auth, no session)
# ---------------------------------------------------------------------------


class TestAgentRegister:
    def test_register_no_body_returns_400(self, client):
        resp = client.post(
            "/api/agents/register",
            data=json.dumps(None),
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_register_missing_token_returns_400(self, client):
        resp = client.post(
            "/api/agents/register",
            data=json.dumps({"hostname": "srv1"}),
            content_type="application/json",
        )
        assert resp.status_code == 400
        assert "token" in resp.get_json()["error"].lower()

    def test_register_missing_hostname_returns_400(self, client):
        resp = client.post(
            "/api/agents/register",
            data=json.dumps({"token": "tok123"}),
            content_type="application/json",
        )
        assert resp.status_code == 400
        assert "hostname" in resp.get_json()["error"].lower()

    @patch("amoskys.api.agents_user.get_distribution_service")
    @patch(
        "amoskys.api.agents_user.get_session_context",
        side_effect=_fake_session_ctx,
    )
    def test_register_success(self, mock_ctx, mock_svc_fn, client):
        mock_svc = MagicMock()
        mock_svc.register_agent.return_value = _FakeRegistrationResult(
            success=True, agent_id="ag-1", agent_info={"name": "agent1"}
        )
        mock_svc_fn.return_value = mock_svc

        resp = client.post(
            "/api/agents/register",
            data=json.dumps({"token": "tok123", "hostname": "srv1"}),
            content_type="application/json",
        )
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["agent_id"] == "ag-1"

    @patch("amoskys.api.agents_user.get_distribution_service")
    @patch(
        "amoskys.api.agents_user.get_session_context",
        side_effect=_fake_session_ctx,
    )
    def test_register_failure_returns_400(self, mock_ctx, mock_svc_fn, client):
        mock_svc = MagicMock()
        mock_svc.register_agent.return_value = _FakeRegistrationResult(
            success=False, error="Invalid token", error_code="INVALID_TOKEN"
        )
        mock_svc_fn.return_value = mock_svc

        resp = client.post(
            "/api/agents/register",
            data=json.dumps({"token": "bad", "hostname": "srv1"}),
            content_type="application/json",
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Tests: POST /api/agents/heartbeat
# ---------------------------------------------------------------------------


class TestAgentHeartbeat:
    def test_heartbeat_no_body_returns_400(self, client):
        resp = client.post(
            "/api/agents/heartbeat",
            data=json.dumps(None),
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_heartbeat_missing_agent_id_returns_400(self, client):
        resp = client.post(
            "/api/agents/heartbeat",
            data=json.dumps({"metadata": {}}),
            content_type="application/json",
        )
        assert resp.status_code == 400

    @patch("amoskys.api.agents_user.get_distribution_service")
    @patch(
        "amoskys.api.agents_user.get_session_context",
        side_effect=_fake_session_ctx,
    )
    def test_heartbeat_success(self, mock_ctx, mock_svc_fn, client):
        mock_svc = MagicMock()
        mock_svc.record_heartbeat.return_value = True
        mock_svc_fn.return_value = mock_svc

        resp = client.post(
            "/api/agents/heartbeat",
            data=json.dumps({"agent_id": "ag-1"}),
            content_type="application/json",
        )
        assert resp.status_code == 200
        assert resp.get_json()["success"] is True

    @patch("amoskys.api.agents_user.get_distribution_service")
    @patch(
        "amoskys.api.agents_user.get_session_context",
        side_effect=_fake_session_ctx,
    )
    def test_heartbeat_agent_not_found_returns_404(self, mock_ctx, mock_svc_fn, client):
        mock_svc = MagicMock()
        mock_svc.record_heartbeat.return_value = False
        mock_svc_fn.return_value = mock_svc

        resp = client.post(
            "/api/agents/heartbeat",
            data=json.dumps({"agent_id": "gone"}),
            content_type="application/json",
        )
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Tests: GET /api/user/agents/package-info
# ---------------------------------------------------------------------------


class TestGetPackageInfo:
    def test_package_info_returns_platforms(self, client):
        p1, p2 = _auth_patches()
        with p1, p2:
            client.set_cookie("amoskys_session", _VALID_TOKEN, domain="localhost")
            resp = client.get("/api/user/agents/package-info")
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["success"] is True
            assert "windows" in data["packages"]
            assert "linux" in data["packages"]
            assert "macos" in data["packages"]
            assert "docker" in data["packages"]
