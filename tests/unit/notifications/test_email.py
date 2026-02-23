"""
Tests for amoskys.notifications.email — Email Transport Infrastructure.

Covers:
  - EmailConfig dataclass
  - get_email_config / reset_email_config
  - render_template
  - send_email (dev mode and production mode)
  - _smtp_connection context manager
  - _log_email_to_file
  - send_verification_email
  - send_password_reset_email
  - send_security_alert_email
  - send_mfa_code_email
"""

from __future__ import annotations

import smtplib
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

import pytest

from amoskys.notifications.email import (
    EmailConfig,
    _log_email_to_file,
    _smtp_connection,
    get_email_config,
    render_template,
    reset_email_config,
    send_email,
    send_mfa_code_email,
    send_password_reset_email,
    send_security_alert_email,
    send_verification_email,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clear_config_cache():
    """Ensure each test starts with a fresh config."""
    reset_email_config()
    yield
    reset_email_config()


def _dev_config(**overrides) -> EmailConfig:
    """Return an EmailConfig in dev mode (logging, not sending)."""
    defaults = dict(
        smtp_host="localhost",
        smtp_port=587,
        use_tls=True,
        username="",
        password="",
        from_address="test@amoskys.com",
        from_name="Test",
        dev_mode=True,
        dev_log_path=Path("/tmp/amoskys_test_emails"),
    )
    defaults.update(overrides)
    return EmailConfig(**defaults)


def _prod_config(**overrides) -> EmailConfig:
    """Return an EmailConfig in production mode."""
    defaults = dict(
        smtp_host="smtp.example.com",
        smtp_port=587,
        use_tls=True,
        username="user",
        password="pass",
        from_address="security@amoskys.com",
        from_name="AMOSKYS",
        dev_mode=False,
    )
    defaults.update(overrides)
    return EmailConfig(**defaults)


# ---------------------------------------------------------------------------
# Tests: EmailConfig dataclass
# ---------------------------------------------------------------------------


class TestEmailConfig:
    def test_defaults(self):
        cfg = EmailConfig()
        assert cfg.smtp_host == "localhost"
        assert cfg.smtp_port == 587
        assert cfg.use_tls is True
        assert cfg.dev_mode is True
        assert cfg.from_address == "security@amoskys.com"
        assert cfg.max_per_minute == 100
        assert cfg.timeout_seconds == 10

    def test_custom_values(self):
        cfg = EmailConfig(smtp_host="mail.test", smtp_port=465, dev_mode=False)
        assert cfg.smtp_host == "mail.test"
        assert cfg.smtp_port == 465
        assert cfg.dev_mode is False


# ---------------------------------------------------------------------------
# Tests: get_email_config / reset_email_config
# ---------------------------------------------------------------------------


class TestGetEmailConfig:
    def test_loads_from_env(self):
        env = {
            "AMOSKYS_EMAIL_SMTP_HOST": "smtp.test.com",
            "AMOSKYS_EMAIL_SMTP_PORT": "465",
            "AMOSKYS_EMAIL_USE_TLS": "false",
            "AMOSKYS_EMAIL_USERNAME": "u",
            "AMOSKYS_EMAIL_PASSWORD": "p",
            "AMOSKYS_EMAIL_FROM_ADDRESS": "from@t.com",
            "AMOSKYS_EMAIL_FROM_NAME": "Name",
            "AMOSKYS_EMAIL_DEV_MODE": "false",
            "AMOSKYS_EMAIL_DEV_LOG_PATH": "/tmp/testlogs",
            "AMOSKYS_EMAIL_MAX_PER_MINUTE": "50",
            "AMOSKYS_EMAIL_MAX_PER_HOUR": "500",
            "AMOSKYS_EMAIL_TIMEOUT": "5",
        }
        with patch.dict("os.environ", env, clear=False):
            cfg = get_email_config()
            assert cfg.smtp_host == "smtp.test.com"
            assert cfg.smtp_port == 465
            assert cfg.use_tls is False
            assert cfg.username == "u"
            assert cfg.password == "p"
            assert cfg.from_address == "from@t.com"
            assert cfg.from_name == "Name"
            assert cfg.dev_mode is False
            assert cfg.max_per_minute == 50
            assert cfg.max_per_hour == 500
            assert cfg.timeout_seconds == 5

    def test_caches_config(self):
        """Second call returns same object."""
        cfg1 = get_email_config()
        cfg2 = get_email_config()
        assert cfg1 is cfg2

    def test_reset_clears_cache(self):
        cfg1 = get_email_config()
        reset_email_config()
        cfg2 = get_email_config()
        # After reset, we get a new config object
        assert cfg1 is not cfg2

    def test_get_bool_true_variants(self):
        """Test 'true', '1', 'yes' are all truthy."""
        for val in ("true", "1", "yes"):
            reset_email_config()
            with patch.dict("os.environ", {"AMOSKYS_EMAIL_USE_TLS": val}, clear=False):
                cfg = get_email_config()
                assert cfg.use_tls is True

    def test_get_bool_false_variants(self):
        """Test 'false', '0', 'no' are all falsy."""
        for val in ("false", "0", "no"):
            reset_email_config()
            with patch.dict("os.environ", {"AMOSKYS_EMAIL_DEV_MODE": val}, clear=False):
                cfg = get_email_config()
                assert cfg.dev_mode is False


# ---------------------------------------------------------------------------
# Tests: render_template
# ---------------------------------------------------------------------------


class TestRenderTemplate:
    @patch("amoskys.notifications.email._get_template_env")
    def test_render_template_calls_jinja(self, mock_env):
        mock_tmpl = MagicMock()
        mock_tmpl.render.return_value = "<h1>Hi</h1>"
        mock_env.return_value.get_template.return_value = mock_tmpl

        result = render_template("verify_email.html", {"email": "a@b.com"})
        assert result == "<h1>Hi</h1>"
        mock_tmpl.render.assert_called_once_with(email="a@b.com")


# ---------------------------------------------------------------------------
# Tests: _smtp_connection
# ---------------------------------------------------------------------------


class TestSmtpConnection:
    @patch("amoskys.notifications.email.smtplib.SMTP")
    def test_connects_with_tls_and_login(self, mock_smtp_cls):
        mock_server = MagicMock()
        mock_smtp_cls.return_value = mock_server

        cfg = _prod_config()
        with _smtp_connection(cfg) as server:
            assert server is mock_server

        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_once_with("user", "pass")
        mock_server.quit.assert_called_once()

    @patch("amoskys.notifications.email.smtplib.SMTP")
    def test_no_tls_when_disabled(self, mock_smtp_cls):
        mock_server = MagicMock()
        mock_smtp_cls.return_value = mock_server

        cfg = _prod_config(use_tls=False)
        with _smtp_connection(cfg) as server:
            pass

        mock_server.starttls.assert_not_called()

    @patch("amoskys.notifications.email.smtplib.SMTP")
    def test_no_login_when_no_username(self, mock_smtp_cls):
        mock_server = MagicMock()
        mock_smtp_cls.return_value = mock_server

        cfg = _prod_config(username="")
        with _smtp_connection(cfg) as server:
            pass

        mock_server.login.assert_not_called()

    @patch("amoskys.notifications.email.smtplib.SMTP")
    def test_close_fallback_when_quit_fails(self, mock_smtp_cls):
        mock_server = MagicMock()
        mock_server.quit.side_effect = smtplib.SMTPException("already closed")
        mock_smtp_cls.return_value = mock_server

        cfg = _prod_config(use_tls=False, username="")
        with _smtp_connection(cfg) as server:
            pass

        mock_server.close.assert_called_once()

    @patch("amoskys.notifications.email.smtplib.SMTP")
    def test_close_also_fails_silently(self, mock_smtp_cls):
        mock_server = MagicMock()
        mock_server.quit.side_effect = Exception("fail")
        mock_server.close.side_effect = Exception("also fail")
        mock_smtp_cls.return_value = mock_server

        cfg = _prod_config(use_tls=False, username="")
        # Should not raise
        with _smtp_connection(cfg) as server:
            pass


# ---------------------------------------------------------------------------
# Tests: _log_email_to_file
# ---------------------------------------------------------------------------


class TestLogEmailToFile:
    @patch("amoskys.notifications.email.Path.open", new_callable=mock_open)
    @patch("amoskys.notifications.email.Path.mkdir")
    def test_logs_email_fields(self, mock_mkdir, mock_file):
        from email.message import EmailMessage

        cfg = _dev_config()
        msg = EmailMessage()
        msg["To"] = "a@b.com"
        msg["From"] = "test@amoskys.com"
        msg["Subject"] = "Test"
        msg.set_content("Hello")

        _log_email_to_file(cfg, msg)

        mock_mkdir.assert_called_once_with(parents=True, exist_ok=True)
        handle = mock_file()
        written = "".join(c.args[0] for c in handle.write.call_args_list)
        assert "a@b.com" in written
        assert "Test" in written


# ---------------------------------------------------------------------------
# Tests: send_email
# ---------------------------------------------------------------------------


class TestSendEmail:
    def test_dev_mode_logs_to_file(self):
        cfg = _dev_config()

        with patch("amoskys.notifications.email._log_email_to_file") as mock_log:
            result = send_email(
                to_address="a@b.com",
                subject="Hi",
                html_body="<p>Hello</p>",
                config=cfg,
            )

            assert result is True
            mock_log.assert_called_once()

    @patch("amoskys.notifications.email._smtp_connection")
    def test_production_sends_via_smtp(self, mock_conn):
        cfg = _prod_config()
        mock_server = MagicMock()
        mock_conn.return_value.__enter__ = MagicMock(return_value=mock_server)
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)

        result = send_email(
            to_address="a@b.com",
            subject="Hi",
            html_body="<p>Hello</p>",
            config=cfg,
        )

        assert result is True
        mock_server.send_message.assert_called_once()

    @patch("amoskys.notifications.email._smtp_connection")
    def test_smtp_error_returns_false(self, mock_conn):
        cfg = _prod_config()
        mock_conn.return_value.__enter__ = MagicMock(
            side_effect=smtplib.SMTPException("fail")
        )
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)

        result = send_email(
            to_address="a@b.com",
            subject="Hi",
            html_body="<p>Hello</p>",
            config=cfg,
        )

        assert result is False

    def test_unexpected_error_returns_false(self):
        cfg = _prod_config()

        with patch(
            "amoskys.notifications.email._smtp_connection",
            side_effect=RuntimeError("boom"),
        ):
            result = send_email(
                to_address="a@b.com",
                subject="Hi",
                html_body="<p>Hello</p>",
                config=cfg,
            )

            assert result is False

    def test_custom_headers_added(self):
        cfg = _dev_config()

        with patch("amoskys.notifications.email._log_email_to_file") as mock_log:
            send_email(
                to_address="a@b.com",
                subject="Hi",
                html_body="<p>Hello</p>",
                headers={"X-Custom": "value"},
                config=cfg,
            )

            msg = mock_log.call_args[0][1]
            assert msg["X-Custom"] == "value"

    def test_text_body_fallback(self):
        cfg = _dev_config()

        with patch("amoskys.notifications.email._log_email_to_file") as mock_log:
            send_email(
                to_address="a@b.com",
                subject="Hi",
                html_body="<p>Hello</p>",
                text_body="plain text",
                config=cfg,
            )

            # Should succeed with both text and html
            assert mock_log.called

    def test_uses_global_config_when_none_provided(self):
        with patch("amoskys.notifications.email._log_email_to_file"):
            result = send_email(
                to_address="a@b.com",
                subject="Hi",
                html_body="<p>Hello</p>",
            )
            # Default config is dev mode, should log
            assert result is True


# ---------------------------------------------------------------------------
# Tests: High-level email helpers
# ---------------------------------------------------------------------------


class TestSendVerificationEmail:
    @patch("amoskys.notifications.email.send_email", return_value=True)
    @patch(
        "amoskys.notifications.email.render_template", return_value="<h1>Verify</h1>"
    )
    def test_sends_verification(self, mock_render, mock_send):
        result = send_verification_email("a@b.com", "https://verify.me/tok")
        assert result is True
        mock_render.assert_called_once()
        args = mock_render.call_args
        assert args[0][0] == "verify_email.html"
        assert args[0][1]["verify_url"] == "https://verify.me/tok"
        mock_send.assert_called_once()

    @patch(
        "amoskys.notifications.email.render_template", side_effect=Exception("no tmpl")
    )
    def test_template_error_returns_false(self, mock_render):
        result = send_verification_email("a@b.com", "https://verify.me/tok")
        assert result is False


class TestSendPasswordResetEmail:
    @patch("amoskys.notifications.email.send_email", return_value=True)
    @patch("amoskys.notifications.email.render_template", return_value="<h1>Reset</h1>")
    def test_sends_reset(self, mock_render, mock_send):
        result = send_password_reset_email("a@b.com", "https://reset.me/tok")
        assert result is True
        mock_render.assert_called_once()
        args = mock_render.call_args
        assert args[0][0] == "password_reset.html"
        assert args[0][1]["reset_url"] == "https://reset.me/tok"

    @patch("amoskys.notifications.email.render_template", side_effect=Exception("fail"))
    def test_template_error_returns_false(self, mock_render):
        result = send_password_reset_email("a@b.com", "https://reset.me/tok")
        assert result is False


class TestSendSecurityAlertEmail:
    @patch("amoskys.notifications.email.send_email", return_value=True)
    @patch("amoskys.notifications.email.render_template", return_value="<h1>Alert</h1>")
    def test_sends_alert(self, mock_render, mock_send):
        result = send_security_alert_email("a@b.com", "New Login", {"ip": "1.2.3.4"})
        assert result is True
        mock_render.assert_called_once()
        args = mock_render.call_args
        assert args[0][0] == "security_alert.html"
        assert args[0][1]["alert_type"] == "New Login"
        mock_send.assert_called_once()
        assert "Security Alert" in mock_send.call_args[1]["subject"]

    @patch("amoskys.notifications.email.render_template", side_effect=Exception("fail"))
    def test_template_error_returns_false(self, mock_render):
        result = send_security_alert_email("a@b.com", "X", {})
        assert result is False


class TestSendMfaCodeEmail:
    @patch("amoskys.notifications.email.send_email", return_value=True)
    @patch("amoskys.notifications.email.render_template", return_value="<h1>MFA</h1>")
    def test_sends_mfa_code(self, mock_render, mock_send):
        result = send_mfa_code_email("a@b.com", "123456")
        assert result is True
        mock_render.assert_called_once()
        args = mock_render.call_args
        assert args[0][0] == "mfa_code.html"
        assert args[0][1]["code"] == "123456"
        assert args[0][1]["expires_minutes"] == 10

    @patch("amoskys.notifications.email.send_email", return_value=True)
    @patch("amoskys.notifications.email.render_template", return_value="<h1>MFA</h1>")
    def test_custom_expiry(self, mock_render, mock_send):
        result = send_mfa_code_email("a@b.com", "999999", expires_minutes=5)
        assert result is True
        assert mock_render.call_args[0][1]["expires_minutes"] == 5

    @patch("amoskys.notifications.email.render_template", side_effect=Exception("fail"))
    def test_template_error_returns_false(self, mock_render):
        result = send_mfa_code_email("a@b.com", "123456")
        assert result is False
