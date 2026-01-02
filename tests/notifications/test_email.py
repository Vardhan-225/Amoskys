"""
Tests for AMOSKYS Email Transport Infrastructure

Comprehensive test coverage for:
- EmailConfig loading and caching
- Template rendering
- Dev mode email logging
- SMTP sending (mocked)
- High-level email helpers

Test Philosophy:
    Email is critical for security. We test every path thoroughly.
"""

from __future__ import annotations

import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Generator
from unittest.mock import MagicMock, patch

import pytest

from amoskys.notifications.email import (
    EmailConfig,
    _get_template_env,
    _log_email_to_file,
    get_email_config,
    render_template,
    reset_email_config,
    send_email,
    send_mfa_code_email,
    send_password_reset_email,
    send_security_alert_email,
    send_verification_email,
)

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture(autouse=True)
def reset_config() -> Generator[None, None, None]:
    """Reset email config cache before and after each test."""
    reset_email_config()
    yield
    reset_email_config()


@pytest.fixture
def temp_log_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for email logs."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def dev_config(temp_log_dir: Path) -> EmailConfig:
    """Create a dev mode config for testing."""
    return EmailConfig(
        smtp_host="localhost",
        smtp_port=587,
        use_tls=True,
        username="",
        password="",
        from_address="test@amoskys.com",
        from_name="AMOSKYS Test",
        dev_mode=True,
        dev_log_path=temp_log_dir,
    )


@pytest.fixture
def prod_config() -> EmailConfig:
    """Create a production mode config for testing."""
    return EmailConfig(
        smtp_host="smtp.example.com",
        smtp_port=587,
        use_tls=True,
        username="smtp_user",
        password="smtp_pass",
        from_address="security@amoskys.com",
        from_name="AMOSKYS Security",
        dev_mode=False,
    )


# =============================================================================
# EmailConfig Tests
# =============================================================================


class TestEmailConfig:
    """Tests for EmailConfig dataclass."""

    def test_default_values(self) -> None:
        """Test default config values are sensible."""
        config = EmailConfig()
        assert config.smtp_host == "localhost"
        assert config.smtp_port == 587
        assert config.use_tls is True
        assert config.dev_mode is True  # Safe default
        assert config.from_address == "security@amoskys.com"

    def test_custom_values(self) -> None:
        """Test custom config values."""
        config = EmailConfig(
            smtp_host="mail.example.com",
            smtp_port=465,
            use_tls=False,
            username="user",
            password="pass",
            dev_mode=False,
        )
        assert config.smtp_host == "mail.example.com"
        assert config.smtp_port == 465
        assert config.use_tls is False
        assert config.dev_mode is False


class TestGetEmailConfig:
    """Tests for get_email_config function."""

    def test_loads_from_environment(self) -> None:
        """Test config loads from environment variables."""
        with patch.dict(
            os.environ,
            {
                "AMOSKYS_EMAIL_SMTP_HOST": "smtp.test.com",
                "AMOSKYS_EMAIL_SMTP_PORT": "465",
                "AMOSKYS_EMAIL_USE_TLS": "false",
                "AMOSKYS_EMAIL_USERNAME": "testuser",
                "AMOSKYS_EMAIL_PASSWORD": "testpass",
                "AMOSKYS_EMAIL_FROM_ADDRESS": "test@test.com",
                "AMOSKYS_EMAIL_FROM_NAME": "Test Sender",
                "AMOSKYS_EMAIL_DEV_MODE": "false",
            },
            clear=False,
        ):
            reset_email_config()
            config = get_email_config()

            assert config.smtp_host == "smtp.test.com"
            assert config.smtp_port == 465
            assert config.use_tls is False
            assert config.username == "testuser"
            assert config.password == "testpass"
            assert config.from_address == "test@test.com"
            assert config.from_name == "Test Sender"
            assert config.dev_mode is False

    def test_caches_config(self) -> None:
        """Test config is cached after first load."""
        config1 = get_email_config()
        config2 = get_email_config()
        assert config1 is config2

    def test_reset_clears_cache(self) -> None:
        """Test reset_email_config clears cache."""
        config1 = get_email_config()
        reset_email_config()
        config2 = get_email_config()
        # Different objects (though may have same values)
        assert config1 is not config2

    def test_boolean_parsing_true_values(self) -> None:
        """Test various true boolean values are parsed correctly."""
        for true_value in ["true", "True", "TRUE", "1", "yes", "YES"]:
            reset_email_config()
            with patch.dict(
                os.environ,
                {"AMOSKYS_EMAIL_USE_TLS": true_value},
                clear=False,
            ):
                reset_email_config()
                config = get_email_config()
                assert config.use_tls is True, f"Failed for value: {true_value}"

    def test_boolean_parsing_false_values(self) -> None:
        """Test various false boolean values are parsed correctly."""
        for false_value in ["false", "False", "FALSE", "0", "no", "NO"]:
            reset_email_config()
            with patch.dict(
                os.environ,
                {"AMOSKYS_EMAIL_USE_TLS": false_value},
                clear=False,
            ):
                reset_email_config()
                config = get_email_config()
                assert config.use_tls is False, f"Failed for value: {false_value}"

    def test_default_dev_mode_is_true(self) -> None:
        """Test dev_mode defaults to True (safe default)."""
        with patch.dict(os.environ, {}, clear=False):
            # Remove any existing AMOSKYS_EMAIL_DEV_MODE
            os.environ.pop("AMOSKYS_EMAIL_DEV_MODE", None)
            reset_email_config()
            config = get_email_config()
            assert config.dev_mode is True


# =============================================================================
# Template Rendering Tests
# =============================================================================


class TestTemplateRendering:
    """Tests for email template rendering."""

    def test_template_env_creation(self) -> None:
        """Test Jinja2 environment is created correctly."""
        env = _get_template_env()
        assert env is not None
        assert env.autoescape is not None

    def test_render_verify_email_template(self) -> None:
        """Test verification email template renders correctly."""
        html = render_template(
            "verify_email.html",
            {
                "verify_url": "https://app.amoskys.com/verify?token=abc123",
                "email": "user@example.com",
                "year": 2024,
            },
        )

        assert "verify_email.html" != ""
        assert "https://app.amoskys.com/verify?token=abc123" in html
        assert "user@example.com" in html
        assert "2024" in html
        assert "Verify Email Address" in html

    def test_render_password_reset_template(self) -> None:
        """Test password reset template renders correctly."""
        html = render_template(
            "password_reset.html",
            {
                "reset_url": "https://app.amoskys.com/reset?token=xyz789",
                "email": "user@example.com",
                "year": 2024,
            },
        )

        assert "https://app.amoskys.com/reset?token=xyz789" in html
        assert "Reset Password" in html
        assert "1 hour" in html

    def test_render_security_alert_template(self) -> None:
        """Test security alert template renders correctly."""
        html = render_template(
            "security_alert.html",
            {
                "alert_type": "Login from new device",
                "details": {
                    "ip_address": "192.168.1.100",
                    "location": "New York, USA",
                    "device": "Chrome on Windows",
                },
                "email": "user@example.com",
                "year": 2024,
            },
        )

        assert "Login from new device" in html
        assert "192.168.1.100" in html
        assert "New York, USA" in html

    def test_render_mfa_code_template(self) -> None:
        """Test MFA code template renders correctly."""
        html = render_template(
            "mfa_code.html",
            {
                "code": "123456",
                "expires_minutes": 10,
                "email": "user@example.com",
                "year": 2024,
            },
        )

        assert "123456" in html
        assert "10 minutes" in html

    def test_template_xss_protection(self) -> None:
        """Test templates escape HTML to prevent XSS."""
        html = render_template(
            "verify_email.html",
            {
                "verify_url": "https://example.com",
                "email": "<script>alert('xss')</script>",
                "year": 2024,
            },
        )

        # Script tags should be escaped
        assert "<script>" not in html
        assert "&lt;script&gt;" in html


# =============================================================================
# Dev Mode Logging Tests
# =============================================================================


class TestDevModeLogging:
    """Tests for dev mode email logging."""

    def test_log_email_creates_directory(self, temp_log_dir: Path) -> None:
        """Test email log directory is created if it doesn't exist."""
        log_path = temp_log_dir / "subdir"
        config = EmailConfig(dev_log_path=log_path, dev_mode=True)

        # Create a minimal email message
        from email.message import EmailMessage

        msg = EmailMessage()
        msg["To"] = "test@example.com"
        msg["From"] = "sender@example.com"
        msg["Subject"] = "Test"
        msg.set_content("Test body")

        _log_email_to_file(config, msg)

        assert log_path.exists()
        assert (log_path / "emails.log").exists()

    def test_log_email_appends_to_file(
        self, dev_config: EmailConfig, temp_log_dir: Path
    ) -> None:
        """Test multiple emails are appended to log file."""
        from email.message import EmailMessage

        # Send two emails
        for i in range(2):
            msg = EmailMessage()
            msg["To"] = f"test{i}@example.com"
            msg["From"] = "sender@example.com"
            msg["Subject"] = f"Test {i}"
            msg.set_content(f"Body {i}")
            _log_email_to_file(dev_config, msg)

        log_file = temp_log_dir / "emails.log"
        content = log_file.read_text()

        assert "test0@example.com" in content
        assert "test1@example.com" in content
        assert content.count("=" * 80) == 2

    def test_log_includes_timestamp(
        self, dev_config: EmailConfig, temp_log_dir: Path
    ) -> None:
        """Test logged email includes timestamp."""
        from email.message import EmailMessage

        msg = EmailMessage()
        msg["To"] = "test@example.com"
        msg["From"] = "sender@example.com"
        msg["Subject"] = "Test"
        msg.set_content("Test body")

        _log_email_to_file(dev_config, msg)

        log_file = temp_log_dir / "emails.log"
        content = log_file.read_text()

        assert "Timestamp:" in content
        # Check ISO format date exists
        current_year = str(datetime.now(UTC).year)
        assert current_year in content


# =============================================================================
# send_email Tests
# =============================================================================


class TestSendEmail:
    """Tests for core send_email function."""

    def test_send_email_dev_mode(self, dev_config: EmailConfig) -> None:
        """Test send_email logs to file in dev mode."""
        result = send_email(
            to_address="user@example.com",
            subject="Test Email",
            html_body="<h1>Hello</h1>",
            config=dev_config,
        )

        assert result is True

        log_file = dev_config.dev_log_path / "emails.log"
        assert log_file.exists()

        content = log_file.read_text()
        assert "user@example.com" in content
        assert "Test Email" in content

    def test_send_email_with_text_body(self, dev_config: EmailConfig) -> None:
        """Test send_email with custom text body."""
        result = send_email(
            to_address="user@example.com",
            subject="Test",
            html_body="<h1>HTML</h1>",
            text_body="Plain text version",
            config=dev_config,
        )

        assert result is True

        log_file = dev_config.dev_log_path / "emails.log"
        content = log_file.read_text()
        assert "Plain text version" in content

    def test_send_email_with_custom_headers(self, dev_config: EmailConfig) -> None:
        """Test send_email with custom headers."""
        result = send_email(
            to_address="user@example.com",
            subject="Test",
            html_body="<h1>HTML</h1>",
            headers={"X-Custom-Header": "CustomValue"},
            config=dev_config,
        )

        assert result is True

        log_file = dev_config.dev_log_path / "emails.log"
        content = log_file.read_text()
        assert "X-Custom-Header" in content
        assert "CustomValue" in content

    def test_send_email_production_mode_success(self, prod_config: EmailConfig) -> None:
        """Test send_email sends via SMTP in production mode."""
        mock_smtp = MagicMock()

        with patch("amoskys.notifications.email.smtplib.SMTP") as mock_smtp_class:
            mock_smtp_class.return_value = mock_smtp
            mock_smtp.__enter__ = MagicMock(return_value=mock_smtp)
            mock_smtp.__exit__ = MagicMock(return_value=False)

            result = send_email(
                to_address="user@example.com",
                subject="Test Email",
                html_body="<h1>Hello</h1>",
                config=prod_config,
            )

            assert result is True
            mock_smtp.starttls.assert_called_once()
            mock_smtp.login.assert_called_once_with("smtp_user", "smtp_pass")
            mock_smtp.send_message.assert_called_once()

    def test_send_email_smtp_error_returns_false(
        self, prod_config: EmailConfig
    ) -> None:
        """Test send_email returns False on SMTP error."""
        import smtplib

        with patch("amoskys.notifications.email.smtplib.SMTP") as mock_smtp_class:
            mock_smtp_class.side_effect = smtplib.SMTPException("Connection failed")

            result = send_email(
                to_address="user@example.com",
                subject="Test",
                html_body="<h1>Test</h1>",
                config=prod_config,
            )

            assert result is False

    def test_send_email_uses_default_config(self) -> None:
        """Test send_email uses get_email_config() when config not provided."""
        with patch("amoskys.notifications.email.get_email_config") as mock_get_config:
            mock_config = EmailConfig(dev_mode=True, dev_log_path=Path("/tmp/test"))
            mock_get_config.return_value = mock_config

            with patch("amoskys.notifications.email._log_email_to_file") as mock_log:
                send_email(
                    to_address="user@example.com",
                    subject="Test",
                    html_body="<h1>Test</h1>",
                )

                mock_get_config.assert_called_once()

    def test_send_email_from_header_format(self, dev_config: EmailConfig) -> None:
        """Test from header is formatted correctly."""
        send_email(
            to_address="user@example.com",
            subject="Test",
            html_body="<h1>Test</h1>",
            config=dev_config,
        )

        log_file = dev_config.dev_log_path / "emails.log"
        content = log_file.read_text()
        assert "AMOSKYS Test <test@amoskys.com>" in content


# =============================================================================
# High-Level Email Helper Tests
# =============================================================================


class TestSendVerificationEmail:
    """Tests for send_verification_email helper."""

    def test_sends_verification_email(self, dev_config: EmailConfig) -> None:
        """Test verification email is sent correctly."""
        with patch(
            "amoskys.notifications.email.get_email_config", return_value=dev_config
        ):
            result = send_verification_email(
                email="user@example.com",
                verify_url="https://app.amoskys.com/verify?token=abc123",
            )

        assert result is True

        log_file = dev_config.dev_log_path / "emails.log"
        content = log_file.read_text()
        assert "Verify your AMOSKYS account" in content
        assert "abc123" in content

    def test_returns_false_on_template_error(self) -> None:
        """Test returns False if template rendering fails."""
        with patch(
            "amoskys.notifications.email.render_template",
            side_effect=Exception("Template error"),
        ):
            result = send_verification_email(
                email="user@example.com",
                verify_url="https://example.com",
            )

        assert result is False


class TestSendPasswordResetEmail:
    """Tests for send_password_reset_email helper."""

    def test_sends_password_reset_email(self, dev_config: EmailConfig) -> None:
        """Test password reset email is sent correctly."""
        with patch(
            "amoskys.notifications.email.get_email_config", return_value=dev_config
        ):
            result = send_password_reset_email(
                email="user@example.com",
                reset_url="https://app.amoskys.com/reset?token=xyz789",
            )

        assert result is True

        log_file = dev_config.dev_log_path / "emails.log"
        content = log_file.read_text()
        assert "Reset your AMOSKYS password" in content
        assert "xyz789" in content

    def test_returns_false_on_template_error(self) -> None:
        """Test returns False if template rendering fails."""
        with patch(
            "amoskys.notifications.email.render_template",
            side_effect=Exception("Template error"),
        ):
            result = send_password_reset_email(
                email="user@example.com",
                reset_url="https://example.com",
            )

        assert result is False


class TestSendSecurityAlertEmail:
    """Tests for send_security_alert_email helper."""

    def test_sends_security_alert_email(self, dev_config: EmailConfig) -> None:
        """Test security alert email is sent correctly."""
        with patch(
            "amoskys.notifications.email.get_email_config", return_value=dev_config
        ):
            result = send_security_alert_email(
                email="user@example.com",
                alert_type="Login from new device",
                details={
                    "ip_address": "192.168.1.1",
                    "location": "Unknown",
                },
            )

        assert result is True

        log_file = dev_config.dev_log_path / "emails.log"
        content = log_file.read_text()
        assert "Security Alert: Login from new device" in content

    def test_returns_false_on_template_error(self) -> None:
        """Test returns False if template rendering fails."""
        with patch(
            "amoskys.notifications.email.render_template",
            side_effect=Exception("Template error"),
        ):
            result = send_security_alert_email(
                email="user@example.com",
                alert_type="Test",
                details={},
            )

        assert result is False


class TestSendMfaCodeEmail:
    """Tests for send_mfa_code_email helper."""

    def test_sends_mfa_code_email(self, dev_config: EmailConfig) -> None:
        """Test MFA code email is sent correctly."""
        with patch(
            "amoskys.notifications.email.get_email_config", return_value=dev_config
        ):
            result = send_mfa_code_email(
                email="user@example.com",
                code="123456",
                expires_minutes=10,
            )

        assert result is True

        log_file = dev_config.dev_log_path / "emails.log"
        content = log_file.read_text()
        assert "Your AMOSKYS verification code: 123456" in content

    def test_uses_default_expires_minutes(self, dev_config: EmailConfig) -> None:
        """Test default expiry is 10 minutes."""
        with patch(
            "amoskys.notifications.email.get_email_config", return_value=dev_config
        ):
            result = send_mfa_code_email(
                email="user@example.com",
                code="654321",
            )

        assert result is True

    def test_returns_false_on_template_error(self) -> None:
        """Test returns False if template rendering fails."""
        with patch(
            "amoskys.notifications.email.render_template",
            side_effect=Exception("Template error"),
        ):
            result = send_mfa_code_email(
                email="user@example.com",
                code="123456",
            )

        assert result is False


# =============================================================================
# SMTP Connection Tests
# =============================================================================


class TestSmtpConnection:
    """Tests for SMTP connection handling."""

    def test_smtp_connection_with_tls(self, prod_config: EmailConfig) -> None:
        """Test SMTP connection enables TLS when configured."""
        mock_smtp = MagicMock()

        with patch("amoskys.notifications.email.smtplib.SMTP") as mock_smtp_class:
            mock_smtp_class.return_value = mock_smtp

            send_email(
                to_address="user@example.com",
                subject="Test",
                html_body="<h1>Test</h1>",
                config=prod_config,
            )

            mock_smtp.starttls.assert_called_once()

    def test_smtp_connection_without_tls(self) -> None:
        """Test SMTP connection skips TLS when disabled."""
        config = EmailConfig(
            smtp_host="localhost",
            smtp_port=25,
            use_tls=False,
            dev_mode=False,
        )
        mock_smtp = MagicMock()

        with patch("amoskys.notifications.email.smtplib.SMTP") as mock_smtp_class:
            mock_smtp_class.return_value = mock_smtp

            send_email(
                to_address="user@example.com",
                subject="Test",
                html_body="<h1>Test</h1>",
                config=config,
            )

            mock_smtp.starttls.assert_not_called()

    def test_smtp_connection_without_auth(self) -> None:
        """Test SMTP connection skips login when no username."""
        config = EmailConfig(
            smtp_host="localhost",
            smtp_port=25,
            use_tls=False,
            username="",
            password="",
            dev_mode=False,
        )
        mock_smtp = MagicMock()

        with patch("amoskys.notifications.email.smtplib.SMTP") as mock_smtp_class:
            mock_smtp_class.return_value = mock_smtp

            send_email(
                to_address="user@example.com",
                subject="Test",
                html_body="<h1>Test</h1>",
                config=config,
            )

            mock_smtp.login.assert_not_called()

    def test_smtp_connection_cleanup_on_error(self) -> None:
        """Test SMTP connection is cleaned up on send error."""
        config = EmailConfig(
            smtp_host="localhost",
            smtp_port=25,
            dev_mode=False,
        )
        mock_smtp = MagicMock()
        mock_smtp.send_message.side_effect = Exception("Send failed")

        with patch("amoskys.notifications.email.smtplib.SMTP") as mock_smtp_class:
            mock_smtp_class.return_value = mock_smtp

            result = send_email(
                to_address="user@example.com",
                subject="Test",
                html_body="<h1>Test</h1>",
                config=config,
            )

            assert result is False
            # quit or close should have been called
            assert mock_smtp.quit.called or mock_smtp.close.called


# =============================================================================
# Integration Tests
# =============================================================================


class TestEmailModuleIntegration:
    """Integration tests for the email module."""

    def test_module_exports(self) -> None:
        """Test all expected functions are exported."""
        from amoskys.notifications import (
            EmailConfig,
            get_email_config,
            reset_email_config,
            send_email,
            send_mfa_code_email,
            send_password_reset_email,
            send_security_alert_email,
            send_verification_email,
        )

        assert EmailConfig is not None
        assert callable(get_email_config)
        assert callable(reset_email_config)
        assert callable(send_email)
        assert callable(send_verification_email)
        assert callable(send_password_reset_email)
        assert callable(send_security_alert_email)
        assert callable(send_mfa_code_email)

    def test_end_to_end_dev_mode(self, temp_log_dir: Path) -> None:
        """Test full email flow in dev mode."""
        with patch.dict(
            os.environ,
            {
                "AMOSKYS_EMAIL_DEV_MODE": "true",
                "AMOSKYS_EMAIL_DEV_LOG_PATH": str(temp_log_dir),
            },
            clear=False,
        ):
            reset_email_config()

            # Send all types of emails
            send_verification_email(
                "user1@example.com", "https://app.amoskys.com/verify?token=abc"
            )
            send_password_reset_email(
                "user2@example.com", "https://app.amoskys.com/reset?token=xyz"
            )
            send_security_alert_email(
                "user3@example.com",
                "Password Changed",
                {"changed_at": "2024-01-01"},
            )
            send_mfa_code_email("user4@example.com", "999888")

            log_file = temp_log_dir / "emails.log"
            content = log_file.read_text()

            assert "user1@example.com" in content
            assert "user2@example.com" in content
            assert "user3@example.com" in content
            assert "user4@example.com" in content
            assert content.count("=" * 80) == 4

    def test_templates_exist(self) -> None:
        """Test all required templates exist."""
        from amoskys.notifications.email import _TEMPLATE_DIR

        assert (_TEMPLATE_DIR / "base.html").exists()
        assert (_TEMPLATE_DIR / "verify_email.html").exists()
        assert (_TEMPLATE_DIR / "password_reset.html").exists()
        assert (_TEMPLATE_DIR / "security_alert.html").exists()
        assert (_TEMPLATE_DIR / "mfa_code.html").exists()
