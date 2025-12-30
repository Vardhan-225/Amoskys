"""
AMOSKYS Email Transport Infrastructure

Enterprise-grade email delivery for authentication workflows:
- Email verification during signup
- Password reset notifications
- Security alerts (login from new device, etc.)
- MFA codes via email

Features:
- Dev mode: Log emails to file instead of sending (for local development)
- SMTP with TLS support
- Jinja2 templating for HTML emails
- Structured logging for all email operations
- Rate limiting hooks (implementation in P3-014)

Configuration (via environment variables):
    AMOSKYS_EMAIL_SMTP_HOST: SMTP server hostname
    AMOSKYS_EMAIL_SMTP_PORT: SMTP port (default: 587)
    AMOSKYS_EMAIL_USE_TLS: Enable TLS (default: true)
    AMOSKYS_EMAIL_USERNAME: SMTP username
    AMOSKYS_EMAIL_PASSWORD: SMTP password
    AMOSKYS_EMAIL_FROM_ADDRESS: Sender email address
    AMOSKYS_EMAIL_FROM_NAME: Sender display name
    AMOSKYS_EMAIL_DEV_MODE: Log emails instead of sending (default: true)
    AMOSKYS_EMAIL_DEV_LOG_PATH: Path to log emails in dev mode

Example Usage:
    >>> from amoskys.notifications.email import send_verification_email
    >>> send_verification_email("user@example.com", "https://app.amoskys.com/verify?token=abc123")

Design Philosophy (Akash Thanneeru + Claude Supremacy):
    Email is a critical security channel. Every email we send should be
    logged, rate-limited, and template-based to prevent injection attacks.
"""

from __future__ import annotations

import os
import smtplib
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Generator, Mapping, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from amoskys.common.logging import get_logger

__all__ = [
    "EmailConfig",
    "get_email_config",
    "reset_email_config",
    "send_email",
    "send_verification_email",
    "send_password_reset_email",
    "send_security_alert_email",
    "send_mfa_code_email",
]

logger = get_logger(__name__)


# =============================================================================
# Configuration
# =============================================================================


@dataclass
class EmailConfig:
    """
    Email transport configuration.

    Loaded from environment variables with sensible defaults for development.
    """

    smtp_host: str = "localhost"
    smtp_port: int = 587
    use_tls: bool = True
    username: str = ""
    password: str = ""
    from_address: str = "security@amoskys.com"
    from_name: str = "AMOSKYS Security"
    dev_mode: bool = True  # Safe default: log instead of send
    dev_log_path: Path = field(default_factory=lambda: Path("/tmp/amoskys_emails"))
    max_per_minute: int = 100
    max_per_hour: int = 1000
    timeout_seconds: int = 10


# Module-level config cache
_email_config: Optional[EmailConfig] = None


def get_email_config() -> EmailConfig:
    """
    Load email configuration from environment variables.

    Configuration is cached after first load.

    Returns:
        EmailConfig instance
    """
    global _email_config

    if _email_config is not None:
        return _email_config

    def get_bool(key: str, default: bool) -> bool:
        value = os.environ.get(key, "").lower()
        if value in ("true", "1", "yes"):
            return True
        if value in ("false", "0", "no"):
            return False
        return default

    _email_config = EmailConfig(
        smtp_host=os.environ.get("AMOSKYS_EMAIL_SMTP_HOST", "localhost"),
        smtp_port=int(os.environ.get("AMOSKYS_EMAIL_SMTP_PORT", "587")),
        use_tls=get_bool("AMOSKYS_EMAIL_USE_TLS", True),
        username=os.environ.get("AMOSKYS_EMAIL_USERNAME", ""),
        password=os.environ.get("AMOSKYS_EMAIL_PASSWORD", ""),
        from_address=os.environ.get(
            "AMOSKYS_EMAIL_FROM_ADDRESS", "security@amoskys.com"
        ),
        from_name=os.environ.get("AMOSKYS_EMAIL_FROM_NAME", "AMOSKYS Security"),
        dev_mode=get_bool("AMOSKYS_EMAIL_DEV_MODE", True),
        dev_log_path=Path(
            os.environ.get("AMOSKYS_EMAIL_DEV_LOG_PATH", "/tmp/amoskys_emails")
        ),
        max_per_minute=int(os.environ.get("AMOSKYS_EMAIL_MAX_PER_MINUTE", "100")),
        max_per_hour=int(os.environ.get("AMOSKYS_EMAIL_MAX_PER_HOUR", "1000")),
        timeout_seconds=int(os.environ.get("AMOSKYS_EMAIL_TIMEOUT", "10")),
    )

    logger.info(
        "Email configuration loaded",
        smtp_host=_email_config.smtp_host,
        smtp_port=_email_config.smtp_port,
        dev_mode=_email_config.dev_mode,
        from_address=_email_config.from_address,
    )

    return _email_config


def reset_email_config() -> None:
    """Reset cached config (useful for testing)."""
    global _email_config
    _email_config = None


# =============================================================================
# Template Rendering
# =============================================================================

# Template directory
_TEMPLATE_DIR = Path(__file__).parent / "templates"


def _get_template_env() -> Environment:
    """Get Jinja2 environment for email templates."""
    return Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
    )


def render_template(template_name: str, context: dict[str, Any]) -> str:
    """
    Render an email template with the given context.

    Args:
        template_name: Name of template file (e.g., "verify_email.html")
        context: Variables to pass to template

    Returns:
        Rendered HTML string
    """
    env = _get_template_env()
    template = env.get_template(template_name)
    return template.render(**context)


# =============================================================================
# SMTP Connection
# =============================================================================


@contextmanager
def _smtp_connection(cfg: EmailConfig) -> Generator[smtplib.SMTP, None, None]:
    """
    Context manager for SMTP connections.

    Handles TLS, authentication, and cleanup.
    """
    server = smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=cfg.timeout_seconds)

    try:
        if cfg.use_tls:
            server.starttls()

        if cfg.username:
            server.login(cfg.username, cfg.password)

        yield server

    finally:
        try:
            server.quit()
        except Exception:
            # If quit fails, just close the connection
            try:
                server.close()
            except Exception:
                pass


# =============================================================================
# Dev Mode Logging
# =============================================================================


def _log_email_to_file(cfg: EmailConfig, msg: EmailMessage) -> None:
    """
    Log email to file instead of sending (dev mode).

    Creates a readable log file with all email details.
    """
    cfg.dev_log_path.mkdir(parents=True, exist_ok=True)
    log_file = cfg.dev_log_path / "emails.log"

    timestamp = datetime.now(UTC).isoformat()

    with log_file.open("a", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write(f"Timestamp: {timestamp}\n")
        f.write(f"To: {msg['To']}\n")
        f.write(f"From: {msg['From']}\n")
        f.write(f"Subject: {msg['Subject']}\n")
        f.write("-" * 40 + "\n")
        f.write(str(msg))
        f.write("\n\n")

    logger.info(
        "Email logged to file (dev_mode=true)",
        path=str(log_file),
        to=msg["To"],
        subject=msg["Subject"],
    )


# =============================================================================
# Core Send Function
# =============================================================================


def send_email(
    to_address: str,
    subject: str,
    html_body: str,
    text_body: Optional[str] = None,
    headers: Optional[Mapping[str, str]] = None,
    config: Optional[EmailConfig] = None,
) -> bool:
    """
    Send an email via SMTP or log to file in dev mode.

    This is the low-level send function. Prefer using the high-level
    helpers (send_verification_email, etc.) for auth workflows.

    Args:
        to_address: Recipient email address
        subject: Email subject line
        html_body: HTML content of email
        text_body: Plain text fallback (optional, auto-generated if not provided)
        headers: Additional email headers
        config: Optional EmailConfig (uses get_email_config() if not provided)

    Returns:
        True if email was sent/logged successfully, False otherwise

    Security Notes:
        - All emails are logged for audit purposes
        - Rate limiting should be applied at the caller level
        - Never include raw tokens in logs
    """
    cfg = config or get_email_config()

    try:
        # Build email message
        msg = EmailMessage()
        msg["From"] = f"{cfg.from_name} <{cfg.from_address}>"
        msg["To"] = to_address
        msg["Subject"] = subject

        # Add custom headers
        if headers:
            for key, value in headers.items():
                msg[key] = value

        # Set content (text first, then HTML alternative)
        text_content = text_body or "Please view this email in an HTML-capable client."
        msg.set_content(text_content)
        msg.add_alternative(html_body, subtype="html")

        # Dev mode: log instead of send
        if cfg.dev_mode:
            _log_email_to_file(cfg, msg)
            return True

        # Production mode: send via SMTP
        with _smtp_connection(cfg) as smtp:
            smtp.send_message(msg)

        logger.info(
            "Email sent successfully",
            to_address=to_address,
            subject=subject,
        )
        return True

    except smtplib.SMTPException as e:
        logger.error(
            "SMTP error sending email",
            to_address=to_address,
            subject=subject,
            error=str(e),
        )
        return False

    except Exception as e:
        logger.exception(
            "Unexpected error sending email",
            to_address=to_address,
            subject=subject,
        )
        return False


# =============================================================================
# High-Level Auth Email Helpers
# =============================================================================


def send_verification_email(email: str, verify_url: str) -> bool:
    """
    Send email verification link to user.

    Used during signup to verify email ownership.

    Args:
        email: User's email address
        verify_url: Full URL with verification token

    Returns:
        True if sent successfully
    """
    try:
        html_body = render_template(
            "verify_email.html",
            {
                "verify_url": verify_url,
                "email": email,
                "year": datetime.now(UTC).year,
            },
        )
    except Exception:
        logger.exception("Failed to render verification email template")
        return False

    return send_email(
        to_address=email,
        subject="Verify your AMOSKYS account",
        html_body=html_body,
    )


def send_password_reset_email(email: str, reset_url: str) -> bool:
    """
    Send password reset link to user.

    Args:
        email: User's email address
        reset_url: Full URL with reset token

    Returns:
        True if sent successfully
    """
    try:
        html_body = render_template(
            "password_reset.html",
            {
                "reset_url": reset_url,
                "email": email,
                "year": datetime.now(UTC).year,
            },
        )
    except Exception:
        logger.exception("Failed to render password reset email template")
        return False

    return send_email(
        to_address=email,
        subject="Reset your AMOSKYS password",
        html_body=html_body,
    )


def send_security_alert_email(
    email: str,
    alert_type: str,
    details: dict[str, Any],
) -> bool:
    """
    Send security alert notification.

    Used for events like:
    - Login from new device/location
    - Password changed
    - MFA enabled/disabled
    - Suspicious activity detected

    Args:
        email: User's email address
        alert_type: Type of security event
        details: Event-specific details for template

    Returns:
        True if sent successfully
    """
    try:
        html_body = render_template(
            "security_alert.html",
            {
                "alert_type": alert_type,
                "details": details,
                "email": email,
                "year": datetime.now(UTC).year,
            },
        )
    except Exception:
        logger.exception("Failed to render security alert email template")
        return False

    return send_email(
        to_address=email,
        subject=f"AMOSKYS Security Alert: {alert_type}",
        html_body=html_body,
    )


def send_mfa_code_email(email: str, code: str, expires_minutes: int = 10) -> bool:
    """
    Send MFA verification code via email.

    Args:
        email: User's email address
        code: Numeric OTP code
        expires_minutes: Code validity period

    Returns:
        True if sent successfully
    """
    try:
        html_body = render_template(
            "mfa_code.html",
            {
                "code": code,
                "expires_minutes": expires_minutes,
                "email": email,
                "year": datetime.now(UTC).year,
            },
        )
    except Exception:
        logger.exception("Failed to render MFA code email template")
        return False

    return send_email(
        to_address=email,
        subject=f"Your AMOSKYS verification code: {code}",
        html_body=html_body,
    )
