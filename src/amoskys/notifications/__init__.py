"""
AMOSKYS Notifications Module

Enterprise-grade notification delivery for authentication and security workflows.

This module provides:
    - Email transport infrastructure (SMTP with TLS, dev mode logging)
    - HTML email templates for auth workflows
    - Structured logging for all notification operations

Usage:
    >>> from amoskys.notifications import send_verification_email
    >>> send_verification_email("user@example.com", "https://app.amoskys.com/verify?token=abc")

Design Philosophy (Akash Thanneeru + Claude Supremacy):
    Notifications are a critical security channel. Every notification sent
    must be logged, rate-limited, and template-based to prevent injection.
"""

from amoskys.notifications.email import (
    EmailConfig,
    get_email_config,
    reset_email_config,
    send_email,
    send_mfa_code_email,
    send_password_reset_email,
    send_security_alert_email,
    send_verification_email,
)

__all__ = [
    # Configuration
    "EmailConfig",
    "get_email_config",
    "reset_email_config",
    # Core send
    "send_email",
    # High-level helpers
    "send_verification_email",
    "send_password_reset_email",
    "send_security_alert_email",
    "send_mfa_code_email",
]
