#!/usr/bin/env python3
"""
AMOSKYS Email Configuration Test Script

This script tests the email configuration by:
1. Loading the email config from environment
2. Attempting to connect to SMTP server
3. Sending a test email

Usage:
    # Test in dev mode (log to file):
    python scripts/test_email_config.py

    # Test production sending:
    AMOSKYS_EMAIL_DEV_MODE=false python scripts/test_email_config.py --send

    # Test with custom recipient:
    python scripts/test_email_config.py --to admin@amoskys.com
"""

import argparse
import os
import sys
from pathlib import Path

# Load environment from .env file
from dotenv import load_dotenv

# Load .env from project root
project_root = Path(__file__).parent.parent
env_path = project_root / ".env"
if env_path.exists():
    load_dotenv(env_path)
    print(f"Loaded environment from {env_path}")
    print()

# Add src to path
sys.path.insert(0, str(project_root / "src"))

from amoskys.notifications.email import (
    EmailConfig,
    get_email_config,
    send_email,
    send_verification_email,
)


def test_config() -> bool:
    """Test that email configuration is valid."""
    print("=" * 80)
    print("AMOSKYS Email Configuration Test")
    print("=" * 80)
    print()

    try:
        cfg = get_email_config()
        print("✅ Email configuration loaded successfully")
        print()
        print("Configuration:")
        print(f"  SMTP Host:        {cfg.smtp_host}")
        print(f"  SMTP Port:        {cfg.smtp_port}")
        print(f"  Use TLS:          {cfg.use_tls}")
        print(f"  Username:         {cfg.username or '(not set)'}")
        print(f"  Password:         {'*' * 8 if cfg.password else '(not set)'}")
        print(f"  From Address:     {cfg.from_address}")
        print(f"  From Name:        {cfg.from_name}")
        print(f"  Dev Mode:         {cfg.dev_mode}")
        if cfg.dev_mode:
            print(f"  Dev Log Path:     {cfg.dev_log_path}")
        print()

        # Validate required fields
        if not cfg.smtp_host or cfg.smtp_host == "localhost":
            print("⚠️  WARNING: SMTP host is not configured (set AMOSKYS_EMAIL_SMTP_HOST)")
            return False

        if not cfg.username:
            print("⚠️  WARNING: SMTP username not set (set AMOSKYS_EMAIL_USERNAME)")
            return False

        if not cfg.password:
            print("⚠️  WARNING: SMTP password not set (set AMOSKYS_EMAIL_PASSWORD)")
            return False

        print("✅ All required configuration fields are set")
        return True

    except Exception as e:
        print(f"❌ Failed to load email configuration: {e}")
        import traceback

        traceback.print_exc()
        return False


def test_smtp_connection() -> bool:
    """Test SMTP connection (only if not in dev mode)."""
    cfg = get_email_config()

    if cfg.dev_mode:
        print("⏭️  Skipping SMTP connection test (dev_mode=true)")
        print("   Emails will be logged to file instead of sent")
        print()
        return True

    print("Testing SMTP connection...")
    try:
        import smtplib

        server = smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=cfg.timeout_seconds)
        print(f"  ✅ Connected to {cfg.smtp_host}:{cfg.smtp_port}")

        if cfg.use_tls:
            server.starttls()
            print("  ✅ TLS started")

        if cfg.username:
            server.login(cfg.username, cfg.password)
            print(f"  ✅ Authenticated as {cfg.username}")

        server.quit()
        print("  ✅ Connection closed gracefully")
        print()
        return True

    except smtplib.SMTPAuthenticationError as e:
        print(f"  ❌ Authentication failed: {e}")
        print("     Check AMOSKYS_EMAIL_USERNAME and AMOSKYS_EMAIL_PASSWORD")
        return False

    except smtplib.SMTPException as e:
        print(f"  ❌ SMTP error: {e}")
        return False

    except Exception as e:
        print(f"  ❌ Connection failed: {e}")
        import traceback

        traceback.print_exc()
        return False


def test_send_email(to_address: str) -> bool:
    """Test sending a test email."""
    cfg = get_email_config()

    print(f"Sending test email to {to_address}...")
    print()

    html_body = """
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {
                font-family: 'Inter', sans-serif;
                background: #0a0e27;
                color: #ffffff;
                padding: 40px;
            }
            .container {
                max-width: 600px;
                margin: 0 auto;
                background: #1a1f3a;
                border: 1px solid #00d9ff;
                border-radius: 8px;
                padding: 40px;
            }
            h1 {
                color: #00d9ff;
                margin-top: 0;
            }
            .status {
                background: rgba(0, 217, 255, 0.1);
                border-left: 4px solid #00d9ff;
                padding: 16px;
                margin: 20px 0;
            }
            .footer {
                margin-top: 40px;
                padding-top: 20px;
                border-top: 1px solid rgba(0, 217, 255, 0.2);
                color: #888;
                font-size: 12px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>✅ Email Configuration Test</h1>
            <p>This is a test email from your AMOSKYS Neural Security Command Platform.</p>

            <div class="status">
                <strong>Status:</strong> Email system operational<br>
                <strong>SMTP Server:</strong> Zoho Mail Professional<br>
                <strong>Transport:</strong> TLS Encrypted
            </div>

            <p>If you're seeing this email, your AMOSKYS email configuration is working correctly!</p>

            <p><strong>Next Steps:</strong></p>
            <ul>
                <li>Set AMOSKYS_EMAIL_DEV_MODE=false for production email sending</li>
                <li>Test password reset flow</li>
                <li>Test email verification flow</li>
            </ul>

            <div class="footer">
                <p>AMOSKYS Neural Security Command Platform<br>
                This is an automated test email.</p>
            </div>
        </div>
    </body>
    </html>
    """

    success = send_email(
        to_address=to_address,
        subject="AMOSKYS Email Configuration Test ✅",
        html_body=html_body,
        text_body="This is a test email from AMOSKYS. If you're seeing this, your email configuration is working!",
    )

    if success:
        if cfg.dev_mode:
            print(f"✅ Email logged to file: {cfg.dev_log_path}/emails.log")
            print()
            print("To send actual emails, set:")
            print("  export AMOSKYS_EMAIL_DEV_MODE=false")
        else:
            print("✅ Email sent successfully!")
        print()
        return True
    else:
        print("❌ Failed to send email")
        print()
        return False


def main():
    parser = argparse.ArgumentParser(description="Test AMOSKYS email configuration")
    parser.add_argument(
        "--to",
        default="security@amoskys.com",
        help="Recipient email address (default: security@amoskys.com)",
    )
    parser.add_argument(
        "--send",
        action="store_true",
        help="Force production send (sets AMOSKYS_EMAIL_DEV_MODE=false)",
    )
    parser.add_argument(
        "--skip-smtp-test",
        action="store_true",
        help="Skip SMTP connection test",
    )

    args = parser.parse_args()

    # Override dev mode if --send specified
    if args.send:
        os.environ["AMOSKYS_EMAIL_DEV_MODE"] = "false"

    # Test 1: Configuration
    if not test_config():
        print()
        print("❌ Configuration test failed")
        sys.exit(1)

    # Test 2: SMTP Connection (optional)
    if not args.skip_smtp_test:
        if not test_smtp_connection():
            print()
            print("❌ SMTP connection test failed")
            sys.exit(1)

    # Test 3: Send test email
    if not test_send_email(args.to):
        print()
        print("❌ Email send test failed")
        sys.exit(1)

    print("=" * 80)
    print("✅ All email tests passed!")
    print("=" * 80)
    sys.exit(0)


if __name__ == "__main__":
    main()
