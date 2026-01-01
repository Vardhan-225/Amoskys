# AMOSKYS Email Configuration Guide

This guide explains how to configure email sending for the AMOSKYS platform using Zoho Mail Professional.

---

## Overview

AMOSKYS uses email for critical authentication workflows:
- ✉️ **Email Verification** - Confirm user email addresses during signup
- 🔑 **Password Reset** - Secure password recovery via email tokens
- 🔐 **Security Alerts** - Login notifications, suspicious activity alerts
- 📱 **MFA Codes** - Multi-factor authentication codes (future)

---

## Configuration Status

### ✅ Current Setup

- **Provider**: Zoho Mail Professional
- **SMTP Server**: smtppro.zoho.com
- **Port**: 587 (TLS)
- **From Address**: security@amoskys.com
- **Mode**: Development (emails logged to file)

---

## Environment Variables

All email configuration is managed via environment variables in the `.env` file:

```bash
# Email Configuration (Zoho Mail Professional)
AMOSKYS_EMAIL_SMTP_HOST=smtppro.zoho.com
AMOSKYS_EMAIL_SMTP_PORT=587
AMOSKYS_EMAIL_USE_TLS=true
AMOSKYS_EMAIL_USERNAME=security@amoskys.com
AMOSKYS_EMAIL_PASSWORD=YOUR_ZOHO_PASSWORD_HERE
AMOSKYS_EMAIL_FROM_ADDRESS=security@amoskys.com
AMOSKYS_EMAIL_FROM_NAME=AMOSKYS Security

# Dev mode: true = log to file, false = send via SMTP
AMOSKYS_EMAIL_DEV_MODE=true
AMOSKYS_EMAIL_DEV_LOG_PATH=/tmp/amoskys_emails

# Rate limits
AMOSKYS_EMAIL_MAX_PER_MINUTE=100
AMOSKYS_EMAIL_MAX_PER_HOUR=1000
AMOSKYS_EMAIL_TIMEOUT=10
```

---

## Development Mode vs Production Mode

### Development Mode (Default)

**Status**: `AMOSKYS_EMAIL_DEV_MODE=true`

**Behavior**:
- Emails are **NOT sent** via SMTP
- Instead, emails are **logged to file**: `/tmp/amoskys_emails/emails.log`
- Verification/reset tokens are **included in API responses** for easy testing
- **Safe for local development** - no risk of sending test emails to real users

**When to Use**:
- Local development and testing
- Debugging email templates
- Testing authentication flows without email infrastructure

**Testing**:
```bash
# Test dev mode (logs to file)
python scripts/test_email_config.py

# View logged emails
tail -f /tmp/amoskys_emails/emails.log
```

### Production Mode

**Status**: `AMOSKYS_EMAIL_DEV_MODE=false`

**Behavior**:
- Emails are **sent via SMTP** using Zoho Mail
- Tokens are **NOT included** in API responses (secure)
- All emails are **logged for audit** purposes
- **Requires valid SMTP credentials**

**When to Use**:
- Staging environment
- Production deployment
- User acceptance testing with real email delivery

**Testing**:
```bash
# Test production mode (sends actual email)
AMOSKYS_EMAIL_DEV_MODE=false python scripts/test_email_config.py --send --to your-email@example.com

# Monitor email logs
tail -f /var/log/amoskys/email.log
```

---

## Setting Up Zoho Mail Password

### Option 1: Use Your Zoho Account Password

**Steps**:
1. Open `.env` file in the project root
2. Locate: `AMOSKYS_EMAIL_PASSWORD=YOUR_ZOHO_PASSWORD_HERE`
3. Replace with your actual Zoho password for `security@amoskys.com`
4. Save the file

**Security Note**: The `.env` file is in `.gitignore` and will never be committed to version control.

### Option 2: Use Zoho App-Specific Password (Recommended)

**Why App-Specific Passwords?**
- More secure than using your main account password
- Can be revoked without changing your main password
- Required if you have 2FA enabled on Zoho

**Steps**:
1. Log in to Zoho Mail admin panel
2. Go to **Settings** → **Security** → **App-Specific Passwords**
3. Generate a new app password for "AMOSKYS Email Transport"
4. Copy the generated password
5. Update `.env`: `AMOSKYS_EMAIL_PASSWORD=generated-app-password`

---

## Email Templates

All email templates are located in: `/src/amoskys/notifications/templates/`

### Available Templates

1. **verify_email.html** - Email verification during signup
2. **password_reset.html** - Password reset requests
3. **security_alert.html** - Security notifications
4. **mfa_code.html** - MFA verification codes

### Template Styling

All templates use the AMOSKYS defense room theme:
- **Primary Color**: `#00d9ff` (cyan)
- **Background**: `#0a0e27` (navy dark)
- **Font**: Inter sans-serif
- **Style**: Glass morphism with neural grid patterns

### Customizing Templates

Templates use Jinja2 syntax:
```html
<h1>Welcome, {{ email }}!</h1>
<a href="{{ verify_url }}">Verify Your Email</a>
<p>This link expires in {{ expiry_hours }} hours.</p>
```

**Edit templates**:
```bash
# Edit verification email
vim src/amoskys/notifications/templates/verify_email.html

# Test changes in dev mode
python scripts/test_email_config.py
cat /tmp/amoskys_emails/emails.log
```

---

## Testing Email Configuration

### Quick Test (Dev Mode)

```bash
# Test configuration and log email to file
python scripts/test_email_config.py

# Expected output:
# ✅ Email configuration loaded successfully
# ✅ All required configuration fields are set
# ✅ Email logged to file: /tmp/amoskys_emails/emails.log
# ✅ All email tests passed!
```

### Production Test (Send Real Email)

```bash
# Test SMTP connection and send email
AMOSKYS_EMAIL_DEV_MODE=false python scripts/test_email_config.py --send --to your-email@example.com

# Expected output:
# ✅ Email configuration loaded successfully
# ✅ Connected to smtppro.zoho.com:587
# ✅ TLS started
# ✅ Authenticated as security@amoskys.com
# ✅ Email sent successfully!
```

### Testing Auth Flows

```bash
# Start Flask app in dev mode
cd web
AMOSKYS_EMAIL_DEV_MODE=true FLASK_DEBUG=true ../.venv/bin/python wsgi.py --dev

# Test signup (email verification)
curl -X POST http://localhost:5001/api/user/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"SecurePass123!"}'

# Dev mode response includes token:
# {
#   "success": true,
#   "dev_verification_token": "abc123...",
#   "dev_verify_url": "/auth/verify-email?token=abc123..."
# }

# Check logged email
cat /tmp/amoskys_emails/emails.log
```

---

## Production Deployment Checklist

Before deploying to production:

### 1. Configure Production Credentials

```bash
# Update .env for production
vim .env

# Set production password
AMOSKYS_EMAIL_PASSWORD=your-actual-zoho-password

# Disable dev mode
AMOSKYS_EMAIL_DEV_MODE=false

# Enable secure cookies (HTTPS required)
AMOSKYS_SECURE_COOKIES=true
```

### 2. Verify SMTP Connectivity

```bash
# Test production SMTP
python scripts/test_email_config.py --send --to admin@amoskys.com
```

### 3. Test Authentication Workflows

```bash
# Test signup → verification → login flow
# 1. Create account
# 2. Check email for verification link
# 3. Verify email
# 4. Login successfully

# Test password reset flow
# 1. Request password reset
# 2. Check email for reset link
# 3. Reset password
# 4. Login with new password
```

### 4. Configure Email Monitoring

```bash
# Set up log rotation
sudo vim /etc/logrotate.d/amoskys-email

# Monitor email delivery
tail -f /var/log/amoskys/email.log

# Set up alerts for failed emails
# (configure monitoring system to alert on SMTP errors)
```

### 5. Verify DNS Records

Ensure Zoho DNS records are configured:

```bash
# MX Records (for receiving email - already set up)
amoskys.com.    MX    10    mx.zoho.com.
amoskys.com.    MX    20    mx2.zoho.com.
amoskys.com.    MX    50    mx3.zoho.com.

# SPF Record (sender authentication)
amoskys.com.    TXT   "v=spf1 include:zoho.com ~all"

# DKIM Record (email signing)
# Generated by Zoho, verify in admin panel

# DMARC Record (policy)
_dmarc.amoskys.com.    TXT    "v=DMARC1; p=none; rua=mailto:security@amoskys.com"
```

---

## Troubleshooting

### Issue: "Authentication failed"

**Cause**: Invalid username or password

**Solution**:
1. Verify `AMOSKYS_EMAIL_USERNAME=security@amoskys.com`
2. Check password is correct in `.env`
3. If 2FA enabled, use app-specific password
4. Test login at https://mail.zoho.com

### Issue: "Connection timeout"

**Cause**: Firewall blocking port 587

**Solution**:
```bash
# Test connectivity
telnet smtppro.zoho.com 587

# If blocked, check firewall rules
sudo ufw allow out 587/tcp

# Or use port 465 (SSL) instead
AMOSKYS_EMAIL_SMTP_PORT=465
```

### Issue: "Emails not sending in production"

**Cause**: Dev mode still enabled

**Solution**:
```bash
# Check current mode
grep EMAIL_DEV_MODE .env

# Should be:
AMOSKYS_EMAIL_DEV_MODE=false

# Restart application after changing
```

### Issue: "Rate limit exceeded"

**Cause**: Too many emails sent too quickly

**Solution**:
```bash
# Check rate limits in .env
AMOSKYS_EMAIL_MAX_PER_MINUTE=100
AMOSKYS_EMAIL_MAX_PER_HOUR=1000

# Increase if needed (check Zoho limits first)
# Monitor email queue
```

---

## Security Best Practices

### 1. Credential Management

✅ **DO**:
- Store credentials in `.env` file (never committed)
- Use app-specific passwords when possible
- Rotate passwords regularly
- Use strong passwords (16+ characters)

❌ **DON'T**:
- Hard-code credentials in source code
- Commit `.env` to version control
- Share credentials in chat or email
- Use weak or default passwords

### 2. Email Content Security

✅ **DO**:
- Use Jinja2 templates (auto-escapes HTML)
- Sanitize all user input in emails
- Include unsubscribe links (future)
- Log all email operations for audit

❌ **DON'T**:
- Include user passwords in emails (ever!)
- Send sensitive data in email body
- Use inline JavaScript in HTML emails
- Skip rate limiting

### 3. Token Security

✅ **DO**:
- Use cryptographically secure random tokens
- Set short expiration times (24 hours for verification, 1 hour for reset)
- Invalidate tokens after use
- Hash tokens before storing in database

❌ **DON'T**:
- Include tokens in logs (redact them)
- Reuse tokens across users
- Allow tokens to work indefinitely
- Send tokens over insecure channels

---

## Rate Limits

### Zoho Mail Limits

- **Free Tier**: Not applicable (using professional)
- **Professional**: 250 emails/day per user
- **Enterprise**: Higher limits available

### AMOSKYS Default Limits

```bash
AMOSKYS_EMAIL_MAX_PER_MINUTE=100  # Max 100 emails per minute
AMOSKYS_EMAIL_MAX_PER_HOUR=1000   # Max 1000 emails per hour
```

**Adjust based on Zoho plan and usage patterns.**

---

## Additional Resources

- **Zoho Mail Documentation**: https://www.zoho.com/mail/help/
- **SMTP Settings**: https://www.zoho.com/mail/help/zoho-smtp.html
- **Email Infrastructure Code**: `/src/amoskys/notifications/email.py`
- **Email Templates**: `/src/amoskys/notifications/templates/`
- **Test Script**: `/scripts/test_email_config.py`
- **Testing Report**: `/TESTING_REPORT.md`

---

## Support

For issues or questions:
1. Check troubleshooting section above
2. Review logs: `/tmp/amoskys_emails/emails.log` (dev) or `/var/log/amoskys/email.log` (prod)
3. Test configuration: `python scripts/test_email_config.py`
4. Contact Zoho support for SMTP issues

---

**Last Updated**: 2025-12-31
**Status**: ✅ Configured and Tested
**Mode**: Development (ready for production)
