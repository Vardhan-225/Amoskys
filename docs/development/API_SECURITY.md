# AMOSKYS API Security Documentation

## Overview

The AMOSKYS authentication API implements multiple layers of security to protect against common web application attacks and ensure data privacy.

---

## Security Features

### 1. Rate Limiting (Flask-Limiter)

**Purpose:** Prevent brute-force attacks, spam, and resource exhaustion.

**Implementation:**
- Global default: 200 requests/day, 50 requests/hour per IP
- Authentication endpoints have stricter limits
- Uses in-memory storage (development) or Redis (production)

**Endpoint-Specific Limits:**

| Endpoint | Rate Limit | Purpose |
|----------|------------|---------|
| `/api/auth/signup` | 10 per hour | Prevent spam account creation |
| `/api/auth/login` | 5 per minute | Prevent brute-force password attacks |
| `/api/auth/forgot-password` | 1 per minute | Prevent email enumeration |
| All other endpoints | 50 per hour | General API protection |

**Response when limit exceeded:**
```json
HTTP 429 Too Many Requests
{
  "error": "Rate limit exceeded. Please try again later.",
  "error_code": "RATE_LIMIT_EXCEEDED",
  "retry_after": "59 seconds"
}
```

**Configuration:**
```bash
# Use Redis for production (supports distributed systems)
export RATE_LIMIT_STORAGE_URL="redis://localhost:6379/0"
```

---

### 2. Security Headers (Flask-Talisman)

**Purpose:** Protect against XSS, clickjacking, and other browser-based attacks.

**Headers Applied:**

| Header | Value | Protection Against |
|--------|-------|-------------------|
| `Strict-Transport-Security` | max-age=31536000 | HTTPS downgrade attacks |
| `X-Content-Type-Options` | nosniff | MIME type sniffing |
| `X-Frame-Options` | DENY | Clickjacking |
| `X-XSS-Protection` | 1; mode=block | Cross-site scripting |
| `Content-Security-Policy` | (see CSP below) | XSS, data injection |
| `Referrer-Policy` | strict-origin-when-cross-origin | Information leakage |

**Content Security Policy (CSP):**
```
default-src 'self';
script-src 'self' 'unsafe-inline' cdn.jsdelivr.net;
style-src 'self' 'unsafe-inline';
img-src 'self' data: https:;
connect-src 'self' ws: wss:;
frame-ancestors 'none';
base-uri 'self';
form-action 'self';
```

**Configuration:**
```bash
# Force HTTPS redirects (production)
export FORCE_HTTPS=true

# Development mode disables strict CSP
export FLASK_DEBUG=true
```

---

### 3. Session Security

**Purpose:** Secure authentication state management.

**Features:**
- HTTPOnly cookies (prevents JavaScript access)
- Secure flag (HTTPS only in production)
- SameSite=Lax (CSRF protection)
- 24-hour expiration with 2-hour idle timeout
- SHA-256 token hashing (never store plaintext)
- IP/User-Agent binding (optional)

**Cookie Configuration:**
```python
SESSION_COOKIE_NAME = "amoskys_session"
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = True  # In production
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_MAX_AGE = 86400  # 24 hours
```

**Environment Variables:**
```bash
# Session configuration
export AMOSKYS_SESSION_LIFETIME_HOURS=24
export AMOSKYS_SESSION_IDLE_TIMEOUT_HOURS=2
export AMOSKYS_SESSION_MAX_PER_USER=10
export AMOSKYS_SESSION_BIND_IP=false
export AMOSKYS_SESSION_BIND_UA=false
```

---

### 4. Password Security

**Purpose:** Protect user passwords from compromise.

**Features:**
- Argon2id hashing (OWASP 2024 recommendations)
- Configurable password policy
- Common password blocklist (122 passwords)
- Automatic rehashing on parameter upgrades

**Password Policy (Default):**
- Minimum 8 characters
- At least 1 uppercase letter
- At least 1 lowercase letter
- At least 1 digit
- At least 1 special character
- Not in common password list

**Argon2id Parameters:**
```python
time_cost=3          # Iterations
memory_cost=64*1024  # 64 MB
parallelism=4        # Threads
hash_len=32          # 256 bits
salt_len=16          # 128 bits
```

---

### 5. Audit Logging

**Purpose:** Security incident investigation and compliance.

**Events Logged:**
- All authentication attempts (success/failure)
- Password changes and resets
- Session creation and revocation
- Account lockouts
- Email verification
- Security alerts

**Log Fields:**
```python
{
  "user_id": "uuid",
  "event_type": "LOGIN_FAILURE",
  "ip_address": "192.168.1.1",
  "user_agent": "Mozilla/5.0...",
  "event_metadata": {"reason": "invalid_password"},
  "created_at": "2025-12-30T15:30:00Z"
}
```

**Querying Audit Logs:**
```python
from amoskys.auth import AuthAuditLog
from amoskys.db import get_session_context

with get_session_context() as db:
    # Failed login attempts in last hour
    recent_failures = db.query(AuthAuditLog).filter(
        AuthAuditLog.event_type == AuditEventType.LOGIN_FAILURE,
        AuthAuditLog.created_at > datetime.utcnow() - timedelta(hours=1)
    ).all()
```

---

### 6. CSRF Protection

**Status:** ✅ Built-in via SameSite cookies

**How it works:**
- SameSite=Lax prevents CSRF for state-changing requests
- For forms, use Flask-WTF (optional enhancement)

**For HTML Forms (if needed):**
```python
from flask_wtf import FlaskForm, CSRFProtect

csrf = CSRFProtect()
csrf.init_app(app)
```

---

### 7. API Key Authentication (Optional)

**Purpose:** Secure programmatic API access.

**Usage:**
```python
from amoskys.api.security import require_api_key

@api_bp.route('/admin/users')
@require_api_key
def list_users():
    # Only accessible with valid API key
    pass
```

**Client Request:**
```bash
curl -H "X-API-Key: your-secret-key" \
  http://localhost:5000/api/admin/users
```

**Configuration:**
```bash
export AMOSKYS_API_KEY="your-secret-api-key"
```

---

## Testing Security Features

### Test Rate Limiting
```bash
# Should succeed 5 times, then fail
for i in {1..6}; do
  curl -X POST http://localhost:5000/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"test@example.com","password":"wrong"}'
  sleep 1
done
```

### Test Security Headers
```bash
curl -I http://localhost:5000/api/auth/me
# Should see X-Content-Type-Options, X-Frame-Options, etc.
```

### Test Session Security
```bash
# Login
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -c cookies.txt \
  -d '{"email":"test@example.com","password":"SecurePass123!"}'

# Access protected endpoint
curl -X GET http://localhost:5000/api/auth/me -b cookies.txt

# Logout
curl -X POST http://localhost:5000/api/auth/logout -b cookies.txt

# Should fail after logout
curl -X GET http://localhost:5000/api/auth/me -b cookies.txt
```

---

## Production Checklist

- [ ] Set `FLASK_DEBUG=false`
- [ ] Set strong `SECRET_KEY` (32+ random bytes)
- [ ] Enable `FORCE_HTTPS=true`
- [ ] Configure Redis for rate limiting
- [ ] Set up PostgreSQL (not SQLite)
- [ ] Configure SMTP for production emails
- [ ] Enable firewall rules (allow 443, deny others)
- [ ] Set up SSL/TLS certificates
- [ ] Configure `ALLOWED_ORIGINS` for CORS (if needed)
- [ ] Review and adjust rate limits for your use case
- [ ] Set up monitoring for failed auth attempts
- [ ] Configure backup strategy for audit logs

---

## Security Best Practices

### Development
1. Never commit `.env` files with secrets
2. Use different database for dev/staging/prod
3. Test with email verification disabled locally
4. Review security headers in browser dev tools

### Production
1. Enable all security features
2. Monitor audit logs daily
3. Rotate API keys regularly
4. Use environment-specific secrets
5. Enable database encryption at rest
6. Set up alerts for suspicious activity
7. Perform regular security audits
8. Keep dependencies updated

---

## Common Security Scenarios

### Preventing Brute-Force Attacks
✅ Login rate limit: 5 attempts/minute
✅ Account lockout after 5 failed attempts
✅ Audit logging of all failures

### Preventing Account Enumeration
✅ Forgot password always returns success
✅ Signup doesn't reveal if email exists
✅ Generic error messages for invalid credentials

### Preventing Session Hijacking
✅ HTTPOnly cookies (no JS access)
✅ Secure flag (HTTPS only)
✅ Session token stored as SHA-256 hash
✅ Optional IP/User-Agent binding

### Preventing XSS
✅ Content Security Policy
✅ X-XSS-Protection header
✅ Output encoding in templates
✅ Input validation on all endpoints

### Preventing CSRF
✅ SameSite=Lax cookies
✅ Origin/Referer validation (future)
✅ Token-based CSRF (optional with Flask-WTF)

---

## Reporting Security Issues

If you discover a security vulnerability:

1. **DO NOT** create a public GitHub issue
2. Email security@amoskys.com with details
3. Include: Description, Steps to reproduce, Impact assessment
4. We'll respond within 48 hours

---

## License & Credits

Security implementation based on:
- OWASP Top 10 (2021)
- NIST Cybersecurity Framework
- Flask Security Best Practices
- Argon2 Password Hashing Competition Winner

Built with:
- Flask-Limiter
- Flask-Talisman
- Argon2-CFFI
- SQLAlchemy

---

*Last updated: December 30, 2025*
