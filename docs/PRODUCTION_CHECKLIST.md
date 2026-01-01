# AMOSKYS Production Deployment Checklist

**Version**: 1.0
**Last Updated**: 2025-12-31
**Status**: Pre-Production

---

## Pre-Deployment Checklist

### 1. Environment Configuration

- [ ] **Create production `.env` file**
  ```bash
  cp .env.template .env
  vim .env
  ```

- [ ] **Configure Email Settings**
  ```bash
  AMOSKYS_EMAIL_SMTP_HOST=smtppro.zoho.com
  AMOSKYS_EMAIL_SMTP_PORT=587
  AMOSKYS_EMAIL_USE_TLS=true
  AMOSKYS_EMAIL_USERNAME=security@amoskys.com
  AMOSKYS_EMAIL_PASSWORD=[your-production-password]
  AMOSKYS_EMAIL_DEV_MODE=false  # CRITICAL: Set to false
  ```

- [ ] **Configure Flask Settings**
  ```bash
  FLASK_ENV=production
  FLASK_DEBUG=false  # CRITICAL: Disable debug mode
  SECRET_KEY=[generate-strong-random-key]
  ```

- [ ] **Enable Secure Cookies**
  ```bash
  AMOSKYS_SECURE_COOKIES=true  # Requires HTTPS
  ```

- [ ] **Configure Database**
  ```bash
  DATABASE_URL=postgresql://user:pass@host:5432/amoskys  # Production DB
  ```

---

### 2. Security Verification

- [ ] **Test Email Sending**
  ```bash
  AMOSKYS_EMAIL_DEV_MODE=false python scripts/test_email_config.py --send
  ```

- [ ] **Verify SSL/TLS Certificates**
  ```bash
  # Check certificate expiration
  openssl s_client -connect amoskys.com:443 -servername amoskys.com | openssl x509 -noout -dates
  ```

- [ ] **Test Authentication Flow**
  - [ ] User signup with email verification
  - [ ] Email verification link works
  - [ ] Login with verified account
  - [ ] Password reset flow
  - [ ] Logout functionality

- [ ] **Verify Security Headers**
  ```bash
  curl -I https://amoskys.com/ | grep -E '(X-Frame|X-XSS|X-Content)'
  ```

- [ ] **Check Rate Limiting**
  - [ ] 50 requests/hour per auth endpoint
  - [ ] 100 emails/minute limit
  - [ ] 1000 emails/hour limit

---

### 3. DNS Configuration

- [ ] **Verify DNS Records**
  ```bash
  # MX records (for receiving email)
  dig amoskys.com MX

  # SPF record (sender authentication)
  dig amoskys.com TXT | grep spf

  # DMARC record (email policy)
  dig _dmarc.amoskys.com TXT
  ```

- [ ] **Test Email Deliverability**
  - [ ] Send test email to Gmail
  - [ ] Send test email to Outlook/Hotmail
  - [ ] Check spam folder
  - [ ] Verify SPF/DKIM/DMARC pass

---

### 4. Database Setup

- [ ] **Create Production Database**
  ```bash
  # PostgreSQL recommended for production
  createdb amoskys_production
  ```

- [ ] **Run Database Migrations**
  ```bash
  alembic upgrade head
  ```

- [ ] **Verify Database Tables**
  ```bash
  psql amoskys_production -c "\dt"
  # Should show: users, sessions, auth_audit_log, etc.
  ```

- [ ] **Configure Database Backups**
  - [ ] Daily automated backups
  - [ ] Backup retention policy (30 days)
  - [ ] Test restore procedure

---

### 5. Application Deployment

- [ ] **Install Production Dependencies**
  ```bash
  pip install -r requirements.txt
  pip install gunicorn  # Production WSGI server
  ```

- [ ] **Configure Gunicorn**
  ```bash
  # Create gunicorn.conf.py
  workers = 4
  bind = "0.0.0.0:5000"
  timeout = 120
  accesslog = "/var/log/amoskys/access.log"
  errorlog = "/var/log/amoskys/error.log"
  ```

- [ ] **Set Up Systemd Service**
  ```bash
  sudo vim /etc/systemd/system/amoskys.service
  sudo systemctl enable amoskys
  sudo systemctl start amoskys
  ```

- [ ] **Configure Nginx Reverse Proxy**
  ```nginx
  server {
      listen 443 ssl http2;
      server_name amoskys.com;

      ssl_certificate /etc/letsencrypt/live/amoskys.com/fullchain.pem;
      ssl_certificate_key /etc/letsencrypt/live/amoskys.com/privkey.pem;

      location / {
          proxy_pass http://127.0.0.1:5000;
          proxy_set_header Host $host;
          proxy_set_header X-Real-IP $remote_addr;
          proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
          proxy_set_header X-Forwarded-Proto $scheme;
      }
  }
  ```

---

### 6. Monitoring & Logging

- [ ] **Configure Log Rotation**
  ```bash
  sudo vim /etc/logrotate.d/amoskys

  /var/log/amoskys/*.log {
      daily
      rotate 30
      compress
      delaycompress
      notifempty
      create 0640 amoskys amoskys
  }
  ```

- [ ] **Set Up Application Monitoring**
  - [ ] Health check endpoint: `/api/health`
  - [ ] Uptime monitoring (e.g., UptimeRobot)
  - [ ] Error tracking (e.g., Sentry)
  - [ ] Performance monitoring (APM)

- [ ] **Configure Email Alerts**
  - [ ] Alert on SMTP failures
  - [ ] Alert on rate limit exceeded
  - [ ] Alert on authentication failures (>10/min)

---

### 7. Performance Optimization

- [ ] **Enable Gzip Compression**
  ```nginx
  gzip on;
  gzip_types text/plain text/css application/json application/javascript;
  ```

- [ ] **Configure Static File Caching**
  ```nginx
  location /static {
      alias /var/www/amoskys/static;
      expires 1y;
      add_header Cache-Control "public, immutable";
  }
  ```

- [ ] **Set Up CDN** (Optional)
  - [ ] CloudFlare for global distribution
  - [ ] Configure cache rules
  - [ ] Enable DDoS protection

---

### 8. Final Testing

- [ ] **Load Testing**
  ```bash
  # Test 100 concurrent users
  ab -n 1000 -c 100 https://amoskys.com/
  ```

- [ ] **Security Scan**
  ```bash
  # Run security vulnerability scan
  python -m bandit -r src/
  python -m safety check
  ```

- [ ] **End-to-End Testing**
  - [ ] New user signup
  - [ ] Email verification
  - [ ] Login
  - [ ] Dashboard access
  - [ ] Password reset
  - [ ] Logout
  - [ ] Agent connection

---

### 9. Documentation

- [ ] **Update Production Docs**
  - [ ] API documentation current
  - [ ] Environment variables documented
  - [ ] Deployment procedure documented
  - [ ] Troubleshooting guide updated

- [ ] **Create Runbooks**
  - [ ] Incident response procedures
  - [ ] Backup and restore procedures
  - [ ] Rollback procedures
  - [ ] Emergency contacts

---

### 10. Go-Live

- [ ] **Schedule Maintenance Window**
  - [ ] Notify users of deployment
  - [ ] Set up status page

- [ ] **Deploy to Production**
  ```bash
  git checkout main
  git pull origin main
  sudo systemctl restart amoskys
  sudo systemctl restart nginx
  ```

- [ ] **Verify Deployment**
  - [ ] Check application logs: `tail -f /var/log/amoskys/error.log`
  - [ ] Test all critical flows
  - [ ] Monitor error rates
  - [ ] Verify email delivery

- [ ] **Post-Deployment Monitoring**
  - [ ] Monitor for 24 hours
  - [ ] Check error logs hourly
  - [ ] Verify email delivery rates
  - [ ] Monitor database performance

---

## Rollback Plan

If critical issues occur:

1. **Stop new user signups**
   ```bash
   # Temporarily disable signup endpoint
   sudo vim /etc/nginx/sites-enabled/amoskys
   # Add: return 503 for /api/user/auth/signup
   sudo systemctl reload nginx
   ```

2. **Rollback to previous version**
   ```bash
   git checkout <previous-stable-commit>
   sudo systemctl restart amoskys
   ```

3. **Restore database** (if needed)
   ```bash
   pg_restore -d amoskys_production /backups/amoskys_latest.dump
   ```

4. **Communicate with users**
   - Post status update
   - Send email notification (if needed)
   - Update ETA for fix

---

## Post-Production Tasks

- [ ] **Monitor for 1 week**
  - [ ] Daily log review
  - [ ] Performance metrics analysis
  - [ ] User feedback collection

- [ ] **Optimize based on metrics**
  - [ ] Database query optimization
  - [ ] Caching improvements
  - [ ] Email delivery optimization

- [ ] **Security Audit**
  - [ ] Penetration testing
  - [ ] Code review for vulnerabilities
  - [ ] Third-party security scan

---

## Critical Contacts

- **System Administrator**: [contact]
- **Database Administrator**: [contact]
- **Security Lead**: [contact]
- **Zoho Support**: support@zoho.com
- **DNS Provider**: [contact]
- **Hosting Provider**: [contact]

---

## Environment Variables Quick Reference

```bash
# Email (Production)
AMOSKYS_EMAIL_DEV_MODE=false
AMOSKYS_EMAIL_SMTP_HOST=smtppro.zoho.com
AMOSKYS_EMAIL_SMTP_PORT=587
AMOSKYS_EMAIL_USERNAME=security@amoskys.com
AMOSKYS_EMAIL_PASSWORD=[production-password]

# Flask (Production)
FLASK_ENV=production
FLASK_DEBUG=false
SECRET_KEY=[random-256-bit-key]

# Security (Production)
AMOSKYS_SECURE_COOKIES=true

# Database (Production)
DATABASE_URL=postgresql://user:pass@host:5432/amoskys
```

---

**Ready for Production**: ⏳ Pending Final Checks
**Next Review**: Before deployment
**Contact**: security@amoskys.com
