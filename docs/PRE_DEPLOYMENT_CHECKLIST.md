# AMOSKYS Pre-Deployment Checklist

**Last Updated:** January 1, 2026  
**Status:** Pre-Production Review

## 🔍 Comprehensive Review Summary

### ✅ Completed Items

| Category | Item | Status |
|----------|------|--------|
| **Authentication** | User signup/login/logout | ✅ Working |
| **Authentication** | Session management | ✅ Working |
| **Authentication** | Password reset flow | ✅ Implemented |
| **Authentication** | Email verification | ✅ Implemented |
| **Admin Panel** | User management | ✅ Working |
| **Admin Panel** | Audit logging | ✅ Working |
| **Admin Panel** | User deletion with confirmation | ✅ Working |
| **Admin Panel** | Session revocation | ✅ Working |
| **Security** | Rate limiting on auth endpoints | ✅ Implemented |
| **Security** | CSRF protection | ✅ Flask default |
| **Security** | Secure headers (Talisman) | ✅ Implemented |
| **Security** | Password hashing (bcrypt) | ✅ Implemented |
| **UI/UX** | Dashboard views | ✅ Working |
| **UI/UX** | 404 error page | ✅ Polished |
| **UI/UX** | 500 error page | ✅ Polished |
| **UI/UX** | Toast notifications | ✅ Improved |
| **Database** | Web database separation | ✅ Complete |
| **Database** | Schema migrations | ✅ Complete |
| **Logging** | Structured JSON logging | ✅ Implemented |
| **Logging** | Request correlation IDs | ✅ Implemented |
| **Config** | Environment variable template | ✅ Created |

---

## 🔧 Items Requiring Attention

### 1. Code Quality Issues

#### Bare `except:` Clauses ✅ FIXED
All bare except clauses have been replaced with specific exception types:
- `src/amoskys/agents/proc/proc_agent.py` → `except OSError:`
- `src/amoskys/agents/auth/auth_agent.py` → `except OSError:`
- `src/amoskys/agents/persistence/persistence_agent.py` → `except OSError:`
- `src/amoskys/agents/peripheral/peripheral_agent.py` → `except OSError:`
- `web/app/api/database_manager.py` → `except Exception:`

#### Print Statements (Low Priority - CLI Output)
The print statements in `src/amoskys/intel/fusion_engine.py` are intentional CLI output for the command-line interface. These are appropriate for user-facing output.

---

### 2. Security Considerations

#### WSGI Development Mode
**File:** `web/wsgi.py`
```python
socketio.run(app, host='0.0.0.0', port=port, debug=True, allow_unsafe_werkzeug=True)
```
**Status:** ✅ OK - Only runs with `--dev` flag

#### Secret Key Warning
**File:** `web/app/__init__.py`
**Status:** ✅ OK - Warns if using default key in production

#### CORS Configuration
**File:** `src/amoskys/api/security.py`
**Status:** ⚠️ Commented out - Enable if using separate frontend

---

### 3. Configuration Requirements

Before deployment, ensure these environment variables are set:

```bash
# Required
SECRET_KEY=<random-32+-char-string>
DATABASE_URL=<database-connection-url>
WEB_DATABASE_URL=<web-database-connection-url>

# Email (Required for email verification)
SMTP_HOST=<smtp-server>
SMTP_PORT=587
SMTP_USER=<email>
SMTP_PASSWORD=<password>

# Security
AMOSKYS_SECURE_COOKIES=true  # Enable with HTTPS

# Logging
LOG_LEVEL=INFO
JSON_LOGS=true
```

---

### 4. Database Files

| Database | Path | Purpose |
|----------|------|---------|
| Core | `data/amoskys.db` | Agents, telemetry metadata |
| Telemetry | `data/telemetry.db` | Event telemetry data |
| Web | `web/data/amoskys_web.db` | Users, sessions, auth |

**Note:** Old `web/data/amoskys.db` has been removed to prevent confusion.

---

### 5. Test Status

```
Unit Tests: 302 passed ✅
Integration Tests: Require running server (expected failures when offline)
Total Collected: 573
```

Run unit tests:
```bash
python -m pytest tests/auth/ tests/common/ tests/component/ -q
```

Run full test suite (requires running server):
```bash
python -m pytest tests/ -q --tb=short
```

---

## 📋 Deployment Checklist

### Pre-Deployment

- [ ] Set all required environment variables
- [ ] Generate secure SECRET_KEY
- [ ] Configure SMTP for email notifications
- [ ] Enable HTTPS and set `AMOSKYS_SECURE_COOKIES=true`
- [ ] Review and test rate limiting settings
- [ ] Run full test suite
- [ ] Review audit logs for any issues

### Database

- [ ] Backup existing databases
- [ ] Verify schema migrations are applied
- [ ] Test database connectivity
- [ ] Configure database backups

### gRPC EventBus

- [ ] Generate TLS certificates for production
- [ ] Configure `GRPC_TLS_ENABLED=true`
- [ ] Set certificate paths
- [ ] Test agent connectivity

### Monitoring

- [ ] Enable Prometheus metrics (`METRICS_ENABLED=true`)
- [ ] Configure log aggregation
- [ ] Set up alerting
- [ ] Configure error tracking (Sentry optional)

### Production Server

- [ ] Use Gunicorn with eventlet worker
- [ ] Configure systemd service
- [ ] Set up nginx reverse proxy
- [ ] Enable HTTP/2
- [ ] Configure SSL certificates

---

## 🚀 Production Deployment Command

```bash
# Start with Gunicorn (production)
cd web
gunicorn --worker-class eventlet \
         --workers 1 \
         --bind 0.0.0.0:8000 \
         --access-logfile - \
         --error-logfile - \
         wsgi:app
```

---

## 📁 Key Configuration Files

| File | Purpose |
|------|---------|
| `.env.example` | Environment variable template |
| `config/amoskys.yaml` | Main application config |
| `deploy/docker-compose.dev.yml` | Docker development setup |
| `deploy/systemd/` | Systemd service files |
| `deploy/nginx/` | Nginx configuration |

---

## 🔗 Related Documentation

- `docs/PRODUCTION_DEPLOYMENT.md` - Full deployment guide
- `docs/API_SECURITY.md` - Security implementation details
- `docs/DEVELOPER_SETUP_GUIDE.md` - Development environment setup
- `docs/OPS_RUNBOOK.md` - Operations procedures

---

## 📝 Remaining Tasks

1. ~~**Fix bare except clauses**~~ ✅ Complete
2. ~~**Fix test import issues**~~ ✅ Complete (302 unit tests passing)
3. **Start gRPC EventBus server** - ✅ Running (PID active, agents publishing)
4. **Connect dashboard to live agent data** - In Progress
5. **Implement event storage** in telemetry database - WAL issue being investigated
6. **Performance testing** under load
7. **Security audit** of API endpoints

---

## 📊 Current System Status

| Component | Status | Notes |
|-----------|--------|-------|
| Flask Web Server | ✅ Running | http://localhost:5001 |
| EventBus gRPC | ✅ Running | Port 50051 with TLS |
| Agents | ✅ Active | 4 agents publishing telemetry |
| Database (Auth) | ✅ Healthy | web/data/amoskys_web.db |
| Database (Core) | ✅ Healthy | data/amoskys.db |
| Unit Tests | ✅ 302 Passing | Auth, common, component |
| Integration Tests | ⚠️ Require Server | Run with server active |
