# Login Page Routing Issue - Post-Deployment Bug

## Problem Statement

**Symptom:** After successful GitHub Release/deployment, login page routes directly to dashboard, bypassing authentication.

**Frequency:** Every successful GitHub push/release

**Impact:** Security risk - unauthenticated access to dashboard

---

## Root Cause Analysis

### Likely Causes (Ranked by Probability)

#### 1. **Session State Persists Across Deployments** (Most Likely)

**What's happening:**
```
User logs in (session created)
    ↓
GitHub Release triggered (new code deployed)
    ↓
Frontend reloads / service restarts
    ↓
Session cookie still valid (backend didn't flush sessions)
    ↓
User visits /login
    ↓
Middleware sees valid session → redirects to /dashboard
    ↓
User bypasses login screen
```

**Evidence to look for:**
- Session storage backend: Redis, in-memory, database?
- Session TTL: Does it survive deployment?
- Deployment process: Does it restart backend without clearing sessions?

**Fix:**
```python
# Option A: Invalidate all sessions on deployment
# In deployment script (e.g., .github/workflows/deploy.yml)
- name: Clear sessions
  run: |
    # If using Redis
    redis-cli FLUSHDB

    # If using database
    psql -c "DELETE FROM sessions WHERE created_at < NOW();"
```

```python
# Option B: Add session version check
# In session middleware
SESSION_VERSION = "v2.1.0"  # Bump on each deployment

def validate_session(session):
    if session.get("app_version") != SESSION_VERSION:
        # Session from old deployment, invalidate
        session.clear()
        return False
    return True
```

---

#### 2. **Frontend Route Guard Broken by Build Process** (Likely)

**What's happening:**
```
GitHub Release
    ↓
Frontend build (webpack/vite)
    ↓
Code splitting / lazy loading changes
    ↓
Route guard logic broken or cached incorrectly
    ↓
/login route missing auth check
    ↓
User lands on /login → immediately redirected to /dashboard
```

**Evidence to look for:**
- Frontend framework: React, Vue, Angular?
- Route guards: `beforeEnter`, `requireAuth`, etc.
- Build artifacts: Check if route guard code is in bundle

**Fix:**
```javascript
// Route guard in router config (React Router example)
import { Navigate } from 'react-router-dom';

function PrivateRoute({ children }) {
    const isAuthenticated = checkAuth();  // Check session/token

    return isAuthenticated ? children : <Navigate to="/login" />;
}

// Ensure /login is NOT wrapped in PrivateRoute
<Route path="/login" element={<LoginPage />} />
<Route path="/dashboard" element={
    <PrivateRoute>
        <Dashboard />
    </PrivateRoute>
} />
```

**Build cache issue:**
```bash
# Clear build cache before deployment
rm -rf node_modules/.cache
rm -rf .next/cache  # Next.js
rm -rf dist/        # General

# Then rebuild
npm run build
```

---

#### 3. **Environment Variable / Feature Flag Flipped** (Possible)

**What's happening:**
```
GitHub Release
    ↓
Environment variables updated
    ↓
AUTH_ENABLED=false (accidentally)
    ↓
Middleware skips auth checks
    ↓
All users can access dashboard
```

**Evidence to look for:**
- `.env` file changes in git history
- Feature flags: LaunchDarkly, ConfigCat, custom system
- Deployment secrets: GitHub Secrets, AWS Parameter Store

**Fix:**
```bash
# Check current env vars
printenv | grep AUTH

# Expected values
AUTH_ENABLED=true
AUTH_REQUIRED=true
SKIP_AUTH=false
```

```yaml
# In .github/workflows/deploy.yml
# Validate environment before deployment
- name: Validate Config
  run: |
    if [ "$AUTH_ENABLED" != "true" ]; then
      echo "ERROR: AUTH_ENABLED must be true"
      exit 1
    fi
```

---

#### 4. **CORS / Credential Handling Changed** (Possible)

**What's happening:**
```
GitHub Release
    ↓
Backend or frontend updated
    ↓
CORS config changed (credentials: 'include' → 'same-origin')
    ↓
Session cookie not sent with requests
    ↓
Backend thinks user is logged out
    ↓
But frontend still has cached "authenticated" state
    ↓
User sees dashboard but API calls fail (or vice versa)
```

**Evidence to look for:**
- Browser network tab: Check `Set-Cookie` headers
- CORS headers: `Access-Control-Allow-Credentials`
- Frontend fetch config: `credentials: 'include'`

**Fix:**
```javascript
// Frontend: Ensure credentials sent
fetch('/api/auth/status', {
    credentials: 'include',  // Send cookies
    headers: {
        'Content-Type': 'application/json'
    }
})
```

```python
# Backend: Ensure CORS allows credentials
from flask_cors import CORS

CORS(app,
    supports_credentials=True,
    origins=['https://dashboard.example.com']
)
```

---

## Diagnostic Steps

### Step 1: Reproduce the Issue

```bash
# 1. Clean browser state
# Clear cookies, localStorage, sessionStorage

# 2. Trigger deployment
git tag v1.2.3
git push origin v1.2.3

# 3. Wait for deployment to complete
# Check GitHub Actions status

# 4. Visit login page
# Open browser, navigate to https://app.example.com/login

# 5. Check behavior
# Does it auto-redirect to /dashboard?
# Are you authenticated without logging in?
```

---

### Step 2: Check Session Storage

```bash
# If using Redis
redis-cli
> KEYS session:*
> GET session:abc123
> TTL session:abc123  # Check expiration

# If using database
psql -c "SELECT * FROM sessions WHERE user_id IS NOT NULL;"
```

**Expected:** Sessions should expire on deployment or after TTL.

**Actual (if buggy):** Sessions persist across deployments indefinitely.

---

### Step 3: Check Frontend Route Guards

```bash
# Inspect built frontend code
cd frontend/dist

# Find router bundle
grep -r "requireAuth\|PrivateRoute" *.js

# Check if /login has guard
grep -A5 "/login" router.*.js
```

**Expected:** `/login` route has no auth guard, `/dashboard` route has guard.

**Actual (if buggy):** `/login` route missing, or guard logic inverted.

---

### Step 4: Check Environment Variables

```bash
# On deployed server
printenv | grep -i auth

# Compare to expected values
diff <(printenv | grep -i auth | sort) expected_env.txt
```

**Expected:** `AUTH_ENABLED=true`, `SKIP_AUTH=false`

**Actual (if buggy):** Auth disabled or feature flag flipped.

---

## Immediate Fix (Hot Patch)

If issue is live in production:

### Option A: Force Session Invalidation

```bash
# SSH to backend server
ssh user@backend.example.com

# Clear all sessions
# If Redis
redis-cli FLUSHDB

# If database
psql -c "DELETE FROM sessions;"

# Restart backend (forces users to re-login)
sudo systemctl restart backend-service
```

### Option B: Rollback Deployment

```bash
# GitHub
git revert <commit-hash>
git push origin main

# Or manual rollback
kubectl rollout undo deployment/backend  # Kubernetes
cf rollback app-name  # Cloud Foundry
eb deploy --version <previous>  # Elastic Beanstalk
```

---

## Long-Term Fix

### 1. Add Session Versioning

```python
# backend/auth.py
import os

SESSION_VERSION = os.getenv("APP_VERSION", "unknown")

def create_session(user_id):
    session = {
        "user_id": user_id,
        "app_version": SESSION_VERSION,
        "created_at": datetime.utcnow()
    }
    return session

def validate_session(session):
    # Invalidate sessions from old deployments
    if session.get("app_version") != SESSION_VERSION:
        logger.warning(f"Session version mismatch: {session.get('app_version')} != {SESSION_VERSION}")
        return False
    return True
```

### 2. Add Deployment Pre-Flight Check

```yaml
# .github/workflows/deploy.yml
- name: Validate Auth Config
  run: |
    # Check environment variables
    if [ "$AUTH_ENABLED" != "true" ]; then
      echo "ERROR: AUTH_ENABLED must be true"
      exit 1
    fi

    # Test auth endpoint
    response=$(curl -s -o /dev/null -w "%{http_code}" https://api.example.com/auth/status)
    if [ "$response" != "401" ]; then
      echo "ERROR: Auth endpoint not returning 401 for unauthenticated request"
      exit 1
    fi
```

### 3. Add Frontend Route Guard Tests

```javascript
// frontend/tests/routes.test.js
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';

test('unauthenticated user redirected from /dashboard to /login', () => {
    // Mock unauthenticated state
    jest.spyOn(authService, 'isAuthenticated').mockReturnValue(false);

    render(
        <MemoryRouter initialEntries={['/dashboard']}>
            <App />
        </MemoryRouter>
    );

    // Should be on login page
    expect(screen.getByText(/login/i)).toBeInTheDocument();
});

test('authenticated user can access /dashboard', () => {
    // Mock authenticated state
    jest.spyOn(authService, 'isAuthenticated').mockReturnValue(true);

    render(
        <MemoryRouter initialEntries={['/dashboard']}>
            <App />
        </MemoryRouter>
    );

    // Should be on dashboard
    expect(screen.getByText(/dashboard/i)).toBeInTheDocument();
});
```

---

## Prevention Checklist

Before each deployment:

- [ ] Auth environment variables validated (`AUTH_ENABLED=true`)
- [ ] Session versioning updated (bump `SESSION_VERSION`)
- [ ] Frontend route guards tested (unauthenticated access blocked)
- [ ] Backend auth middleware tested (401 for missing/invalid tokens)
- [ ] Integration tests run (login flow end-to-end)
- [ ] Deployment rollback plan ready (previous version tagged)

---

## Monitoring

Add alerts for auth bypass:

```python
# Backend: Log suspicious auth patterns
if request.path == '/dashboard' and not is_authenticated(request):
    logger.warning(f"Unauthenticated access attempt to /dashboard from {request.remote_addr}")
    metrics.increment('auth.bypass_attempt')
```

```yaml
# Prometheus alert
- alert: AuthBypassAttempts
  expr: rate(auth_bypass_attempt_total[5m]) > 10
  labels:
    severity: critical
  annotations:
    summary: "High rate of auth bypass attempts detected"
```

---

## Next Steps

1. **Reproduce issue** in staging environment
2. **Collect evidence**:
   - Check session storage before/after deployment
   - Inspect frontend route bundles
   - Validate environment variables
3. **Apply hot patch** if in production (invalidate sessions)
4. **Implement long-term fix** (session versioning + pre-flight checks)
5. **Add monitoring** (auth bypass alerts)

---

**Need more info?**
- What's the frontend framework? (React, Vue, Angular?)
- What's the backend framework? (Flask, Django, Node.js?)
- Where are sessions stored? (Redis, PostgreSQL, in-memory?)
- What's the deployment process? (GitHub Actions, manual, CD pipeline?)
