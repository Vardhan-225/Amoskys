# AMOSKYS API Testing Guide

## Quick Start

### 1. Start the Flask Development Server

Open Terminal 1:
```bash
cd /Users/athanneeru/Downloads/GitHub/Amoskys

# Set environment variables for development
export AMOSKYS_EMAIL_DEV_MODE=true
export FLASK_DEBUG=true

# Start the server
python3 web/wsgi.py --dev
```

**Expected output:**
```
🧠⚡ AMOSKYS Development Server Starting...
⚠️  WARNING: Development mode - not suitable for production
 * Running on http://0.0.0.0:5001
 * Restarting with stat
 * Debugger is active!
```

**Note:** Server runs on port **5001** (not 5000)

---

### 2. Update Test Script for Port 5001

The test script needs to use the correct port. Let's update it:

```bash
# Quick fix for the test script
sed -i.bak 's/localhost:5000/localhost:5001/g' scripts/test_auth_api.sh
```

Or manually edit `scripts/test_auth_api.sh` line 13:
```bash
API_URL="${API_URL:-http://localhost:5001/api/auth}"  # Changed from 5000
```

---

### 3. Run Automated Tests

Open Terminal 2:
```bash
cd /Users/athanneeru/Downloads/GitHub/Amoskys
./scripts/test_auth_api.sh
```

**Expected output:**
```
🧠⚡ AMOSKYS Authentication API Test Suite
==========================================
API URL: http://localhost:5001/api/auth
Test Email: test-1735598400@amoskys.local

📝 Test 1: User Signup
----------------------
Response: {"success":true,"user_id":"...","verification_required":true}
✅ PASSED: User created with ID: uuid-here

📝 Test 2: Login Attempt
------------------------
Response: {"success":false,"error":"Email not verified","error_code":"UNVERIFIED_EMAIL"}
⚠️  Email verification required (expected for new accounts)
   Skipping authenticated endpoint tests
```

---

## Manual Testing

### Test 1: Create a User (No Email Verification)

First, let's disable email verification for testing:

```bash
# In Terminal 1 (where Flask is running), restart with:
export AMOSKYS_EMAIL_VERIFICATION_REQUIRED=false
python3 web/wsgi.py --dev
```

Then in Terminal 2:

```bash
# Signup
curl -X POST http://localhost:5001/api/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@amoskys.local",
    "password": "SecureTest123!",
    "full_name": "Test User"
  }' | python3 -m json.tool
```

**Expected:**
```json
{
  "success": true,
  "user_id": "uuid-here",
  "verification_required": false,
  "message": "User created successfully"
}
```

---

### Test 2: Login

```bash
# Login and save cookies
curl -X POST http://localhost:5001/api/auth/login \
  -H "Content-Type: application/json" \
  -c cookies.txt \
  -d '{
    "email": "test@amoskys.local",
    "password": "SecureTest123!"
  }' | python3 -m json.tool
```

**Expected:**
```json
{
  "success": true,
  "session_token": "***",
  "user_id": "uuid-here",
  "message": "Login successful"
}
```

**Check cookie was set:**
```bash
cat cookies.txt
# Should show: amoskys_session
```

---

### Test 3: Get Current User (Protected Endpoint)

```bash
# Use saved cookie
curl -X GET http://localhost:5001/api/auth/me \
  -b cookies.txt | python3 -m json.tool
```

**Expected:**
```json
{
  "success": true,
  "user": {
    "id": "uuid",
    "email": "test@amoskys.local",
    "full_name": "Test User",
    "role": "user",
    "is_verified": true,
    "mfa_enabled": false,
    "created_at": "2025-12-30T...",
    "last_login_at": "2025-12-30T..."
  }
}
```

---

### Test 4: Change Password

```bash
curl -X POST http://localhost:5001/api/auth/change-password \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{
    "current_password": "SecureTest123!",
    "new_password": "NewSecure456!"
  }' | python3 -m json.tool
```

**Expected:**
```json
{
  "success": true,
  "message": "Password changed successfully"
}
```

---

### Test 5: Logout

```bash
curl -X POST http://localhost:5001/api/auth/logout \
  -b cookies.txt | python3 -m json.tool
```

**Expected:**
```json
{
  "success": true,
  "message": "Logged out successfully"
}
```

---

### Test 6: Access After Logout (Should Fail)

```bash
curl -X GET http://localhost:5001/api/auth/me \
  -b cookies.txt | python3 -m json.tool
```

**Expected:**
```json
{
  "error": "Authentication required",
  "error_code": "NO_SESSION"
}
```

---

## Testing Rate Limiting

### Test Login Rate Limit (5 per minute)

```bash
# Try to login 6 times rapidly
for i in {1..6}; do
  echo "\n--- Attempt $i ---"
  curl -X POST http://localhost:5001/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"test@amoskys.local","password":"wrong"}' \
    | python3 -m json.tool
  sleep 1
done
```

**Expected:** After 5 attempts, you should see:
```json
{
  "error": "Rate limit exceeded. Please try again later.",
  "error_code": "RATE_LIMIT_EXCEEDED",
  "retry_after": "59 seconds"
}
```

---

## Testing Security Headers

```bash
curl -I http://localhost:5001/api/auth/me
```

**Expected headers:**
```
HTTP/1.1 401 UNAUTHORIZED
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
X-Powered-By: AMOSKYS
Set-Cookie: amoskys_session=deleted; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Path=/; SameSite=Lax
```

---

## Testing Error Cases

### Missing Fields
```bash
curl -X POST http://localhost:5001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@amoskys.local"}' \
  | python3 -m json.tool
```

**Expected:**
```json
{
  "error": "Email and password required",
  "error_code": "MISSING_FIELDS"
}
```

### Invalid Credentials
```bash
curl -X POST http://localhost:5001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@amoskys.local","password":"wrongpass"}' \
  | python3 -m json.tool
```

**Expected:**
```json
{
  "success": false,
  "error": "Invalid email or password",
  "error_code": "INVALID_CREDENTIALS"
}
```

### Weak Password
```bash
curl -X POST http://localhost:5001/api/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"email":"weak@test.com","password":"weak"}' \
  | python3 -m json.tool
```

**Expected:**
```json
{
  "success": false,
  "error": "Password must be at least 8 characters",
  "error_code": "INVALID_PASSWORD"
}
```

---

## Troubleshooting

### Server won't start
```bash
# Check if port 5001 is already in use
lsof -i :5001

# Kill existing process
kill -9 <PID>
```

### Database errors
```bash
# Reinitialize the database
.venv/bin/python scripts/init_auth_db.py
```

### Import errors
```bash
# Reinstall dependencies
.venv/bin/pip install -e ".[dev,web,agents]"
```

### Rate limit blocking you
```bash
# Wait 1 minute, or restart Flask server to reset in-memory limits
```

---

## Next Steps

After manual testing works:

1. **Add Frontend UI** - Create login/signup forms
2. **Set up Redis** - For distributed rate limiting
3. **Configure SMTP** - For production email sending
4. **Add MFA/2FA** - TOTP with Google Authenticator
5. **Deploy to Production** - With PostgreSQL and HTTPS

---

*Last updated: December 30, 2025*
