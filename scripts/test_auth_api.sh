#!/bin/bash
#
# AMOSKYS Authentication API Testing Script
#
# Prerequisites:
#   1. Flask server running: .venv/bin/flask run
#   2. Database initialized: .venv/bin/python scripts/init_auth_db.py
#
# Usage:
#   ./scripts/test_auth_api.sh
#

set -e

API_URL="${API_URL:-http://localhost:5001/api/user/auth}"
COOKIES_FILE="/tmp/amoskys_cookies.txt"
TEST_EMAIL="test-$(date +%s)@amoskys.local"
TEST_PASSWORD="SecureTestPass123!"

echo "🧠⚡ AMOSKYS Authentication API Test Suite"
echo "=========================================="
echo "API URL: $API_URL"
echo "Test Email: $TEST_EMAIL"
echo ""

# Cleanup
rm -f "$COOKIES_FILE"

# =============================================================================
# Test 1: User Signup
# =============================================================================
echo "📝 Test 1: User Signup"
echo "----------------------"
SIGNUP_RESPONSE=$(curl -s -X POST "$API_URL/signup" \
  -H "Content-Type: application/json" \
  -d "{
    \"email\": \"$TEST_EMAIL\",
    \"password\": \"$TEST_PASSWORD\",
    \"full_name\": \"Test User\"
  }")

echo "Response: $SIGNUP_RESPONSE"
USER_ID=$(echo "$SIGNUP_RESPONSE" | python3 -c "import sys, json; data = json.load(sys.stdin); print(data.get('user', {}).get('id', ''))")

if [ -z "$USER_ID" ]; then
  echo "❌ FAILED: No user_id in response"
  exit 1
fi

echo "✅ PASSED: User created with ID: $USER_ID"
echo ""

# =============================================================================
# Test 2: Login (will fail if email verification required)
# =============================================================================
echo "📝 Test 2: Login Attempt"
echo "------------------------"
LOGIN_RESPONSE=$(curl -s -X POST "$API_URL/login" \
  -H "Content-Type: application/json" \
  -c "$COOKIES_FILE" \
  -d "{
    \"email\": \"$TEST_EMAIL\",
    \"password\": \"$TEST_PASSWORD\"
  }")

echo "Response: $LOGIN_RESPONSE"

SUCCESS=$(echo "$LOGIN_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('success', False))")

if [ "$SUCCESS" = "True" ]; then
  echo "✅ PASSED: Login successful"
  SESSION_TOKEN=$(cat "$COOKIES_FILE" | grep amoskys_session | awk '{print $NF}')
  echo "   Session token: ${SESSION_TOKEN:0:20}..."
else
  ERROR_CODE=$(echo "$LOGIN_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('error_code', 'UNKNOWN'))")
  if [ "$ERROR_CODE" = "EMAIL_NOT_VERIFIED" ] || [ "$ERROR_CODE" = "UNVERIFIED_EMAIL" ]; then
    echo "⚠️  Email verification required (expected for new accounts)"
    echo "   Skipping authenticated endpoint tests"
    echo ""
    echo "=========================================="
    echo "✅ API Test Suite: PARTIAL (2/8 tests)"
    echo "   - Signup works ✅"
    echo "   - Email verification required ⚠️"
    echo ""
    echo "To test authenticated endpoints:"
    echo "  1. Disable email verification in AuthServiceConfig"
    echo "  2. Or manually verify email in database"
    exit 0
  else
    echo "❌ FAILED: Login failed with error: $ERROR_CODE"
    exit 1
  fi
fi
echo ""

# =============================================================================
# Test 3: Get Current User (/me)
# =============================================================================
echo "📝 Test 3: Get Current User"
echo "----------------------------"
ME_RESPONSE=$(curl -s -X GET "$API_URL/me" \
  -b "$COOKIES_FILE")

echo "Response: $ME_RESPONSE"

USER_EMAIL=$(echo "$ME_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('user', {}).get('email', ''))")

if [ "$USER_EMAIL" = "$TEST_EMAIL" ]; then
  echo "✅ PASSED: Current user retrieved"
else
  echo "❌ FAILED: Email mismatch"
  exit 1
fi
echo ""

# =============================================================================
# Test 4: Change Password
# =============================================================================
echo "📝 Test 4: Change Password"
echo "--------------------------"
NEW_PASSWORD="NewSecure456!"
CHANGE_RESPONSE=$(curl -s -X POST "$API_URL/change-password" \
  -H "Content-Type: application/json" \
  -b "$COOKIES_FILE" \
  -d "{
    \"current_password\": \"$TEST_PASSWORD\",
    \"new_password\": \"$NEW_PASSWORD\"
  }")

echo "Response: $CHANGE_RESPONSE"

SUCCESS=$(echo "$CHANGE_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('success', False))")

if [ "$SUCCESS" = "True" ]; then
  echo "✅ PASSED: Password changed"
  TEST_PASSWORD="$NEW_PASSWORD"
else
  echo "❌ FAILED: Password change failed"
  exit 1
fi
echo ""

# =============================================================================
# Test 5: Logout
# =============================================================================
echo "📝 Test 5: Logout"
echo "-----------------"
LOGOUT_RESPONSE=$(curl -s -X POST "$API_URL/logout" \
  -b "$COOKIES_FILE")

echo "Response: $LOGOUT_RESPONSE"

SUCCESS=$(echo "$LOGOUT_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('success', False))")

if [ "$SUCCESS" = "True" ]; then
  echo "✅ PASSED: Logout successful"
else
  echo "❌ FAILED: Logout failed"
  exit 1
fi
echo ""

# =============================================================================
# Test 6: Access Protected Endpoint After Logout (should fail)
# =============================================================================
echo "📝 Test 6: Access After Logout (should fail)"
echo "---------------------------------------------"
ME_RESPONSE=$(curl -s -X GET "$API_URL/me" \
  -b "$COOKIES_FILE")

echo "Response: $ME_RESPONSE"

ERROR_CODE=$(echo "$ME_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('error_code', ''))")

if [ "$ERROR_CODE" = "NO_SESSION" ] || [ "$ERROR_CODE" = "INVALID_SESSION" ]; then
  echo "✅ PASSED: Access denied after logout"
else
  echo "❌ FAILED: Should deny access after logout"
  exit 1
fi
echo ""

# =============================================================================
# Test 7: Login with New Password
# =============================================================================
echo "📝 Test 7: Login with New Password"
echo "-----------------------------------"
LOGIN_RESPONSE=$(curl -s -X POST "$API_URL/login" \
  -H "Content-Type: application/json" \
  -c "$COOKIES_FILE" \
  -d "{
    \"email\": \"$TEST_EMAIL\",
    \"password\": \"$TEST_PASSWORD\"
  }")

echo "Response: $LOGIN_RESPONSE"

SUCCESS=$(echo "$LOGIN_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('success', False))")

if [ "$SUCCESS" = "True" ]; then
  echo "✅ PASSED: Login with new password successful"
else
  echo "❌ FAILED: Login with new password failed"
  exit 1
fi
echo ""

# =============================================================================
# Test 8: Logout All Sessions
# =============================================================================
echo "📝 Test 8: Logout All Sessions"
echo "-------------------------------"
LOGOUT_ALL_RESPONSE=$(curl -s -X POST "$API_URL/logout-all" \
  -b "$COOKIES_FILE")

echo "Response: $LOGOUT_ALL_RESPONSE"

SUCCESS=$(echo "$LOGOUT_ALL_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('success', False))")
SESSIONS_REVOKED=$(echo "$LOGOUT_ALL_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('sessions_revoked', 0))")

if [ "$SUCCESS" = "True" ]; then
  echo "✅ PASSED: All sessions revoked (count: $SESSIONS_REVOKED)"
else
  echo "❌ FAILED: Logout all failed"
  exit 1
fi
echo ""

# Cleanup
rm -f "$COOKIES_FILE"

echo "=========================================="
echo "✅ API Test Suite: ALL TESTS PASSED (8/8)"
echo "=========================================="
echo ""
echo "🎉 Authentication API is working correctly!"
echo ""
echo "Manual tests to try:"
echo "  • Forgot password flow: POST /api/auth/forgot-password"
echo "  • Email verification: GET /api/auth/verify-email?token=..."
echo "  • Duplicate signup: POST /api/auth/signup (same email)"
echo "  • Invalid credentials: POST /api/auth/login (wrong password)"
echo ""
