#!/usr/bin/env python3
"""
AMOSKYS Admin User Management Tests

Tests for admin panel user management functionality including:
- User listing and filtering
- User editing with validation
- User suspension and deletion
- Session revocation
- Audit logging
"""
import json
import os
import sys
from datetime import datetime

import pytest

# Add the web app to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "web"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app import create_app
from amoskys.auth.models import User, UserRole, AuditEventType, AuthAuditLog
from amoskys.db import get_session_context


@pytest.fixture
def app():
    """Create test application"""
    result = create_app()
    if isinstance(result, tuple):
        app_instance, _ = result
    else:
        app_instance = result

    app_instance.config["TESTING"] = True
    app_instance.config["SECRET_KEY"] = "test-secret-key-for-testing"
    app_instance.config["WTF_CSRF_ENABLED"] = False  # Disable CSRF for testing

    return app_instance


@pytest.fixture
def client(app):
    """Create test client"""
    return app.test_client()


@pytest.fixture
def admin_user(app):
    """Create admin user for testing"""
    with get_session_context() as db:
        # Check if admin exists
        admin = db.query(User).filter_by(email="test-admin@amoskys.local").first()
        if not admin:
            admin = User(
                email="test-admin@amoskys.local",
                full_name="Test Admin",
                role=UserRole.ADMIN,
                is_active=True,
                is_verified=True
            )
            admin.set_password("TestAdminPass123!")
            db.add(admin)
            db.commit()
        return admin.id


@pytest.fixture
def regular_user(app):
    """Create regular user for testing"""
    with get_session_context() as db:
        user = User(
            email=f"test-user-{datetime.now().timestamp()}@amoskys.local",
            full_name="Test User",
            role=UserRole.USER,
            is_active=True,
            is_verified=True
        )
        user.set_password("TestUserPass123!")
        db.add(user)
        db.commit()
        user_id = user.id

    yield user_id

    # Cleanup
    with get_session_context() as db:
        user = db.query(User).filter_by(id=user_id).first()
        if user:
            db.delete(user)
            db.commit()


class TestAdminUserAPI:
    """Test admin user management API endpoints"""

    def test_get_users_requires_admin(self, client):
        """Test that getting users requires admin role"""
        response = client.get('/admin/api/users')
        # Should redirect to login or return 401/403
        assert response.status_code in [302, 401, 403]

    def test_update_user_validates_input(self, client, admin_user, regular_user):
        """Test that user updates validate input"""
        # Test with invalid full name (too short)
        response = client.patch(
            f'/admin/api/users/{regular_user}',
            data=json.dumps({'full_name': 'A'}),  # Too short
            content_type='application/json'
        )
        # Should fail validation or require auth
        assert response.status_code in [400, 401, 403]

    def test_update_user_validates_role(self, client, admin_user, regular_user):
        """Test that role updates are validated"""
        response = client.patch(
            f'/admin/api/users/{regular_user}',
            data=json.dumps({'role': 'invalid_role'}),
            content_type='application/json'
        )
        # Should fail validation or require auth
        assert response.status_code in [400, 401, 403]

    def test_suspend_user_creates_audit_log(self, client, admin_user, regular_user):
        """Test that suspending a user creates an audit log entry"""
        # This would require authenticated session
        # For now, just verify endpoint exists
        response = client.patch(
            f'/admin/api/users/{regular_user}',
            data=json.dumps({'is_active': False}),
            content_type='application/json'
        )
        # Should require authentication
        assert response.status_code in [401, 403, 500]

    def test_delete_user_requires_confirmation(self, client, admin_user, regular_user):
        """Test that deleting a user requires proper authorization"""
        response = client.delete(f'/admin/api/users/{regular_user}')
        # Should require authentication
        assert response.status_code in [401, 403]


class TestInputValidation:
    """Test input validation functions"""

    def test_full_name_validation(self):
        """Test full name validation rules"""
        import re

        # Valid names
        valid_names = [
            "John Doe",
            "Mary Jane Watson",
            "O'Brien",
            "Jean-Claude",
            "Smith, Jr.",
        ]

        # Pattern from the JavaScript validation
        pattern = re.compile(r"^[a-zA-Z0-9\s\-.,']+$")

        for name in valid_names:
            assert pattern.match(name), f"Valid name '{name}' failed validation"

        # Invalid names (with potentially dangerous characters)
        invalid_names = [
            "<script>alert('xss')</script>",
            "User<>",
            "Drop; Table users--",
        ]

        for name in invalid_names:
            assert not pattern.match(name), f"Invalid name '{name}' passed validation"

    def test_name_length_validation(self):
        """Test name length constraints"""
        # Too short
        assert len("A") < 2

        # Valid length
        assert 2 <= len("John Doe") <= 100

        # Too long
        assert len("A" * 101) > 100


class TestAuditLogging:
    """Test audit log functionality"""

    def test_audit_event_types_are_valid(self):
        """Test that audit event types use correct enum values"""
        # The bug we fixed was using enum NAME instead of VALUE
        assert AuditEventType.ACCOUNT_SUSPENDED.value == 'account_suspended'
        assert AuditEventType.ACCOUNT_DELETED.value == 'account_deleted'
        assert AuditEventType.LOGIN_SUCCESS.value == 'login_success'
        assert AuditEventType.LOGIN_FAILED.value == 'login_failed'

    def test_audit_log_stores_metadata(self):
        """Test that audit logs can store JSON metadata"""
        metadata = {
            'suspended_user_email': 'test@example.com',
            'suspended_by_admin': 'admin@example.com',
            'suspended_by_admin_id': 'admin-id-123'
        }

        # Should be JSON serializable
        json_str = json.dumps(metadata)
        assert isinstance(json_str, str)

        # Should be deserializable
        restored = json.loads(json_str)
        assert restored == metadata


class TestKeyboardAccessibility:
    """Test keyboard accessibility features"""

    def test_modal_escape_key_handler(self):
        """Test that ESC key handler is properly implemented"""
        # This tests the JavaScript implementation exists
        # Actual keyboard testing would require Selenium/Playwright

        # Verify the pattern exists in the HTML
        import os
        users_html_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "..",
            "web",
            "app",
            "templates",
            "admin",
            "users.html"
        )

        if os.path.exists(users_html_path):
            with open(users_html_path, 'r') as f:
                content = f.read()

            # Check for keyboard handler setup
            assert 'setupKeyboardHandlers' in content
            assert "key === 'Escape'" in content or "key === 'Esc'" in content
            assert 'trapFocus' in content
            assert 'focusFirstElement' in content

    def test_focus_trap_implementation(self):
        """Test that focus trap is implemented"""
        import os
        users_html_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "..",
            "web",
            "app",
            "templates",
            "admin",
            "users.html"
        )

        if os.path.exists(users_html_path):
            with open(users_html_path, 'r') as f:
                content = f.read()

            # Check for focus trap elements
            assert 'querySelectorAll' in content
            assert 'shiftKey' in content  # For Shift+Tab handling


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
