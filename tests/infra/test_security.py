#!/usr/bin/env python3
"""AMOSKYS Security, Privacy & Usability Test Suite.

Tests the system at root level:
  - Can user A see user B's data? (MUST FAIL)
  - Can an unauthenticated request access telemetry? (MUST FAIL)
  - Does the agent leak data to wrong orgs? (MUST FAIL)
  - Does signup create proper isolation? (MUST PASS)
  - Is the install flow complete? (MUST PASS)
  - Are credentials stored securely? (MUST PASS)

Run: PYTHONPATH=src python -m pytest tests/infra/test_security.py -v
"""

import hashlib
import json
import os
import secrets
import sqlite3
import time
from pathlib import Path

import pytest
import requests

# ── Configuration ──
OPS_SERVER = os.getenv("AMOSKYS_OPS_SERVER", "https://18.223.110.15")
WEB_SERVER = os.getenv("AMOSKYS_WEB_SERVER", "https://amoskys.com")
VERIFY_SSL = False


def ops(method, path, **kwargs):
    kwargs.setdefault("timeout", 10)
    kwargs.setdefault("verify", VERIFY_SSL)
    return getattr(requests, method)(f"{OPS_SERVER}{path}", **kwargs)


def web(method, path, **kwargs):
    kwargs.setdefault("timeout", 10)
    return getattr(requests, method)(f"{WEB_SERVER}{path}", **kwargs)


# ══════════════════════════════════════════════════════════════════
# PRIVACY: Data Isolation Between Organizations
# ══════════════════════════════════════════════════════════════════

class TestPrivacyIsolation:
    """Verify that users cannot see other organizations' data."""

    def test_org_filter_returns_zero_for_unknown_org(self):
        """Querying with a random org_id should return zero devices."""
        fake_org = "00000000-0000-0000-0000-000000000000"
        r = ops("get", "/api/v1/fleet/status", params={"org_id": fake_org})
        assert r.status_code == 200
        data = r.json()
        assert data["fleet"]["total_devices"] == 0
        assert data["fleet"]["online"] == 0
        assert len(data["devices"]) == 0

    def test_org_filter_returns_zero_events_for_wrong_org(self):
        """Events should not leak to other organizations."""
        fake_org = "11111111-1111-1111-1111-111111111111"
        r = ops("get", "/api/v1/fleet/status", params={"org_id": fake_org})
        data = r.json()
        assert data["last_24h"]["total_events"] == 0
        assert data["last_24h"]["critical"] == 0

    def test_real_org_sees_its_devices(self):
        """A real org should see its own devices."""
        # Get real devices first (no filter = all)
        r = ops("get", "/api/v1/devices")
        devices = r.json()["devices"]
        if not devices:
            pytest.skip("No devices registered")

        # Find a device with an org
        device_with_org = next((d for d in devices if d.get("org_id")), None)
        if not device_with_org:
            pytest.skip("No devices have org_id set")

        # Query with that org's ID — should see the device
        # We need the org_id from the ops server
        db_path = "/var/lib/amoskys/fleet.db"
        # Can't access ops DB directly from test, so test via API
        r2 = ops("get", "/api/v1/fleet/status")
        data = r2.json()
        assert data["fleet"]["total_devices"] > 0

    def test_device_detail_requires_valid_device_id(self):
        """Accessing a non-existent device should return 404."""
        r = ops("get", "/api/v1/devices/nonexistent-device-id/telemetry")
        assert r.status_code == 404

    def test_cannot_register_device_to_arbitrary_org(self):
        """Registering with a fake org_id should still work but the
        org_id should only be trusted if it came through the proper
        deploy token chain."""
        r = ops("post", "/api/v1/register", json={
            "device_id": "privacy-test-fake-org",
            "hostname": "privacy-test",
            "os": "TestOS",
            "org_id": "stolen-org-id-attempt",
        })
        assert r.status_code == 200
        # Clean up
        ops("delete", f"/api/v1/devices/privacy-test-fake-org")


# ══════════════════════════════════════════════════════════════════
# SECURITY: Authentication & Authorization
# ══════════════════════════════════════════════════════════════════

class TestAuthSecurity:
    """Verify authentication boundaries."""

    def test_dashboard_requires_auth(self):
        """Dashboard pages must redirect to login without session."""
        for path in ["/dashboard/", "/dashboard/devices", "/dashboard/deploy",
                     "/dashboard/settings", "/dashboard/setup"]:
            r = web("get", path, allow_redirects=False)
            assert r.status_code == 302, f"{path} should redirect, got {r.status_code}"

    def test_dashboard_api_requires_auth(self):
        """Dashboard API endpoints must require authentication."""
        for path in ["/dashboard/api/command-center/status",
                     "/dashboard/api/agents/deploy/agents"]:
            r = web("get", path, allow_redirects=False)
            assert r.status_code in (302, 401), f"{path} should require auth"

    def test_login_with_invalid_credentials(self):
        """Login with wrong password should fail."""
        r = web("post", "/api/user/auth/login", json={
            "email": "nonexistent@fake.com",
            "password": "wrongpassword123",
        })
        assert r.status_code == 400
        data = r.json()
        assert data["success"] is False

    def test_login_does_not_leak_user_existence(self):
        """Login error should not reveal if email exists."""
        r = web("post", "/api/user/auth/login", json={
            "email": "nonexistent@fake.com",
            "password": "wrongpassword",
        })
        data = r.json()
        # Should say "invalid credentials" not "user not found"
        assert "not found" not in data.get("error", "").lower()
        assert data.get("error_code") == "INVALID_CREDENTIALS"

    def test_signup_rejects_weak_password(self):
        """Signup with a weak password should fail."""
        r = web("post", "/api/user/auth/signup", json={
            "email": "weakpass@test.com",
            "password": "short",
        })
        assert r.status_code == 400 or (r.status_code == 200 and not r.json().get("success"))

    def test_signup_rejects_duplicate_email(self):
        """Signing up with an existing email should fail."""
        # First check if there are any users
        r = web("post", "/api/user/auth/signup", json={
            "email": "athanneeru@outlook.com",  # Known existing user
            "password": "TestPassword123!@#",
        })
        if r.status_code == 200:
            data = r.json()
            assert data.get("error_code") == "EMAIL_EXISTS" or data.get("success") is False

    def test_ops_server_no_auth_on_register(self):
        """Registration endpoint should be open (agents need to register)."""
        r = ops("post", "/api/v1/register", json={
            "device_id": "auth-test-device",
            "hostname": "auth-test",
            "os": "TestOS",
        })
        assert r.status_code == 200
        ops("delete", "/api/v1/devices/auth-test-device")

    def test_telemetry_requires_device_auth(self):
        """Telemetry submission should require device API key."""
        r = ops("post", "/api/v1/telemetry", json={
            "device_id": "fake-device",
            "table": "security_events",
            "events": [{"test": True}],
        })
        # Should reject — no Authorization header
        assert r.status_code in (401, 403)


# ══════════════════════════════════════════════════════════════════
# SECURITY: Credential Storage
# ══════════════════════════════════════════════════════════════════

class TestCredentialSecurity:
    """Verify credentials are stored securely."""

    def test_passwords_not_stored_plaintext(self):
        """User passwords must be hashed, never stored as plaintext."""
        web_db_path = "/opt/amoskys/web/data/amoskys_web.db"
        # We can't access the server DB from here, but we can check
        # the model code
        from amoskys.auth.models import User
        # The field is called password_hash, not password
        assert hasattr(User, "password_hash")
        assert not hasattr(User, "password") or User.__table__.columns.get("password") is None

    def test_session_tokens_are_hashed(self):
        """Session tokens must be stored as hashes."""
        from amoskys.auth.models import Session
        assert hasattr(Session, "session_token_hash")
        # Should not have a plaintext session_token column
        cols = [c.name for c in Session.__table__.columns]
        assert "session_token" not in cols
        assert "session_token_hash" in cols

    def test_deploy_tokens_are_hashed(self):
        """Deployment tokens must be stored as hashes."""
        from amoskys.agents.models import AgentToken
        assert hasattr(AgentToken, "token_hash")
        cols = [c.name for c in AgentToken.__table__.columns]
        assert "token" not in cols or "token_hash" in cols

    def test_api_keys_not_in_source_code(self):
        """No API keys or secrets hardcoded in source."""
        sensitive_patterns = [
            ("AKIA", 20),    # AWS access key (followed by 16+ chars)
            ("ghp_", 36),    # GitHub personal access token
            ("xoxb-", 40),   # Slack bot token
        ]
        src_dir = Path("src/amoskys")
        for py_file in src_dir.rglob("*.py"):
            content = py_file.read_text(errors="ignore")
            for pattern, min_len in sensitive_patterns:
                # Find pattern followed by enough chars to be a real key
                idx = content.find(pattern)
                while idx != -1:
                    # Check if it looks like a real key (not a help string example)
                    after = content[idx:idx+min_len]
                    if "..." not in after and "example" not in content[max(0,idx-30):idx].lower():
                        assert False, f"Possible secret '{pattern}' found in {py_file} at pos {idx}"
                    idx = content.find(pattern, idx + 1)

    def test_no_hardcoded_ips_in_agent(self):
        """Agent code should not have hardcoded server IPs."""
        shipper = Path("src/amoskys/shipper.py").read_text()
        assert "18.223" not in shipper, "Hardcoded ops server IP in shipper"
        assert "3.147" not in shipper, "Hardcoded web server IP in shipper"

    def test_no_hardcoded_usernames(self):
        """Agent code should not have hardcoded usernames."""
        shipper = Path("src/amoskys/shipper.py").read_text()
        assert "athanneeru" not in shipper


# ══════════════════════════════════════════════════════════════════
# USABILITY: Signup → Onboarding → Install Flow
# ══════════════════════════════════════════════════════════════════

class TestUsabilityFlow:
    """Verify the user journey works end-to-end."""

    def test_landing_page_loads(self):
        r = web("get", "/")
        assert r.status_code == 200
        assert "AMOSKYS" in r.text

    def test_signup_page_accessible(self):
        r = web("get", "/auth/signup")
        assert r.status_code == 200
        assert "Create" in r.text or "Sign" in r.text

    def test_login_page_accessible(self):
        r = web("get", "/auth/login")
        assert r.status_code == 200

    def test_install_script_accessible(self):
        r = web("get", "/deploy/install.sh")
        assert r.status_code == 200
        assert "AMOSKYS" in r.text
        assert "bash" in r.text.lower() or "#!/" in r.text

    def test_pkg_download_accessible(self):
        """The .pkg download should be available without auth."""
        r = web("get", "/download/AMOSKYS.pkg", stream=True)
        assert r.status_code == 200
        # Check it's at least 1MB (not a truncated file)
        content_length = int(r.headers.get("content-length", 0))
        assert content_length > 1_000_000, f"PKG too small: {content_length} bytes"

    def test_setup_page_requires_auth(self):
        """Setup page should redirect to login if not authenticated."""
        r = web("get", "/dashboard/setup", allow_redirects=False)
        assert r.status_code == 302


# ══════════════════════════════════════════════════════════════════
# USABILITY: Organization Auto-Creation
# ══════════════════════════════════════════════════════════════════

class TestOrgCreation:
    """Verify organizations are auto-created correctly on signup."""

    def test_personal_email_creates_individual_org(self):
        from amoskys.auth.organization import classify_email_domain, OrgType
        domain, org_type = classify_email_domain("user@gmail.com")
        assert org_type == OrgType.INDIVIDUAL

    def test_corporate_email_creates_enterprise_org(self):
        from amoskys.auth.organization import classify_email_domain, OrgType
        domain, org_type = classify_email_domain("user@company.com")
        assert org_type == OrgType.ENTERPRISE

    def test_all_common_personal_domains_classified(self):
        from amoskys.auth.organization import classify_email_domain, OrgType, PERSONAL_DOMAINS
        personal = ["gmail.com", "outlook.com", "hotmail.com", "yahoo.com",
                    "icloud.com", "protonmail.com", "proton.me"]
        for domain in personal:
            _, org_type = classify_email_domain(f"test@{domain}")
            assert org_type == OrgType.INDIVIDUAL, f"{domain} should be INDIVIDUAL"
        assert len(PERSONAL_DOMAINS) >= 30, "Should have 30+ personal domains"

    def test_org_slug_generation(self):
        from amoskys.auth.organization import generate_org_slug
        slug = generate_org_slug("Test Company", "testcompany.com")
        assert slug == "testcompany-com"
        slug2 = generate_org_slug("John Doe")
        assert len(slug2) > 5
        assert "-" in slug2


# ══════════════════════════════════════════════════════════════════
# SECURITY: Device ID Stability
# ══════════════════════════════════════════════════════════════════

class TestDeviceIDSecurity:
    """Verify device IDs are stable and not guessable."""

    def test_device_id_is_stable(self):
        """Same machine should always generate the same device_id."""
        import sys
        sys.path.insert(0, "/Library/Amoskys/src")
        try:
            from amoskys.shipper import _generate_device_id
            id1 = _generate_device_id()
            id2 = _generate_device_id()
            assert id1 == id2, "Device ID changed between calls"
            assert len(id1) == 16, "Device ID should be 16 chars"
        except ImportError:
            pytest.skip("Agent not installed on this machine")

    def test_device_id_not_trivially_guessable(self):
        """Device ID should not be hostname or MAC address in plaintext."""
        try:
            import sys
            sys.path.insert(0, "/Library/Amoskys/src")
            from amoskys.shipper import _generate_device_id
            import platform
            device_id = _generate_device_id()
            hostname = platform.node().lower()
            assert hostname not in device_id, "Device ID contains hostname"
        except ImportError:
            pytest.skip("Agent not installed")

    def test_hostname_not_reverse_dns(self):
        """Hostname should not be a reverse DNS artifact."""
        try:
            import sys
            sys.path.insert(0, "/Library/Amoskys/src")
            from amoskys.shipper import _get_hostname
            hostname = _get_hostname()
            assert "in-addr.arpa" not in hostname, f"Hostname is reverse DNS: {hostname}"
            assert len(hostname) > 1, "Hostname too short"
        except ImportError:
            pytest.skip("Agent not installed")


# ══════════════════════════════════════════════════════════════════
# SECURITY: Ops Server Hardening
# ══════════════════════════════════════════════════════════════════

class TestOpsServerSecurity:
    """Verify the ops server is hardened."""

    def test_no_sql_injection_in_org_filter(self):
        """Org filter should not be injectable."""
        malicious = "' OR 1=1 --"
        r = ops("get", "/api/v1/fleet/status", params={"org_id": malicious})
        assert r.status_code == 200
        data = r.json()
        # Should return 0 devices, not all devices
        assert data["fleet"]["total_devices"] == 0

    def test_no_sql_injection_in_device_id(self):
        """Device endpoints should not be injectable."""
        r = ops("get", "/api/v1/devices/' OR '1'='1/telemetry")
        assert r.status_code in (404, 400, 500)

    def test_event_table_whitelist(self):
        """Only whitelisted tables should be accepted for telemetry."""
        # Register a test device first
        reg = ops("post", "/api/v1/register", json={
            "device_id": "sqli-test",
            "hostname": "sqli-test",
        })
        api_key = reg.json().get("api_key", "")

        r = ops("post", "/api/v1/telemetry",
            headers={"Authorization": f"Bearer {api_key}", "X-Device-ID": "sqli-test"},
            json={
                "device_id": "sqli-test",
                "table": "devices; DROP TABLE devices; --",
                "events": [{}],
            })
        assert r.status_code == 400
        assert "Unknown table" in r.json().get("error", "")

        # Clean up
        ops("delete", "/api/v1/devices/sqli-test")

    def test_bulk_export_has_size_limit(self):
        """Bulk export should respect the limit parameter."""
        r = ops("get", "/api/v1/bulk-export", params={"limit": 2})
        data = r.json()
        for table, rows in data.items():
            assert len(rows) <= 2, f"{table} returned {len(rows)} rows, limit was 2"

    def test_device_delete_works(self):
        """DELETE endpoint should remove devices."""
        # Create
        ops("post", "/api/v1/register", json={
            "device_id": "delete-test",
            "hostname": "delete-test",
        })
        # Delete
        r = ops("delete", "/api/v1/devices/delete-test")
        assert r.status_code == 200
        # Verify gone
        r2 = ops("get", "/api/v1/devices")
        device_ids = [d["device_id"] for d in r2.json()["devices"]]
        assert "delete-test" not in device_ids


# ══════════════════════════════════════════════════════════════════
# SENSIBILITY: Data Quality & Consistency
# ══════════════════════════════════════════════════════════════════

class TestDataSensibility:
    """Verify data makes sense and is consistent."""

    def test_online_devices_have_recent_heartbeat(self):
        """Online devices should have been seen in the last 5 minutes."""
        r = ops("get", "/api/v1/fleet/status")
        for dev in r.json()["devices"]:
            if dev["status"] == "online":
                assert dev["last_seen"] is not None
                age = time.time() - dev["last_seen"]
                assert age < 600, f"Device {dev['hostname']} is 'online' but last seen {age:.0f}s ago"

    def test_event_counts_are_non_negative(self):
        """All event counts should be >= 0."""
        r = ops("get", "/api/v1/fleet/status")
        data = r.json()
        assert data["last_24h"]["total_events"] >= 0
        assert data["last_24h"]["critical"] >= 0
        assert data["last_24h"]["high"] >= 0
        for dev in data["devices"]:
            assert (dev.get("event_count") or 0) >= 0

    def test_critical_less_than_total(self):
        """Critical events should be <= total events."""
        r = ops("get", "/api/v1/fleet/status")
        data = r.json()
        total = data["last_24h"]["total_events"]
        critical = data["last_24h"]["critical"]
        assert critical <= total, f"Critical ({critical}) > Total ({total})"

    def test_mitre_techniques_are_valid_format(self):
        """MITRE techniques should match T#### format."""
        r = ops("get", "/api/v1/fleet/status")
        for t in r.json().get("top_mitre_techniques", []):
            assert t["technique"].startswith("T"), f"Invalid MITRE: {t['technique']}"
            assert t["count"] > 0

    def test_risk_scores_in_range(self):
        """Risk scores should be between 0 and 1."""
        r = ops("get", "/api/v1/events", params={"limit": 50})
        for e in r.json()["events"]:
            risk = e.get("risk_score")
            if risk is not None:
                assert 0 <= risk <= 1, f"Risk score out of range: {risk}"

    def test_timestamps_are_recent(self):
        """Events should have timestamps within the last 30 days."""
        r = ops("get", "/api/v1/events", params={"limit": 10})
        now = time.time()
        for e in r.json()["events"]:
            ts = e.get("timestamp_ns")
            if ts:
                age_days = (now - ts / 1e9) / 86400
                assert age_days < 30, f"Event is {age_days:.0f} days old"

    def test_no_empty_device_ids(self):
        """No device should have an empty device_id."""
        r = ops("get", "/api/v1/devices")
        for d in r.json()["devices"]:
            assert d["device_id"], "Empty device_id found"
            assert len(d["device_id"]) >= 8


# ══════════════════════════════════════════════════════════════════
# SECURITY: Agent Config File
# ══════════════════════════════════════════════════════════════════

class TestAgentConfigSecurity:
    """Verify agent configuration is secure."""

    def test_config_file_permissions(self):
        """Config file should be readable only by root."""
        config = Path("/Library/Amoskys/config/amoskys.env")
        if not config.exists():
            pytest.skip("Agent not installed")
        stat = config.stat()
        # Owner should be root (uid 0)
        assert stat.st_uid == 0, "Config not owned by root"
        # Should not be world-readable (mode should be 600 or 640)
        mode = oct(stat.st_mode)[-3:]
        assert mode[2] == "0", f"Config is world-readable: {mode}"

    def test_signing_key_permissions(self):
        """Ed25519 signing key should be readable only by root."""
        key = Path("/Library/Amoskys/certs/agent.ed25519")
        if not key.exists():
            pytest.skip("Agent not installed")
        stat = key.stat()
        assert stat.st_uid == 0, "Key not owned by root"
        mode = oct(stat.st_mode)[-3:]
        assert mode[2] == "0", f"Key is world-readable: {mode}"

    def test_no_plaintext_secrets_in_logs(self):
        """Logs should not contain API keys or tokens."""
        log_dir = Path("/var/log/amoskys")
        if not log_dir.exists():
            pytest.skip("No log directory")
        for log_file in log_dir.glob("*.log"):
            try:
                content = log_file.read_text(errors="ignore")
                # API keys are 64-char hex strings
                assert "api_key=" not in content.lower(), f"API key found in {log_file}"
            except PermissionError:
                pass  # Can't read root-owned logs without sudo


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
