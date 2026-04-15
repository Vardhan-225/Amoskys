"""
Pytest configuration for AMOSKYS test suite
Ensures proper Python path setup for all tests
"""
import sys
import os
from pathlib import Path

# Add src directory to Python path for imports
project_root = Path(__file__).parent
src_path = project_root / "src"
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

# Set PYTHONPATH for subprocess calls in tests
current_pythonpath = os.environ.get('PYTHONPATH', '')
if str(src_path) not in current_pythonpath:
    if current_pythonpath:
        os.environ['PYTHONPATH'] = f"{src_path}:{current_pythonpath}"
    else:
        os.environ['PYTHONPATH'] = str(src_path)

# =============================================================================
# CRITICAL: Set test environment variables BEFORE any Flask app imports
# This ensures security features (like HTTPS redirection) are disabled for tests
# =============================================================================
os.environ.setdefault("FLASK_DEBUG", "true")
os.environ.setdefault("FORCE_HTTPS", "false")
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-pytest")
os.environ.setdefault("TESTING", "true")
# Stable agent secrets for test reproducibility (never used in production)
os.environ.setdefault("AMOSKYS_AGENT_FLOW_SECRET", "test-flow-agent-secret-for-pytest")
os.environ.setdefault("AMOSKYS_AGENT_ADMIN_SECRET", "test-admin-agent-secret-for-pytest")

def pytest_configure(config):
    """Configure pytest with AMOSKYS-specific settings"""
    config.addinivalue_line(
        "markers", "unit: marks tests as unit tests"
    )
    config.addinivalue_line(
        "markers", "component: marks tests as component tests"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
    config.addinivalue_line(
        "markers", "security: marks tests as security tests"
    )

import pytest


@pytest.fixture
def tmp_db_path(tmp_path):
    """B5.3: Per-test isolated SQLite database path.

    Each test that uses this fixture gets a unique, isolated database file
    in a temporary directory. This prevents SQLite contention between tests.

    Usage:
        def test_something(tmp_db_path):
            store = TelemetryStore(tmp_db_path)
            ...
    """
    return str(tmp_path / "test_telemetry.db")


@pytest.fixture
def tmp_wal_path(tmp_path):
    """B5.3: Per-test isolated WAL database path."""
    return str(tmp_path / "test_wal.db")


def pytest_sessionstart(session):
    """Called after the Session object has been created"""
    print("🧠⚡ AMOSKYS Test Suite - Neural Command Platform Testing")
    print(f"📂 Project root: {project_root}")
    print(f"🐍 Python path: {src_path}")
    
    # Verify critical imports work
    try:
        import amoskys.proto.messaging_schema_pb2 as pb
        print("✅ Protobuf imports verified")
    except ImportError as e:
        print(f"❌ Import verification failed: {e}")
        raise
