#!/usr/bin/env python3
"""Local UI preview server — boots the real Flask dashboard with auth bypassed
so the authenticated pages can be rendered and screenshotted locally.

NOT for production. Uses LOGIN_DISABLED (the built-in test bypass) and points
telemetry reads at the local fleet_cache snapshot.

Run:  scripts/local_ui_preview.py  (serves http://127.0.0.1:8890)
"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
os.environ.setdefault("SECRET_KEY", "local-preview-not-secret-" + "0" * 40)
os.environ.setdefault("JWT_SECRET_KEY", os.environ["SECRET_KEY"])
os.environ.setdefault("AMOSKYS_ENV", "development")
os.environ.setdefault("FLASK_ENV", "development")
os.environ["LOGIN_DISABLED"] = "true"  # create_app reads this from env (app/__init__.py:27)
os.environ["FORCE_HTTPS"] = "false"  # Talisman: allow plain HTTP for local preview (security.py:219)
# point the insight service + bridge reads at the local snapshot
os.environ.setdefault(
    "AMOSKYS_FLEET_CACHE",
    str(ROOT / "docs/_local/amoskys_redesign/build/fleet_cache.db"),
)
os.environ.setdefault("CC_DB_PATH", os.environ["AMOSKYS_FLEET_CACHE"])

sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "web"))

from app import create_app  # noqa: E402

_created = create_app()
app = _created[0] if isinstance(_created, tuple) else _created
app.config["LOGIN_DISABLED"] = True  # render authed pages without a session
app.config["WTF_CSRF_ENABLED"] = False

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8890"))
    print(f"local UI preview on http://127.0.0.1:{port} (auth bypassed)")
    app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)
