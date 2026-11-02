#!/usr/bin/env python3
"""Local AMOSKYS proof preflight.

This is intentionally narrower than tools/amoskys_doctor.py. The production
doctor checks deployed daemons and /var/lib state; this checks whether the repo
can prove what it is about to run locally.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
THREAT_INTEL_STALE_DAYS = 3.0
REQUIRED_IMPORTS = (
    "amoskys",
    "numpy",
    "flask",
    "pytest",
    "sqlalchemy",
    "argon2",
    "flask_limiter",
    "flask_wtf",
    "flask_talisman",
    "mcp",
)


def _resolve(path: str) -> Path:
    p = Path(path)
    if not p.is_absolute():
        p = ROOT / p
    return p


def _status(mark: str, title: str, detail: str = "") -> None:
    suffix = f" - {detail}" if detail else ""
    print(f"{mark} {title}{suffix}")


def _run_python(python: Path) -> tuple[dict, str]:
    required_imports = json.dumps(REQUIRED_IMPORTS)
    code = f"""
import importlib
import json
import sys

REQUIRED_IMPORTS = {required_imports}
mods = {{}}
for name in REQUIRED_IMPORTS:
    try:
        mod = importlib.import_module(name)
        mods[name] = getattr(mod, "__version__", "ok")
    except Exception as exc:
        mods[name] = {{"error": str(exc)}}

print(json.dumps({{
    "executable": sys.executable,
    "prefix": sys.prefix,
    "base_prefix": sys.base_prefix,
    "mods": mods,
}}))
"""
    env = dict(os.environ)
    env["PYTHONPATH"] = f"{ROOT / 'src'}:{env.get('PYTHONPATH', '')}"
    proc = subprocess.run(
        [str(python), "-c", code],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
    )
    if proc.returncode != 0:
        return {}, (proc.stderr or proc.stdout).strip()
    return json.loads(proc.stdout), ""


def _iso_age_days(value: str) -> float:
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - parsed).total_seconds() / 86400


def _check_threat_db(path: Path) -> tuple[int, str, float | None]:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)
    try:
        count = int(conn.execute("SELECT COUNT(*) FROM indicators").fetchone()[0])
        newest = conn.execute("SELECT MAX(added_at) FROM indicators").fetchone()[0]
        age_days = _iso_age_days(newest) if newest else None
        return count, newest or "unknown", age_days
    finally:
        conn.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="AMOSKYS local proof preflight")
    parser.add_argument("--venv", default="amoskys-venv")
    parser.add_argument("--python", default="amoskys-venv/bin/python")
    parser.add_argument("--threat-db", default=str(ROOT / "data" / "threat_intel.db"))
    args = parser.parse_args()

    failures: list[str] = []
    warnings: list[str] = []
    venv = _resolve(args.venv)
    python = _resolve(args.python)
    threat_db = _resolve(args.threat_db)
    env_threat_db = os.getenv("AMOSKYS_THREAT_INTEL_DB", "")

    print("AMOSKYS local doctor preflight")
    print("-" * 32)

    if venv.is_dir():
        _status("OK", "venv exists", str(venv.relative_to(ROOT)))
    else:
        failures.append(f"venv missing: {venv}")
        _status("FAIL", "venv missing", str(venv))

    if python.exists() and os.access(python, os.X_OK):
        _status("OK", "runtime python executable", str(python.relative_to(ROOT)))
    else:
        failures.append(f"runtime python missing or not executable: {python}")
        _status("FAIL", "runtime python missing", str(python))

    if python.exists() and os.access(python, os.X_OK):
        py_info, py_error = _run_python(python)
        if py_error:
            failures.append(f"runtime python failed: {py_error}")
            _status("FAIL", "runtime python failed", py_error.splitlines()[-1])
        else:
            prefix = Path(py_info.get("prefix", ""))
            if prefix == venv:
                _status(
                    "OK", "runtime prefix matches venv", str(prefix.relative_to(ROOT))
                )
            else:
                failures.append(f"runtime prefix {prefix} does not match venv {venv}")
                _status("FAIL", "runtime prefix mismatch", str(prefix))

            mods = py_info.get("mods", {})
            for name in REQUIRED_IMPORTS:
                value = mods.get(name)
                if isinstance(value, dict) and value.get("error"):
                    failures.append(f"import {name} failed: {value['error']}")
                    _status("FAIL", f"import {name}", value["error"])
                else:
                    _status("OK", f"import {name}", str(value))

    if not threat_db.is_absolute():
        failures.append("threat-intel DB path is not absolute")
        _status("FAIL", "threat-intel path is not absolute", str(threat_db))
    elif not threat_db.exists():
        failures.append(f"threat-intel DB missing: {threat_db}")
        _status("FAIL", "threat-intel DB missing", str(threat_db))
    else:
        try:
            count, newest, age_days = _check_threat_db(threat_db)
            if count <= 0:
                failures.append("threat-intel DB has 0 indicators")
                _status("FAIL", "threat-intel DB empty", "0 indicators")
            elif age_days is None:
                warnings.append("threat-intel DB has no newest added_at timestamp")
                _status(
                    "WARN",
                    "threat-intel freshness unknown",
                    f"{count} indicators, newest timestamp missing",
                )
            elif age_days > THREAT_INTEL_STALE_DAYS:
                warnings.append(f"threat-intel stale: newest {age_days:.1f}d old")
                _status(
                    "WARN",
                    "threat-intel stale",
                    f"{count} indicators, newest {age_days:.1f}d old ({newest})",
                )
            else:
                _status(
                    "OK",
                    "threat-intel DB armed",
                    f"{count} indicators, newest {age_days:.1f}d old ({newest})",
                )
        except Exception as exc:
            failures.append(f"threat-intel DB unreadable: {exc}")
            _status("FAIL", "threat-intel DB unreadable", str(exc))

    if env_threat_db:
        env_path = Path(env_threat_db)
        if env_path == threat_db:
            _status("OK", "AMOSKYS_THREAT_INTEL_DB exported", env_threat_db)
        else:
            failures.append(
                "AMOSKYS_THREAT_INTEL_DB points somewhere else: "
                f"{env_threat_db} != {threat_db}"
            )
            _status("FAIL", "AMOSKYS_THREAT_INTEL_DB mismatch", env_threat_db)
    else:
        warnings.append("AMOSKYS_THREAT_INTEL_DB is not exported")
        _status("WARN", "AMOSKYS_THREAT_INTEL_DB not exported")

    env_file = ROOT / ".env"
    if env_file.exists():
        found = False
        for line in env_file.read_text().splitlines():
            if line.strip().startswith("AMOSKYS_THREAT_INTEL_DB="):
                found = True
                configured = line.split("=", 1)[1].strip()
                if Path(configured) == threat_db:
                    _status("OK", ".env threat-intel wiring", configured)
                else:
                    failures.append(f".env threat-intel mismatch: {configured}")
                    _status("FAIL", ".env threat-intel mismatch", configured)
                break
        if not found:
            warnings.append(".env does not set AMOSKYS_THREAT_INTEL_DB")
            _status("WARN", ".env threat-intel wiring missing")

    print("-" * 32)
    if failures:
        print(f"FAILED ({len(failures)} blocking issue(s), {len(warnings)} warning(s))")
        return 1
    if warnings:
        print(f"DEGRADED ({len(warnings)} warning(s))")
        return 0
    print("HEALTHY")
    return 0


if __name__ == "__main__":
    sys.exit(main())
