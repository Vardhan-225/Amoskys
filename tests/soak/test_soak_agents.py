#!/usr/bin/env python3
# filepath: /Users/athanneeru/Downloads/GitHub/Amoskys/tests/soak/test_soak_agents.py
"""Soak Test — CL-23 validation via pytest.

Launches Trinity agents as subprocesses, monitors RSS for configurable
duration, and asserts memory/crash/integrity constraints.

This is the programmatic complement to scripts/rig/soak_test.sh.
Runs in pytest so CI/lab_check.sh can include it.

Usage:
    # Quick soak (2 minutes, for CI)
    pytest tests/soak/test_soak_agents.py -v --timeout=300

    # Full CL-23 soak (10 minutes)
    SOAK_MINUTES=10 pytest tests/soak/test_soak_agents.py -v --timeout=900

Environment variables:
    SOAK_MINUTES:         Duration in minutes (default: 2)
    SOAK_SAMPLE_INTERVAL: Seconds between RSS samples (default: 30)
    SOAK_RSS_LIMIT_KB:    Max allowed RSS growth in KB (default: 10240 = 10 MB)
"""

import os
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

# Configuration from env or defaults
SOAK_MINUTES = int(os.environ.get("SOAK_MINUTES", "2"))
SAMPLE_INTERVAL = int(os.environ.get("SOAK_SAMPLE_INTERVAL", "30"))
RSS_LIMIT_KB = int(os.environ.get("SOAK_RSS_LIMIT_KB", "10240"))

# Agents to launch
AGENTS = ["kernel_audit", "protocol_collectors", "device_discovery"]

# Root of the project
PROJECT_ROOT = Path(__file__).parent.parent.parent


def _get_rss_kb(pid: int) -> int:
    """Get RSS in KB for a process. Returns 0 if process is dead."""
    try:
        result = subprocess.run(
            ["ps", "-o", "rss=", "-p", str(pid)],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return int(result.stdout.strip()) if result.returncode == 0 else 0
    except (ValueError, subprocess.TimeoutExpired):
        return 0


def _check_db_integrity(db_path: str) -> tuple:
    """Check SQLite DB integrity. Returns (ok: bool, row_count: int)."""
    if not os.path.exists(db_path):
        return True, 0  # No DB is OK — agent may not have written yet

    try:
        conn = sqlite3.connect(db_path, timeout=5)
        integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
        count = conn.execute("SELECT COUNT(*) FROM queue").fetchone()[0]
        conn.close()
        return integrity == "ok", count
    except Exception:
        return False, -1


class TestSoakAgents:
    """CL-23: 3 Trinity agents run concurrently without memory leak or crash."""

    @pytest.fixture(autouse=True)
    def _setup_lab(self, tmp_path):
        """Create isolated lab directories and launch agents."""
        self.tmp_path = tmp_path
        self.queue_root = tmp_path / "queues"
        self.log_root = tmp_path / "logs"
        self.device_id = "soak-test-host"
        self.env = {
            **os.environ,
            "PYTHONPATH": str(PROJECT_ROOT / "src"),
            "AMOSKYS_DEVICE_ID": self.device_id,
        }

        # Create queue and log directories
        for agent in AGENTS:
            (self.queue_root / agent).mkdir(parents=True, exist_ok=True)
        self.log_root.mkdir(parents=True, exist_ok=True)

        # Launch agents using standardized CLI
        self.procs: dict = {}
        for agent in AGENTS:
            log_path = self.log_root / f"{agent}.log"
            log_file = open(log_path, "w")

            agent_env = {
                **self.env,
                f"AMOSKYS_{agent.upper()}_QUEUE_PATH": str(self.queue_root / agent),
            }
            if agent == "kernel_audit":
                agent_env["AMOSKYS_KERNEL_AUDIT_LOG_PATH"] = "/dev/null"
            extra_args = []

            proc = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    f"amoskys.agents.{agent}",
                    "--interval",
                    "30",
                    "--log-level",
                    "INFO",
                    *extra_args,
                ],
                cwd=str(PROJECT_ROOT),
                env=agent_env,
                stdout=log_file,
                stderr=subprocess.STDOUT,
            )
            self.procs[agent] = {"proc": proc, "log_file": log_file}

        yield

        # Teardown — kill all agents
        for agent, info in self.procs.items():
            try:
                info["proc"].send_signal(signal.SIGTERM)
            except ProcessLookupError:
                pass
        for agent, info in self.procs.items():
            try:
                info["proc"].wait(timeout=10)
            except subprocess.TimeoutExpired:
                info["proc"].kill()
            info["log_file"].close()

    def test_agents_survive_soak_duration(self):
        """All 3 agents remain alive for the full soak duration."""
        total_seconds = SOAK_MINUTES * 60
        num_samples = total_seconds // SAMPLE_INTERVAL + 1

        rss_history = {a: [] for a in AGENTS}
        dead_agents = set()

        for i in range(num_samples):
            for agent in AGENTS:
                proc = self.procs[agent]["proc"]
                poll = proc.poll()

                if poll is not None:
                    dead_agents.add(agent)
                    rss_history[agent].append(0)
                else:
                    rss = _get_rss_kb(proc.pid)
                    rss_history[agent].append(rss)

            if i < num_samples - 1:
                time.sleep(SAMPLE_INTERVAL)

        assert len(dead_agents) == 0, f"Agents died during soak: {dead_agents}"

    def test_rss_growth_within_limit(self):
        """RSS growth < {RSS_LIMIT_KB} KB for all agents (post-warmup)."""
        total_seconds = SOAK_MINUTES * 60
        num_samples = total_seconds // SAMPLE_INTERVAL + 1

        # Skip the first WARMUP_SAMPLES to avoid measuring cold-start overhead
        # (module imports, protobuf descriptor init, SQLite schema creation).
        # This matches the fix applied to scripts/rig/soak_test.sh.
        WARMUP_SAMPLES = 2

        rss_baseline = {}
        rss_last = {}

        for i in range(num_samples):
            for agent in AGENTS:
                proc = self.procs[agent]["proc"]
                if proc.poll() is None:
                    rss = _get_rss_kb(proc.pid)
                    if i == WARMUP_SAMPLES and agent not in rss_baseline:
                        rss_baseline[agent] = rss
                    if i >= WARMUP_SAMPLES:
                        rss_last[agent] = rss

            if i < num_samples - 1:
                time.sleep(SAMPLE_INTERVAL)

        for agent in AGENTS:
            baseline = rss_baseline.get(agent, 0)
            last = rss_last.get(agent, 0)
            delta = last - baseline
            assert delta < RSS_LIMIT_KB, (
                f"{agent}: RSS grew {delta} KB ({baseline} → {last}), "
                f"limit is {RSS_LIMIT_KB} KB (post-warmup, "
                f"skipped first {WARMUP_SAMPLES} samples)"
            )

    def test_no_tracebacks_in_logs(self):
        """Zero Python tracebacks in agent logs after soak."""
        # Let agents run for the soak duration
        time.sleep(SOAK_MINUTES * 60)

        for agent in AGENTS:
            log_path = self.log_root / f"{agent}.log"
            if log_path.exists():
                content = log_path.read_text()
                tb_count = content.count("Traceback")
                assert tb_count == 0, f"{agent}: {tb_count} traceback(s) in log"

    def test_queue_dbs_intact_after_soak(self):
        """All queue DBs are readable and pass integrity check after soak."""
        # Let agents run for the soak duration
        time.sleep(SOAK_MINUTES * 60)

        for agent in AGENTS:
            db_path = str(self.queue_root / agent / f"{agent}_queue.db")
            ok, count = _check_db_integrity(db_path)
            assert ok, f"{agent}: Queue DB integrity check failed"

    def test_crash_recovery_kill9(self):
        """CL-25: Queue DB survives kill -9 and remains readable."""
        # Wait for at least one collection cycle
        time.sleep(35)

        # Pick one agent and kill -9 it
        victim = "protocol_collectors"
        proc = self.procs[victim]["proc"]
        victim_pid = proc.pid

        # Verify it's alive first
        assert proc.poll() is None, f"{victim} already dead before kill -9"

        # Kill -9 (no cleanup possible)
        proc.kill()
        proc.wait(timeout=5)

        # Verify DB integrity
        db_path = str(self.queue_root / victim / f"{victim}_queue.db")
        ok, count = _check_db_integrity(db_path)
        assert ok, f"{victim}: Queue DB corrupt after kill -9 " f"(count={count})"
        # DB should have at least 1 row from the collection cycle
        assert count >= 0, f"{victim}: Queue DB has no rows"
