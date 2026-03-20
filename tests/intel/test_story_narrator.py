"""
Tests for StoryEngine and IGRIS Narrator
==========================================
Creates mock fusion incidents and verifies story reconstruction,
pattern matching, kill chain mapping, and template narration.

Run: PYTHONPATH=src pytest tests/intel/test_story_narrator.py -v
"""

import json
import sqlite3
import tempfile
import time
from pathlib import Path

import pytest

from amoskys.igris.narrator import Briefing, Narrator
from amoskys.intel.story_engine import (
    KILL_CHAIN_STAGES,
    KNOWN_PATTERNS,
    TECHNIQUE_NAMES,
    TECHNIQUE_TO_STAGE,
    AttackStory,
    StageEvidence,
    StoryEngine,
)

# ── Fixtures ─────────────────────────────────────────────────────


@pytest.fixture
def mock_dbs(tmp_path):
    """Create temporary telemetry and fusion DBs with test data."""
    tel_db = str(tmp_path / "telemetry.db")
    fus_db = str(tmp_path / "fusion.db")

    now_ns = int(time.time() * 1e9)
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%S+00:00")

    # ── Telemetry DB ──
    conn = sqlite3.connect(tel_db)
    conn.execute(
        """CREATE TABLE security_events (
        id INTEGER PRIMARY KEY, timestamp_ns INTEGER, event_category TEXT,
        risk_score REAL, mitre_techniques TEXT, collection_agent TEXT,
        event_action TEXT, raw_attributes_json TEXT
    )"""
    )
    conn.execute(
        """CREATE TABLE persistence_events (
        id INTEGER PRIMARY KEY, timestamp_ns INTEGER, mechanism TEXT,
        path TEXT, state TEXT, risk_score REAL
    )"""
    )
    conn.execute(
        """CREATE TABLE flow_events (
        id INTEGER PRIMARY KEY, timestamp_ns INTEGER, remote_ip TEXT,
        remote_port INTEGER, risk_score REAL, event_category TEXT
    )"""
    )
    conn.execute(
        """CREATE TABLE dns_events (
        id INTEGER PRIMARY KEY, timestamp_ns INTEGER, query_name TEXT,
        risk_score REAL, mitre_techniques TEXT
    )"""
    )
    conn.execute(
        """CREATE TABLE fim_events (
        id INTEGER PRIMARY KEY, timestamp_ns INTEGER, path TEXT,
        action TEXT, risk_score REAL
    )"""
    )

    # AMOS Stealer events
    conn.execute(
        "INSERT INTO security_events VALUES (1, ?, 'browser_credential_theft', 0.90, "
        "'[\"T1555.003\"]', 'macos_infostealer_guard', 'steal', NULL)",
        (now_ns,),
    )
    conn.execute(
        "INSERT INTO security_events VALUES (2, ?, 'session_cookie_theft', 0.85, "
        "'[\"T1539\"]', 'macos_infostealer_guard', 'steal', NULL)",
        (now_ns + 1000,),
    )
    conn.execute(
        "INSERT INTO security_events VALUES (3, ?, 'keychain_cli_abuse', 0.92, "
        "'[\"T1555.001\"]', 'macos_auth', 'dump', NULL)",
        (now_ns + 2000,),
    )
    conn.execute(
        "INSERT INTO persistence_events VALUES (1, ?, 'launchagent_user', "
        "'/Users/test/Library/LaunchAgents/com.amos.plist', 'new', 0.90)",
        (now_ns - 5000,),
    )
    conn.execute(
        "INSERT INTO security_events VALUES (4, ?, 'sensitive_file_exfil', 0.90, "
        "'[\"T1041\"]', 'macos_infostealer_guard', 'exfil', NULL)",
        (now_ns + 10000,),
    )

    # SSH brute force events
    conn.execute(
        "INSERT INTO security_events VALUES (5, ?, 'ssh_brute_force', 0.80, "
        "'[\"T1110.001\"]', 'macos_auth', 'brute', NULL)",
        (now_ns + 50000,),
    )
    conn.execute(
        "INSERT INTO flow_events VALUES (1, ?, '192.168.237.132', 22, 0.70, 'c2')",
        (now_ns + 55000,),
    )

    # DNS C2 events
    conn.execute(
        "INSERT INTO dns_events VALUES (1, ?, 'xk7m2p9q.evil.com', 0.85, '[\"T1568.002\"]')",
        (now_ns + 100000,),
    )
    conn.execute(
        "INSERT INTO dns_events VALUES (2, ?, 'f3n8v5w1.evil.com', 0.80, '[\"T1071.004\"]')",
        (now_ns + 101000,),
    )

    conn.commit()
    conn.close()

    # ── Fusion DB ──
    conn = sqlite3.connect(fus_db)
    conn.execute(
        """CREATE TABLE incidents (
        incident_id TEXT, device_id TEXT, severity TEXT, tactics TEXT,
        techniques TEXT, rule_name TEXT, summary TEXT, start_ts TEXT,
        end_ts TEXT, event_ids TEXT, metadata TEXT, created_at TEXT,
        agent_weights TEXT, weighted_confidence REAL, contributing_agents TEXT,
        start_ts_ns INTEGER, end_ts_ns INTEGER, duration_seconds REAL,
        mitre_sequence TEXT, observation_count INTEGER, observation_metadata TEXT,
        incident_context_json TEXT
    )"""
    )
    conn.execute(
        """CREATE TABLE device_risk (
        device_id TEXT, score INTEGER, level TEXT, reason_tags TEXT,
        supporting_events TEXT, metadata TEXT, updated_at TEXT
    )"""
    )

    # AMOS Stealer incident
    conn.execute(
        "INSERT INTO incidents VALUES ("
        "'INC-001', 'mac-1', 'critical', "
        '\'["persistence", "credential_access", "exfiltration"]\', '
        '\'["T1543.001", "T1555.001", "T1555.003", "T1539", "T1041"]\', '
        "'high_risk_detections', 'AMOS Stealer sequence detected', "
        "?, ?, '[1,2,3,4]', '{}', ?, "
        '\'{}\', 0.92, \'["macos_infostealer_guard", "macos_auth", "macos_persistence"]\', '
        "?, ?, 12.0, "
        '\'["persistence", "credential_access", "exfiltration"]\', 4, \'{}\', NULL'
        ")",
        (now_iso, now_iso, now_iso, now_ns - 5000, now_ns + 10000),
    )

    # SSH incident
    conn.execute(
        "INSERT INTO incidents VALUES ("
        "'INC-002', 'mac-1', 'high', "
        "'[\"credential_access\"]', "
        "'[\"T1110.001\"]', "
        "'ssh_brute_force', 'SSH brute force from 192.168.237.132', "
        "?, ?, '[5]', '{}', ?, "
        "'{}', 0.80, '[\"macos_auth\"]', "
        "?, ?, 5.0, "
        "'[\"credential_access\"]', 1, '{}', NULL"
        ")",
        (now_iso, now_iso, now_iso, now_ns + 50000, now_ns + 55000),
    )

    # DNS C2 incident
    conn.execute(
        "INSERT INTO incidents VALUES ("
        "'INC-003', 'mac-1', 'high', "
        "'[\"command_and_control\"]', "
        '\'["T1568.002", "T1071.004"]\', '
        "'dns_c2', 'DNS C2 channel detected', "
        "?, ?, '[]', '{}', ?, "
        "'{}', 0.75, '[\"macos_dns\"]', "
        "?, ?, 1.0, "
        "'[\"command_and_control\"]', 2, '{}', NULL"
        ")",
        (now_iso, now_iso, now_iso, now_ns + 100000, now_ns + 101000),
    )

    conn.commit()
    conn.close()

    return tel_db, fus_db


@pytest.fixture
def engine(mock_dbs):
    tel_db, fus_db = mock_dbs
    return StoryEngine(telemetry_db=tel_db, fusion_db=fus_db)


@pytest.fixture
def narrator():
    return Narrator(use_claude=False)


# ── StoryEngine Tests ────────────────────────────────────────────


class TestStoryEngine:

    def test_build_stories_returns_results(self, engine):
        stories = engine.build_stories(hours=24, min_severity="high")
        assert len(stories) >= 1

    def test_amos_pattern_matched(self, engine):
        stories = engine.build_stories(hours=24, min_severity="high")
        amos = [s for s in stories if s.pattern_name == "amos_stealer"]
        assert len(amos) >= 1

    def test_amos_kill_chain_stages(self, engine):
        stories = engine.build_stories(hours=24, min_severity="high")
        amos = [s for s in stories if s.pattern_name == "amos_stealer"][0]
        assert amos.stage_count >= 2

    def test_amos_severity_critical(self, engine):
        stories = engine.build_stories(hours=24, min_severity="high")
        amos = [s for s in stories if s.pattern_name == "amos_stealer"][0]
        assert amos.severity == "critical"

    def test_amos_confidence_high(self, engine):
        stories = engine.build_stories(hours=24, min_severity="high")
        amos = [s for s in stories if s.pattern_name == "amos_stealer"][0]
        assert amos.confidence > 0.8

    def test_amos_has_techniques(self, engine):
        stories = engine.build_stories(hours=24, min_severity="high")
        amos = [s for s in stories if s.pattern_name == "amos_stealer"][0]
        assert len(amos.techniques) >= 3

    def test_amos_has_affected_assets(self, engine):
        stories = engine.build_stories(hours=24, min_severity="high")
        amos = [s for s in stories if s.pattern_name == "amos_stealer"][0]
        assert len(amos.affected_assets) >= 1

    def test_amos_has_narrative_context(self, engine):
        stories = engine.build_stories(hours=24, min_severity="high")
        amos = [s for s in stories if s.pattern_name == "amos_stealer"][0]
        assert "stages" in amos.narrative_context

    def test_amos_story_id_format(self, engine):
        stories = engine.build_stories(hours=24, min_severity="high")
        amos = [s for s in stories if s.pattern_name == "amos_stealer"][0]
        assert amos.story_id.startswith("STORY-")

    def test_amos_to_dict(self, engine):
        stories = engine.build_stories(hours=24, min_severity="high")
        amos = [s for s in stories if s.pattern_name == "amos_stealer"][0]
        d = amos.to_dict()
        assert "kill_chain" in d
        assert "story_id" in d

    def test_ssh_brute_force_events_present(self, engine):
        stories = engine.build_stories(hours=24, min_severity="high")
        assert any("T1110.001" in s.techniques for s in stories)

    def test_dns_c2_detected(self, engine):
        stories = engine.build_stories(hours=24, min_severity="high")
        has_dns = any(s.pattern_name == "dns_c2" for s in stories) or any(
            "T1568.002" in s.techniques for s in stories
        )
        assert has_dns

    def test_build_story_for_incident(self, engine):
        story = engine.build_story_for_incident("INC-001")
        assert story is not None
        assert story.stage_count >= 1

    def test_build_story_for_nonexistent_incident(self, engine):
        story = engine.build_story_for_incident("INC-DOESNOTEXIST")
        assert story is None

    def test_technique_to_stage_coverage(self):
        assert len(TECHNIQUE_TO_STAGE) > 50

    def test_known_patterns_count(self):
        assert len(KNOWN_PATTERNS) >= 5

    def test_kill_chain_stages_ordered(self):
        assert KILL_CHAIN_STAGES[0] == "reconnaissance"
        assert KILL_CHAIN_STAGES[-1] == "impact"

    def test_technique_names_populated(self):
        assert len(TECHNIQUE_NAMES) > 30
        assert "T1543.001" in TECHNIQUE_NAMES

    def test_severity_filter_medium(self, engine):
        stories = engine.build_stories(hours=24, min_severity="medium")
        assert len(stories) >= 1

    def test_empty_db_returns_empty(self, tmp_path):
        tel_db = str(tmp_path / "empty_tel.db")
        fus_db = str(tmp_path / "empty_fus.db")
        # Create empty DBs
        for db in (tel_db, fus_db):
            conn = sqlite3.connect(db)
            conn.close()
        engine = StoryEngine(telemetry_db=tel_db, fusion_db=fus_db)
        stories = engine.build_stories(hours=1)
        assert stories == []


# ── Narrator Tests ───────────────────────────────────────────────


class TestNarrator:

    def test_amos_briefing_produced(self, engine, narrator):
        stories = engine.build_stories(hours=24, min_severity="high")
        amos = [s for s in stories if s.pattern_name == "amos_stealer"][0]
        briefing = narrator.narrate(amos)
        assert briefing is not None
        assert isinstance(briefing, Briefing)

    def test_amos_briefing_title(self, engine, narrator):
        stories = engine.build_stories(hours=24, min_severity="high")
        amos = [s for s in stories if s.pattern_name == "amos_stealer"][0]
        briefing = narrator.narrate(amos)
        assert len(briefing.title) > 0
        assert "AMOS" in briefing.title

    def test_amos_briefing_text(self, engine, narrator):
        stories = engine.build_stories(hours=24, min_severity="high")
        amos = [s for s in stories if s.pattern_name == "amos_stealer"][0]
        briefing = narrator.narrate(amos)
        assert len(briefing.text) > 50

    def test_amos_briefing_actions(self, engine, narrator):
        stories = engine.build_stories(hours=24, min_severity="high")
        amos = [s for s in stories if s.pattern_name == "amos_stealer"][0]
        briefing = narrator.narrate(amos)
        assert len(briefing.recommended_actions) >= 3

    def test_amos_briefing_source_is_template(self, engine, narrator):
        stories = engine.build_stories(hours=24, min_severity="high")
        amos = [s for s in stories if s.pattern_name == "amos_stealer"][0]
        briefing = narrator.narrate(amos)
        assert briefing.source == "template"

    def test_amos_briefing_severity(self, engine, narrator):
        stories = engine.build_stories(hours=24, min_severity="high")
        amos = [s for s in stories if s.pattern_name == "amos_stealer"][0]
        briefing = narrator.narrate(amos)
        assert briefing.severity == "critical"

    def test_amos_briefing_kill_chain_summary(self, engine, narrator):
        stories = engine.build_stories(hours=24, min_severity="high")
        amos = [s for s in stories if s.pattern_name == "amos_stealer"][0]
        briefing = narrator.narrate(amos)
        assert len(briefing.kill_chain_summary) > 0
        assert "→" in briefing.kill_chain_summary

    def test_terminal_colored_output(self, engine, narrator):
        stories = engine.build_stories(hours=24, min_severity="high")
        amos = [s for s in stories if s.pattern_name == "amos_stealer"][0]
        briefing = narrator.narrate(amos)
        output = briefing.to_terminal(colors=True)
        assert "IGRIS" in output
        assert "Recommended" in output

    def test_terminal_plain_output(self, engine, narrator):
        stories = engine.build_stories(hours=24, min_severity="high")
        amos = [s for s in stories if s.pattern_name == "amos_stealer"][0]
        briefing = narrator.narrate(amos)
        output = briefing.to_terminal(colors=False)
        assert "IGRIS" in output

    def test_generic_narration(self, narrator):
        unknown = AttackStory(
            story_id="STORY-unknown",
            incident_ids=["INC-999"],
            pattern_name=None,
            pattern_label="Unknown Attack Chain",
            kill_chain=[],
            severity="medium",
            confidence=0.5,
            techniques=["T1059.004", "T1082"],
            affected_assets=["/tmp/evil.sh"],
            first_event=time.time() - 60,
            last_event=time.time(),
            raw_event_count=5,
            narrative_context={
                "stages": [],
                "all_techniques": ["T1059.004", "T1082"],
                "technique_descriptions": {
                    "T1059.004": "Unix Shell",
                    "T1082": "System Discovery",
                },
                "affected_assets": ["/tmp/evil.sh"],
                "file_paths": ["/tmp/evil.sh"],
                "ips": [],
                "domains": [],
                "incident_summaries": ["Unknown activity"],
                "contributing_agents": ["macos_process"],
            },
        )
        briefing = narrator.narrate(unknown)
        assert briefing is not None
        assert len(briefing.text) > 20
        assert briefing.source == "template"

    def test_duration_subsecond(self, narrator):
        assert narrator._format_duration(0.5) == "< 1 second"

    def test_duration_seconds(self, narrator):
        assert "seconds" in narrator._format_duration(45)

    def test_duration_minutes(self, narrator):
        assert "minutes" in narrator._format_duration(300)

    def test_duration_hours(self, narrator):
        assert "hours" in narrator._format_duration(7200)
