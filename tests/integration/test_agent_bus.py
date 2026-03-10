"""Integration tests for AgentBus, KillChainTracker, and Detection Framework.

Tests cross-agent communication, kill-chain progression tracking,
and Sigma rule evaluation against real probe event types.
"""

from __future__ import annotations

import time

import pytest

from amoskys.agents.common.agent_bus import (
    AgentBus,
    PeerAlert,
    ThreatContext,
    get_agent_bus,
    reset_agent_bus,
)
from amoskys.agents.common.kill_chain import (
    KILL_CHAIN_STAGES,
    TACTIC_TO_STAGE,
    KillChainTracker,
)
from amoskys.detection.sigma_engine import SigmaEngine

# ── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def fresh_bus():
    """Reset AgentBus singleton before each test."""
    reset_agent_bus()
    yield
    reset_agent_bus()


@pytest.fixture
def bus() -> AgentBus:
    return get_agent_bus()


@pytest.fixture
def tracker() -> KillChainTracker:
    return KillChainTracker(ttl_seconds=60.0)


@pytest.fixture
def sigma_engine() -> SigmaEngine:
    engine = SigmaEngine()
    engine.load_rules("src/amoskys/detection/rules/sigma/")
    return engine


# ── AgentBus Tests ───────────────────────────────────────────────────────────


class TestAgentBusPostAndRead:
    """Verify agents can post and read threat contexts."""

    def test_post_context_and_read(self, bus: AgentBus):
        ctx = ThreatContext(
            agent_name="macos_process",
            timestamp_ns=int(time.time() * 1e9),
            active_pids={100, 200, 300},
            suspicious_ips=set(),
            persistence_paths=set(),
            active_techniques={"T1059"},
            risk_indicators={"cpu_abuse": 0.8},
        )
        bus.post_context("macos_process", ctx)

        read_back = bus.get_context("macos_process")
        assert read_back is not None
        assert read_back.agent_name == "macos_process"
        assert 100 in read_back.active_pids
        assert "T1059" in read_back.active_techniques

    def test_get_all_contexts(self, bus: AgentBus):
        for agent in ["macos_process", "macos_network", "macos_auth"]:
            bus.post_context(
                agent,
                ThreatContext(
                    agent_name=agent,
                    timestamp_ns=int(time.time() * 1e9),
                    active_pids=set(),
                    suspicious_ips=set(),
                    persistence_paths=set(),
                    active_techniques=set(),
                    risk_indicators={},
                ),
            )

        all_ctx = bus.get_all_contexts()
        assert len(all_ctx) == 3
        assert "macos_process" in all_ctx
        assert "macos_network" in all_ctx

    def test_nonexistent_agent_returns_none(self, bus: AgentBus):
        assert bus.get_context("nonexistent_agent") is None


class TestPeerAlerts:
    """Verify peer alert propagation."""

    def test_post_and_get_alerts(self, bus: AgentBus):
        alert = PeerAlert(
            source_agent="macos_network",
            alert_type="c2_detected",
            timestamp_ns=int(time.time() * 1e9),
            data={"remote_ip": "10.0.0.99", "pid": 1234},
        )
        bus.post_alert(alert)

        alerts = bus.get_alerts(since_ns=int((time.time() - 10) * 1e9))
        assert len(alerts) == 1
        assert alerts[0].alert_type == "c2_detected"
        assert alerts[0].data["remote_ip"] == "10.0.0.99"

    def test_alerts_filter_by_timestamp(self, bus: AgentBus):
        old_ns = int((time.time() - 100) * 1e9)
        new_ns = int(time.time() * 1e9)

        bus.post_alert(
            PeerAlert(
                source_agent="macos_auth",
                alert_type="brute_force",
                timestamp_ns=old_ns,
                data={},
            )
        )
        bus.post_alert(
            PeerAlert(
                source_agent="macos_auth",
                alert_type="credential_dump",
                timestamp_ns=new_ns,
                data={},
            )
        )

        # Only get alerts since 50 seconds ago
        recent = bus.get_alerts(since_ns=int((time.time() - 50) * 1e9))
        assert len(recent) == 1
        assert recent[0].alert_type == "credential_dump"

    def test_alert_visible_to_all_agents(self, bus: AgentBus):
        """PeerAlert from NetworkAgent should be visible to ProcessAgent."""
        bus.post_alert(
            PeerAlert(
                source_agent="macos_network",
                alert_type="lateral_movement",
                timestamp_ns=int(time.time() * 1e9),
                data={"target_ip": "192.168.1.50"},
            )
        )

        # Any agent reading alerts sees it
        alerts = bus.get_alerts(since_ns=0)
        assert len(alerts) >= 1
        assert any(a.alert_type == "lateral_movement" for a in alerts)


class TestCrossAgentQueries:
    """Verify cross-agent query methods."""

    def test_get_suspicious_ips(self, bus: AgentBus):
        bus.post_context(
            "macos_network",
            ThreatContext(
                agent_name="macos_network",
                timestamp_ns=int(time.time() * 1e9),
                active_pids=set(),
                suspicious_ips={"10.0.0.99", "192.168.1.100"},
                persistence_paths=set(),
                active_techniques=set(),
                risk_indicators={},
            ),
        )
        bus.post_context(
            "macos_dns",
            ThreatContext(
                agent_name="macos_dns",
                timestamp_ns=int(time.time() * 1e9),
                active_pids=set(),
                suspicious_ips={"10.0.0.99", "172.16.0.50"},
                persistence_paths=set(),
                active_techniques=set(),
                risk_indicators={},
            ),
        )

        all_ips = bus.get_all_suspicious_ips()
        assert "10.0.0.99" in all_ips
        assert "192.168.1.100" in all_ips
        assert "172.16.0.50" in all_ips

    def test_get_active_techniques(self, bus: AgentBus):
        bus.post_context(
            "macos_process",
            ThreatContext(
                agent_name="macos_process",
                timestamp_ns=int(time.time() * 1e9),
                active_pids=set(),
                suspicious_ips=set(),
                persistence_paths=set(),
                active_techniques={"T1059", "T1204"},
                risk_indicators={},
            ),
        )
        bus.post_context(
            "macos_persistence",
            ThreatContext(
                agent_name="macos_persistence",
                timestamp_ns=int(time.time() * 1e9),
                active_pids=set(),
                suspicious_ips=set(),
                persistence_paths={"/Library/LaunchAgents/evil.plist"},
                active_techniques={"T1543.001"},
                risk_indicators={},
            ),
        )

        all_techs = bus.get_all_active_techniques()
        assert "T1059" in all_techs
        assert "T1543.001" in all_techs


# ── Kill-Chain Tracker Tests ─────────────────────────────────────────────────


class TestKillChainTracker:
    """Verify kill-chain progression tracking."""

    def test_single_stage_recording(self, tracker: KillChainTracker):
        state = tracker.record_stage(
            device_id="macbook-pro",
            stage="reconnaissance",
            agent_name="macos_discovery",
            event_type="arp_host_burst",
            mitre_technique="T1018",
            confidence=0.8,
        )
        assert state.stages_reached == 1
        assert "reconnaissance" in state.unique_stages

    def test_multi_stage_progression(self, tracker: KillChainTracker):
        stages = [
            ("reconnaissance", "macos_discovery", "T1018"),
            ("delivery", "macos_auth", "T1566"),
            ("exploitation", "macos_process", "T1059"),
            ("installation", "macos_persistence", "T1543"),
        ]
        for stage, agent, tech in stages:
            state = tracker.record_stage(
                device_id="target-host",
                stage=stage,
                agent_name=agent,
                mitre_technique=tech,
                confidence=0.8,
            )

        assert state.stages_reached == 4
        assert state.is_multi_stage
        assert state.stage_sequence == [
            "reconnaissance",
            "delivery",
            "exploitation",
            "installation",
        ]

    def test_record_from_tactic(self, tracker: KillChainTracker):
        tracker.record_from_tactic(
            device_id="host-1",
            mitre_tactic="credential_access",
            agent_name="macos_auth",
            mitre_technique="T1110",
            confidence=0.85,
        )
        state = tracker.get_progression("host-1")
        assert state is not None
        assert "exploitation" in state.unique_stages

    def test_tactic_to_stage_mapping(self):
        """Every MITRE tactic has a kill-chain stage mapping."""
        expected_tactics = [
            "reconnaissance",
            "initial_access",
            "execution",
            "persistence",
            "privilege_escalation",
            "defense_evasion",
            "credential_access",
            "discovery",
            "lateral_movement",
            "collection",
            "command_and_control",
            "exfiltration",
            "impact",
        ]
        for tactic in expected_tactics:
            assert tactic in TACTIC_TO_STAGE, f"Missing mapping for {tactic}"

    def test_get_active_chains(self, tracker: KillChainTracker):
        for host in ["host-1", "host-2", "host-3"]:
            tracker.record_stage(
                device_id=host,
                stage="reconnaissance",
                agent_name="macos_discovery",
            )

        active = tracker.get_active_chains()
        assert len(active) == 3

    def test_get_multi_stage_chains(self, tracker: KillChainTracker):
        # Host-1: 1 stage (not multi)
        tracker.record_stage("host-1", "reconnaissance", "discovery")

        # Host-2: 3 stages (multi)
        for stage in ["reconnaissance", "exploitation", "installation"]:
            tracker.record_stage("host-2", stage, "correlation")

        multi = tracker.get_multi_stage_chains(min_stages=3)
        assert len(multi) == 1
        assert multi[0].device_id == "host-2"

    def test_clear_device(self, tracker: KillChainTracker):
        tracker.record_stage("host-1", "reconnaissance", "discovery")
        tracker.record_stage("host-2", "exploitation", "process")

        tracker.clear(device_id="host-1")

        assert tracker.get_progression("host-1") is None
        assert tracker.get_progression("host-2") is not None

    def test_duplicate_stages_counted_once(self, tracker: KillChainTracker):
        """Recording same stage twice still counts as 1 unique stage."""
        tracker.record_stage("host-1", "reconnaissance", "agent-a")
        tracker.record_stage("host-1", "reconnaissance", "agent-b")

        state = tracker.get_progression("host-1")
        assert state.stages_reached == 1
        assert len(state.observations) == 2


# ── Sigma Engine Integration Tests ──────────────────────────────────────────


class TestSigmaRuleLoading:
    """Verify Sigma rules load and provide coverage."""

    def test_rules_load_from_directory(self, sigma_engine: SigmaEngine):
        assert sigma_engine.rule_count >= 50

    def test_all_12_tactics_covered(self, sigma_engine: SigmaEngine):
        coverage = sigma_engine.get_coverage()
        expected_tactics = {
            "credential_access",
            "command_and_control",
            "defense_evasion",
            "discovery",
            "exfiltration",
            "execution",
            "impact",
            "initial_access",
            "persistence",
            "privilege_escalation",
            "collection",
            "lateral_movement",
        }
        assert expected_tactics.issubset(set(coverage.tactic_to_rules.keys()))

    def test_rule_has_mitre_technique(self, sigma_engine: SigmaEngine):
        """Every rule should have at least one MITRE technique."""
        for rule_id, rule in sigma_engine._rules.items():
            assert (
                len(rule.mitre_techniques) > 0
            ), f"Rule {rule_id} has no MITRE techniques"


class TestSigmaEventMatching:
    """Verify Sigma rules match expected events."""

    def test_ssh_brute_force_matches(self, sigma_engine: SigmaEngine):
        event = {"event_type": "ssh_login_failure", "source_ip": "10.0.0.1"}
        matches = sigma_engine.evaluate(event)
        rule_ids = [m.rule_id for m in matches]
        assert "amoskys-cred-001" in rule_ids

    def test_dga_domain_matches(self, sigma_engine: SigmaEngine):
        event = {"event_type": "dga_domain_detected", "domain": "xkj3h2.evil.com"}
        matches = sigma_engine.evaluate(event)
        rule_ids = [m.rule_id for m in matches]
        assert "amoskys-c2-003" in rule_ids

    def test_data_destruction_matches(self, sigma_engine: SigmaEngine):
        event = {"event_type": "data_destruction", "query": "DROP TABLE users"}
        matches = sigma_engine.evaluate(event)
        rule_ids = [m.rule_id for m in matches]
        assert "amoskys-impact-003" in rule_ids

    def test_benign_event_no_match(self, sigma_engine: SigmaEngine):
        event = {"event_type": "normal_heartbeat", "status": "ok"}
        matches = sigma_engine.evaluate(event)
        assert len(matches) == 0

    def test_match_includes_mitre_data(self, sigma_engine: SigmaEngine):
        event = {"event_type": "ssh_login_failure", "source_ip": "10.0.0.1"}
        matches = sigma_engine.evaluate(event)
        assert len(matches) >= 1
        match = matches[0]
        assert len(match.mitre_techniques) > 0
        assert match.confidence > 0


# ── End-to-End: AgentBus + KillChain + Sigma ─────────────────────────────────


class TestEndToEndDetection:
    """Simulate a multi-agent attack detection scenario."""

    def test_full_attack_chain(
        self, bus: AgentBus, tracker: KillChainTracker, sigma_engine: SigmaEngine
    ):
        """Simulate: recon → brute force → persistence → C2 → exfil."""
        device = "victim-host"

        # Step 1: Discovery agent detects recon
        tracker.record_stage(
            device,
            "reconnaissance",
            "macos_discovery",
            mitre_technique="T1018",
            confidence=0.7,
        )
        bus.post_context(
            "macos_discovery",
            ThreatContext(
                agent_name="macos_discovery",
                timestamp_ns=int(time.time() * 1e9),
                active_pids=set(),
                suspicious_ips={"10.0.0.99"},
                persistence_paths=set(),
                active_techniques={"T1018"},
                risk_indicators={"new_hosts": 0.5},
            ),
        )

        # Step 2: Auth agent detects brute force
        tracker.record_stage(
            device,
            "exploitation",
            "macos_auth",
            mitre_technique="T1110",
            confidence=0.85,
        )
        event = {"event_type": "ssh_login_failure", "source_ip": "10.0.0.99"}
        sigma_matches = sigma_engine.evaluate(event)
        assert len(sigma_matches) >= 1  # SSH brute force rule fires

        # Step 3: Persistence agent detects LaunchAgent
        tracker.record_stage(
            device,
            "installation",
            "macos_persistence",
            mitre_technique="T1543.001",
            confidence=0.9,
        )

        # Step 4: DNS agent detects C2 beaconing
        tracker.record_stage(
            device,
            "command_and_control",
            "macos_dns",
            mitre_technique="T1071.004",
            confidence=0.85,
        )
        bus.post_alert(
            PeerAlert(
                source_agent="macos_dns",
                alert_type="c2_beaconing",
                timestamp_ns=int(time.time() * 1e9),
                data={"domain": "evil-c2.com"},
            )
        )

        # Step 5: Internet activity detects exfil
        tracker.record_stage(
            device,
            "actions_on_objectives",
            "macos_internet_activity",
            mitre_technique="T1567",
            confidence=0.75,
        )

        # Verify kill chain
        state = tracker.get_progression(device)
        assert state is not None
        assert state.stages_reached >= 4
        assert state.is_multi_stage

        # Verify AgentBus has cross-agent data
        all_ips = bus.get_all_suspicious_ips()
        assert "10.0.0.99" in all_ips

        # Verify alerts propagated
        alerts = bus.get_alerts(since_ns=0)
        assert any(a.alert_type == "c2_beaconing" for a in alerts)

    def test_sigma_coverage_meets_minimum(self, sigma_engine: SigmaEngine):
        """Verify minimum MITRE coverage threshold."""
        coverage = sigma_engine.get_coverage()
        assert (
            coverage.total_techniques >= 40
        ), f"Only {coverage.total_techniques} techniques covered, need >= 40"
        assert (
            coverage.total_tactics >= 12
        ), f"Only {coverage.total_tactics} tactics covered, need >= 12"
