"""
Multi-Dimensional Scoring Engine — Signal vs Noise Classification

Computes three independent scores for each security event:
  - geometric_score:  Spatial/network pattern analysis (IP rep, geo, ASN)
  - temporal_score:   Time/frequency anomaly detection (off-hours, bursts)
  - behavioral_score: Deviation from established baselines (rarity, escalation)

These are fused into a final_classification (legitimate/suspicious/malicious)
weighted by AMRDR agent reliability when available.

The scores fill the ML columns in the security_events table that were
reserved for this purpose but previously left empty.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import time
from collections import defaultdict, deque
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────

# RFC1918 / link-local networks (internal = low geometric risk)
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
]

# High-risk event categories (behavioral boost)
_HIGH_RISK_CATEGORIES = frozenset(
    {
        "brute_force",
        "credential_stuffing",
        "lateral_movement",
        "privilege_escalation",
        "persistence",
        "exfiltration",
        "dns_tunnel",
        "reverse_shell",
        "rootkit",
    }
)

# Fusion weights for final classification
_GEO_WEIGHT = 0.35
_TEMP_WEIGHT = 0.25
_BEHAV_WEIGHT = 0.40

# Classification thresholds
_MALICIOUS_THRESHOLD = 0.70
_SUSPICIOUS_THRESHOLD = 0.40


def _is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is in a private/reserved range."""
    if not ip_str:
        return True  # No IP = treat as internal
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except (ValueError, TypeError):
        return True


class EventBaseline:
    """Maintains sliding-window counters for event rarity calculations.

    Tracks (device_id, event_category, event_action) occurrence counts
    over a 24-hour window. Uses sorted deques with bisect for O(log n)
    time-range queries instead of O(n) list filtering.

    Per-device counters provide O(1) rarity denominators, eliminating
    the previous O(keys) scan across all event keys per call.
    """

    def __init__(self, window_seconds: int = 86400) -> None:
        self._window = window_seconds
        # (device_id, category, action) → sorted deque of timestamps
        self._events: Dict[Tuple[str, str, str], deque] = defaultdict(deque)
        # device_id → total event count in window (O(1) rarity denominator)
        self._device_counts: Dict[str, int] = defaultdict(int)
        # (device_id, source_ip, action) → first-seen timestamp
        self._first_seen: Dict[Tuple[str, str, str], float] = {}
        # (device_id, category) → sorted deque of timestamps for burst detection
        self._burst_tracker: Dict[Tuple[str, str], deque] = defaultdict(deque)
        self._total_events = 0
        self._last_cleanup = 0.0

    def record(
        self,
        device_id: str,
        category: str,
        action: str,
        source_ip: str = "",
        ts: Optional[float] = None,
    ) -> None:
        """Record an event occurrence. O(1) amortized."""
        now = ts or time.time()
        key = (device_id, category or "", action or "")
        self._events[key].append(now)
        self._device_counts[device_id] += 1
        self._total_events += 1

        # Track first-seen for (device, source_ip, action)
        if source_ip:
            fs_key = (device_id, source_ip, action or "")
            if fs_key not in self._first_seen:
                self._first_seen[fs_key] = now

        # Burst tracking per (device, category)
        burst_key = (device_id, category or "")
        self._burst_tracker[burst_key].append(now)

        # Periodic cleanup every 60s to bound memory
        if now - self._last_cleanup > 60:
            self.cleanup(now)

    def _trim_deque(self, dq: deque, cutoff: float) -> int:
        """Remove timestamps older than cutoff from front of deque. O(k) where k = expired."""
        removed = 0
        while dq and dq[0] < cutoff:
            dq.popleft()
            removed += 1
        return removed

    def get_rarity(
        self, device_id: str, category: str, action: str, ts: Optional[float] = None
    ) -> float:
        """Return rarity score 0.0 (common) to 1.0 (never seen before).

        O(1) amortized — uses pre-computed device counter for denominator.
        """
        now = ts or time.time()
        cutoff = now - self._window
        key = (device_id, category or "", action or "")

        dq = self._events.get(key)
        if dq is None or len(dq) == 0:
            return 1.0

        # Trim expired entries from front
        expired = self._trim_deque(dq, cutoff)
        if expired:
            self._device_counts[device_id] = max(
                0, self._device_counts.get(device_id, 0) - expired
            )

        count = len(dq)
        if count == 0:
            return 1.0

        total = max(self._device_counts.get(device_id, 0), 1)
        frequency = count / total
        return max(0.0, min(1.0, 1.0 - frequency))

    def is_first_seen(
        self, device_id: str, source_ip: str, action: str, ts: Optional[float] = None
    ) -> bool:
        """Check if this (device, source_ip, action) was seen for the first time recently."""
        now = ts or time.time()
        fs_key = (device_id, source_ip, action or "")
        first = self._first_seen.get(fs_key)
        if first is None:
            return True
        return (now - first) < 60

    def get_burst_count(
        self,
        device_id: str,
        category: str,
        window_seconds: int = 60,
        ts: Optional[float] = None,
    ) -> int:
        """Count events of same category within a short window. O(k) amortized."""
        now = ts or time.time()
        cutoff = now - window_seconds
        burst_key = (device_id, category or "")
        dq = self._burst_tracker.get(burst_key)
        if dq is None:
            return 0
        self._trim_deque(dq, cutoff)
        return len(dq)

    def cleanup(self, ts: Optional[float] = None) -> int:
        """Remove entries older than the window. Returns number of keys removed."""
        now = ts or time.time()
        self._last_cleanup = now
        cutoff = now - self._window
        removed = 0
        for key in list(self._events.keys()):
            dq = self._events[key]
            expired = self._trim_deque(dq, cutoff)
            if expired:
                device_id = key[0]
                self._device_counts[device_id] = max(
                    0, self._device_counts.get(device_id, 0) - expired
                )
            if not dq:
                del self._events[key]
                removed += 1
        for key in list(self._burst_tracker.keys()):
            self._trim_deque(self._burst_tracker[key], now - 120)
            if not self._burst_tracker[key]:
                del self._burst_tracker[key]
        return removed

    def save(self, path: str = "data/intel/baseline.json") -> None:
        """Snapshot current state to disk."""
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            data = {
                "total_events": self._total_events,
                "event_keys": len(self._events),
                "first_seen_keys": len(self._first_seen),
                "saved_at": time.time(),
            }
            with open(path, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.debug("Baseline save failed: %s", e)


# ── Geometric Scorer ──────────────────────────────────────────────────


class GeometricScorer:
    """Scores spatial/network patterns in an event.

    Factors:
      - Source IP internal vs external
      - Threat intel match (from enrichment)
      - GeoIP country mismatch
      - ASN reputation
    """

    def score(self, event: Dict[str, Any]) -> Tuple[float, List[Dict]]:
        """Compute geometric score and contributing factors.

        Returns:
            (score, factors) where factors is a list of
            {"name": str, "contribution": float, "detail": str}
        """
        factors = []
        total = 0.0

        source_ip = (
            event.get("source_ip", "")
            or event.get("indicators", {}).get("source_ip", "")
            if isinstance(event.get("indicators"), dict)
            else ""
        )
        # Try to extract from indicators string
        if not source_ip and isinstance(event.get("indicators"), str):
            try:
                ind = json.loads(event["indicators"])
                source_ip = ind.get("source_ip", "")
            except (json.JSONDecodeError, TypeError):
                pass

        # Factor 1: Internal vs External IP
        if source_ip and not _is_private_ip(source_ip):
            contrib = 0.30
            total += contrib
            factors.append(
                {
                    "name": "External Source IP",
                    "contribution": contrib,
                    "detail": f"IP {source_ip} is external (not RFC1918)",
                }
            )

        # Factor 2: Threat intel match
        threat_match = event.get("threat_match") or event.get("threat_intel_match")
        if isinstance(event.get("indicators"), dict):
            threat_match = threat_match or event["indicators"].get("threat_match")
        if threat_match:
            contrib = 0.40
            total += contrib
            factors.append(
                {
                    "name": "Threat Intelligence Match",
                    "contribution": contrib,
                    "detail": f"IP/domain matched threat feed: {threat_match}",
                }
            )

        # Factor 3: Country anomaly (non-US/expected country for a US device)
        country = event.get("country_code") or event.get("geo_country", "")
        if isinstance(event.get("indicators"), dict):
            country = country or event["indicators"].get("country_code", "")
        if country and country not in ("US", "CA", "GB", "DE", "AU", "JP", ""):
            contrib = 0.15
            total += contrib
            factors.append(
                {
                    "name": "Unusual Source Country",
                    "contribution": contrib,
                    "detail": f"Source country {country} is uncommon for this device",
                }
            )

        # Factor 4: ASN reputation
        asn_name = event.get("asn_name", "")
        if isinstance(event.get("indicators"), dict):
            asn_name = asn_name or event["indicators"].get("asn_name", "")
        risky_asns = {
            "bulletproof",
            "hosting",
            "vps",
            "cloud",
            "digitalocean",
            "linode",
            "vultr",
            "ovh",
            "hetzner",
        }
        if asn_name and any(ra in asn_name.lower() for ra in risky_asns):
            contrib = 0.15
            total += contrib
            factors.append(
                {
                    "name": "Hosting/VPS ASN",
                    "contribution": contrib,
                    "detail": f"ASN '{asn_name}' is a hosting provider (common attack origin)",
                }
            )

        return (min(1.0, total), factors)


# ── Temporal Scorer ───────────────────────────────────────────────────


class TemporalScorer:
    """Scores time/frequency anomalies.

    Factors:
      - Off-hours activity (outside 06:00-22:00)
      - Burst detection (>5 same-category events in 60s)
      - First-seen source+action pair
    """

    def __init__(self, baseline: EventBaseline) -> None:
        self._baseline = baseline

    def score(self, event: Dict[str, Any]) -> Tuple[float, List[Dict]]:
        """Compute temporal score and contributing factors."""
        factors = []
        total = 0.0

        device_id = event.get("device_id", "unknown")
        category = event.get("event_category", "")
        action = event.get("event_action", "")
        source_ip = ""
        indicators = (
            event.get("indicators") if isinstance(event.get("indicators"), dict) else {}
        )
        if indicators:
            source_ip = indicators.get("source_ip", "")

        # Factor 1: Off-hours activity
        # Prefer probe detection timestamp over ingestion timestamp
        hour = None
        evt_ts_ns = event.get("event_timestamp_ns")
        ts_dt = event.get("timestamp_dt", "")
        if evt_ts_ns and evt_ts_ns > 0:
            try:
                from datetime import datetime as _dt
                from datetime import timezone as _tz

                probe_dt = _dt.fromtimestamp(evt_ts_ns / 1e9, tz=_tz.utc)
                hour = probe_dt.hour
            except (OSError, ValueError, OverflowError):
                pass
        if hour is None and ts_dt and "T" in str(ts_dt):
            try:
                time_part = str(ts_dt).split("T")[1]
                hour = int(time_part.split(":")[0])
            except (IndexError, ValueError):
                pass

        if hour is not None and (hour < 6 or hour >= 22):
            contrib = 0.25
            total += contrib
            factors.append(
                {
                    "name": "Off-Hours Activity",
                    "contribution": contrib,
                    "detail": f"Event at {hour:02d}:00 (outside normal 06:00-22:00)",
                }
            )

        # Factor 2: Burst detection
        burst = self._baseline.get_burst_count(device_id, category)
        if burst > 5:
            contrib = min(0.40, 0.08 * burst)  # Scale with burst size, cap at 0.40
            total += contrib
            factors.append(
                {
                    "name": "Event Burst",
                    "contribution": contrib,
                    "detail": f"{burst} events of type '{category}' in last 60 seconds",
                }
            )

        # Factor 3: First-seen source
        if source_ip and self._baseline.is_first_seen(device_id, source_ip, action):
            contrib = 0.30
            total += contrib
            factors.append(
                {
                    "name": "First-Seen Source",
                    "contribution": contrib,
                    "detail": f"First time seeing {source_ip} performing '{action}' on this device",
                }
            )

        # Factor 4: Probe latency anomaly — delayed events are suspicious
        probe_latency = event.get("probe_latency_ns")
        if probe_latency is not None and probe_latency > 30_000_000_000:  # > 30 seconds
            contrib = 0.15
            total += contrib
            latency_s = probe_latency / 1e9
            factors.append(
                {
                    "name": "High Probe Latency",
                    "contribution": contrib,
                    "detail": f"Event delayed {latency_s:.1f}s from detection to ingestion",
                }
            )

        # Factor 5: Endpoint temporal probe signals (pass-through from correlation probes)
        endpoint_signals = [
            ("burst_score", 1.0, 0.10, "Endpoint Burst Score"),
            ("acceleration", 0.003, 0.08, "Endpoint Acceleration"),
            ("jitter_score", 0.6, 0.07, "Endpoint Periodicity"),
        ]
        for key, threshold, max_contrib, label in endpoint_signals:
            val = indicators.get(key)
            if val is not None:
                try:
                    val = float(val)
                except (TypeError, ValueError):
                    continue
                if val > threshold:
                    total += max_contrib
                    factors.append(
                        {
                            "name": label,
                            "contribution": max_contrib,
                            "detail": f"{key}={val:.3f} (threshold {threshold})",
                        }
                    )

        return (min(1.0, total), factors)


# ── Behavioral Scorer ─────────────────────────────────────────────────


class BehavioralScorer:
    """Scores deviation from established baselines.

    Factors:
      - Event rarity (inverse frequency in 24h window)
      - High-risk category flag
      - Cross-agent corroboration
      - Risk score from agent (high agent risk = behavioral anomaly)
    """

    def __init__(self, baseline: EventBaseline) -> None:
        self._baseline = baseline

    def score(self, event: Dict[str, Any]) -> Tuple[float, List[Dict]]:
        """Compute behavioral score and contributing factors."""
        factors = []
        total = 0.0

        device_id = event.get("device_id", "unknown")
        category = event.get("event_category", "")
        action = event.get("event_action", "")

        # Factor 1: Event rarity
        rarity = self._baseline.get_rarity(device_id, category, action)
        if rarity > 0.7:
            contrib = rarity * 0.30  # Scale contribution with rarity
            total += contrib
            factors.append(
                {
                    "name": "Rare Event Pattern",
                    "contribution": round(contrib, 3),
                    "detail": f"Event '{category}/{action}' has rarity {rarity:.2f} (1.0=never seen)",
                }
            )

        # Factor 2: High-risk category
        cat_lower = (category or "").lower().replace(" ", "_")
        if cat_lower in _HIGH_RISK_CATEGORIES or any(
            hr in cat_lower for hr in _HIGH_RISK_CATEGORIES
        ):
            contrib = 0.25
            total += contrib
            factors.append(
                {
                    "name": "High-Risk Category",
                    "contribution": contrib,
                    "detail": f"Category '{category}' is inherently high-risk",
                }
            )

        # Factor 3: Agent-reported risk score
        risk = event.get("risk_score", 0.0) or 0.0
        if risk >= 0.6:
            contrib = risk * 0.30  # Agent's own assessment matters
            total += contrib
            factors.append(
                {
                    "name": "Agent Risk Assessment",
                    "contribution": round(contrib, 3),
                    "detail": f"Agent reported risk_score={risk:.2f}",
                }
            )

        # Factor 4: Requires investigation flag
        if event.get("requires_investigation"):
            contrib = 0.15
            total += contrib
            factors.append(
                {
                    "name": "Investigation Required",
                    "contribution": contrib,
                    "detail": "Agent flagged this event for manual review",
                }
            )

        return (min(1.0, total), factors)


# ── Device Baseline (LEARNING / DETECTION modes) ─────────────────────


class BaselineMode(str, Enum):
    LEARNING = "learning"
    DETECTION = "detection"


class DeviceBaseline:
    """Per-device behavioral baseline with LEARNING/DETECTION modes.

    LEARNING mode: Records all (category, action) pairs as "normal" for this
    device. Builds frequency profiles, time-of-day patterns, and expected
    process/file/IP sets.

    DETECTION mode: Compares incoming events against learned baseline.
    Events matching learned patterns get suppressed scores (→ legitimate).
    Novel events get elevated scores (→ suspicious/malicious).
    """

    def __init__(self, device_id: str, learning_hours: int = 24) -> None:
        self.device_id = device_id
        self.mode = BaselineMode.LEARNING
        self.learning_hours = learning_hours
        self.started_at = time.time()
        self.transitioned_at: Optional[float] = None

        # Learned patterns
        self.known_actions: Dict[Tuple[str, str], int] = defaultdict(int)
        self.known_processes: Set[str] = set()
        self.known_suid_files: Set[str] = set()
        self.time_profile: Dict[int, int] = defaultdict(int)  # hour → event count
        self.known_source_ips: Set[str] = set()
        self.known_agents: Set[str] = set()
        self._total_learned = 0

    def record_learning(self, event: Dict[str, Any]) -> None:
        """Record an event during the learning phase."""
        category = event.get("event_category", "")
        action = event.get("event_action", "")
        self.known_actions[(category, action)] += 1
        self._total_learned += 1

        # Track time-of-day
        ts_dt = event.get("timestamp_dt", "")
        if ts_dt and "T" in str(ts_dt):
            try:
                hour = int(str(ts_dt).split("T")[1].split(":")[0])
                self.time_profile[hour] += 1
            except (IndexError, ValueError):
                pass

        # Track source IPs
        source_ip = ""
        indicators = event.get("indicators")
        if isinstance(indicators, dict):
            source_ip = indicators.get("source_ip", "")
        if source_ip:
            self.known_source_ips.add(source_ip)

        # Track collection agents
        agent = event.get("collection_agent", "")
        if agent:
            self.known_agents.add(agent)

        # Track SUID files (for FIM baseline)
        if category in ("suid_bit_added", "sgid_bit_added"):
            path = event.get("target_resource", "")
            if path:
                self.known_suid_files.add(path)

    def is_known_pattern(self, event: Dict[str, Any]) -> float:
        """Return how "known" an event is: 0.0 = fully novel, 1.0 = fully known.

        Combines multiple signals:
        - Category/action pair frequency (40%)
        - Source IP familiarity (20%)
        - Time-of-day normality (20%)
        - Agent familiarity (20%)
        """
        score = 0.0
        category = event.get("event_category", "")
        action = event.get("event_action", "")

        # Category/action known?
        count = self.known_actions.get((category, action), 0)
        if count > 0:
            # More frequent during learning = more "known"
            total = max(self._total_learned, 1)
            freq = count / total
            score += 0.40 * min(1.0, freq * 20)  # Saturates at 5% frequency

        # Source IP known?
        source_ip = ""
        indicators = event.get("indicators")
        if isinstance(indicators, dict):
            source_ip = indicators.get("source_ip", "")
        if not source_ip or source_ip in self.known_source_ips:
            score += 0.20  # No IP or known IP = normal

        # Time of day normal?
        ts_dt = event.get("timestamp_dt", "")
        if ts_dt and "T" in str(ts_dt):
            try:
                hour = int(str(ts_dt).split("T")[1].split(":")[0])
                if self.time_profile.get(hour, 0) > 0:
                    score += 0.20
            except (IndexError, ValueError):
                score += 0.10  # Can't determine, partial credit

        # Agent known?
        agent = event.get("collection_agent", "")
        if not agent or agent in self.known_agents:
            score += 0.20

        return min(1.0, score)

    @property
    def learning_progress(self) -> float:
        """Return learning progress as 0.0–1.0."""
        elapsed_hours = (time.time() - self.started_at) / 3600
        return min(1.0, elapsed_hours / max(self.learning_hours, 1))

    @property
    def hours_remaining(self) -> float:
        """Hours remaining in learning mode."""
        if self.mode == BaselineMode.DETECTION:
            return 0.0
        elapsed = (time.time() - self.started_at) / 3600
        return max(0.0, self.learning_hours - elapsed)

    def should_transition(self) -> bool:
        """Return True if learning period has elapsed."""
        return self.learning_progress >= 1.0

    def transition_to_detection(self) -> None:
        """Switch from LEARNING to DETECTION mode."""
        self.mode = BaselineMode.DETECTION
        self.transitioned_at = time.time()
        logger.info(
            "DeviceBaseline %s: LEARNING → DETECTION (%d actions, %d IPs, %d events learned)",
            self.device_id,
            len(self.known_actions),
            len(self.known_source_ips),
            self._total_learned,
        )

    def save(self, path: str) -> None:
        """Persist baseline state to JSON."""
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            data = {
                "device_id": self.device_id,
                "mode": self.mode.value,
                "learning_hours": self.learning_hours,
                "started_at": self.started_at,
                "transitioned_at": self.transitioned_at,
                "known_actions": {
                    f"{k[0]}|{k[1]}": v for k, v in self.known_actions.items()
                },
                "known_processes": list(self.known_processes),
                "known_suid_files": list(self.known_suid_files),
                "time_profile": dict(self.time_profile),
                "known_source_ips": list(self.known_source_ips),
                "known_agents": list(self.known_agents),
                "total_learned": self._total_learned,
                "saved_at": time.time(),
            }
            with open(path, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.debug("DeviceBaseline save failed for %s: %s", self.device_id, e)

    @classmethod
    def load(cls, path: str) -> Optional["DeviceBaseline"]:
        """Load baseline from JSON. Returns None if file doesn't exist."""
        try:
            if not os.path.exists(path):
                return None
            with open(path) as f:
                data = json.load(f)
            bl = cls(
                device_id=data["device_id"],
                learning_hours=data.get("learning_hours", 24),
            )
            bl.mode = BaselineMode(data.get("mode", "learning"))
            bl.started_at = data.get("started_at", time.time())
            bl.transitioned_at = data.get("transitioned_at")
            bl.known_actions = defaultdict(
                int,
                {
                    tuple(k.split("|")): v
                    for k, v in data.get("known_actions", {}).items()
                },
            )
            bl.known_processes = set(data.get("known_processes", []))
            bl.known_suid_files = set(data.get("known_suid_files", []))
            bl.time_profile = defaultdict(
                int, {int(k): v for k, v in data.get("time_profile", {}).items()}
            )
            bl.known_source_ips = set(data.get("known_source_ips", []))
            bl.known_agents = set(data.get("known_agents", []))
            bl._total_learned = data.get("total_learned", 0)
            return bl
        except Exception as e:
            logger.debug("DeviceBaseline load failed from %s: %s", path, e)
            return None

    def status(self) -> Dict[str, Any]:
        """Return baseline status for API."""
        return {
            "device_id": self.device_id,
            "mode": self.mode.value,
            "learning_progress_pct": round(self.learning_progress * 100, 1),
            "hours_remaining": round(self.hours_remaining, 1),
            "patterns_learned": self._total_learned,
            "known_actions_count": len(self.known_actions),
            "known_ips_count": len(self.known_source_ips),
            "known_agents_count": len(self.known_agents),
        }


# ── Scoring Engine (Orchestrator) ─────────────────────────────────────


class ScoringEngine:
    """Orchestrates multi-dimensional scoring for security events.

    Combines geometric (spatial), temporal (time), and behavioral (baseline)
    scores into a final classification weighted by AMRDR agent reliability.

    Usage:
        engine = ScoringEngine()
        scored = engine.score_event(event_dict)
        # scored now has geometric_score, temporal_score, behavioral_score,
        # final_classification, and score_factors populated
    """

    def __init__(
        self,
        baseline: Optional[EventBaseline] = None,
        learning_hours: int = 0,
    ) -> None:
        self._baseline = baseline or EventBaseline()
        self._geo = GeometricScorer()
        self._temp = TemporalScorer(self._baseline)
        self._behav = BehavioralScorer(self._baseline)
        self._total_scored = 0
        self._classification_counts: Dict[str, int] = defaultdict(int)

        # Per-device behavioral baselines (LEARNING → DETECTION)
        self._device_baselines: Dict[str, DeviceBaseline] = {}
        self._baseline_dir = "data/intel/baselines"
        self._learning_hours = learning_hours
        self._load_baselines()

        # INADS-inspired sequence scorer (attack chain detection)
        self._seq = SequenceScorer(window_seconds=600)

        # Dynamic thresholds (auto-calibrating per category)
        self._dynamic_thresholds = DynamicThresholds()

        # Calibration offsets per (category, action) — adjusted by feedback
        self._calibration: Dict[Tuple[str, str], float] = {}
        self._calibration_path = "data/intel/calibration.json"
        self._load_calibration()

        # SOMA Brain: ML model adapter (hot-reloads trained models)
        self._model_adapter = None
        try:
            from amoskys.intel.soma_brain import ModelScorerAdapter

            self._model_adapter = ModelScorerAdapter()
            logger.info(
                "ModelScorerAdapter initialized (ML scoring available when models trained)"
            )
        except Exception:
            pass

    def _load_baselines(self) -> None:
        """Load persisted device baselines from disk."""
        try:
            if not os.path.exists(self._baseline_dir):
                return
            for fname in os.listdir(self._baseline_dir):
                if not fname.endswith(".json"):
                    continue
                path = os.path.join(self._baseline_dir, fname)
                bl = DeviceBaseline.load(path)
                if bl:
                    self._device_baselines[bl.device_id] = bl
            if self._device_baselines:
                logger.info(
                    "Loaded %d device baselines (%d in DETECTION mode)",
                    len(self._device_baselines),
                    sum(
                        1
                        for b in self._device_baselines.values()
                        if b.mode == BaselineMode.DETECTION
                    ),
                )
        except Exception as e:
            logger.debug("Baseline load failed: %s", e)

    def _get_or_create_baseline(self, device_id: str) -> DeviceBaseline:
        """Get existing baseline or create new one in LEARNING mode.

        If learning_hours=0, immediately transitions to DETECTION mode
        (useful for testing or when baselines are pre-loaded).
        """
        if device_id not in self._device_baselines:
            bl = DeviceBaseline(
                device_id=device_id,
                learning_hours=self._learning_hours,
            )
            if self._learning_hours == 0:
                bl.transition_to_detection()
            self._device_baselines[device_id] = bl
        return self._device_baselines[device_id]

    def get_baseline_status(self, device_id: Optional[str] = None) -> Dict[str, Any]:
        """Get SOMA baseline status for API."""
        if device_id and device_id in self._device_baselines:
            return self._device_baselines[device_id].status()
        # Aggregate status across all devices
        baselines = list(self._device_baselines.values())
        if not baselines:
            return {
                "mode": "learning",
                "devices": 0,
                "learning_progress_pct": 0.0,
                "hours_remaining": self._learning_hours,
                "patterns_learned": 0,
                "known_actions_count": 0,
            }
        learning = [b for b in baselines if b.mode == BaselineMode.LEARNING]
        detection = [b for b in baselines if b.mode == BaselineMode.DETECTION]
        avg_progress = sum(b.learning_progress for b in baselines) / len(baselines)
        return {
            "mode": "detection" if not learning else "learning",
            "devices": len(baselines),
            "devices_learning": len(learning),
            "devices_detection": len(detection),
            "learning_progress_pct": round(avg_progress * 100, 1),
            "hours_remaining": round(
                max((b.hours_remaining for b in baselines), default=0.0), 1
            ),
            "patterns_learned": sum(b._total_learned for b in baselines),
            "known_actions_count": sum(len(b.known_actions) for b in baselines),
        }

    def set_baseline_mode(self, mode: str, device_id: Optional[str] = None) -> bool:
        """Manually override baseline mode for a device or all devices."""
        target_mode = BaselineMode(mode)
        targets = (
            [self._device_baselines[device_id]]
            if device_id and device_id in self._device_baselines
            else list(self._device_baselines.values())
        )
        if not targets:
            return False
        for bl in targets:
            if (
                target_mode == BaselineMode.DETECTION
                and bl.mode == BaselineMode.LEARNING
            ):
                bl.transition_to_detection()
                bl.save(os.path.join(self._baseline_dir, f"{bl.device_id}.json"))
            elif (
                target_mode == BaselineMode.LEARNING
                and bl.mode == BaselineMode.DETECTION
            ):
                bl.mode = BaselineMode.LEARNING
                bl.started_at = time.time()
                logger.info("DeviceBaseline %s: reset to LEARNING", bl.device_id)
        return True

    def _load_calibration(self) -> None:
        """Load calibration offsets from disk."""
        try:
            if os.path.exists(self._calibration_path):
                with open(self._calibration_path) as f:
                    raw = json.load(f)
                self._calibration = {
                    tuple(k.split("|")): v for k, v in raw.get("offsets", {}).items()
                }
                logger.info("Loaded %d calibration offsets", len(self._calibration))
        except Exception as e:
            logger.debug("Calibration load failed: %s", e)

    def save_calibration(self) -> None:
        """Persist calibration offsets to disk."""
        try:
            os.makedirs(os.path.dirname(self._calibration_path), exist_ok=True)
            data = {
                "offsets": {f"{k[0]}|{k[1]}": v for k, v in self._calibration.items()},
                "saved_at": time.time(),
            }
            with open(self._calibration_path, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.debug("Calibration save failed: %s", e)

    @property
    def baseline(self) -> EventBaseline:
        """Access the event baseline for external recording."""
        return self._baseline

    def _score_learning_mode(
        self, event: Dict[str, Any], device_bl: DeviceBaseline, device_id: str
    ) -> Dict[str, Any]:
        """Handle scoring during LEARNING mode — record and classify as legitimate."""
        device_bl.record_learning(event)
        if device_bl.should_transition():
            device_bl.transition_to_detection()
            device_bl.save(os.path.join(self._baseline_dir, f"{device_id}.json"))
        event["geometric_score"] = 0.0
        event["temporal_score"] = 0.0
        event["behavioral_score"] = 0.0
        event["final_classification"] = "legitimate"
        event["composite_score"] = 0.0
        event["score_factors"] = [
            {
                "name": "SOMA Learning Mode",
                "contribution": 0.0,
                "detail": f"Baseline learning {device_bl.learning_progress * 100:.0f}% complete",
            }
        ]
        self._total_scored += 1
        self._classification_counts["legitimate"] += 1
        return event

    def score_event(
        self, event: Dict[str, Any], agent_weight: float = 1.0
    ) -> Dict[str, Any]:
        """Score a security event across all three dimensions.

        Mutates the event dict in-place, adding:
          - geometric_score (0.0-1.0)
          - temporal_score (0.0-1.0)
          - behavioral_score (0.0-1.0)
          - final_classification (legitimate/suspicious/malicious)
          - score_factors (list of contributing factors for explainability)

        Args:
            event: Mutable event dictionary.
            agent_weight: AMRDR fusion weight for the collecting agent (0-1).

        Returns:
            The same event dict with scores populated.
        """
        device_id = event.get("device_id", "unknown")

        # Record in EventBaseline before scoring
        self._baseline.record(
            device_id=device_id,
            category=event.get("event_category", ""),
            action=event.get("event_action", ""),
            source_ip=(
                event.get("indicators", {}).get("source_ip", "")
                if isinstance(event.get("indicators"), dict)
                else ""
            ),
        )

        # DeviceBaseline: LEARNING mode → record pattern, classify as legitimate
        device_bl = self._get_or_create_baseline(device_id)
        if device_bl.mode == BaselineMode.LEARNING:
            return self._score_learning_mode(event, device_bl, device_id)

        # DETECTION mode — full scoring with baseline awareness
        known_factor = device_bl.is_known_pattern(event)

        # Compute three dimensions
        geo_score, geo_factors = self._geo.score(event)
        temp_score, temp_factors = self._temp.score(event)
        behav_score, behav_factors = self._behav.score(event)

        # Apply baseline suppression: known patterns reduce behavioral score
        # known_factor=1.0 → behavioral reduced by 70% (familiar pattern)
        # known_factor=0.0 → full behavioral score (novel event)
        if known_factor > 0.1:
            suppression = 0.70 * known_factor
            original_behav = behav_score
            behav_score = behav_score * (1.0 - suppression)
            if original_behav > 0.01:
                behav_factors.append(
                    {
                        "name": "Baseline Suppression",
                        "contribution": round(-(original_behav - behav_score), 3),
                        "detail": f"Known pattern (familiarity={known_factor:.2f}), behavioral reduced by {suppression * 100:.0f}%",
                    }
                )

        # SOMA suppression: frequency-based memory from IGRIS
        try:
            from amoskys.intel.soma import UnifiedSOMA

            soma = UnifiedSOMA()
            soma_result = soma.assess(
                category=event.get("event_category", ""),
                process=event.get("process_name", ""),
                path=event.get("path", event.get("exe", "")),
                risk=event.get("risk_score", 0),
            )
            soma.close()

            if soma_result.suppression_factor > 0.1:
                original_behav = behav_score
                behav_score = behav_score * (1.0 - soma_result.suppression_factor)
                if original_behav > 0.01:
                    behav_factors.append(
                        {
                            "name": "SOMA Suppression",
                            "contribution": round(-(original_behav - behav_score), 3),
                            "detail": f"SOMA: {soma_result.verdict} (seen {soma_result.seen_count}x, "
                            f"suppression={soma_result.suppression_factor:.0%})",
                        }
                    )
            elif soma_result.novelty > 0.7:
                # Novel event — boost behavioral score
                novel_boost = 0.15 * soma_result.novelty
                behav_score = min(1.0, behav_score + novel_boost)
                behav_factors.append(
                    {
                        "name": "SOMA Novelty Boost",
                        "contribution": round(novel_boost, 3),
                        "detail": f"SOMA: {soma_result.verdict} (novelty={soma_result.novelty:.2f})",
                    }
                )
        except Exception:
            pass  # SOMA not available — score without it

        # INADS sequence scoring: boost behavioral if attack chain detected
        category = event.get("event_category", "")
        seq_score, seq_name = self._seq.record_and_score(device_id, category)
        if seq_score > 0.0 and seq_name:
            seq_boost = seq_score * 0.30  # Up to +0.30 for full chain match
            behav_score = min(1.0, behav_score + seq_boost)
            behav_factors.append(
                {
                    "name": "Attack Sequence Detected",
                    "contribution": round(seq_boost, 3),
                    "detail": f"Kill chain match ({seq_score * 100:.0f}%): {seq_name}",
                }
            )

        # Apply calibration offset
        cal_key = (category, event.get("event_action", ""))
        offset = self._calibration.get(cal_key, 0.0)

        # Determine fusion weights — redistribute when geo data is absent.
        if geo_score < 1e-9 and not geo_factors:
            w_geo, w_temp, w_behav = 0.0, 0.38, 0.62
        else:
            w_geo, w_temp, w_behav = _GEO_WEIGHT, _TEMP_WEIGHT, _BEHAV_WEIGHT

        # ML model scoring — blends in when available (G1: call method with parens)
        ml_score, ml_factors = 0.0, []
        if self._model_adapter and self._model_adapter.available():
            ml_score, ml_factors = self._model_adapter.score(event)

        # Fuse into composite score (with ML blend when active)
        if ml_score > 0.0 and self._model_adapter and self._model_adapter.available():
            w_ml = 0.30
            scale = 0.70  # Redistribute 30% from heuristics to ML
            raw_composite = (
                w_geo * scale * geo_score
                + w_temp * scale * temp_score
                + w_behav * scale * behav_score
                + w_ml * ml_score
            )
        else:
            raw_composite = (
                w_geo * geo_score + w_temp * temp_score + w_behav * behav_score
            )
        composite = max(0.0, min(1.0, (raw_composite + offset) * agent_weight))

        # Classify using dynamic thresholds (auto-calibrated per category)
        sus_thresh, mal_thresh = self._dynamic_thresholds.get_thresholds(
            category, event.get("event_action", "")
        )

        # Trust-aware classification: Apple system processes and AMOSKYS self-traffic
        # get capped — they can never classify as "malicious"
        trust_disposition = event.get("trust_disposition", "unknown")
        if trust_disposition == "apple_system":
            # Apple system process: cap at "legitimate", reduce composite score
            composite = min(composite, sus_thresh * 0.5)
        elif trust_disposition == "self":
            # AMOSKYS own traffic: always legitimate
            composite = 0.0

        if composite >= mal_thresh:
            classification = "malicious"
        elif composite >= sus_thresh:
            classification = "suspicious"
        else:
            classification = "legitimate"

        # Preserve agent's original classification if more severe —
        # EXCEPT for trusted actors where we know the classification is wrong.
        _SEVERITY_ORDER = {"legitimate": 0, "suspicious": 1, "malicious": 2}
        original = event.get("final_classification", "legitimate")
        if trust_disposition == "unknown":
            # Only apply the never-downgrade rule for unknown processes
            if _SEVERITY_ORDER.get(original, 0) > _SEVERITY_ORDER.get(
                classification, 0
            ):
                classification = original

        # Populate event
        event["geometric_score"] = round(geo_score, 4)
        event["temporal_score"] = round(temp_score, 4)
        event["behavioral_score"] = round(behav_score, 4)
        event["final_classification"] = classification
        event["composite_score"] = round(composite, 4)
        event["score_factors"] = geo_factors + temp_factors + behav_factors + ml_factors

        self._total_scored += 1
        self._classification_counts[classification] += 1

        return event

    def recalibrate(self, category: str, action: str, is_false_positive: bool) -> None:
        """Adjust scoring threshold for a (category, action) pair based on feedback.

        If FP: raise threshold (less sensitive) → positive offset
        If TP: lower threshold (more sensitive) → negative offset
        """
        cal_key = (category, action)
        current = self._calibration.get(cal_key, 0.0)
        if is_false_positive:
            # Raise threshold — make it harder to trigger
            self._calibration[cal_key] = max(-0.5, current - 0.02)
        else:
            # Lower threshold — make it more sensitive
            self._calibration[cal_key] = min(0.5, current + 0.01)

        # Also feed dynamic thresholds
        self._dynamic_thresholds.record_outcome(
            category, action, is_true_positive=not is_false_positive
        )

    def stats(self) -> Dict[str, Any]:
        """Return scoring statistics."""
        return {
            "total_scored": self._total_scored,
            "classifications": dict(self._classification_counts),
            "calibration_entries": len(self._calibration),
            "baseline_keys": len(self._baseline._events),
            "device_baselines": len(self._device_baselines),
            "baselines_in_detection": sum(
                1
                for b in self._device_baselines.values()
                if b.mode == BaselineMode.DETECTION
            ),
            "model_adapter": (
                self._model_adapter.status() if self._model_adapter else None
            ),
        }

    def close(self) -> None:
        """Persist state before shutdown."""
        self.save_calibration()
        self._baseline.save()
        self._dynamic_thresholds.save()
        # Persist all device baselines
        os.makedirs(self._baseline_dir, exist_ok=True)
        for bl in self._device_baselines.values():
            bl.save(os.path.join(self._baseline_dir, f"{bl.device_id}.json"))


# ── INADS-Inspired Sequence Scorer ───────────────────────────────────


class SequenceScorer:
    """INADS-style sliding-window attack sequence analysis.

    Maintains per-device event sequences and detects known attack
    progression patterns (kill chain fragments). Returns a match score
    that boosts behavioral scoring when events follow known attack chains.
    """

    # Known attack sequences: each is a list of event_category prefixes
    # that form an attack progression. Ordered from initial access → impact.
    ATTACK_SEQUENCES: List[List[str]] = [
        # Brute force → success → reconnaissance
        ["auth_failure", "auth_success", "process_exec"],
        # SUID plant → privilege escalation → persistence
        ["suid_bit_added", "privilege_escalation", "service_creation"],
        # Service creation → config change → persistence
        ["service_creation", "config_modification", "persistence"],
        # File change → permission change → execution
        ["file_integrity", "permission_change", "process_exec"],
        # Discovery → lateral movement → exfiltration
        ["discovery", "lateral_movement", "exfiltration"],
        # DNS tunneling → data staging → exfiltration
        ["dns_tunnel", "file_integrity", "exfiltration"],
        # Login → sudo escalation → critical file change
        ["auth_success", "privilege_escalation", "critical_file_tampered"],
    ]

    def __init__(self, window_seconds: int = 600, max_history: int = 100) -> None:
        self._window = window_seconds
        self._max_history = max_history
        # device_id → deque of (timestamp, category)
        self._device_sequences: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=max_history)
        )

    def record_and_score(
        self, device_id: str, category: str, ts: Optional[float] = None
    ) -> Tuple[float, Optional[str]]:
        """Record event and return sequence match score.

        Returns:
            (score, matched_sequence_name) where score is 0.0–1.0.
            matched_sequence_name is None if no match, else a description.
        """
        now = ts or time.time()
        seq = self._device_sequences[device_id]
        seq.append((now, category.lower() if category else ""))

        # Trim events outside window
        cutoff = now - self._window
        while seq and seq[0][0] < cutoff:
            seq.popleft()

        # Extract recent categories (chronological order)
        recent = [cat for _, cat in seq]

        best_score = 0.0
        best_name: Optional[str] = None

        for chain in self.ATTACK_SEQUENCES:
            match_count = self._match_chain(recent, chain)
            if match_count >= 2:  # At least 2 steps matched
                ratio = match_count / len(chain)
                if ratio > best_score:
                    best_score = ratio
                    best_name = " → ".join(chain[:match_count])

        return (min(1.0, best_score), best_name)

    @staticmethod
    def _match_chain(recent: List[str], chain: List[str]) -> int:
        """Count how many chain steps match in order within recent events.

        Uses subsequence matching — chain steps don't need to be consecutive
        but must appear in order.
        """
        chain_idx = 0
        for cat in recent:
            if chain_idx >= len(chain):
                break
            if cat.startswith(chain[chain_idx]) or chain[chain_idx] in cat:
                chain_idx += 1
        return chain_idx


# ── Dynamic Thresholds (Auto-Calibrating) ────────────────────────────


class DynamicThresholds:
    """Auto-calibrating classification thresholds per (category, action).

    Tracks false positive rate from analyst feedback. Categories with high
    FP rates get raised thresholds (less sensitive). Categories with low
    FP rates get lowered thresholds (more sensitive).

    Used by ScoringEngine to replace static _SUSPICIOUS_THRESHOLD and
    _MALICIOUS_THRESHOLD per event category.
    """

    # Default thresholds (reference module-level constants)
    DEFAULT_SUSPICIOUS = _SUSPICIOUS_THRESHOLD
    DEFAULT_MALICIOUS = _MALICIOUS_THRESHOLD

    # Limits on how far thresholds can drift
    MIN_SUSPICIOUS = 0.25
    MAX_SUSPICIOUS = 0.60
    MIN_MALICIOUS = 0.50
    MAX_MALICIOUS = 0.85

    def __init__(self, max_observations: int = 100) -> None:
        self._max_obs = max_observations
        # (category, action) → deque of bools (True=TP, False=FP)
        self._observations: Dict[Tuple[str, str], deque] = defaultdict(
            lambda: deque(maxlen=max_observations)
        )
        # (category, action) → (suspicious_thresh, malicious_thresh)
        self._thresholds: Dict[Tuple[str, str], Tuple[float, float]] = {}
        self._path = "data/intel/dynamic_thresholds.json"
        self._load()

    def record_outcome(
        self, category: str, action: str, is_true_positive: bool
    ) -> None:
        """Record a TP/FP observation for a (category, action) pair."""
        key = (category, action)
        self._observations[key].append(is_true_positive)
        # Recalibrate this key
        self._recalibrate_key(key)

    def get_thresholds(self, category: str, action: str) -> Tuple[float, float]:
        """Get (suspicious, malicious) thresholds for this category.

        Returns adjusted thresholds if enough feedback, otherwise defaults.
        """
        key = (category, action)
        if key in self._thresholds:
            return self._thresholds[key]
        return (self.DEFAULT_SUSPICIOUS, self.DEFAULT_MALICIOUS)

    def _recalibrate_key(self, key: Tuple[str, str]) -> None:
        """Recalibrate thresholds for a specific key based on FP rate."""
        obs = self._observations[key]
        if len(obs) < 10:
            return  # Not enough data

        fp_count = sum(1 for o in obs if not o)
        fp_rate = fp_count / len(obs)

        # Base thresholds
        sus = self.DEFAULT_SUSPICIOUS
        mal = self.DEFAULT_MALICIOUS

        if fp_rate > 0.30:
            # High FP rate → raise thresholds (less sensitive)
            adjustment = min(0.15, (fp_rate - 0.30) * 0.5)
            sus += adjustment
            mal += adjustment
        elif fp_rate < 0.05:
            # Very low FP rate → lower thresholds (more sensitive)
            adjustment = min(0.10, (0.05 - fp_rate) * 2)
            sus -= adjustment
            mal -= adjustment

        # Clamp to limits
        sus = max(self.MIN_SUSPICIOUS, min(self.MAX_SUSPICIOUS, sus))
        mal = max(self.MIN_MALICIOUS, min(self.MAX_MALICIOUS, mal))

        self._thresholds[key] = (sus, mal)

    def recalibrate_all(self) -> int:
        """Recalibrate all tracked categories. Returns number adjusted."""
        count = 0
        for key in self._observations:
            old = self._thresholds.get(key)
            self._recalibrate_key(key)
            if self._thresholds.get(key) != old:
                count += 1
        return count

    def save(self) -> None:
        """Persist thresholds to disk."""
        try:
            os.makedirs(os.path.dirname(self._path), exist_ok=True)
            data = {
                "thresholds": {
                    f"{k[0]}|{k[1]}": list(v) for k, v in self._thresholds.items()
                },
                "observations_count": {
                    f"{k[0]}|{k[1]}": len(v) for k, v in self._observations.items()
                },
                "saved_at": time.time(),
            }
            with open(self._path, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.debug("DynamicThresholds save failed: %s", e)

    def _load(self) -> None:
        """Load persisted thresholds."""
        try:
            if not os.path.exists(self._path):
                return
            with open(self._path) as f:
                data = json.load(f)
            for key_str, vals in data.get("thresholds", {}).items():
                parts = key_str.split("|", 1)
                if len(parts) == 2 and len(vals) == 2:
                    self._thresholds[tuple(parts)] = (vals[0], vals[1])
            if self._thresholds:
                logger.info("Loaded %d dynamic thresholds", len(self._thresholds))
        except Exception as e:
            logger.debug("DynamicThresholds load failed: %s", e)
