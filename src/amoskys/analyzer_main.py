#!/usr/bin/env python3
"""AMOSKYS Analyzer Daemon — Tier 2.

Reads events from WAL files written by the Collector (Tier 1) and runs
the full analysis pipeline:
  1. Enrichment (GeoIP, ASN, threat intel, MITRE mapping)
  2. Scoring (geometric, temporal, behavioral, sequence)
  3. Detection (180 probes, 56 Sigma rules)
  4. Correlation (13 fusion rules, kill chain tracking)
  5. Storage (telemetry.db domain tables, incidents, rollups)
  6. IGRIS (coherence assessment, signal emission, autonomous defense)

Usage:
    PYTHONPATH=src python -m amoskys.analyzer_main
"""

from __future__ import annotations

import json
import logging
import os
import signal
import sys
import threading
import time
from pathlib import Path

logger = logging.getLogger("amoskys.analyzer")

# DB paths are env-overridable so the analyzer ("the brain") can be pointed at a
# Command-Center fleet DB for re-scoring without changing single-machine defaults.
# With no env set, these resolve to the exact same paths as before:
#   DATA_DIR       -> data/
#   TELEMETRY_DB   -> data/telemetry.db
#   FUSION_DB      -> data/intel/fusion.db
DATA_DIR = Path(os.environ.get("AMOSKYS_DATA_DIR", "data"))
WAL_DIR = DATA_DIR / "wal"
TELEMETRY_DB = Path(
    os.environ.get("AMOSKYS_TELEMETRY_DB", str(DATA_DIR / "telemetry.db"))
)
FUSION_DB = Path(
    os.environ.get("AMOSKYS_FUSION_DB", str(DATA_DIR / "intel" / "fusion.db"))
)
# The fleet-rescore TARGET is a Command-Center fleet DB (fleet.db) — SEPARATE from
# TELEMETRY_DB, which backs the analyzer's own TelemetryStore and expects the full
# TelemetryStore schema (fleet.db does not have it, e.g. no `is_suspicious`).
# Defaults to TELEMETRY_DB so single-machine / direct-call usage is unchanged; on a
# fleet node set AMOSKYS_FLEET_DB=/var/lib/amoskys/fleet.db and keep
# AMOSKYS_TELEMETRY_DB pointed at a fresh analyzer-owned DB.
FLEET_DB = Path(os.environ.get("AMOSKYS_FLEET_DB", str(TELEMETRY_DB)))

# Columns the scoring/enrichment pipeline writes onto security_events. fleet.db
# (authored by command_center) is missing composite_score / risk_score_raw /
# last_scored; _rescore_fleet_db adds any that are absent, idempotently.
_FLEET_SCORE_COLUMNS = (
    ("risk_score_raw", "REAL"),
    ("geometric_score", "REAL"),
    ("temporal_score", "REAL"),
    ("behavioral_score", "REAL"),
    ("composite_score", "REAL"),
    ("final_classification", "TEXT"),
    ("enrichment_status", "TEXT"),
    ("last_scored", "INTEGER"),
)


def _ensure_fleet_score_columns(conn) -> None:
    """Idempotently add the scoring columns to security_events.

    fleet.db (written by command_center) may lack composite_score /
    risk_score_raw / last_scored. Each ALTER is wrapped so an already-present
    column (SQLite raises 'duplicate column name') is simply skipped.
    """
    for col, col_type in _FLEET_SCORE_COLUMNS:
        try:
            conn.execute(f"ALTER TABLE security_events ADD COLUMN {col} {col_type}")
        except Exception:
            # Column already exists (duplicate column name) — nothing to do.
            pass


def _build_fusion_view(event_data, device_id):
    """Best-effort construct a lightweight TelemetryEventView from a fleet row.

    We have no protobuf here (fleet.db rows are already flattened), so we build
    the view + its security_event dict directly. Kept minimal — just enough for
    fusion correlation rules to see the event. Returns None on any failure so
    the caller can treat fusion as strictly best-effort.
    """
    from datetime import datetime, timezone

    from amoskys.intel.models import TelemetryEventView

    ts_ns = int(
        event_data.get("event_timestamp_ns") or event_data.get("timestamp_ns") or 0
    )
    if ts_ns > 0:
        ts = datetime.fromtimestamp(ts_ns / 1e9, tz=timezone.utc)
    else:
        ts = datetime.now(timezone.utc)

    security_event = {
        "event_category": event_data.get("event_category", "") or "",
        "event_action": event_data.get("event_action", "") or "",
        "event_outcome": event_data.get("event_outcome", "") or "",
        "source_ip": event_data.get("remote_ip", "") or "",
        "risk_score": float(event_data.get("risk_score", 0.0) or 0.0),
        "mitre_techniques": event_data.get("mitre_techniques", []) or [],
        "requires_investigation": False,
    }

    view = TelemetryEventView(
        event_id=str(event_data.get("event_id") or event_data.get("id") or ""),
        device_id=str(device_id or ""),
        event_type=str(event_data.get("event_type", "SECURITY") or "SECURITY"),
        severity=str(event_data.get("final_classification", "") or ""),
        timestamp=ts,
        attributes={
            k: str(v)
            for k, v in event_data.items()
            if v is not None and not isinstance(v, (dict, list))
        },
        event_timestamp_ns=ts_ns,
        probe_name=event_data.get("probe_name") or None,
        collection_agent=event_data.get("collection_agent") or None,
        security_event=security_event,
    )
    return view


def _rescore_fleet_db(db_path, scorer, enricher, fusion, batch: int = 500) -> int:
    """Re-score a Command-Center fleet DB's ``security_events`` in place.

    fleet.db is written by command_center from shipped agent telemetry and has
    the raw event but no brain-computed scores. This makes the analyzer ("the
    brain") the scorer for fleet events: it enriches each unscored row, runs the
    ScoringEngine, best-effort feeds fusion, and writes the 8 score columns back.

    Selection: rows WHERE composite_score IS NULL OR last_scored IS NULL, and
    (to avoid racing fresh command_center inserts) only rows at least ~2s old.
    ``received_at`` is an epoch REAL in fleet.db, so ``received_at <
    strftime('%s','now')-2`` compares like-for-like; if that column is absent we
    fall back to an id-based cutoff (id <= max(id)-batch guard via ORDER BY id).

    Args:
        db_path: Path to the fleet DB (sqlite3 file).
        scorer: A ScoringEngine (mutates event dict with score columns).
        enricher: An EnrichmentPipeline (or None) — enrich runs before scoring.
        fusion: A FusionEngine (or None) — add_event is best-effort.
        batch: Max rows to score per call.

    Returns:
        Number of rows successfully scored this call.
    """
    import sqlite3 as _sqlite3

    scored = 0
    skipped = 0
    conn = None
    try:
        conn = _sqlite3.connect(str(db_path), timeout=10.0)
        conn.execute("PRAGMA busy_timeout=10000")
        try:
            conn.execute("PRAGMA journal_mode=WAL")
        except Exception:
            pass
        conn.row_factory = _sqlite3.Row

        _ensure_fleet_score_columns(conn)
        conn.commit()

        # Discover which columns actually exist so the age filter degrades safely.
        existing_cols = {
            r[1] for r in conn.execute("PRAGMA table_info(security_events)").fetchall()
        }

        need = "(composite_score IS NULL OR last_scored IS NULL)"
        if "received_at" in existing_cols:
            # received_at is epoch seconds (REAL) — same units as strftime('%s').
            age_guard = "AND received_at < (strftime('%s','now') - 2)"
        else:
            # No received_at: fall back to id-based ordering (oldest first). The
            # 2s-race guard is unavailable, so we simply take the oldest rows.
            age_guard = ""

        rows = conn.execute(
            f"SELECT * FROM security_events WHERE {need} {age_guard} "
            f"ORDER BY id LIMIT ?",
            (batch,),
        ).fetchall()

        now_epoch = int(time.time())
        for row in rows:
            # Bind id up-front (before any risky work) so the error handler can
            # always name the offending row.
            try:
                row_id = row["id"]
            except (IndexError, KeyError):
                row_id = None
            try:
                event_data = {k: row[k] for k in row.keys()}
                device_id = event_data.get("device_id", "") or "unknown"

                # mitre_techniques is stored as a JSON string in fleet.db —
                # decode so scoring/fusion see a list, not a raw string.
                mt = event_data.get("mitre_techniques")
                if isinstance(mt, str) and mt:
                    try:
                        event_data["mitre_techniques"] = json.loads(mt)
                    except (json.JSONDecodeError, TypeError):
                        pass

                # Enrich (GeoIP/ASN/ThreatIntel) then score. Both mutate in place.
                if enricher is not None:
                    try:
                        enricher.enrich(event_data)
                    except Exception:
                        logger.debug(
                            "Fleet enrich failed for id=%s", row_id, exc_info=True
                        )

                scorer.score_event(event_data)

                # Best-effort fusion feed — never let a fusion error abort scoring.
                if fusion is not None:
                    try:
                        view = _build_fusion_view(event_data, device_id)
                        if view is not None:
                            fusion.add_event(view)
                    except Exception:
                        logger.debug(
                            "Fleet fusion feed failed for id=%s", row_id, exc_info=True
                        )

                conn.execute(
                    "UPDATE security_events SET "
                    "risk_score_raw=?, geometric_score=?, temporal_score=?, "
                    "behavioral_score=?, composite_score=?, final_classification=?, "
                    "enrichment_status=?, last_scored=? WHERE id=?",
                    (
                        event_data.get("risk_score_raw"),
                        event_data.get("geometric_score"),
                        event_data.get("temporal_score"),
                        event_data.get("behavioral_score"),
                        event_data.get("composite_score"),
                        event_data.get("final_classification"),
                        event_data.get("enrichment_status"),
                        now_epoch,
                        row_id,
                    ),
                )
                scored += 1
            except Exception as e:
                # One bad row must not abort the batch.
                skipped += 1
                logger.warning("Fleet rescore: skipping row id=%s: %s", row_id, e)

        conn.commit()
    except Exception as e:
        logger.error("Fleet rescore failed for %s: %s", db_path, e)
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass

    if scored or skipped:
        logger.info(
            "Fleet rescore: scored %d, skipped %d (%s)", scored, skipped, db_path
        )
    return scored


def main(run_once: bool = False) -> int:
    """Analyzer process entry point.

    Args:
        run_once: When True, run a single fleet-DB rescore batch and exit 0
            (for validation / cron-style invocation) instead of entering the
            continuous analysis loop.
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    logger.info("AMOSKYS Analyzer Daemon starting (pid=%d)", os.getpid())

    shutdown_event = threading.Event()

    def handle_signal(signum, frame):
        logger.info("Analyzer received signal %d, shutting down", signum)
        shutdown_event.set()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    # ── Initialize pipeline components ──
    try:
        from amoskys.storage.telemetry_store import TelemetryStore

        store = TelemetryStore(str(TELEMETRY_DB))
        logger.info("TelemetryStore initialized: %s", TELEMETRY_DB)
    except Exception as e:
        logger.error("Failed to initialize TelemetryStore: %s", e)
        return 1

    # Enrichment pipeline (GeoIP, ASN, ThreatIntel, MITRE)
    enrichment = None
    try:
        from amoskys.enrichment import EnrichmentPipeline

        enrichment = EnrichmentPipeline()
        logger.info("EnrichmentPipeline initialized: %s", enrichment.status())
    except Exception as e:
        logger.warning("EnrichmentPipeline not available: %s", e)

    try:
        from amoskys.intel.scoring import ScoringEngine

        scorer = ScoringEngine()
        logger.info("ScoringEngine initialized")
    except Exception as e:
        logger.warning("ScoringEngine not available: %s", e)
        scorer = None

    # ── Sigma detection-as-code engine (56 stateless rules) ──
    sigma = None
    try:
        from amoskys.detection.sigma_engine import SigmaEngine

        sigma = SigmaEngine()
        logger.info(
            "SigmaEngine initialized — %d rules loaded, %d techniques covered",
            sigma.rule_count,
            len(sigma.get_coverage().technique_to_rules),
        )
    except Exception as e:
        logger.warning("SigmaEngine not available: %s", e)

    # ── Forensic context enricher (cross-agent attribution) ──
    forensic = None
    try:
        from amoskys.enrichment.forensic_context import ForensicContextEnricher

        forensic = ForensicContextEnricher()
        logger.info(
            "ForensicContextEnricher initialized — cross-agent attribution active"
        )
    except Exception as e:
        logger.warning("ForensicContextEnricher not available: %s", e)

    # ── SOMA frequency memory (baseline learning) ──
    soma = None
    try:
        from amoskys.intel.soma import UnifiedSOMA

        soma = UnifiedSOMA()
        logger.info("SOMA frequency memory initialized — baseline learning active")
    except Exception as e:
        logger.warning("SOMA not available: %s", e)

    # ── Probe self-calibration (Beta-Binomial precision tracking) ──
    probe_cal = None
    try:
        from amoskys.intel.probe_calibration import ProbeCalibrator

        probe_cal = ProbeCalibrator()
        logger.info("ProbeCalibrator initialized — probe self-calibration active")
    except Exception as e:
        logger.warning("ProbeCalibrator not available: %s", e)

    # ── Telemetry Shipper (fleet mode — ships events to Command Center) ──
    shipper = None
    try:
        from amoskys.shipper import ShipperConfig, TelemetryShipper

        shipper_config = ShipperConfig.from_env()
        if shipper_config.enabled:
            shipper = TelemetryShipper(shipper_config)
            shipper.start()
            logger.info(
                "Telemetry shipper started — server=%s",
                shipper_config.server_url,
            )
        else:
            logger.info("Telemetry shipper disabled (set AMOSKYS_SERVER to enable)")
    except Exception as e:
        logger.warning("Telemetry shipper not available: %s", e)

    # ── Agent Signature Vector (ASV) — sliding window of active agents ──
    # Tracks which agents fired security events in the last 60 seconds.
    # Injected into events as '_asv' for INADS 6th cluster scoring.
    from collections import defaultdict

    _asv_window: dict[str, float] = {}  # agent_name → last_fire_epoch
    _ASV_WINDOW_SEC = 60.0

    def _update_asv(agent_name: str) -> list:
        """Record agent activation and return current ASV (agents active in window)."""
        now = time.time()
        _asv_window[agent_name] = now
        # Expire stale entries
        cutoff = now - _ASV_WINDOW_SEC
        stale = [k for k, v in _asv_window.items() if v < cutoff]
        for k in stale:
            del _asv_window[k]
        return list(_asv_window.keys())

    logger.info("ASV tracker initialized — 60s sliding window for agent signatures")

    try:
        from amoskys.intel.fusion_engine import FusionEngine

        # AMRDR: BayesianReliabilityTracker for real agent trust scoring
        try:
            from amoskys.intel.reliability import BayesianReliabilityTracker

            _amrdr = BayesianReliabilityTracker(
                store_path=str(DATA_DIR / "intel" / "reliability.db")
            )
            logger.info("AMRDR BayesianReliabilityTracker initialized")
        except Exception as _amrdr_err:
            _amrdr = None
            logger.warning("AMRDR fallback to NoOp: %s", _amrdr_err)

        fusion = FusionEngine(
            db_path=str(FUSION_DB),
            probe_calibrator=probe_cal,
            reliability_tracker=_amrdr,
        )
        logger.info(
            "FusionEngine initialized: %s (AMRDR + probe calibrator wired)", FUSION_DB
        )
    except Exception as e:
        logger.warning("FusionEngine not available: %s", e)
        fusion = None

    try:
        from amoskys.agents.common.kill_chain import KillChainTracker

        kill_chain = KillChainTracker(ttl_seconds=3600)
        logger.info("KillChainTracker initialized")
    except Exception as e:
        logger.warning("KillChainTracker not available: %s", e)
        kill_chain = None

    # ── Event deduplication ──
    from amoskys.storage.dedup import EventDeduplicator

    dedup = EventDeduplicator(ttl_seconds=600, max_cache=50000)

    # ── IGRIS ──
    igris = None
    try:
        from amoskys.igris.supervisor import Igris

        igris = Igris()
        logger.info("IGRIS supervisor initialized")
    except Exception as e:
        logger.warning("IGRIS supervisor not available: %s", e)

    # ── IGRIS Tactical Engine (the minister) ──
    tactical = None
    try:
        from amoskys.igris.tactical import IGRISTacticalEngine

        tactical = IGRISTacticalEngine()
        logger.info("IGRIS tactical engine initialized — the minister is awake")
    except Exception as e:
        logger.warning("IGRIS tactical not available: %s", e)

    # ── WAL Processor (if available) ──
    wal_processor = None
    try:
        from amoskys.storage.wal_processor import WALProcessor

        wal_path = str(WAL_DIR / "flowagent.db")
        if Path(wal_path).exists():
            wal_processor = WALProcessor(
                wal_path=wal_path,
                store_path=str(TELEMETRY_DB),
            )
            logger.info("WAL processor initialized: %s", wal_path)
    except Exception as e:
        logger.warning("WAL processor not available: %s", e)

    # ── Direct Queue Reader (single-machine mode, bypasses EventBus) ──
    queue_dir = DATA_DIR / "queue"

    def _drain_agent_queues(budget, rotate=0):
        """Read events directly from per-agent queue DBs into telemetry.db.

        This bypasses the EventBus → WAL path for single-machine deployment.
        Each agent writes DeviceTelemetry protobufs to its own queue DB.
        We read them, deserialize, and store directly.

        Bounded + fair: process at most ``budget`` queue rows per call so a single
        cycle stays responsive (low latency), and rotate which queue leads so a
        high-volume agent (e.g. macos_auth) cannot starve the others. ``budget``
        replaces the old hardcoded LIMIT 5000-per-queue-per-cycle, which made one
        cycle drain the entire backlog and run for hours.
        """
        import glob
        import sqlite3 as _sqlite3

        from amoskys.proto import universal_telemetry_pb2 as pb2

        total = 0
        qpaths = sorted(glob.glob(str(queue_dir / "*.db")))
        if qpaths and rotate:
            r = rotate % len(qpaths)
            qpaths = qpaths[r:] + qpaths[:r]
        per_queue_cap = max(1, budget // 4)  # no single queue takes >1/4 of a cycle
        for qdb_path in qpaths:
            remaining = budget - total
            if remaining <= 0:
                break
            try:
                conn = _sqlite3.connect(qdb_path, timeout=2)
                rows = conn.execute(
                    "SELECT id, bytes FROM queue ORDER BY id LIMIT ?",
                    (min(remaining, per_queue_cap),),
                ).fetchall()

                if not rows:
                    conn.close()
                    continue

                processed_ids = []
                for row_id, raw_bytes in rows:
                    try:
                        dt = pb2.DeviceTelemetry()
                        dt.ParseFromString(raw_bytes)

                        for ev in dt.events:
                            if ev.event_type == "SECURITY" and ev.HasField(
                                "security_event"
                            ):
                                se = ev.security_event
                                attrs = dict(ev.attributes)

                                # Enrich with GeoIP/ASN/ThreatIntel
                                if enrichment is not None:
                                    try:
                                        enrichment.enrich(attrs)
                                    except Exception:
                                        pass

                                # Derive detection_source for agent
                                # attribution when collection_agent
                                # is empty
                                agent = dt.collection_agent or attrs.get(
                                    "detection_source", ""
                                )

                                event_data = {
                                    "event_id": ev.event_id,
                                    "device_id": dt.device_id,
                                    "event_type": ev.event_type,
                                    "event_category": se.event_category,
                                    "event_action": attrs.get(
                                        "event_action", se.event_category
                                    ),
                                    "event_outcome": "alert",
                                    "risk_score": se.risk_score,
                                    "confidence": float(attrs.get("confidence", "0.5")),
                                    "mitre_techniques": list(se.mitre_techniques),
                                    "collection_agent": agent,
                                    "description": attrs.get("description", ""),
                                    "raw_attributes_json": json.dumps(attrs),
                                    "event_timestamp_ns": ev.event_timestamp_ns
                                    or dt.timestamp_ns,
                                    # Enrichment results (enricher writes geo_dst_*/asn_dst_*
                                    # because IP is promoted from remote_ip → dst_ip)
                                    "geo_src_country": attrs.get("geo_src_country")
                                    or attrs.get("geo_dst_country"),
                                    "geo_src_city": attrs.get("geo_src_city")
                                    or attrs.get("geo_dst_city"),
                                    "geo_src_latitude": attrs.get("geo_src_latitude")
                                    or attrs.get("geo_dst_latitude"),
                                    "geo_src_longitude": attrs.get("geo_src_longitude")
                                    or attrs.get("geo_dst_longitude"),
                                    "asn_src_org": attrs.get("asn_src_org")
                                    or attrs.get("asn_dst_org"),
                                    "asn_src_number": attrs.get("asn_src_number")
                                    or attrs.get("asn_dst_number"),
                                    "asn_src_network_type": attrs.get(
                                        "asn_src_network_type"
                                    )
                                    or attrs.get("asn_dst_network_type"),
                                    "threat_intel_match": attrs.get(
                                        "threat_intel_match", False
                                    ),
                                    "enrichment_status": attrs.get(
                                        "enrichment_status", "raw"
                                    ),
                                    # Typed columns from probe attributes
                                    "remote_ip": attrs.get("remote_ip"),
                                    "remote_port": attrs.get("remote_port"),
                                    "process_name": attrs.get("process_name"),
                                    "pid": attrs.get("pid"),
                                    "exe": attrs.get("exe"),
                                    "cmdline": attrs.get("cmdline"),
                                    "username": attrs.get("username"),
                                    "protocol": attrs.get("protocol"),
                                    "domain": attrs.get("domain"),
                                    "path": attrs.get("path"),
                                    "sha256": attrs.get("sha256"),
                                    "probe_name": attrs.get("probe_name"),
                                    "detection_source": attrs.get("detection_source"),
                                }

                                # Score the event before storage
                                if dedup.is_duplicate(event_data):
                                    continue
                                dedup.record(event_data)

                                # SOMA: record observation + get verdict for probe calibration
                                soma_verdict = None
                                if soma is not None:
                                    try:
                                        soma.observe(
                                            category=se.event_category,
                                            process=attrs.get("process_name", ""),
                                            path=attrs.get(
                                                "exe", attrs.get("path", "")
                                            ),
                                            domain=agent,
                                            risk=se.risk_score,
                                        )
                                    except Exception as _obs_err:
                                        logger.debug(
                                            "SOMA observe failed: %s", _obs_err
                                        )
                                    try:
                                        soma_result = soma.assess(
                                            category=se.event_category,
                                            process=attrs.get("process_name", ""),
                                            path=attrs.get(
                                                "exe", attrs.get("path", "")
                                            ),
                                            risk=se.risk_score,
                                        )
                                        soma_verdict = soma_result.verdict
                                    except Exception as _assess_err:
                                        logger.debug(
                                            "SOMA assess failed: %s", _assess_err
                                        )

                                # Probe calibration: feed SOMA verdict back
                                if probe_cal is not None and soma_verdict:
                                    try:
                                        probe_name = attrs.get(
                                            "probe_name",
                                            ev.source_component or se.event_category,
                                        )
                                        weight = probe_cal.update(
                                            probe_name, soma_verdict
                                        )
                                        # Apply precision weight to risk score
                                        if weight < 0.95:
                                            event_data["risk_score"] = round(
                                                event_data["risk_score"] * weight, 4
                                            )
                                            event_data["probe_precision"] = round(
                                                weight, 4
                                            )
                                    except Exception as _cal_err:
                                        logger.warning(
                                            "Probe calibration failed: %s", _cal_err
                                        )

                                # ASV: update agent activation window and inject into event
                                asv_list = _update_asv(agent)
                                event_data["_asv"] = asv_list

                                # Forensic context: fill WHO/HOW/CHAIN from
                                # cross-agent data (process cache, file stat, MITRE)
                                if forensic is not None:
                                    try:
                                        forensic.enrich_event(event_data)
                                    except Exception:
                                        logger.debug(
                                            "Forensic enrichment failed",
                                            exc_info=True,
                                        )

                                if scorer is not None:
                                    try:
                                        scorer.score_event(event_data)
                                    except Exception:
                                        pass

                                # Sigma detection-as-code: evaluate against 56 rules
                                if sigma is not None:
                                    try:
                                        # Sigma rules match on event_type; probes
                                        # use event_category with different naming.
                                        # Map probe categories to sigma conventions.
                                        _SIGMA_ALIASES = {
                                            "macos_launchagent_new": "new_launch_agent",
                                            "macos_launchagent_modified": "new_launch_agent",
                                            "macos_cron_new": "cron_modification",
                                            "macos_cron_modified": "cron_modification",
                                            "macos_quarantine_bypass": "quarantine_bypass",
                                            "macos_hidden_file_new": "hidden_file_created",
                                            "log_tampering_detected": "log_timestamp_gap",
                                            "suspicious_script": "suspicious_spawn",
                                            "binary_from_temp": "suspicious_spawn",
                                            "browser_to_terminal": "browser_to_terminal",
                                            "browser_credential_theft": "credential_harvest",
                                            "session_cookie_theft": "session_cookie_theft",
                                            "keychain_cli_abuse": "credential_harvest",
                                            "exfil_spike": "data_exfil_http",
                                            "cloud_exfil_detected": "cloud_storage_connection",
                                            "cloud_sync_active": "cloud_storage_connection",
                                            "c2_beacon_suspect": "c2_web_beacon",
                                            "connection_burst_detected": "c2_web_beacon",
                                            "cleartext_protocol": "data_exfil_http",
                                            "lateral_ssh": "outbound_ssh",
                                            "high_cpu": "crypto_mining_detected",
                                            "fake_password_dialog": "fake_password_dialog",
                                            "port_scan_detected": "schema_enumeration",
                                            "long_lived_connection": "long_lived_connection",
                                        }
                                        sigma_input = dict(event_data)
                                        cat = sigma_input.get("event_category", "")
                                        sigma_input["event_type"] = _SIGMA_ALIASES.get(
                                            cat, cat
                                        )
                                        sigma_matches = sigma.evaluate(sigma_input)
                                        if sigma_matches:
                                            best = max(
                                                sigma_matches,
                                                key=lambda m: {
                                                    "critical": 4,
                                                    "high": 3,
                                                    "medium": 2,
                                                    "low": 1,
                                                }.get(m.level, 0),
                                            )
                                            event_data["detection_source"] = (
                                                event_data.get("detection_source", "")
                                                + "|sigma"
                                            )
                                            ind = event_data.get("indicators", {})
                                            if isinstance(ind, str):
                                                ind = json.loads(ind)
                                            ind["sigma_rule_id"] = best.rule_id
                                            ind["sigma_rule_title"] = best.rule_title
                                            ind["sigma_level"] = best.level
                                            event_data["indicators"] = ind
                                            # Promote MITRE from sigma if richer
                                            if best.mitre_techniques:
                                                raw_mt = event_data.get(
                                                    "mitre_techniques", []
                                                )
                                                if isinstance(raw_mt, str):
                                                    try:
                                                        raw_mt = json.loads(raw_mt)
                                                    except (
                                                        json.JSONDecodeError,
                                                        TypeError,
                                                    ):
                                                        raw_mt = []
                                                existing = set(
                                                    raw_mt
                                                    if isinstance(raw_mt, list)
                                                    else []
                                                )
                                                for t in best.mitre_techniques:
                                                    existing.add(t)
                                                event_data["mitre_techniques"] = list(
                                                    existing
                                                )
                                    except Exception:
                                        logger.debug(
                                            "Sigma evaluation failed",
                                            exc_info=True,
                                        )

                                # ── Tier classification ──
                                # ATTACK: real threat, show to user
                                # OBSERVATION: baseline telemetry, feed SOMA only
                                _risk = event_data.get("risk_score", 0.0) or 0.0
                                _conf = event_data.get("confidence", 0.0) or 0.0
                                _sev = str(
                                    attrs.get("severity", se.event_category or "")
                                ).upper()
                                _has_sigma = "|sigma" in event_data.get(
                                    "detection_source", ""
                                )
                                if (
                                    (_risk >= 0.4 and _conf >= 0.6)
                                    or _sev in ("HIGH", "CRITICAL")
                                    or _has_sigma
                                ):
                                    event_data["tier"] = "attack"
                                else:
                                    event_data["tier"] = "observation"

                                store.insert_security_event(event_data)

                                # Feed fusion engine — use from_protobuf() which
                                # promotes SecurityEvent into typed audit/process/flow
                                # views that fusion rules can match against
                                if fusion:
                                    from amoskys.intel.models import TelemetryEventView

                                    try:
                                        view = TelemetryEventView.from_protobuf(
                                            ev, dt.device_id
                                        )
                                        _probe_nm = attrs.get(
                                            "probe_name",
                                            ev.source_component or se.event_category,
                                        )
                                        view.probe_name = _probe_nm
                                        view.collection_agent = (
                                            ev.source_component or ""
                                        )
                                        view.probe_precision = (
                                            probe_cal.get_weight(_probe_nm)
                                            if probe_cal
                                            else 1.0
                                        )
                                        fusion.add_event(view)
                                    except Exception as e:
                                        logger.warning("Failed to feed fusion: %s", e)

                            elif ev.event_type == "OBSERVATION":
                                attrs = dict(ev.attributes)
                                domain = attrs.get("_domain", dt.collection_agent)
                                ts_ns = ev.event_timestamp_ns or dt.timestamp_ns

                                # SOMA: record observation for baseline
                                if soma is not None:
                                    try:
                                        soma.observe(
                                            category=domain,
                                            process=attrs.get("process_name", ""),
                                            path=attrs.get(
                                                "exe",
                                                attrs.get(
                                                    "path", attrs.get("dst_ip", "")
                                                ),
                                            ),
                                            domain=domain,
                                            risk=float(attrs.get("risk_score", 0) or 0),
                                        )
                                    except Exception:
                                        pass

                                # Route observations to domain-specific tables
                                # Enrichment for any observation with IP fields
                                if enrichment is not None and any(
                                    attrs.get(k)
                                    for k in ("src_ip", "dst_ip", "remote_ip")
                                ):
                                    try:
                                        enrichment.enrich(attrs)
                                    except Exception:
                                        pass

                                # Build common fields
                                from datetime import datetime as _dt_cls
                                from datetime import timezone as _tz_cls

                                _ts_dt = _dt_cls.fromtimestamp(
                                    ts_ns / 1e9, tz=_tz_cls.utc
                                ).isoformat()
                                _base = {
                                    "timestamp_ns": ts_ns,
                                    "timestamp_dt": _ts_dt,
                                    "device_id": dt.device_id,
                                    "collection_agent": dt.collection_agent,
                                    "agent_version": dt.agent_version,
                                    "event_source": "observation",
                                }

                                try:
                                    if domain == "process":
                                        store.insert_process_event(
                                            {
                                                **_base,
                                                "pid": attrs.get("pid"),
                                                "exe": attrs.get("exe"),
                                                "cmdline": attrs.get("cmdline"),
                                                "ppid": attrs.get("ppid"),
                                                "username": attrs.get("username"),
                                                "name": attrs.get(
                                                    "name", attrs.get("process_name")
                                                ),
                                                "parent_name": attrs.get("parent_name"),
                                                "status": attrs.get("status"),
                                                "cpu_percent": attrs.get("cpu_percent"),
                                                "memory_percent": attrs.get(
                                                    "memory_percent"
                                                ),
                                                "create_time": attrs.get("create_time"),
                                                "process_guid": attrs.get(
                                                    "process_guid"
                                                ),
                                            }
                                        )

                                        # Populate process_genealogy for kill chain tracking
                                        _pid = attrs.get("pid")
                                        if _pid is not None:
                                            try:
                                                store.db.execute(
                                                    """INSERT OR REPLACE INTO process_genealogy
                                                    (device_id, pid, ppid, name, exe, cmdline, username,
                                                     parent_name, create_time, is_alive, first_seen_ns, last_seen_ns, process_guid)
                                                    VALUES (?,?,?,?,?,?,?,?,?,1,?,?,?)""",
                                                    (
                                                        dt.device_id,
                                                        int(_pid) if _pid else 0,
                                                        int(attrs.get("ppid") or 0),
                                                        attrs.get(
                                                            "name",
                                                            attrs.get("process_name"),
                                                        ),
                                                        attrs.get("exe"),
                                                        attrs.get("cmdline"),
                                                        attrs.get("username"),
                                                        attrs.get("parent_name"),
                                                        attrs.get("create_time"),
                                                        ts_ns,
                                                        ts_ns,
                                                        attrs.get("process_guid"),
                                                    ),
                                                )
                                            except Exception:
                                                pass

                                    elif domain == "flow":
                                        # Unique ns offset per flow event —
                                        # prevents UNIQUE constraint collision
                                        _flow_counter = (
                                            getattr(store, "_flow_ns_ctr", 0) + 1
                                        )
                                        store._flow_ns_ctr = _flow_counter
                                        _flow_ts = _base["timestamp_ns"] + (
                                            _flow_counter % 1_000_000
                                        )
                                        store.insert_flow_event(
                                            {
                                                **_base,
                                                "timestamp_ns": _flow_ts,
                                                "src_ip": attrs.get("src_ip"),
                                                "dst_ip": attrs.get("dst_ip"),
                                                "src_port": attrs.get("src_port"),
                                                "dst_port": attrs.get("dst_port"),
                                                "protocol": attrs.get("protocol"),
                                                "bytes_tx": int(
                                                    attrs.get("bytes_tx", 0) or 0
                                                ),
                                                "bytes_rx": int(
                                                    attrs.get("bytes_rx", 0) or 0
                                                ),
                                                "pid": attrs.get("pid"),
                                                "process_name": attrs.get(
                                                    "process_name"
                                                ),
                                                "conn_user": attrs.get("conn_user"),
                                                "state": attrs.get("state"),
                                                "geo_dst_country": attrs.get(
                                                    "geo_dst_country"
                                                ),
                                                "geo_dst_city": attrs.get(
                                                    "geo_dst_city"
                                                ),
                                                "geo_dst_latitude": attrs.get(
                                                    "geo_dst_latitude"
                                                ),
                                                "geo_dst_longitude": attrs.get(
                                                    "geo_dst_longitude"
                                                ),
                                                "asn_dst_org": attrs.get("asn_dst_org"),
                                                "asn_dst_number": attrs.get(
                                                    "asn_dst_number"
                                                ),
                                                "asn_dst_network_type": attrs.get(
                                                    "asn_dst_network_type"
                                                ),
                                                "threat_intel_match": attrs.get(
                                                    "threat_intel_match", False
                                                ),
                                            }
                                        )

                                    elif domain == "dns":
                                        store.insert_dns_event(
                                            {
                                                **_base,
                                                "domain": attrs.get("domain"),
                                                "record_type": attrs.get("record_type"),
                                                "response_code": attrs.get(
                                                    "response_code"
                                                ),
                                                "risk_score": float(
                                                    attrs.get("risk_score", 0) or 0
                                                ),
                                                "event_type": attrs.get(
                                                    "event_type", "query"
                                                ),
                                                "process_name": attrs.get(
                                                    "process_name"
                                                ),
                                                "pid": attrs.get("pid"),
                                            }
                                        )

                                    elif domain in ("fim", "filesystem"):
                                        _name = attrs.get("name", "")
                                        _ext = ""
                                        if _name and "." in _name:
                                            _ext = "." + _name.rsplit(".", 1)[-1]
                                        store.insert_fim_event(
                                            {
                                                **_base,
                                                "path": attrs.get("path"),
                                                "file_extension": attrs.get(
                                                    "extension", _ext
                                                ),
                                                "change_type": attrs.get(
                                                    "change_type", "snapshot"
                                                ),
                                                "new_hash": attrs.get("sha256", ""),
                                                "owner_uid": int(
                                                    attrs.get("uid", 0) or 0
                                                ),
                                                "is_suid": attrs.get("is_suid", False),
                                                "mtime": attrs.get("mtime"),
                                                "size": int(attrs.get("size", 0) or 0),
                                                "risk_score": float(
                                                    attrs.get("risk_score", 0) or 0
                                                ),
                                                "event_type": "file_snapshot",
                                                "raw_attributes_json": json.dumps(
                                                    attrs
                                                ),
                                            }
                                        )

                                    elif domain == "persistence":
                                        store.insert_persistence_event(
                                            {
                                                **_base,
                                                "mechanism": attrs.get(
                                                    "mechanism",
                                                    attrs.get("category", ""),
                                                ),
                                                "path": attrs.get("path"),
                                                "change_type": attrs.get("change_type"),
                                                "label": attrs.get(
                                                    "label", attrs.get("name", "")
                                                ),
                                                "sha256": attrs.get("sha256"),
                                                "risk_score": float(
                                                    attrs.get("risk_score", 0) or 0
                                                ),
                                            }
                                        )

                                    elif domain == "peripheral":
                                        store.insert_peripheral_event(
                                            {
                                                **_base,
                                                "peripheral_device_id": attrs.get(
                                                    "device_id", ""
                                                ),
                                                "event_type": attrs.get(
                                                    "event_type", "DETECTED"
                                                ),
                                                "device_name": attrs.get("device_name"),
                                                "device_type": attrs.get("device_type"),
                                                "vendor_id": attrs.get("vendor_id"),
                                                "risk_score": float(
                                                    attrs.get("risk_score", 0) or 0
                                                ),
                                            }
                                        )

                                    elif domain == "auth":
                                        store.insert_audit_event(
                                            {
                                                **_base,
                                                "event_type": attrs.get(
                                                    "event_type", "auth"
                                                ),
                                                # Map auth-specific fields from collector
                                                "pid": attrs.get("client_pid")
                                                or attrs.get("pid"),
                                                "exe": attrs.get("client_exe")
                                                or attrs.get("exe"),
                                                "comm": attrs.get("process", ""),
                                                "username": attrs.get("username", ""),
                                                "source_ip": attrs.get("source_ip", ""),
                                                "reason": attrs.get("message", "")[
                                                    :500
                                                ],
                                                "risk_score": float(
                                                    attrs.get("risk_score", 0) or 0
                                                ),
                                                "raw_attributes_json": json.dumps(
                                                    {
                                                        k: v
                                                        for k, v in attrs.items()
                                                        if k not in ("message",)
                                                    },
                                                    default=str,
                                                ),
                                            }
                                        )

                                    else:
                                        # Unknown domain → generic observation table
                                        store.insert_observation_event(
                                            {
                                                "event_id": ev.event_id,
                                                "device_id": dt.device_id,
                                                "domain": domain,
                                                "event_timestamp_ns": ts_ns,
                                                "raw_attributes_json": json.dumps(
                                                    attrs
                                                ),
                                            }
                                        )

                                except Exception as e:
                                    # Fallback: store in generic observations
                                    try:
                                        store.insert_observation_event(
                                            {
                                                "event_id": ev.event_id,
                                                "device_id": dt.device_id,
                                                "domain": domain,
                                                "event_timestamp_ns": ts_ns,
                                                "raw_attributes_json": json.dumps(
                                                    attrs
                                                ),
                                            }
                                        )
                                    except Exception:
                                        logger.debug(
                                            "Failed to store %s observation: %s",
                                            domain,
                                            e,
                                        )

                        processed_ids.append(row_id)
                        total += 1
                    except Exception as e:
                        logger.warning("Skipping corrupted queue row %s: %s", row_id, e)
                        processed_ids.append(row_id)  # Skip corrupted

                # Delete processed rows
                if processed_ids:
                    placeholders = ",".join("?" * len(processed_ids))
                    conn.execute(
                        f"DELETE FROM queue WHERE id IN ({placeholders})",
                        processed_ids,
                    )
                    conn.commit()
                conn.close()
            except Exception as e:
                logger.warning("Queue processing failed for %s: %s", qdb_path, e)
        return total

    logger.info("Direct queue reader enabled (single-machine mode)")

    # ── Fleet re-scoring mode ──
    # When AMOSKYS_FLEET_RESCORE is truthy (or --once is passed), the brain scores
    # events in a Command-Center fleet DB (TELEMETRY_DB, pointed via
    # AMOSKYS_TELEMETRY_DB at fleet.db). This is what makes the brain the scorer
    # for shipped fleet telemetry, not just single-machine queues.
    _fleet_rescore_enabled = bool(os.environ.get("AMOSKYS_FLEET_RESCORE"))

    if run_once:
        # Single batch then exit 0 — for validation and cron-style use.
        if scorer is None:
            logger.error("--once requires a ScoringEngine; none available")
            return 1
        logger.info("Fleet rescore --once: scoring one batch from %s", FLEET_DB)
        try:
            n = _rescore_fleet_db(FLEET_DB, scorer, enrichment, fusion)
            logger.info("Fleet rescore --once complete: %d rows scored", n)
        finally:
            if scorer is not None:
                try:
                    scorer.close()
                except Exception:
                    pass
        return 0

    # ── Analysis loop ──
    # Adaptive cadence (no hardcoded batches): drain a bounded number of rows per
    # cycle and pace subsystems by wall-clock, not cycle count, so the loop stays
    # responsive ("high frame rate") whether idle or chewing through a backlog.
    DRAIN_MAX_ROWS = int(os.getenv("AMOSKYS_DRAIN_MAX_ROWS", "1500"))
    TACTICAL_EVERY_S, IGRIS_EVERY_S = 10.0, 60.0
    FUSION_EVERY_S, RETENTION_EVERY_S = 60.0, 600.0
    _last = {"tactical": 0.0, "igris": 0.0, "fusion": 0.0, "retention": 0.0, "log": 0.0}
    cycle = 0
    total_events_processed = 0

    while not shutdown_event.is_set():
        try:
            cycle += 1
            t0 = time.time()
            events_this_cycle = 0

            # Process WAL batches (EventBus path)
            if wal_processor:
                try:
                    processed = wal_processor.process_batch(batch_size=DRAIN_MAX_ROWS)
                    events_this_cycle += processed
                except Exception:
                    logger.error("WAL processing failed", exc_info=True)

            # Direct queue drain (single-machine path — bypasses EventBus).
            # Bounded to DRAIN_MAX_ROWS, rotated by cycle for cross-agent fairness.
            try:
                drained = _drain_agent_queues(DRAIN_MAX_ROWS, rotate=cycle)
                events_this_cycle += drained
            except Exception:
                logger.error("Queue drain failed", exc_info=True)

            # Fleet re-scoring (fleet mode — bypasses the stub
            # FusionEngine.ingest_telemetry_from_db). Scores command_center's
            # fleet.db events in place each cycle when AMOSKYS_FLEET_RESCORE is set.
            if _fleet_rescore_enabled and scorer is not None:
                try:
                    rescored = _rescore_fleet_db(FLEET_DB, scorer, enrichment, fusion)
                    events_this_cycle += rescored
                except Exception:
                    logger.error("Fleet rescore failed", exc_info=True)

            # IGRIS tactical assessment (~every 10s, wall-clock paced)
            if tactical and t0 - _last["tactical"] >= TACTICAL_EVERY_S:
                _last["tactical"] = t0
                try:
                    state = tactical.assess()
                    if state.hunt_mode:
                        logger.warning(
                            "IGRIS HUNT MODE: posture=%s directives=%d pids=%s",
                            state.posture,
                            len(state.active_directives),
                            state.watched_pids[:5],
                        )
                except Exception:
                    logger.debug("IGRIS tactical assessment failed", exc_info=True)

            # IGRIS observation cycle (~every 60s — organism coherence)
            if igris and t0 - _last["igris"] >= IGRIS_EVERY_S:
                _last["igris"] = t0
                try:
                    igris.observe()
                except Exception:
                    logger.debug("IGRIS observation failed", exc_info=True)

            # Run fusion evaluation (~every 60s, wall-clock paced)
            if fusion and t0 - _last["fusion"] >= FUSION_EVERY_S:
                _last["fusion"] = t0
                try:
                    # Evaluate all devices with recent events
                    for device_id in fusion.get_active_devices():
                        incidents = fusion.evaluate_device(device_id)
                        if incidents:
                            logger.info(
                                "Fusion created %d incidents for %s",
                                len(incidents),
                                device_id,
                            )
                            # Bridge fusion incidents → telemetry.db
                            for inc in incidents:
                                try:
                                    store.create_incident(
                                        {
                                            "title": f"[{inc.rule_name}] {inc.summary}",
                                            "description": inc.summary,
                                            "severity": (
                                                inc.severity.name.lower()
                                                if hasattr(inc.severity, "name")
                                                else str(inc.severity)
                                            ),
                                            "source_event_ids": inc.event_ids,
                                            "mitre_techniques": inc.techniques,
                                            "indicators": (
                                                inc.metadata
                                                if hasattr(inc, "metadata")
                                                else {}
                                            ),
                                        }
                                    )
                                except Exception:
                                    logger.debug(
                                        "Failed to bridge incident %s",
                                        getattr(inc, "incident_id", "?"),
                                        exc_info=True,
                                    )
                except Exception:
                    logger.debug("Fusion evaluation failed", exc_info=True)

            # Retention cleanup (~every 10 min, wall-clock paced). Cycle-count
            # gating silently STOPPED running when cycles took hours — which is
            # how telemetry.db grew to 27 GB and corrupted. Wall-clock fixes it.
            if t0 - _last["retention"] >= RETENTION_EVERY_S:
                _last["retention"] = t0
                try:
                    deleted = store.cleanup_old_data(max_age_days=3)
                    total_deleted = sum(deleted.values())
                    if total_deleted > 0:
                        logger.info("Retention: cleaned %d old rows", total_deleted)
                except Exception:
                    logger.debug("Retention cleanup failed", exc_info=True)

            total_events_processed += events_this_cycle
            dt = (time.time() - t0) * 1000

            if (events_this_cycle > 0 and t0 - _last["log"] >= 2.0) or cycle % 30 == 1:
                _last["log"] = t0
                logger.info(
                    "Cycle %d: processed %d events in %.0fms (total: %d)",
                    cycle,
                    events_this_cycle,
                    dt,
                    total_events_processed,
                )

            # Write heartbeat
            _write_heartbeat(cycle, events_this_cycle, total_events_processed, dt)

        except Exception:
            logger.error("Analysis cycle %d failed", cycle, exc_info=True)

        # Adaptive pacing: if we hit the drain budget there is more backlog —
        # loop again almost immediately (high frame rate). If we drained less, we
        # are caught up — relax to 2s to stay cheap.
        shutdown_event.wait(
            timeout=0.05 if events_this_cycle >= DRAIN_MAX_ROWS else 2.0
        )

    # ── Shutdown: persist state so baselines survive restarts ──
    logger.info(
        "Analyzer shutting down after %d cycles, %d total events — persisting state",
        cycle,
        total_events_processed,
    )
    if scorer is not None:
        try:
            scorer.close()
            logger.info(
                "ScoringEngine state persisted (baselines, calibration, thresholds)"
            )
        except Exception as e:
            logger.warning("ScoringEngine close failed: %s", e)
    if soma is not None:
        try:
            soma.close()
        except Exception:
            pass
    if shipper is not None:
        try:
            shipper.stop()
            logger.info("Telemetry shipper stopped")
        except Exception:
            pass
    return 0


def _write_heartbeat(cycle: int, events_this_cycle: int, total: int, latency_ms: float):
    """Write heartbeat file for watchdog liveness check."""
    heartbeat_dir = Path("data/heartbeats")
    heartbeat_dir.mkdir(parents=True, exist_ok=True)
    heartbeat = {
        "agent": "analyzer",
        "cycle": cycle,
        "events_this_cycle": events_this_cycle,
        "total_events": total,
        "latency_ms": round(latency_ms, 1),
        "timestamp": time.time(),
        "pid": os.getpid(),
    }
    try:
        (heartbeat_dir / "analyzer.json").write_text(json.dumps(heartbeat))
    except OSError:
        pass


def _parse_args(argv=None):
    """Parse CLI args for the analyzer entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="AMOSKYS Analyzer Daemon (Tier 2 brain)."
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help=(
            "Run a single fleet-DB rescore batch and exit 0 "
            "(for validation / cron-style use). Scores AMOSKYS_TELEMETRY_DB "
            "(point it at fleet.db) in place."
        ),
    )
    return parser.parse_args(argv)


if __name__ == "__main__":
    _args = _parse_args()
    sys.exit(main(run_once=_args.once))
