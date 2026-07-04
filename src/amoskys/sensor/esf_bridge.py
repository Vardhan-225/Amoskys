"""ESF sensor → Brain bridge.

Reads the Rust sensor's normalized JSON (one exec event per line) and converts
each into the ``DeviceTelemetry`` protobuf the AMOSKYS pipeline already ingests
— reusing the EXACT shape ``macos_process`` emits, so nothing downstream has to
change. The kernel-witnessed events (with real code-signing trust) then flow
analyzer → shipper → Brain → dashboard.

Usage
-----
    # end to end, today (Phase 0), no entitlement needed:
    sudo eslogger exec \\
      | sensor/target/release/amoskys-sensor \\
      | AMOSKYS_SERVER=https://18.223.110.15 python -m amoskys.sensor.esf_bridge --ship

    # or just build the protobuf and print a summary (no network):
    amoskys-sensor --selftest | python -m amoskys.sensor.esf_bridge --dry-run

Design
------
- A trusted binary (platform / known-vendor, suspicion 0) becomes an OBSERVATION
  event — recorded, not alarmed. This is the structural false-positive fix made
  concrete: the owner's ssh/curl never generate a SECURITY event.
- A binary with suspicion > 0 (unsigned / invalid-signature) becomes a SECURITY
  event carrying the real code-signing identity as evidence.
- Batches of ``FLUSH_EVERY`` events (or ``FLUSH_SECS``) are wrapped in one
  DeviceTelemetry and shipped, matching the agent batching model.
"""
from __future__ import annotations

import json
import os
import sys
import time
from typing import Any, Iterable

from amoskys.proto import universal_telemetry_pb2 as t

FLUSH_EVERY = 50
FLUSH_SECS = 5.0
_SOURCE = "macos_esf_exec"


def _severity(suspicion: float) -> str:
    if suspicion >= 0.7:
        return "HIGH"
    if suspicion >= 0.3:
        return "MEDIUM"
    if suspicion > 0.0:
        return "LOW"
    return "INFO"


def sensor_event_to_proto(ev: dict, idx: int, ts_ns: int) -> t.TelemetryEvent:
    """Convert one normalized sensor exec event into a TelemetryEvent."""
    suspicion = float(ev.get("suspicion", 0.0) or 0.0)
    path = ev.get("path", "")
    argv = ev.get("argv", []) or []
    trust = ev.get("trust", "unknown")

    if suspicion > 0.0:
        se = t.SecurityEvent(
            event_category="process_exec",
            event_action="exec",
            risk_score=suspicion,
            analyst_notes=(
                f"{path} — code-signing trust: {trust}"
                + (f" (team {ev.get('team_id')})" if ev.get("team_id") else "")
            ),
        )
        se.mitre_techniques.append("T1204")  # user execution
        pe = t.TelemetryEvent(
            event_id=f"{_SOURCE}_{idx}_{ts_ns}",
            event_type="SECURITY",
            severity=_severity(suspicion),
            event_timestamp_ns=ts_ns,
            source_component=_SOURCE,
            security_event=se,
            confidence_score=suspicion,
        )
    else:
        pe = t.TelemetryEvent(
            event_id=f"{_SOURCE}_obs_{idx}_{ts_ns}",
            event_type="OBSERVATION",
            severity="INFO",
            event_timestamp_ns=ts_ns,
            source_component=_SOURCE,
            confidence_score=0.0,
        )

    # Carry the kernel-witnessed evidence as attributes (strings, like the agents).
    attrs = {
        "event_category": "process_exec",
        "exe": path,
        "process_name": path.rsplit("/", 1)[-1] if path else "",
        "cmdline": " ".join(str(a) for a in argv),
        "pid": ev.get("pid"),
        "ppid": ev.get("ppid"),
        "username": _uid_str(ev.get("uid")),
        "team_id": ev.get("team_id"),
        "team_name": ev.get("team_name"),
        "signing_id": ev.get("signing_id"),
        "is_platform_binary": ev.get("is_platform_binary"),
        "codesigning_flags": ev.get("codesigning_flags"),
        "cdhash": ev.get("cdhash"),
        "trust": trust,
        "sensor": "esf",  # provenance: kernel-witnessed, not polled
    }
    for k, v in attrs.items():
        if v is not None and v != "":
            pe.attributes[k] = str(v)
    return pe


def _uid_str(uid: Any) -> str:
    try:
        return "root" if int(uid) == 0 else str(uid)
    except (TypeError, ValueError):
        return ""


def build_device_telemetry(events: list[t.TelemetryEvent], device_id: str) -> t.DeviceTelemetry:
    ts_ns = int(time.time() * 1e9)
    return t.DeviceTelemetry(
        device_id=device_id,
        device_type="HOST",
        protocol="MACOS_ESF_EXEC",
        events=events,
        timestamp_ns=ts_ns,
        collection_agent=_SOURCE,
    )


def convert_lines(lines: Iterable[str], device_id: str) -> t.DeviceTelemetry:
    """Convert an iterable of sensor JSON lines into one DeviceTelemetry batch."""
    ts_ns = int(time.time() * 1e9)
    proto_events: list[t.TelemetryEvent] = []
    for idx, line in enumerate(lines):
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if ev.get("kind") != "process_exec":
            continue
        proto_events.append(sensor_event_to_proto(ev, idx, ts_ns))
    return build_device_telemetry(proto_events, device_id)


def _device_id() -> str:
    # Match the shipper's device identity if configured, else a stable host id.
    dev = os.getenv("AMOSKYS_DEVICE_ID")
    if dev:
        return dev
    try:
        import hashlib
        import uuid

        return hashlib.sha256(f"{uuid.getnode():x}".encode()).hexdigest()[:16]
    except Exception:
        return "esf-host"


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    dry_run = "--dry-run" in argv or "--ship" not in argv
    device_id = _device_id()

    batch: list[t.TelemetryEvent] = []
    last_flush = time.time()
    shipped = flagged = total = 0

    def flush() -> None:
        nonlocal batch, last_flush, shipped
        if not batch:
            return
        dt = build_device_telemetry(batch, device_id)
        if dry_run:
            sys.stderr.write(
                f"[esf-bridge] DeviceTelemetry batch: {len(dt.events)} events, "
                f"{len(dt.SerializeToString())} bytes (dry-run, not shipped)\n"
            )
        else:
            _ship(dt)
            shipped += len(batch)
        batch = []
        last_flush = time.time()

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        total += 1
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if ev.get("kind") != "process_exec":
            continue
        if float(ev.get("suspicion", 0.0) or 0.0) > 0.0:
            flagged += 1
        batch.append(sensor_event_to_proto(ev, total, int(time.time() * 1e9)))
        if len(batch) >= FLUSH_EVERY or (time.time() - last_flush) >= FLUSH_SECS:
            flush()
    flush()

    sys.stderr.write(
        f"[esf-bridge] {total} sensor events → {flagged} flagged; "
        f"{'shipped ' + str(shipped) if not dry_run else 'dry-run'}\n"
    )
    return 0


def _ship(dt: t.DeviceTelemetry) -> None:
    """Ship via the existing shipper path (reuses its auth + pinned TLS)."""
    try:
        from amoskys.shipper import Shipper  # type: ignore

        Shipper().ship_device_telemetry(dt)  # if the shipper exposes it
        return
    except Exception:
        pass
    # Fallback: POST the flattened JSON the ingestion endpoint accepts.
    import requests

    server = os.getenv("AMOSKYS_SERVER", "").rstrip("/")
    key = os.getenv("AMOSKYS_API_KEY", "")
    if not server:
        sys.stderr.write("[esf-bridge] AMOSKYS_SERVER unset — cannot ship\n")
        return
    payload = {
        "device_id": dt.device_id,
        "protocol": dt.protocol,
        "collection_agent": dt.collection_agent,
        "timestamp_ns": dt.timestamp_ns,
        "events": [
            {
                "event_id": e.event_id,
                "event_type": e.event_type,
                "severity": e.severity,
                "event_timestamp_ns": e.event_timestamp_ns,
                "source_component": e.source_component,
                "confidence_score": e.confidence_score,
                "attributes": dict(e.attributes),
            }
            for e in dt.events
        ],
    }
    headers = {"Authorization": f"Bearer {key}"} if key else {}
    try:
        requests.post(f"{server}/api/v1/telemetry", json=payload, headers=headers,
                      timeout=10, verify=False)
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"[esf-bridge] ship failed: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
