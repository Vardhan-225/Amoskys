"""Response actions — the teeth, finally connected to a button.

Everything below the console already existed: six response verbs in the MCP
tools, a ``device_commands`` ledger carrying TTL, priority, dedup key, policy
decision and a rollback plan, an ops endpoint the device polls, and an executor
on the device implementing eleven command types. The only missing pieces were a
way for anything but the MCP process to create a command, and a place for a
person to press.

Three rules shape this module.

**The rollback text must be true.** "Shows its rollback plan before you commit"
becomes another lie the moment it promises an undo that does not exist. Of the
six verbs, exactly one has a real counter-command (ISOLATE → UNISOLATE); the
network blocks are reversible only by hand; killing a process is not reversible
at all. Each action therefore carries a ``reversibility`` of ``automatic``,
``manual`` or ``irreversible``, and the manual ones carry the literal command
that undoes them, read off the device-side implementation in ``shipper.py``.

**A human presses.** IGRIS may propose an action with its evidence attached;
nothing in this module is reachable from the analyst loop. Dispatch requires an
authenticated admin and an explicit reason that is stored with the command.

**Off unless switched on.** ``AMOSKYS_RESPONSE_ENABLED`` gates the whole
surface, and the ops server independently refuses to create commands unless it
has an operator key. Two switches, both defaulting to off, because the failure
mode here is a web request that kills a process on someone's laptop.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
from pathlib import Path

import requests

logger = logging.getLogger(__name__)

# Reversibility, stated honestly per verb.
AUTOMATIC = "automatic"
MANUAL = "manual"
IRREVERSIBLE = "irreversible"

ACTION_CATALOGUE = {
    "COLLECT_NOW": {
        "label": "Look again now",
        "blurb": "Ask the device to run a collection cycle immediately instead of "
        "waiting for the next one.",
        "danger": "low",
        "reversibility": AUTOMATIC,
        "rollback": {"kind": AUTOMATIC, "detail": "Nothing to undo — this only reads."},
        "params": (),
    },
    "ISOLATE": {
        "label": "Isolate this Mac",
        "blurb": "Block all network traffic except the AMOSKYS telemetry channel. "
        "The machine keeps reporting to you and reaches nothing else.",
        "danger": "extreme",
        "reversibility": AUTOMATIC,
        "rollback": {
            "kind": AUTOMATIC,
            "command_type": "UNISOLATE",
            "detail": "One click: 'Reconnect this Mac' sends UNISOLATE, which flushes "
            "the pf anchor.",
        },
        "params": (),
    },
    "UNISOLATE": {
        "label": "Reconnect this Mac",
        "blurb": "Remove network isolation and let the machine talk to the world again.",
        "danger": "medium",
        "reversibility": AUTOMATIC,
        "rollback": {
            "kind": AUTOMATIC,
            "command_type": "ISOLATE",
            "detail": "One click: isolate it again.",
        },
        "params": (),
    },
    "KILL_PROCESS": {
        "label": "Kill this process",
        "blurb": "Send SIGKILL to the process. Unsaved work in it is lost.",
        "danger": "high",
        "reversibility": IRREVERSIBLE,
        "rollback": {
            "kind": IRREVERSIBLE,
            "detail": "A killed process cannot be un-killed. If it is a daemon the OS "
            "may restart it; if it is your editor, its unsaved buffer is gone.",
        },
        "params": ("pid",),
    },
    "BLOCK_IP": {
        "label": "Block this address",
        "blurb": "Add a pf rule dropping traffic to and from this IP.",
        "danger": "high",
        "reversibility": MANUAL,
        "rollback": {
            "kind": MANUAL,
            "detail": "There is no unblock command yet. Undo by hand on the device:",
            "shell": "sudo pfctl -a amoskys -F rules",
        },
        "params": ("ip",),
    },
    "BLOCK_DOMAIN": {
        "label": "Sinkhole this domain",
        "blurb": "Point the domain at 127.0.0.1 in /etc/hosts and flush the DNS cache.",
        "danger": "high",
        "reversibility": MANUAL,
        "rollback": {
            "kind": MANUAL,
            "detail": "There is no un-sinkhole command yet. Undo by hand on the device:",
            "shell": "sudo sed -i '' '/# AMOSKYS-BLOCK/d' /etc/hosts && "
            "sudo dscacheutil -flushcache",
        },
        "params": ("domain",),
    },
    "QUARANTINE_FILE": {
        "label": "Quarantine this file",
        "blurb": "Move the file into data/quarantine and strip every permission bit.",
        "danger": "high",
        "reversibility": MANUAL,
        "rollback": {
            "kind": MANUAL,
            "detail": "The file is moved, not deleted. Restore it by hand on the device:",
            "shell": "sudo chmod 600 data/quarantine/<name>.<ts> && "
            "sudo mv data/quarantine/<name>.<ts> <original path>",
        },
        "params": ("path",),
    },
}


def enabled() -> bool:
    return os.getenv("AMOSKYS_RESPONSE_ENABLED", "").lower() in ("1", "true", "yes")


def _ops_base() -> str:
    return (os.getenv("AMOSKYS_OPS_SERVER") or "https://18.223.110.15").rstrip("/")


def _operator_key() -> str:
    return os.getenv("CC_OPERATOR_KEY", "")


def availability() -> dict:
    """Why the response surface is or is not usable, in words a person can act on."""
    if not enabled():
        return {
            "available": False,
            "reason": "Response actions are switched off on this server "
            "(AMOSKYS_RESPONSE_ENABLED is not set).",
        }
    if not _operator_key():
        return {
            "available": False,
            "reason": "This server has no operator key, so it cannot ask the fleet "
            "backend to queue an action (CC_OPERATOR_KEY is not set).",
        }
    if not _ops_ca():
        return {
            "available": False,
            "reason": "The pinned ops CA is missing on this server, so an action "
            "could only be sent over an unverified channel. Refusing rather than "
            "shipping the operator key to an unauthenticated peer.",
        }
    return {"available": True, "reason": None}


# ── Deriving parameters from evidence ────────────────────────────────────────
_RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_DOMAIN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.I
)
_RE_PID = re.compile(r"\bpid[=: ]+(\d{1,7})\b", re.I)
_RE_PATH = re.compile(r"(?:^|\s)((?:~|/)[\w./~-]{4,})")

# Never offer to act on our own plumbing or the machine's own loopback.
_NEVER_TARGET_HOSTS = ("127.0.0.1", "0.0.0.0", "localhost", "::1")

# A dotted string is not a domain just because it has dots in it. Measured on
# real evidence, `com.amoskys.live.plist` matched the domain pattern and would
# have been offered as "Sinkhole this domain" — a nonsense action against a
# filename. Reverse-DNS bundle identifiers and file names are excluded.
_NOT_A_DOMAIN_SUFFIX = (
    ".plist",
    ".json",
    ".db",
    ".log",
    ".py",
    ".sh",
    ".conf",
    ".cfg",
    ".yaml",
    ".yml",
    ".txt",
    ".app",
    ".pkg",
    ".dylib",
    ".so",
    ".sock",
    ".lock",
    ".tmp",
    ".bak",
    ".pem",
    ".key",
    ".crt",
    ".local",
)
_BUNDLE_ID_PREFIXES = ("com.", "org.", "io.", "net.", "app.")


def _is_targetable_domain(value: str) -> bool:
    lowered = value.lower()
    if lowered.endswith(_NOT_A_DOMAIN_SUFFIX):
        return False
    # A reverse-DNS bundle id has more labels than a hostname usually does and
    # its last label is not a TLD (com.amoskys.live -> "live").
    if lowered.startswith(_BUNDLE_ID_PREFIXES) and lowered.count(".") >= 2:
        return False
    if lowered in _NEVER_TARGET_HOSTS:
        return False
    for host in _ops_hosts():
        if lowered == host.lower():
            return False
    return True


def _is_targetable_ip(value: str) -> bool:
    if value in _NEVER_TARGET_HOSTS:
        return False
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    if addr.is_loopback or addr.is_unspecified or addr.is_multicast:
        return False
    for host in _ops_hosts():
        if value == host:
            return False
    return True


def _ops_hosts() -> tuple[str, ...]:
    raw = f"{os.getenv('AMOSKYS_SERVER', '')} {os.getenv('AMOSKYS_OPS_SERVER', '')}"
    hosts = []
    for token in raw.replace("https://", " ").replace("http://", " ").split():
        host = token.split("/")[0].split(":")[0].strip()
        if host:
            hosts.append(host)
    return tuple(hosts)


def derive_targets(evidence_rows: list[dict]) -> dict:
    """Candidate action parameters read out of the evidence, not typed by a client.

    The dispatch endpoint only ever accepts a target that appears here, so a
    crafted request cannot turn "block an address" into "block the gateway".
    """
    ips, domains, pids, paths = [], [], [], []
    for row in evidence_rows or []:
        text = row.get("description") or ""
        for match in _RE_IPV4.findall(text):
            if _is_targetable_ip(match) and match not in ips:
                ips.append(match)
        for match in _RE_DOMAIN.findall(text):
            lowered = match.lower()
            if (
                lowered not in domains
                and not _RE_IPV4.fullmatch(lowered)
                and _is_targetable_domain(lowered)
            ):
                domains.append(lowered)
        pid_match = _RE_PID.search(text)
        if pid_match and pid_match.group(1) not in pids:
            pids.append(pid_match.group(1))
        for match in _RE_PATH.findall(text):
            if match not in paths and not match.startswith("/usr/"):
                paths.append(match)
    return {
        "ip": ips[:5],
        "domain": domains[:5],
        "pid": pids[:5],
        "path": paths[:5],
    }


def propose(item: dict, evidence_rows: list[dict]) -> list[dict]:
    """Actions worth offering for one ledger item, with their real targets.

    An action with no target derived from evidence is not offered: a button that
    needs a PID the page does not have would just be another dead control.
    """
    targets = derive_targets(evidence_rows)
    device_ids = item.get("device_ids") or []
    offered = []

    for command_type in (
        "COLLECT_NOW",
        "KILL_PROCESS",
        "BLOCK_IP",
        "BLOCK_DOMAIN",
        "QUARANTINE_FILE",
        "ISOLATE",
    ):
        spec = ACTION_CATALOGUE[command_type]
        needed = spec["params"]
        if needed:
            key = needed[0]
            options = targets.get(key) or []
            if not options:
                continue
        else:
            options = []
        offered.append(
            {
                "command_type": command_type,
                "label": spec["label"],
                "blurb": spec["blurb"],
                "danger": spec["danger"],
                "reversibility": spec["reversibility"],
                "rollback": spec["rollback"],
                "param": needed[0] if needed else None,
                "options": options,
                "devices": device_ids,
            }
        )
    return offered


# ── Dispatch ─────────────────────────────────────────────────────────────────
def dispatch(
    device_id: str,
    command_type: str,
    param_value: str | None,
    reason: str,
    requested_by: str,
    allowed_targets: dict,
) -> tuple[dict, int]:
    """Queue one action on the fleet backend. Returns (payload, http_status)."""
    state = availability()
    if not state["available"]:
        return {"error": "response_disabled", "detail": state["reason"]}, 503

    spec = ACTION_CATALOGUE.get(command_type)
    if not spec:
        return {"error": "unknown_action", "detail": command_type}, 400
    if not reason.strip():
        return {"error": "reason_required", "detail": "Say why — it is stored."}, 400

    payload = {}
    if spec["params"]:
        key = spec["params"][0]
        if not param_value:
            return {"error": "target_required", "detail": f"{key} is required"}, 400
        # The target must be one the server itself derived from evidence.
        if str(param_value) not in [str(v) for v in (allowed_targets.get(key) or [])]:
            return (
                {
                    "error": "target_not_in_evidence",
                    "detail": f"{param_value} does not appear in this item's evidence.",
                },
                400,
            )
        payload[key] = int(param_value) if key == "pid" else param_value

    rollback = dict(spec["rollback"])
    url = f"{_ops_base()}/api/v1/devices/{device_id}/commands"
    body = {
        "command_type": command_type,
        "payload": payload,
        "reason": reason.strip()[:500],
        "requested_by": requested_by,
        "rollback": rollback,
        "priority": 1,
        "ttl": 900,
    }
    try:
        resp = _ops_session().post(
            url,
            json=body,
            headers={"Authorization": f"Bearer {_operator_key()}"},
            timeout=10,
        )
    except requests.RequestException as exc:
        logger.warning("action dispatch failed: %s", exc)
        kind, detail = _describe_request_error(exc)
        return ({"error": kind, "detail": detail}, 502)
    try:
        data = resp.json()
    except ValueError:
        data = {"error": "bad_response", "detail": resp.text[:200]}
    return data, resp.status_code


def ledger(limit: int = 100, device_id: str | None = None) -> tuple[dict, int]:
    """The action ledger: who asked for what, why, and what came back."""
    state = availability()
    if not state["available"]:
        return {"commands": [], "unavailable": state["reason"]}, 200
    params = {"limit": limit}
    if device_id:
        params["device_id"] = device_id
    try:
        resp = _ops_session().get(
            f"{_ops_base()}/api/v1/commands",
            params=params,
            headers={"Authorization": f"Bearer {_operator_key()}"},
            timeout=10,
        )
        return resp.json(), resp.status_code
    except (requests.RequestException, ValueError):
        return (
            {
                "commands": [],
                "unavailable": "The fleet backend did not answer — the action "
                "history could not be read. This is not the same as 'no actions'.",
            },
            200,
        )


def cancel(command_id: str) -> tuple[dict, int]:
    state = availability()
    if not state["available"]:
        return {"error": "response_disabled", "detail": state["reason"]}, 503
    try:
        resp = _ops_session().post(
            f"{_ops_base()}/api/v1/commands/{command_id}/cancel",
            headers={"Authorization": f"Bearer {_operator_key()}"},
            timeout=10,
        )
        return resp.json(), resp.status_code
    except (requests.RequestException, ValueError):
        return {"error": "ops_unreachable", "detail": "Nothing was changed."}, 502


# Resolved from the package, not the CWD. gunicorn runs with --chdir
# /opt/amoskys/web, where a relative "deploy/certs/..." resolves to a path that
# does not exist — os.path.exists() then returned False and every ops call went
# out with verify=False, carrying the operator bearer token to a bare IP with no
# hostname check to fall back on. telemetry_bridge.py and routes_command_center
# both already anchor this to the package root; this matches them.
_REPO_ROOT = Path(__file__).resolve().parents[3]
_DEFAULT_OPS_CA = _REPO_ROOT / "deploy" / "certs" / "ops-ca.pem"


def _ops_ca() -> str | None:
    """The pinned ops CA.

    Reads AMOSKYS_CA_BUNDLE first — that is the name shipper.py and
    telemetry_bridge.py already use, and an operator who sets it expects every
    ops caller to honour it. AMOSKYS_OPS_CA is kept as an alias so an existing
    deployment that set the wrong one does not silently lose its pin.
    """
    for env in ("AMOSKYS_CA_BUNDLE", "AMOSKYS_OPS_CA"):
        value = (os.getenv(env) or "").strip()
        if value:
            if os.path.isfile(value):
                return value
            # STRICTER THAN shipper.py ON PURPOSE. The shipper falls back to the
            # packaged CA so a missing file never stops telemetry flowing —
            # correct there, because the cost of stopping is blindness. Here the
            # cost of continuing is a request that can kill a process or cut a
            # machine off the network, sent to a peer verified against a CA the
            # operator did not choose. An explicitly configured path that is not
            # there is a configuration error, and this surface refuses.
            logger.warning(
                "%s set to %s but no such file — response actions disabled",
                env,
                value,
            )
            return None
    packaged = str(_DEFAULT_OPS_CA)
    return packaged if os.path.exists(packaged) else None


def _ops_session() -> requests.Session:
    """A session pinned the way every other ops caller in this repo pins.

    Passing ``verify=<ca path>`` to requests performs full RFC 6125 hostname
    matching. The ops certificate is self-signed and carries NO subjectAltName,
    and the ops URL is a bare IP — so that check cannot succeed, and every
    response action would have failed TLS before reaching the server. The
    failure then surfaced to the operator as "the fleet backend did not
    answer", which is a different and much less actionable statement than "this
    server could not verify the backend's certificate".

    shipper.py solved this already: require the chain to validate against the
    pinned CA (CERT_REQUIRED — full MITM protection) and suppress only the
    SAN/hostname match, which is the single check the missing SAN breaks. This
    reuses that adapter rather than reimplementing it.
    """
    session = requests.Session()
    ca = _ops_ca()
    if ca:
        try:
            from amoskys.shipper import _PinnedCAAdapter

            session.mount("https://", _PinnedCAAdapter(ca))
        except Exception:  # pragma: no cover - defensive
            logger.warning("pinned CA adapter unavailable", exc_info=True)
            session.verify = ca
    else:
        # Unreachable via availability(), which refuses without a CA. Never
        # False: an accidental caller gets the system trust store, not no TLS.
        session.verify = True
    return session


def _describe_request_error(exc: Exception) -> tuple[str, str]:
    """Name the failure the operator actually has.

    A certificate that will not verify and a server that is down need different
    things done about them, and reporting the first as the second sends someone
    to check connectivity that was never the problem.
    """
    if isinstance(exc, requests.exceptions.SSLError):
        return (
            "ops_tls_failed",
            "This server could not verify the fleet backend's TLS certificate, "
            "so nothing was sent. Check the pinned CA (AMOSKYS_CA_BUNDLE) — the "
            "backend itself may be perfectly healthy.",
        )
    if isinstance(exc, requests.exceptions.Timeout):
        return (
            "ops_timeout",
            "The fleet backend did not respond in time, so nothing was queued.",
        )
    return (
        "ops_unreachable",
        "The fleet backend did not answer, so nothing was queued.",
    )


# ── Fleet membership ─────────────────────────────────────────────────────────
def retire_device(device_id: str, reason: str, requested_by: str) -> tuple[dict, int]:
    """Retire a device from the fleet views, keeping its record.

    Deliberately not a delete. In a security product the fact that a machine
    once existed, and what it reported, is evidence — a console that can erase
    a device from fleet history is a console an intruder would want. This hides
    it and stops it counting, and it can be undone.
    """
    state = availability()
    if not state["available"]:
        return {"error": "response_disabled", "detail": state["reason"]}, 503
    if not reason.strip():
        return {"error": "reason_required", "detail": "Say why — it is stored."}, 400
    try:
        resp = _ops_session().post(
            f"{_ops_base()}/api/v1/devices/{device_id}/retire",
            json={"reason": reason.strip()[:500], "requested_by": requested_by},
            headers={"Authorization": f"Bearer {_operator_key()}"},
            timeout=10,
        )
        return resp.json(), resp.status_code
    except (requests.RequestException, ValueError) as exc:
        logger.warning("device retire failed: %s", exc)
        return (
            {
                "error": "ops_unreachable",
                "detail": "The fleet backend did not answer, so nothing changed.",
            },
            502,
        )


def unretire_device(device_id: str) -> tuple[dict, int]:
    """Bring a retired device back — the undo that makes retiring safe."""
    state = availability()
    if not state["available"]:
        return {"error": "response_disabled", "detail": state["reason"]}, 503
    try:
        resp = _ops_session().post(
            f"{_ops_base()}/api/v1/devices/{device_id}/unretire",
            headers={"Authorization": f"Bearer {_operator_key()}"},
            timeout=10,
        )
        return resp.json(), resp.status_code
    except (requests.RequestException, ValueError):
        return {"error": "ops_unreachable", "detail": "Nothing changed."}, 502
