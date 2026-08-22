"""Endpoint Security authorization visibility probe."""

from __future__ import annotations

import os
import platform
import sqlite3
import time
from pathlib import Path
from typing import Any

_TCC_SERVICE = "kTCCServiceEndpointSecurityClient"
# Sequoia enforces Full Disk Access at es_new_client() in ADDITION to the
# Endpoint Security client grant. Both must be held by the SAME executable, and
# they are separately grantable — which is how this machine ended up with the
# ESF grant on the app-bundle binary and FDA on a bare binary of the same name.
_TCC_FDA_SERVICE = "kTCCServiceSystemPolicyAllFiles"
_REPO_ROOT = Path(__file__).resolve().parents[3]
_DEFAULT_BIN = (
    _REPO_ROOT
    / "macos-esf-shim"
    / "AmoskysSentinel.app"
    / "Contents"
    / "MacOS"
    / "amoskys-sentinel"
)
_DEFAULT_LOG_PATHS = (
    Path(os.getenv("AMOSKYS_SENTINEL_LOG", "") or "/var/log/amoskys/sentinel.log"),
    _REPO_ROOT / "logs" / "sentinel.log",
)
_DEFAULT_TCC_DB_PATHS = (
    Path("/Library/Application Support/com.apple.TCC/TCC.db"),
    Path.home() / "Library" / "Application Support" / "com.apple.TCC" / "TCC.db",
)


def _device_id() -> str:
    return (
        os.getenv("AMOSKYS_DEVICE_ID")
        or os.getenv("MCP_DEVICE_ID")
        or platform.node()
        or "local-device"
    )


def _read_tail(path: Path, max_bytes: int = 65536) -> str:
    try:
        with path.open("rb") as fh:
            try:
                fh.seek(0, os.SEEK_END)
                size = fh.tell()
                fh.seek(max(0, size - max_bytes), os.SEEK_SET)
            except OSError:
                pass
            return fh.read().decode("utf-8", errors="replace")
    except Exception:
        return ""


def _latest_sentinel_line(log_paths: list[Path]) -> tuple[str, str]:
    latest_line = ""
    latest_path = ""
    for path in log_paths:
        if not path.exists():
            continue
        text = _read_tail(path)
        for line in reversed(text.splitlines()):
            line = line.strip()
            if "amoskys-sentinel:" in line or "es_new_client" in line:
                return line, str(path)
        if text.strip() and not latest_line:
            latest_line = text.strip().splitlines()[-1].strip()
            latest_path = str(path)
    return latest_line, latest_path


def _tcc_clients(binary: Path) -> list[str]:
    clients = [
        os.getenv("AMOSKYS_SENTINEL_BUNDLE_ID", "").strip() or "com.amoskys.agent"
    ]
    if binary:
        clients.append(str(binary))
        if len(binary.parents) >= 3:
            clients.append(str(binary.parents[2]))
    extra = os.getenv("AMOSKYS_SENTINEL_TCC_CLIENTS", "")
    clients.extend(part.strip() for part in extra.split(",") if part.strip())
    return list(dict.fromkeys(clients))


def _inspect_fda(paths: list[Path], binary: Path | None) -> dict[str, Any]:
    """Is Full Disk Access held by the executable that will actually run?

    ESF and FDA are separate grants and are separately targetable, so a Sentinel
    can hold one and not the other. Worse, they can be held by DIFFERENT files
    that share a basename — which is exactly what happened here:

        kTCCServiceEndpointSecurityClient
          .../AmoskysSentinel.app/Contents/MacOS/amoskys-sentinel   allowed
        kTCCServiceSystemPolicyAllFiles
          .../macos-esf-shim/amoskys-sentinel                       allowed

    Both rows say "allowed"; neither covers the running binary for both
    services. The Sentinel logged "needs Full Disk Access (TCC)" 104,830 times
    while the probe reported an Endpoint Security denial, sending anyone
    debugging it at the wrong grant entirely.

    Returns the FDA state for the runtime binary plus any same-basename grants
    held by a DIFFERENT path, so the mismatch is reported rather than inferred.
    """
    if not binary:
        return {"state": "unknown"}
    target = str(binary)
    basename = binary.name
    state = "missing"
    others: list[dict[str, Any]] = []
    ghosts: list[dict[str, Any]] = []
    for path in paths:
        if not path.exists():
            continue
        try:
            conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=2)
            try:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT client, auth_value FROM access WHERE service = ?",
                    (_TCC_FDA_SERVICE,),
                ).fetchall()
            finally:
                conn.close()
        except Exception:
            continue
        for r in rows:
            client = str(r["client"])
            auth = _safe_int(r["auth_value"])
            if client == target:
                state = "allowed" if auth == 2 else "denied"
            elif client.endswith("/" + basename) and auth == 2:
                # A path-form grant (client starts with "/") can outlive the
                # file it names. System Settings still lists it with a
                # checkmark, so the grant LOOKS held while protecting nothing.
                # That is the worst failure shape this module exists to catch:
                # a green control panel over a blind sensor. Checked without
                # reading client_type so this survives TCC schema drift.
                is_path = client.startswith("/")
                exists = os.path.exists(client) if is_path else True
                entry = {
                    "client": client,
                    "auth_value": auth,
                    "path_exists": exists,
                }
                others.append(entry)
                if is_path and not exists:
                    ghosts.append(entry)
    return {
        "state": state,
        "same_name_elsewhere": others,
        "ghost_grants": ghosts,
        "target": target,
    }


def _fda_clause(fda: dict[str, Any]) -> str:
    """One sentence naming the FDA problem, or "" when FDA is not a problem.

    Appended to whatever the primary verdict is, because ESF and FDA fail
    INDEPENDENTLY and the old code returned on the first blocker it found.
    That turned a two-fault machine into two debugging sessions: fix the ESF
    grant, restart, wait, and only then learn FDA was also missing.
    """
    state = fda.get("state")
    if state in ("allowed", "unknown"):
        return ""
    ghosts = fda.get("ghost_grants") or []
    if ghosts:
        stale = ghosts[0]["client"]
        return (
            ". Full Disk Access is ALSO not held: the entry named "
            f"'{os.path.basename(stale)}' points at {stale}, which no longer "
            "exists. System Settings shows that entry enabled, so FDA looks "
            "granted while protecting a deleted file. Remove it and add the "
            ".app bundle itself."
        )
    others = fda.get("same_name_elsewhere") or []
    if others:
        return (
            ". Full Disk Access is ALSO not held by this binary — a file with "
            f"the same name holds it instead ({others[0]['client']})."
        )
    return ". Full Disk Access is ALSO not held by this binary."


def _safe_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _tcc_row_state(row: dict[str, Any]) -> str:
    if "auth_value" in row:
        auth_value = _safe_int(row.get("auth_value"))
        if auth_value == 2:
            return "allowed"
        if auth_value == 0:
            return "denied"
        if auth_value == 3:
            return "limited"
        return "unknown"
    if "allowed" in row:
        return "allowed" if _safe_int(row.get("allowed")) == 1 else "denied"
    return "unknown"


def _query_tcc_path(path: Path, clients: list[str]) -> tuple[list[dict[str, Any]], int]:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=2)
    conn.row_factory = sqlite3.Row
    try:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(access)")}
        if not columns:
            return [], 0
        wanted = [
            "service",
            "client",
            "client_type",
            "auth_value",
            "allowed",
            "prompt_count",
            "auth_reason",
            "auth_version",
            "flags",
            "last_modified",
        ]
        selected = [column for column in wanted if column in columns]
        order_col = "last_modified" if "last_modified" in columns else "rowid"
        placeholders = ",".join("?" for _ in clients)
        rows = conn.execute(
            f"""
            SELECT {", ".join(selected)}
            FROM access
            WHERE service = ? AND client IN ({placeholders})
            ORDER BY {order_col} DESC
            """,
            (_TCC_SERVICE, *clients),
        ).fetchall()
        service_count = conn.execute(
            "SELECT COUNT(*) FROM access WHERE service = ?",
            (_TCC_SERVICE,),
        ).fetchone()[0]
        return [dict(row) for row in rows], int(service_count or 0)
    finally:
        conn.close()


def _inspect_tcc(
    *,
    paths: list[Path],
    clients: list[str],
    binary: Path | None = None,
) -> dict[str, Any]:
    errors = []
    rows = []
    service_rows = 0
    readable_paths = []

    for path in paths:
        if not path.exists():
            continue
        try:
            path_rows, path_service_rows = _query_tcc_path(path, clients)
            readable_paths.append(str(path))
            service_rows += path_service_rows
            for row in path_rows:
                row["_db_path"] = str(path)
                row["_state"] = _tcc_row_state(row)
                rows.append(row)
        except Exception as exc:
            errors.append({"path": str(path), "error": str(exc)})

    if rows:
        # Bundle-id denial deliberately outranks a path allow, even a NEWER
        # one. macOS evaluates a signed bundled app by its designated
        # requirement / bundle identifier, so a path row for a binary inside
        # the bundle is not necessarily what the kernel consults — and for a
        # BLINDNESS probe the conservative direction is the correct one:
        # reporting "you may be blind" when grants conflict is safe; reporting
        # "authorized" off the more permissive row is exactly the
        # blind-shown-as-clean failure this module exists to catch.
        # See test_esf_authorization_probe_bundle_denial_beats_newer_path_allow.
        primary_client = clients[0] if clients else None
        primary_rows = [row for row in rows if row.get("client") == primary_client]
        denied_row = next((row for row in rows if row.get("_state") == "denied"), None)
        row = primary_rows[0] if primary_rows else (denied_row or rows[0])
        states = {str(row.get("_state") or "unknown") for row in rows}
        return {
            "authority": "tcc_db",
            "state": row["_state"],
            "client": row.get("client"),
            "db_path": row.get("_db_path"),
            "row": row,
            "conflict": len(states) > 1,
            "states_seen": sorted(states),
            "matched_rows": rows,
            "clients_checked": clients,
            "readable_paths": readable_paths,
            "errors": errors,
        }
    if readable_paths:
        return {
            "authority": "tcc_db",
            "state": "missing",
            "clients_checked": clients,
            "readable_paths": readable_paths,
            "endpoint_security_service_rows": service_rows,
            "errors": errors,
        }
    return {
        "authority": "unavailable",
        "state": "unavailable",
        "clients_checked": clients,
        "errors": errors,
    }


def _event(
    *,
    device_id: str,
    checked_at: float,
    kind: str,
    status: str,
    reason: str,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    return {
        "event_key": f"sentinel:{device_id}:{kind}",
        "device_id": device_id,
        "sensor": "amoskys_sentinel",
        "kind": kind,
        "status": status,
        "reason": reason,
        "since": checked_at,
        "last_seen": checked_at,
        "evidence": evidence,
        "source": "local_esf_authorization_probe",
        "active": True,
        "count": 1,
    }


def inspect_esf_authorization(
    *,
    log_paths: list[str | Path] | None = None,
    binary_path: str | Path | None = None,
    tcc_db_paths: list[str | Path] | None = None,
    tcc_clients: list[str] | None = None,
    device_id: str | None = None,
    now: float | None = None,
) -> dict[str, Any] | None:
    """Return a blindness-health event for local Sentinel authorization state.

    Returns None when there is no local Sentinel artifact or log. A healthy
    Sentinel also returns None because it is not an active blindness event.
    """
    paths = [Path(p) for p in (log_paths or _DEFAULT_LOG_PATHS)]
    binary = Path(binary_path or os.getenv("AMOSKYS_SENTINEL_BIN", "") or _DEFAULT_BIN)
    tcc_paths = [Path(p) for p in (tcc_db_paths or _DEFAULT_TCC_DB_PATHS)]
    clients = list(tcc_clients or _tcc_clients(binary))
    sentinel_present = binary.exists() or any(path.exists() for path in paths)
    if not sentinel_present:
        return None

    line, source_path = _latest_sentinel_line(paths)
    checked_at = float(now or time.time())
    resolved_device_id = device_id or _device_id()
    tcc = _inspect_tcc(paths=tcc_paths, clients=clients, binary=binary)
    # Inspected UP FRONT, not inside the FDA branch. ESF and FDA are separate
    # grants that fail independently, and every verdict below returns early —
    # so computing FDA lazily meant the first blocker found masked the second.
    # On this machine both were broken at once: the ESF grant was denied for
    # the bundle id AND the FDA grant pointed at a deleted file. Reporting one
    # at a time turns a single fix into a fix-restart-rediscover loop.
    fda = _inspect_fda(tcc_paths, binary)
    fda_note = _fda_clause(fda)
    evidence = {
        "binary": str(binary),
        "binary_exists": binary.exists(),
        "log_path": source_path,
        "latest_line": line,
        "tcc": tcc,
        "fda": fda,
    }

    if tcc["state"] == "denied":
        evidence["tcc_service"] = _TCC_SERVICE
        return _event(
            device_id=resolved_device_id,
            checked_at=checked_at,
            kind="endpoint_security_tcc",
            status="unauthorized",
            reason="AMOSKYS Sentinel installed, but Endpoint Security TCC is denied" + fda_note,
            evidence=evidence,
        )
    if tcc["state"] == "missing" and "guarding exec" not in line:
        evidence["tcc_service"] = _TCC_SERVICE
        return _event(
            device_id=resolved_device_id,
            checked_at=checked_at,
            kind="endpoint_security_tcc_missing_grant",
            status="unauthorized",
            reason="AMOSKYS Sentinel has no Endpoint Security TCC grant" + fda_note,
            evidence=evidence,
        )
    if tcc["state"] == "limited":
        evidence["tcc_service"] = _TCC_SERVICE
        return _event(
            device_id=resolved_device_id,
            checked_at=checked_at,
            kind="endpoint_security_tcc_limited",
            status="unauthorized",
            reason="AMOSKYS Sentinel Endpoint Security TCC grant is limited" + fda_note,
            evidence=evidence,
        )
    if tcc["state"] == "allowed" and (not line or "guarding exec" in line):
        return None

    if "guarding exec" in line:
        return None
    if "needs Full Disk Access" in line or "ERR_NOT_PERMITTED" in line:
        # This used to report an Endpoint Security denial, which sent anyone
        # debugging it at the wrong grant. FDA and ESF are separate services;
        # the Sentinel can hold one and not the other, and the log line names
        # FDA explicitly. Report what is actually missing, and say WHICH file
        # needs the grant — because the common failure is a same-named binary
        # holding it at a different path.
        status = "unauthorized"
        kind = "endpoint_security_fda"
        evidence["tcc_service"] = _TCC_FDA_SERVICE
        if fda.get("same_name_elsewhere"):
            other = fda["same_name_elsewhere"][0]["client"]
            reason = (
                "AMOSKYS Sentinel needs Full Disk Access on "
                f"{fda.get('target')} — a different file with the same name "
                f"holds it instead ({other}). Grant FDA to the app bundle's "
                "binary."
            )
        else:
            reason = (
                "AMOSKYS Sentinel needs Full Disk Access on "
                f"{fda.get('target')} (Endpoint Security grant is present)"
            )
    elif "missing com.apple.developer.endpoint-security.client entitlement" in line:
        status = "blind"
        kind = "endpoint_security_entitlement"
        reason = "AMOSKYS Sentinel lacks the Endpoint Security entitlement"
    elif "must run as root" in line or "ERR_NOT_PRIVILEGED" in line:
        status = "blind"
        kind = "endpoint_security_privilege"
        reason = "AMOSKYS Sentinel is not running with root privileges"
    elif "es_subscribe failed" in line:
        status = "blind"
        kind = "endpoint_security_subscribe"
        reason = "AMOSKYS Sentinel could not subscribe to Endpoint Security events"
    elif "es_new_client failed" in line:
        status = "blind"
        kind = "endpoint_security_client"
        reason = "AMOSKYS Sentinel could not create an Endpoint Security client"
    else:
        status = "unknown"
        kind = "endpoint_security_status_unknown"
        reason = "AMOSKYS Sentinel is installed, but authorization state is unknown"

    return _event(
        device_id=resolved_device_id,
        checked_at=checked_at,
        kind=kind,
        status=status,
        reason=reason,
        evidence=evidence,
    )
