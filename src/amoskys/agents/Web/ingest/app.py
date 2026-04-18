"""FastAPI app for AMOSKYS Web event ingest.

Endpoints:
  GET  /health                — liveness + event count summary
  POST /v1/events             — ingest a single event envelope
  GET  /v1/events/tail        — (dev helper) last 20 events for a site

Auth: Bearer token in Authorization header.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware

from amoskys.agents.Web.ingest import __version__
from amoskys.agents.Web.ingest.schema import EventEnvelope, IngestResponse
from amoskys.agents.Web.ingest.storage import EventStore


logger = logging.getLogger("amoskys.ingest")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s %(message)s")


# ─────────────────────────────────────────────────────────────
# Config from env
# ─────────────────────────────────────────────────────────────

DB_PATH = os.environ.get("AMOSKYS_INGEST_DB_PATH", "data/web_events.db")
DEV_TOKEN = os.environ.get("AMOSKYS_INGEST_TOKEN", "dev-token-change-me")
VERIFY_CHAIN = os.environ.get("AMOSKYS_INGEST_VERIFY_CHAIN", "true").lower() != "false"


# ─────────────────────────────────────────────────────────────
# App + store
# ─────────────────────────────────────────────────────────────

app = FastAPI(
    title="AMOSKYS Web Event Ingest",
    version=__version__,
    description="Receives signed event envelopes from Aegis + Argos.",
)

# CORS — open for dev, tighten per-tenant in prod
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)

store = EventStore(DB_PATH)
store.ensure_dev_tenant(DEV_TOKEN)


# ─────────────────────────────────────────────────────────────
# Auth
# ─────────────────────────────────────────────────────────────

def require_bearer(
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
) -> str:
    """Verify bearer token, return the tenant_id it maps to."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing or malformed Authorization: Bearer <token>",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = authorization[len("Bearer ") :].strip()
    tenant_id = store.tenant_from_token(token)
    if not tenant_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="unknown bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return tenant_id


# ─────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────

@app.get("/health")
def health() -> dict:
    counts = store.event_counts()
    return {
        "status": "ok",
        "version": __version__,
        "verify_chain": VERIFY_CHAIN,
        "event_count_by_type": counts,
        "total_events": sum(counts.values()),
    }


@app.post("/v1/events", response_model=IngestResponse)
def ingest_event(
    envelope: EventEnvelope,
    tenant_id: Annotated[str, Depends(require_bearer)],
) -> IngestResponse:
    """Ingest a single event envelope.

    Server sets tenant_id from the bearer token — client values are
    ignored for safety (clients can only influence their own tenant's
    data, never another tenant's).
    """
    # Force tenant_id to the one derived from the token
    envelope.tenant_id = tenant_id

    # Determine origin if not explicitly set (infer from event_type prefix)
    origin = envelope.origin
    if origin is None:
        if envelope.event_type.startswith("aegis."):
            origin = "aegis"
        elif envelope.event_type.startswith("argos."):
            origin = "argos"
        else:
            origin = "unknown"
    else:
        origin = origin.value if hasattr(origin, "value") else str(origin)

    warnings: list[str] = []

    # Chain verification
    chain_ok = True
    if VERIFY_CHAIN:
        expected_prev = store.expected_prev_sig(tenant_id, envelope.site_id, origin)
        submitted_prev = envelope.prev_sig
        # The FIRST event from a site has prev_sig=None and expected=None — both match.
        # Empty string can happen from Aegis; treat as None.
        submitted_norm = submitted_prev if submitted_prev else None
        expected_norm = expected_prev if expected_prev else None
        if submitted_norm != expected_norm:
            chain_ok = False
            warnings.append(
                f"chain break: submitted prev_sig={submitted_norm}, expected={expected_norm}"
            )
            store.note_chain_break(
                tenant_id=tenant_id,
                site_id=envelope.site_id,
                origin=origin,
                event_id=envelope.event_id,
                expected_prev=expected_norm,
                submitted_prev=submitted_norm,
                reason="chain mismatch",
            )
            # Soft-accept for now; hard-reject in prod
            logger.warning(
                "chain break tenant=%s site=%s origin=%s event=%s",
                tenant_id, envelope.site_id, origin, envelope.event_id,
            )

    persisted_at = store.insert_event(
        event_id=envelope.event_id,
        tenant_id=tenant_id,
        site_id=envelope.site_id,
        origin=origin,
        event_type=envelope.event_type,
        severity=envelope.severity.value,
        event_timestamp_ns=envelope.event_timestamp_ns,
        sig=envelope.sig,
        prev_sig=envelope.prev_sig,
        envelope=envelope.model_dump(mode="json"),
    )

    return IngestResponse(
        accepted=True,
        event_id=envelope.event_id,
        persisted_at=persisted_at,
        chain_ok=chain_ok,
        tenant_id=tenant_id,
        warnings=warnings,
    )


@app.get("/v1/events/tail")
def tail_events(
    tenant_id: Annotated[str, Depends(require_bearer)],
    site_id: str = Query(...),
    limit: int = Query(20, ge=1, le=200),
) -> dict:
    """Dev helper — last N events for a site."""
    import json as _json
    with store._conn() as c:
        rows = c.execute(
            """SELECT event_id, event_type, severity, event_timestamp_ns,
                      sig, prev_sig, envelope_json
               FROM web_events
               WHERE tenant_id=? AND site_id=?
               ORDER BY event_timestamp_ns DESC LIMIT ?""",
            (tenant_id, site_id, limit),
        ).fetchall()
        events = []
        for r in rows:
            events.append({
                "event_id": r["event_id"],
                "event_type": r["event_type"],
                "severity": r["severity"],
                "event_timestamp_ns": r["event_timestamp_ns"],
                "sig": r["sig"][:16],
                "prev_sig": (r["prev_sig"] or "")[:16],
                "attributes": _json.loads(r["envelope_json"]).get("attributes", {}),
            })
        return {"tenant_id": tenant_id, "site_id": site_id, "events": events}


def main() -> None:
    import uvicorn
    host = os.environ.get("AMOSKYS_INGEST_HOST", "0.0.0.0")
    port = int(os.environ.get("AMOSKYS_INGEST_PORT", "8765"))
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
