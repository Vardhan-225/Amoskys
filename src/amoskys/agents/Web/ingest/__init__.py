"""AMOSKYS Web — Event Ingest API.

FastAPI service that accepts signed event envelopes from Aegis (defensive
side) and Argos (offensive side), verifies them, and persists them to the
AMOSKYS Web DB for IGRIS-Web cortex consumption.

v0 is intentionally minimal:
  - SQLite storage (easy dev setup; migrate to Postgres for production
    multi-tenant scale)
  - Single dev bearer token (per-tenant token issuance is v0.2)
  - Chain verification opt-in (default on, disable via env for bring-up)
  - Schema validation via Pydantic

Run:
    PYTHONPATH=src python -m amoskys.agents.Web.ingest

Environment variables:
    AMOSKYS_INGEST_DB_PATH   default: data/web_events.db
    AMOSKYS_INGEST_TOKEN     default: "dev-token" (MUST be overridden in prod)
    AMOSKYS_INGEST_HOST      default: 0.0.0.0
    AMOSKYS_INGEST_PORT      default: 8765
    AMOSKYS_INGEST_VERIFY_CHAIN  default: "true" — set "false" for bring-up
"""

__version__ = "0.1.0-alpha"
