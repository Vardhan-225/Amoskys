"""Argos storage — customer-scoped persistence for engagements, recon, findings.

Customer data is the crown-jewels of this product. If it leaks, we're done.
Every file in this package enforces:

  - File mode 0600 on the SQLite DB
  - WAL journaling for durability during interrupt
  - Audit log on every state-changing call
  - No plaintext secrets in metadata blobs
"""

from amoskys.agents.Web.argos.storage.assets_db import (
    AssetKind,
    AssetsDB,
    AuditEntry,
    ConsentMethod,
    Customer,
    Operator,
    OperatorAgreement,
    OperatorRole,
    ReconRun,
    ScanJob,
    ScanQueue,
    StoredFinding,
    SurfaceAsset,
)

__all__ = [
    "AssetKind",
    "AssetsDB",
    "AuditEntry",
    "ConsentMethod",
    "Customer",
    "Operator",
    "OperatorAgreement",
    "OperatorRole",
    "ReconRun",
    "ScanJob",
    "ScanQueue",
    "StoredFinding",
    "SurfaceAsset",
]
