"""Customer consent model — four ways a customer authorizes us.

Each method produces the same outcome in storage (`consent_verified_at_ns`
is set) but carries different audit evidence.

    DNS_TXT         : cold-outreach cryptographic proof of domain control
    SIGNED_CONTRACT : paper pentest; operator attests with ArtifactRef
    EMAIL           : written email auth; operator attests with ArtifactRef
    LAB_SELF        : dev only — never for customer engagements

Bug-bounty hunting is NOT a customer consent method. It's AMOSKYS
internal tooling gated by operator identity + accepted agreement.
See argos/operators.py and argos.hunt.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from typing import Optional

logger = logging.getLogger("amoskys.argos.consent")


# ── Artifact reference (signed contract / email) ──────────────────


@dataclass
class ArtifactRef:
    """Reference to the authorizing artifact for SIGNED_CONTRACT / EMAIL.

    Minimal shape — we don't store the contract itself, just a pointer.
    If legal needs the artifact, they reach out to the operator by
    customer_id and use `ref_type` + `ref_value` to locate it.
    """

    ref_type: str   # "docusign_envelope" | "contract_number" | "email_message_id" | "file_path" | "other"
    ref_value: str  # the identifier itself
    notes: str = ""

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)

    @classmethod
    def from_json(cls, raw: Optional[str]) -> Optional["ArtifactRef"]:
        if not raw:
            return None
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return None
        return cls(
            ref_type=data.get("ref_type", "other"),
            ref_value=data.get("ref_value", ""),
            notes=data.get("notes", ""),
        )
