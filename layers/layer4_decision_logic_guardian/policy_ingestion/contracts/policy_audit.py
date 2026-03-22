from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Optional, Dict, Any
from datetime import datetime


PolicyAuditEventType = Literal[
    "PROPOSED_SUBMITTED",
    "PROPOSED_REJECTED",
    "POLICY_APPROVED",
    "POLICY_DEPRECATED",
    "POLICY_SUPERSEDED",
    "MAPPING_APPROVED",
]


@dataclass(frozen=True)
class PolicyAuditEvent:
    event_type: PolicyAuditEventType
    tenant_id: Optional[str]

    event_id: str
    at_utc: datetime = field(default_factory=datetime.utcnow)

    actor: str = "unknown"  # who did it
    notes: Optional[str] = None

    data: Dict[str, Any] = field(default_factory=dict)
