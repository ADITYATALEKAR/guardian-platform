from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal
from datetime import datetime


TriggerType = Literal["DIRECT_VIOLATION", "AT_RISK", "ENABLED_BY"]


@dataclass(frozen=True)
class ApprovedPatternMapping:
    """
    Human-approved mapping that connects:
    Guardian Pattern Label -> Policy Requirement
    """

    mapping_id: str
    policy_id: str
    pattern_label: str
    trigger_type: TriggerType

    approved_by: str
    approved_at_utc: datetime = field(default_factory=datetime.utcnow)

    rationale: str = ""

    def __post_init__(self):
        if not self.mapping_id:
            raise ValueError("mapping_id cannot be empty")
        if not self.policy_id:
            raise ValueError("policy_id cannot be empty")
        if not self.pattern_label:
            raise ValueError("pattern_label cannot be empty")
