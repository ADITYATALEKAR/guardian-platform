"""
Purpose

Created ONLY via explicit human approval

Immutable once active (versioned instead)

Used by PolicyEngine

Regulator-auditable


"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Optional
from datetime import datetime


PolicySource = Literal["REGULATORY", "INTERNAL"]
PolicyStatus = Literal["ACTIVE", "DEPRECATED", "SUPERSEDED"]


@dataclass(frozen=True)
class ApprovedPolicy:
    """
    Canonical, approved, deterministic policy record.

    This is the only object that PolicyEngine may use for evaluation.
    """

    policy_id: str
    tenant_id: Optional[str]  # None means global policy (applies to all tenants)

    source: PolicySource
    jurisdiction: Optional[str]  # None = global
    framework: str
    policy_name: str

    requirement_text: str
    violation_risk: str
    remediation_deadline_days: Optional[int]
    enforcement_authority: Optional[str]

    version: str
    status: PolicyStatus = "ACTIVE"

    approved_by: str = "unknown"
    approved_at_utc: datetime = field(default_factory=datetime.utcnow)

    # evolution
    supersedes_policy_id: Optional[str] = None
    superseded_by_policy_id: Optional[str] = None  # forward link (nice-to-have)

    def __post_init__(self):
        if not self.policy_id:
            raise ValueError("policy_id cannot be empty")
        if not self.framework:
            raise ValueError("framework cannot be empty")
        if not self.policy_name:
            raise ValueError("policy_name cannot be empty")
        if not self.requirement_text:
            raise ValueError("requirement_text cannot be empty")
        if not self.violation_risk:
            raise ValueError("violation_risk cannot be empty")
        if not self.version:
            raise ValueError("version cannot be empty")
