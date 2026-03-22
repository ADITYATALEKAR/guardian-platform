from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import List, Optional


class PolicyStatus(str, Enum):
    VIOLATED = "VIOLATED"
    AT_RISK = "AT_RISK"
    COMPLIANT = "COMPLIANT"


class PolicySeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class RiskLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass(frozen=True)
class PolicyFinding:
    policy_id: str
    policy_name: str
    framework: str

    status: PolicyStatus
    trigger_patterns: List[str]

    requirement: str
    current_state: str

    violation_risk: str
    required_action: str
    remediation_deadline_days: Optional[int]

    regulator: Optional[str]
    violation_severity: PolicySeverity


@dataclass(frozen=True)
class PolicyResponse:
    findings: List[PolicyFinding]

    overall_risk_level: RiskLevel
    violation_count: int
    at_risk_count: int
    compliant_count: int

    immediate_action_required: bool
    most_urgent_deadline_days: Optional[int]

    generated_at_utc: datetime
    policy_version: str

    def filter_violated(self) -> List[PolicyFinding]:
        return [f for f in self.findings if f.status == PolicyStatus.VIOLATED]

    def filter_at_risk(self) -> List[PolicyFinding]:
        return [f for f in self.findings if f.status == PolicyStatus.AT_RISK]
