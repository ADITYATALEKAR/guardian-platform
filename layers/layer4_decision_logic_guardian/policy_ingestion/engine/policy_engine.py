"""
Layer 4 – Policy Engine (Registry-backed)
=========================================

What this file is:
- Deterministic, auditable policy enforcement engine for Layer 4 Guardian.
- Evaluates detected Layer-4 pattern labels against APPROVED policy registry mappings.
- Produces a PolicyResponse with explicit findings and an overall risk level.

Why we are changing it:
- Previous implementation could NEVER emit PolicyStatus.COMPLIANT because findings
  were only created when a policy was triggered by a pattern.
- Bank-grade compliance systems must provide an explicit COMPLIANT output when
  no violations/risks exist.

Depends on:
- FilePolicyRegistry (or any PolicyRegistry implementation)
- ApprovedPolicy + ApprovedPatternMapping contracts

Used by:
- GuardianCore (Layer 4) policy enforcement path
- GuardianQueries / decision response renderers

Bank-grade rules:
- Same inputs => same outputs (ordering, aggregation)
- Never auto-interpret policy text at runtime (no NLP here)
- All compliance decisions are driven ONLY by approved mappings
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional, Protocol, Dict, Tuple

from layers.layer4_decision_logic_guardian.policy_ingestion.contracts.policy_response import (
    PolicyFinding,
    PolicyResponse,
    PolicySeverity,
    PolicyStatus,
    RiskLevel,
)


# ============================================================
# REGISTRY INTERFACES (what PolicyEngine expects)
# ============================================================

@dataclass(frozen=True)
class ApprovedPolicy:
    """
    Minimal shape PolicyEngine needs from the registry.
    (Registry can store more fields; engine intentionally ignores them.)
    """
    policy_id: str
    tenant_id: str
    source: str  # REGULATORY | INTERNAL
    jurisdiction: Optional[str]

    framework: str
    policy_name: str

    requirement_text: str
    violation_risk: str
    remediation_deadline_days: Optional[int]
    enforcement_authority: Optional[str]

    version: str
    status: str  # ACTIVE | DEPRECATED | SUPERSEDED


@dataclass(frozen=True)
class ApprovedPatternMapping:
    mapping_id: str
    policy_id: str
    pattern_label: str
    trigger_type: str  # DIRECT_VIOLATION | AT_RISK
    approved_by: str
    approved_at_utc: datetime
    rationale: str


class PolicyRegistry(Protocol):
    """
    Registry contract used by PolicyEngine.
    Your FilePolicyRegistry must implement these.
    """

    def get_policies_for_pattern(
        self,
        *,
        tenant_id: str,
        pattern_label: str,
        jurisdiction: Optional[str] = None,
        include_internal: bool = True,
    ) -> List[ApprovedPolicy]:
        ...

    def get_mappings_for_policy(
        self,
        *,
        tenant_id: str,
        policy_id: str,
    ) -> List[ApprovedPatternMapping]:
        ...


# ============================================================
# POLICY ENGINE (Registry-backed)
# ============================================================

class PolicyEngine:
    """
    Deterministic policy evaluator.

    High-level behavior:
    - For each pattern label, fetch active approved policies mapped to it.
    - Determine whether each triggered policy is a VIOLATION or AT_RISK.
    - Aggregate into a PolicyResponse with bounded, JSON-safe values.

    Bank-grade behavior:
    - If NO triggers match, emit an explicit COMPLIANT summary finding.
    - This prevents "empty findings ambiguity" for regulators.
    """

    DEFAULT_COMPLIANT_POLICY_ID = "__COMPLIANCE_SUMMARY__"
    DEFAULT_COMPLIANT_FRAMEWORK = "AVYAKTA_POLICY_ENGINE"
    DEFAULT_COMPLIANT_NAME = "Compliance Summary"

    def __init__(self, registry: PolicyRegistry):
        self.registry = registry

    def evaluate(
        self,
        *,
        tenant_id: str,
        pattern_labels: List[str],
        jurisdiction: Optional[str] = None,
        include_internal: bool = True,
        policy_version: str = "registry",
    ) -> PolicyResponse:
        """
        Evaluate patterns against approved policy registry.

        Parameters:
        - tenant_id: tenant context
        - pattern_labels: list of detected pattern labels from Guardian analysis
        - jurisdiction: optional filter (e.g., "INDIA", "EUROPE", "UNITED STATES")
        - include_internal: include tenant internal policies
        - policy_version: emitted as metadata in response

        Returns:
        - PolicyResponse (always deterministic ordering + explicit compliance)
        """
        labels = self._canonicalize_patterns(pattern_labels)

        findings: List[PolicyFinding] = []
        # policy_id -> (status, severity, patterns)
        policy_hits: Dict[str, Tuple[PolicyStatus, PolicySeverity, List[str], ApprovedPolicy]] = {}

        for pattern in labels:
            policies = self.registry.get_policies_for_pattern(
                tenant_id=tenant_id,
                pattern_label=pattern,
                jurisdiction=jurisdiction,
                include_internal=include_internal,
            )

            for policy in policies:
                if policy.policy_id not in policy_hits:
                    status, severity = self._status_for_pattern(
                        tenant_id=tenant_id,
                        policy_id=policy.policy_id,
                        pattern=pattern,
                    )
                    policy_hits[policy.policy_id] = (status, severity, [pattern], policy)
                else:
                    # merge patterns deterministically
                    cur_status, cur_sev, cur_patterns, pol = policy_hits[policy.policy_id]
                    if pattern not in cur_patterns:
                        cur_patterns.append(pattern)
                        cur_patterns.sort()
                    # escalation: VIOLATED > AT_RISK > COMPLIANT
                    status, severity = self._escalate(cur_status, cur_sev, pattern, tenant_id, pol.policy_id)
                    policy_hits[policy.policy_id] = (status, severity, cur_patterns, pol)

        # Build findings in deterministic order
        for policy_id in sorted(policy_hits.keys()):
            status, severity, patterns, policy = policy_hits[policy_id]
            findings.append(
                PolicyFinding(
                    policy_id=policy.policy_id,
                    policy_name=policy.policy_name,
                    framework=policy.framework,
                    status=status,
                    trigger_patterns=list(patterns),
                    requirement=policy.requirement_text,
                    current_state=f"Detected patterns: {', '.join(patterns)}",
                    violation_risk=policy.violation_risk,
                    required_action=f"Remediate patterns ({', '.join(patterns)}) to satisfy {policy.policy_id}",
                    remediation_deadline_days=policy.remediation_deadline_days,
                    regulator=policy.enforcement_authority,
                    violation_severity=severity,
                )
            )

        #  Bank-grade: if no triggered findings exist, emit explicit COMPLIANT summary
        if not findings:
            findings.append(self._compliant_summary_finding(jurisdiction=jurisdiction))

        violated = [f for f in findings if f.status == PolicyStatus.VIOLATED]
        at_risk = [f for f in findings if f.status == PolicyStatus.AT_RISK]
        compliant = [f for f in findings if f.status == PolicyStatus.COMPLIANT]

        overall, immediate = self._aggregate_overall_risk(
            violated_count=len(violated),
            at_risk_count=len(at_risk),
        )

        most_urgent = self._most_urgent_deadline(findings)

        return PolicyResponse(
            findings=findings,
            overall_risk_level=overall,
            violation_count=len(violated),
            at_risk_count=len(at_risk),
            compliant_count=len(compliant),
            immediate_action_required=immediate,
            most_urgent_deadline_days=most_urgent,
            generated_at_utc=datetime.utcnow(),
            policy_version=policy_version,
        )

    # -------------------------
    # Internal helpers
    # -------------------------

    def _canonicalize_patterns(self, pattern_labels: List[str]) -> List[str]:
        """
        Deterministic canonicalization:
        - drop falsy/empty
        - strip whitespace
        - unique
        - sort
        """
        out = []
        seen = set()
        for p in pattern_labels or []:
            if not isinstance(p, str):
                continue
            s = p.strip()
            if not s:
                continue
            if s in seen:
                continue
            seen.add(s)
            out.append(s)
        out.sort()
        return out

    def _status_for_pattern(self, *, tenant_id: str, policy_id: str, pattern: str) -> Tuple[PolicyStatus, PolicySeverity]:
        """
        Determine whether the mapping is VIOLATED or AT_RISK.
        If mapping lookup fails, safe default = VIOLATED (bank-grade conservative).
        """
        mappings = self.registry.get_mappings_for_policy(
            tenant_id=tenant_id,
            policy_id=policy_id,
        )
        mapping_for_pattern = next((m for m in mappings if m.pattern_label == pattern), None)

        trigger_type = mapping_for_pattern.trigger_type if mapping_for_pattern else "DIRECT_VIOLATION"
        trigger_type = str(trigger_type).strip().upper()

        if trigger_type == "AT_RISK":
            return (PolicyStatus.AT_RISK, PolicySeverity.HIGH)

        return (PolicyStatus.VIOLATED, PolicySeverity.CRITICAL)

    def _escalate(
        self,
        cur_status: PolicyStatus,
        cur_severity: PolicySeverity,
        pattern: str,
        tenant_id: str,
        policy_id: str,
    ) -> Tuple[PolicyStatus, PolicySeverity]:
        """
        Escalation rule:
        - if any pattern maps to VIOLATED => policy is VIOLATED
        - else if any AT_RISK => policy is AT_RISK
        """
        new_status, new_sev = self._status_for_pattern(tenant_id=tenant_id, policy_id=policy_id, pattern=pattern)

        order = {
            PolicyStatus.COMPLIANT: 0,
            PolicyStatus.AT_RISK: 1,
            PolicyStatus.VIOLATED: 2,
        }
        if order[new_status] > order[cur_status]:
            return new_status, new_sev
        return cur_status, cur_severity

    def _aggregate_overall_risk(self, *, violated_count: int, at_risk_count: int) -> Tuple[RiskLevel, bool]:
        """
        Risk aggregation (deterministic):
        - Any VIOLATED => CRITICAL + immediate action
        - >=2 AT_RISK => HIGH
        - 1 AT_RISK => MEDIUM
        - else => LOW
        """
        if violated_count > 0:
            return RiskLevel.CRITICAL, True
        if at_risk_count >= 2:
            return RiskLevel.HIGH, False
        if at_risk_count == 1:
            return RiskLevel.MEDIUM, False
        return RiskLevel.LOW, False

    def _most_urgent_deadline(self, findings: List[PolicyFinding]) -> Optional[int]:
        deadlines = [
            int(f.remediation_deadline_days)
            for f in findings
            if f.remediation_deadline_days is not None
        ]
        return min(deadlines) if deadlines else None

    def _compliant_summary_finding(self, *, jurisdiction: Optional[str]) -> PolicyFinding:
        """
        Creates an explicit COMPLIANT result when no triggers exist.
        This is a compliance reporting construct, not a regulation itself.
        """
        j = (jurisdiction or "GLOBAL").strip() or "GLOBAL"
        return PolicyFinding(
            policy_id=self.DEFAULT_COMPLIANT_POLICY_ID,
            policy_name=self.DEFAULT_COMPLIANT_NAME,
            framework=self.DEFAULT_COMPLIANT_FRAMEWORK,
            status=PolicyStatus.COMPLIANT,
            trigger_patterns=[],
            requirement=f"No approved policy violations detected for jurisdiction: {j}.",
            current_state="No mapped policy triggers were detected from Guardian pattern labels.",
            violation_risk="None",
            required_action="No action required.",
            remediation_deadline_days=None,
            regulator=None,
            violation_severity=PolicySeverity.LOW,
        )
