"""
Layer 4 – Policy Assessment Response Contract

PolicyResponse.py

PURPOSE
-------
This module defines the canonical response model for Guardian's Policy Engine (Layer 4).

It is the CONTRACT between:
- Guardian's Policy Engine (Layer 4) — computes policy violations
- Layer 4.5 NLP — translates policy violations into narrative
- UI/API (Layer 5-6) — renders policy violations to users and regulators

PROPERTIES
----------
- Immutable (frozen dataclass)
- Type-safe (no dicts, no string soup)
- Auditable (every field traceable to regulatory source)
- Deterministic (same patterns → same violations always)

REGULATORY CONTEXT
------------------
This contract enforces that AVYAKTA can answer:
1. Which laws apply to this bank?
2. Are we violating them RIGHT NOW?
3. What are the consequences?
4. What must we do to fix it?
5. When must we do it?
6. Who is the regulator?

Every field exists because a lawyer or regulator needs it.
"""

from dataclasses import dataclass
from typing import List, Literal, Optional
from datetime import datetime


# ======================================================================
# POLICY FINDING - SINGLE VIOLATION OR COMPLIANCE STATE
# ======================================================================

@dataclass(frozen=True)
class PolicyFinding:
    """
    One policy requirement and its current compliance state.
    
    This represents:
    - A specific law or regulation
    - Whether it is violated, at-risk, or compliant
    - Why (which patterns triggered it)
    - What happens if not fixed
    - What must be done to fix it
    
    Example:
    --------
    PolicyFinding(
        policy_id="EU-PSD2-SEC-2.4.1",
        policy_name="Cryptographic Requirements",
        framework="EU-PSD2",
        status="VIOLATED",
        trigger_patterns=["entropy_exhaustion", "protocol_downgrade"],
        requirement="Use cryptography meeting ISO/IEC 19790 level 2+",
        current_state="Entropy source degraded to 82% quality. TLS downgrade negotiation observed.",
        violation_risk="Fines up to €20M or 4% global turnover. Payment license suspension.",
        required_action="Upgrade entropy source to FIPS 140-3. Enforce TLS 1.2+ minimum.",
        remediation_deadline_days=7,
        regulator="European Banking Authority (EBA)",
        violation_severity="CRITICAL"
    )
    """
    
    # ====================================================================
    # IDENTIFICATION
    # ====================================================================
    
    policy_id: str
    """
    Unique identifier for this policy requirement.
    
    Format: {FRAMEWORK}-{SECTION}-{SUBSECTION}
    Examples:
    - "EU-PSD2-SEC-2.4.1" (EU Payment Services Directive 2, Security, Section 2.4.1)
    - "GDPR-ART-32" (General Data Protection Regulation, Article 32)
    - "PCI-DSS-3.4" (Payment Card Industry Data Security Standard, Requirement 3.4)
    - "HIPAA-164.312" (Health Insurance Portability and Accountability Act, Section 164.312)
    """
    
    policy_name: str
    """
    Human-readable name for this policy.
    
    Examples:
    - "Cryptographic Requirements"
    - "Personal Data Protection"
    - "Encryption and Key Management"
    - "Authentication and Access Control"
    """
    
    framework: str
    """
    Which regulatory framework does this belong to?
    
    Values: "EU-PSD2", "GDPR", "PCI-DSS", "HIPAA", "SOC2", "ISO27001", etc.
    """
    
    # ====================================================================
    # COMPLIANCE STATUS
    # ====================================================================
    
    status: Literal["VIOLATED", "AT_RISK", "COMPLIANT"]
    """
    Current compliance state.
    
    VIOLATED:  Policy requirement is not met RIGHT NOW. Immediate action required.
               Guardian detected patterns that directly violate this policy.
    
    AT_RISK:   Policy will be violated if current trend continues.
               Guardian detected escalating patterns that are approaching violation.
    
    COMPLIANT: Policy requirement is currently being met.
               Guardian found no violation signals.
    """
    
    # ====================================================================
    # WHAT TRIGGERED THIS
    # ====================================================================
    
    trigger_patterns: List[str]
    """
    Which detected patterns caused this policy finding?
    
    Pattern labels from PatternResponse.label that matched this policy's trigger rules.
    
    Examples:
    - ["entropy_exhaustion", "protocol_downgrade"]
    - ["session_replay", "weak_authentication"]
    - ["unencrypted_transmission"]
    
    These are EXACT matches to pattern_labels.py patterns.
    If trigger_patterns is empty, status should be "COMPLIANT".
    """
    
    # ====================================================================
    # THE REGULATION
    # ====================================================================
    
    requirement: str
    """
    What does the law require?
    
    This is the actual regulatory text, not interpretation.
    Should be quotable in a regulatory response.
    
    Example:
    "Payment Service Providers must implement strong authentication for payment
    transactions. Cryptographic material must meet ISO/IEC 19790 Level 2 requirements
    and be rotated according to approved schedule."
    """
    
    current_state: str
    """
    What Guardian observed in the system right now.
    
    This is the EVIDENCE that led to this finding.
    Should cite specific patterns, metrics, or observations.
    
    Example:
    "Entropy source quality degraded to 82%. TLS 1.0 downgrade negotiation detected
    on payment-gateway-3. Session tokens without binding detected on 6 endpoints."
    """
    
    # ====================================================================
    # CONSEQUENCES
    # ====================================================================
    
    violation_risk: str
    """
    What happens if this is violated?
    
    Include:
    - Financial penalties (fines, ranges)
    - Operational consequences (license loss, account closure)
    - Legal consequences (lawsuits, criminal liability)
    - Notification obligations (customer breach notification, regulator reporting)
    
    Example:
    "Up to €20M fine or 4% of global annual turnover, whichever is higher.
    Payment processing license suspension. Mandatory breach notification to EBA.
    Customer notification required within 72 hours."
    """
    
    # ====================================================================
    # REMEDIATION
    # ====================================================================
    
    required_action: str
    """
    What must be done to achieve compliance?
    
    This should be SPECIFIC and ACTIONABLE.
    Guardian tells you WHAT, not HOW (that's engineering's job).
    
    Example:
    "Replace entropy source with FIPS 140-3 Level 3+ hardware. Disable TLS < 1.2
    at all connection negotiation points. Rotate all cryptographic keys using
    new entropy source. Implement session binding to device fingerprint."
    """
    
    remediation_deadline_days: Optional[int]
    """
    How many days to fix this?
    
    This is the regulatory deadline, not an engineering estimate.
    
    Common regulatory timelines:
    - 1-2 days: Active security incident / breach
    - 3 days: GDPR incident notification
    - 7 days: PSD2 critical security issue
    - 30 days: PSD2 security update
    - 90 days: General compliance remediation
    
    None = No specific deadline (compliant or low-risk at_risk)
    """
    
    # ====================================================================
    # REGULATOR
    # ====================================================================
    
    regulator: Optional[str]
    """
    Which authority oversees this policy?
    
    Examples:
    - "European Banking Authority (EBA)" for PSD2
    - "Data Protection Authority" for GDPR
    - "Payment Card Industry (PCI)" for PCI-DSS
    - "Centers for Medicare & Medicaid Services (CMS)" for HIPAA
    
    This tells the bank WHO to report to if violated.
    """
    
    # ====================================================================
    # SEVERITY (for UI/alerting prioritization)
    # ====================================================================
    
    violation_severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    """
    How severe is this violation?
    
    CRITICAL: Immediate threat to business operations or legal standing
              (e.g., PSD2 encryption violation, active breach)
    
    HIGH:     Significant fines or operational disruption if not fixed
              (e.g., GDPR data protection gap, payment license at risk)
    
    MEDIUM:   Notable compliance gap with moderate consequences
              (e.g., SOC2 audit finding, policy enforcement gap)
    
    LOW:      Minor compliance issue with limited impact
              (e.g., documentation gap, configuration drift)
    
    Derived from: status + remediation_deadline_days + violation_risk
    """


# ======================================================================
# POLICY RESPONSE - COMPLETE POLICY ASSESSMENT
# ======================================================================

@dataclass(frozen=True)
class PolicyResponse:
    """
    Complete policy compliance assessment from Guardian.
    
    This is what GuardianQueryResponse.policy contains.
    
    It answers:
    1. Which policies apply to this entity/system?
    2. Are we violating any?
    3. What are the legal and financial consequences?
    4. What must we do and when?
    
    Example:
    --------
    PolicyResponse(
        findings=[
            PolicyFinding(
                policy_id="EU-PSD2-SEC-2.4.1",
                status="VIOLATED",
                violation_severity="CRITICAL",
                ...
            ),
            PolicyFinding(
                policy_id="GDPR-ART-32",
                status="AT_RISK",
                violation_severity="HIGH",
                ...
            ),
            PolicyFinding(
                policy_id="PCI-DSS-3.4",
                status="COMPLIANT",
                ...
            ),
        ],
        overall_risk_level="CRITICAL",
        violation_count=1,
        at_risk_count=1,
        compliant_count=1,
        immediate_action_required=True,
        most_urgent_deadline_days=7
    )
    """
    
    # ====================================================================
    # FINDINGS
    # ====================================================================
    
    findings: List[PolicyFinding]
    """
    All policy assessments.
    
    Should include:
    - VIOLATED policies (highest priority)
    - AT_RISK policies (escalating concern)
    - COMPLIANT policies (for completeness and audit trail)
    
    Sorted by severity and deadline (most urgent first).
    """
    
    # ====================================================================
    # AGGREGATE RISK
    # ====================================================================
    
    overall_risk_level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    """
    Highest risk level across all findings.
    
    CRITICAL: Any policy is VIOLATED
    HIGH:     Multiple policies are AT_RISK or one is AT_RISK with short deadline
    MEDIUM:   Some policies are AT_RISK but deadlines are reasonable
    LOW:      All policies COMPLIANT or no applicable policies
    
    This is what executives see in headlines.
    """
    
    violation_count: int
    """Number of findings with status=VIOLATED"""
    
    at_risk_count: int
    """Number of findings with status=AT_RISK"""
    
    compliant_count: int
    """Number of findings with status=COMPLIANT"""
    
    # ====================================================================
    # URGENCY
    # ====================================================================
    
    immediate_action_required: bool
    """
    True if ANY finding has:
    - status=VIOLATED, OR
    - status=AT_RISK with remediation_deadline_days <= 7
    
    This triggers C-level escalation.
    """
    
    most_urgent_deadline_days: Optional[int]
    """
    Shortest remediation deadline across all findings.
    
    This is the true deadline for the bank.
    If this is 3 days, everything else is secondary.
    
    None = No violated/at-risk policies with deadlines.
    """
    
    # ====================================================================
    # METADATA
    # ====================================================================
    
    generated_at_utc: datetime
    """When was this assessment computed?"""
    
    policy_version: str
    """
    Which version of the policy library was used?
    
    Allows audit trail: "This violation was assessed using policy_v2.1"
    Later updates can reference this: "v2.2 changed deadline from 7 to 3 days"
    """


# ======================================================================
# HELPER FUNCTIONS FOR WORKING WITH POLICIES
# ======================================================================

def filter_violated(response: PolicyResponse) -> List[PolicyFinding]:
    """Get only the violated policies."""
    return [f for f in response.findings if f.status == "VIOLATED"]


def filter_at_risk(response: PolicyResponse) -> List[PolicyFinding]:
    """Get only the at-risk policies."""
    return [f for f in response.findings if f.status == "AT_RISK"]


def filter_compliant(response: PolicyResponse) -> List[PolicyFinding]:
    """Get only the compliant policies."""
    return [f for f in response.findings if f.status == "COMPLIANT"]


def get_most_urgent(response: PolicyResponse) -> Optional[PolicyFinding]:
    """Get the policy with the shortest deadline."""
    urgent = [f for f in response.findings if f.remediation_deadline_days is not None]
    return min(urgent, key=lambda f: f.remediation_deadline_days) if urgent else None


def requires_regulator_notification(response: PolicyResponse) -> bool:
    """
    True if any policy violation requires reporting to regulator.
    
    For now, assume all VIOLATED policies require notification.
    This can be extended per-regulator later.
    """
    return any(f.status == "VIOLATED" for f in response.findings)