"""
Layer 4.5 – Guardian NLP & Semantic Narrative Engine

GuardianNarrative.py

ENHANCED WITH CAMPAIGN & POLICY INTEGRATION

This module deterministically compiles GuardianQueryResponse (Layer 4 output)
into structured, human-meaningful narratives for Layers 5–6 rendering.

RUNTIME STATUS
==============
This module is not on the active production runtime path. Legacy imports are
retained here only for compatibility during cleanup. Do not route new runtime
flows through this module until those dependencies are migrated.

NOW INCLUDES:
- Policy violations (regulatory risk)
- Campaign detection (coordinated attacks)
- Time-to-exploitation (attacker timeline)
- Blast radius (impact scope)

PRINCIPLES
==========
1. NO invention — only compile what Guardian emits
2. NO hallucination — all prose from templates
3. DETERMINISTIC — same input → same output always
4. AUDITABLE — every field traced to source
5. TYPE-SAFE — works with real GuardianQueryResponse objects

DATA FLOW
=========
GuardianQueryResponse
  ├── alert (AlertResponse)
  ├── patterns (List[PatternResponse])
  ├── advisory (AdvisoryResponse)
  ├── impact (Optional[ImpactResponse])
  ├── justification (JustificationResponse)
  ├── policy (Optional[PolicyResponse])          ← NEW
  └── campaign (Optional[CampaignResponse])      ← NEW
              ↓
        build_guardian_narrative()
              ↓
         GuardianNarrative
  ├── executive (ExecutiveNarrative)
  │   ├── regulatory_risk_summary (NEW)
  │   ├── campaign_summary (NEW)
  │   └── time_to_critical (NEW)
  │
  ├── operational (OperationalNarrative)
  │   ├── policy_violations (NEW)
  │   ├── campaign_context (NEW)
  │   ├── attacker_capability (NEW)
  │   └── time_to_exploitation (NEW)
  │
  └── audit (AuditNarrative)
      ├── policy_trail (NEW)
      ├── campaign_trail (NEW)
      └── complete_provenance
"""

from dataclasses import dataclass, field
from typing import List, Optional, Literal, Dict, Any
from enum import Enum
from datetime import datetime

# ======================================================================
# IMPORTS – STRICTLY LAYER 4 OUTPUT
# ======================================================================

from layers.layer4_decision_logic_guardian.legacy.node_adapters import ServiceNode


from layers.layer4_decision_logic_guardian.contracts.guardian_query_response import (
    GuardianQueryResponse,
)
from layers.layer4_decision_logic_guardian.legacy.contracts import PatternResponse
from layers.layer4_decision_logic_guardian.contracts.alert_response import AlertResponse
from layers.layer4_decision_logic_guardian.legacy.contracts.advisory_response import AdvisoryResponse
from layers.layer4_decision_logic_guardian.legacy.contracts.impact_response import ImpactResponse
from layers.layer4_decision_logic_guardian.legacy.contracts.justification_response import (
    JustificationResponse,
)
from layers.layer4_decision_logic_guardian.legacy.contracts.policy_response import (
    PolicyResponse,
    PolicyFinding,
)
from layers.layer4_decision_logic_guardian.legacy.contracts.campaign_response import (
    CampaignResponse,
    CampaignFinding,
)

from layers.layer4_decision_logic_guardian.legacy.actor_extractor import (ActorContext)



from types import SimpleNamespace
from datetime import datetime

def _normalize_alert(alert):
    """
    Normalize AlertResponse into legacy narrative-compatible shape.
    This is a READ-ONLY adapter. No mutation.
    """

    # Confidence normalization
    if isinstance(getattr(alert, "confidence", None), (int, float)):
        confidence = SimpleNamespace(
            observed=float(alert.confidence),
            ceiling=float(alert.confidence),
            rationale=None,
        )
    else:
        confidence = getattr(alert, "confidence", None)

    return SimpleNamespace(
        # identity
        entity_id=getattr(alert, "entity_id", None),
        session_id=getattr(alert, "session_id", None),

        # severity / level
        level=getattr(alert, "alert_kind", None),
        alert_level=getattr(alert, "alert_kind", None),

        # confidence (OBJECT, not float)
        confidence=confidence,

        # evidence
        evidence_ids=getattr(alert, "evidence_ids", []),

        # policy / schema
        policy_version=getattr(alert, "policy_version", None),
        schema_version=getattr(alert, "schema_version", "v1"),

        # timing
        generated_at_utc=getattr(
            alert,
            "generated_at_utc",
            datetime.utcnow(),
        ),
    )


# ======================================================================
# CONTROLLED VOCABULARIES & ENUMS
# ======================================================================

class ThreatSeverity(str, Enum):
    """Threat severity mapped from pattern confidence"""
    CRITICAL = "CRITICAL"      # confidence >= 0.75
    HIGH = "HIGH"              # confidence 0.60–0.75
    MEDIUM = "MEDIUM"          # confidence 0.40–0.60
    LOW = "LOW"                # confidence < 0.40


class AlertLevelCategory(str, Enum):
    """Guardian alert level categorization"""
    RED = "RED"                # Active threat, immediate action
    ORANGE = "ORANGE"          # Elevated risk, urgent attention
    YELLOW = "YELLOW"          # Notable anomaly, monitor closely
    GREEN = "GREEN"            # Baseline, minimal concern


class TrendCategory(str, Enum):
    """Trend direction from advisory"""
    ESCALATING = "escalating"
    STABLE = "stable"
    DECELERATING = "decelerating"


class ExecutiveUrgency(str, Enum):
    """C-level urgency classification"""
    IMMEDIATE = "IMMEDIATE"    # Action required within hours
    URGENT = "URGENT"          # Action required within day
    ELEVATED = "ELEVATED"      # Action required within week
    MONITOR = "MONITOR"        # Continue observation


# ======================================================================
# PATTERN LANGUAGE TEMPLATES
# ======================================================================

PATTERN_LANGUAGE: Dict[str, Dict[str, str]] = {
    "entropy_exhaustion": {
        "display_name": "Cryptographic Entropy Degradation",
        "what_is_happening": (
            "The cryptographic entropy source is approaching exhaustion. "
            "The system is drawing random values faster than the entropy pool can replenish. "
            "This reduces the quality of randomness used for key generation."
        ),
        "business_impact": (
            "Reduced entropy means cryptographic keys become more predictable. "
            "Predictable keys undermine the security guarantees that protect "
            "payment transactions, customer data, and authentication tokens. "
            "Regulatory standards (PSD2, HIPAA, SOC2) require high-entropy cryptography."
        ),
        "remediation_hint": (
            "Entropy sources must be monitored and refreshed. "
            "Upgrade to FIPS 140-3 certified entropy hardware if degradation persists."
        ),
    },
    
    "protocol_downgrade": {
        "display_name": "Cryptographic Protocol Downgrade",
        "what_is_happening": (
            "Connections are being negotiated toward weaker cryptographic protocols. "
            "TLS downgrade attempts, SSL fallback, or cipher suite degradation detected. "
            "This forces encryption to use older, less secure algorithms."
        ),
        "business_impact": (
            "Downgraded protocols (TLS 1.0, SSLv3) are vulnerable to known exploits. "
            "Attackers can intercept encrypted traffic and potentially decrypt it. "
            "Customer data and payment information are at risk. "
            "This violates PSD2 minimum encryption standards."
        ),
        "remediation_hint": (
            "Disable TLS versions < 1.2 at protocol negotiation. "
            "Enforce TLS 1.3 where possible. Remove weak cipher suites."
        ),
    },
    
    "session_replay": {
        "display_name": "Session Replay Activity",
        "what_is_happening": (
            "Authentication session tokens are being reused outside their original context. "
            "Previously-captured sessions are being replayed against the system. "
            "This bypasses normal authentication without credential compromise."
        ),
        "business_impact": (
            "Attackers can gain unauthorized access to accounts and systems without "
            "stealing passwords or defeating MFA. Replayed sessions inherit the original "
            "user's permissions and access level. Payment transactions, account modifications, "
            "and data access become possible without detection."
        ),
        "remediation_hint": (
            "Implement session binding (tie session to IP, device fingerprint). "
            "Invalidate old sessions when user logs out. Add timestamp/nonce validation."
        ),
    },
    
    "credential_reuse": {
        "display_name": "Credential Reuse Attack",
        "what_is_happening": (
            "Credentials harvested from one system are being tested against other systems. "
            "Username/password pairs are being attempted across multiple services. "
            "This indicates lateral movement or mass account compromise."
        ),
        "business_impact": (
            "Attackers gain access to multiple systems using the same credentials. "
            "Payment systems, admin consoles, and customer databases may be compromised "
            "simultaneously. The blast radius depends on how widely credentials are reused."
        ),
        "remediation_hint": (
            "Enforce unique credentials per system. Implement password managers. "
            "Monitor for credential reuse patterns across service boundaries."
        ),
    },
    
    "anomalous_access_pattern": {
        "display_name": "Anomalous Access Pattern",
        "what_is_happening": (
            "Access requests deviate significantly from established baseline behavior. "
            "Unusual times, locations, frequencies, or data volumes detected. "
            "This indicates potential unauthorized access or account compromise."
        ),
        "business_impact": (
            "Unauthorized access can lead to data theft, system modification, or fraud. "
            "The specific impact depends on what the anomalous access is doing. "
            "If admin access, system compromise is possible. If data access, breach risk is high."
        ),
        "remediation_hint": (
            "Investigate the anomalous access source. Verify user identity. "
            "Consider resetting credentials if compromise suspected."
        ),
    },
    
    "unencrypted_transmission": {
        "display_name": "Unencrypted Data Transmission",
        "what_is_happening": (
            "Sensitive data is being transmitted without encryption. "
            "Payment information, credentials, or personal data sent over plaintext channels. "
            "Network eavesdropping can capture data in transit."
        ),
        "business_impact": (
            "Customer payment card data, authentication credentials, and personal information "
            "are accessible to any network observer. This violates PSD2, PCI DSS, GDPR, and HIPAA. "
            "Data breach liability is immediate and severe."
        ),
        "remediation_hint": (
            "Enforce HTTPS/TLS for all sensitive data. Use transport-layer encryption. "
            "Verify encryption in code review and network policy."
        ),
    },
    
    "weak_authentication": {
        "display_name": "Weak Authentication Mechanism",
        "what_is_happening": (
            "Authentication is using weak or deprecated methods. "
            "Single-factor authentication, unprotected API keys, hardcoded credentials, "
            "or insecure session handling detected."
        ),
        "business_impact": (
            "Weak authentication allows attackers to impersonate legitimate users. "
            "Account takeover becomes easy without MFA. Payment transactions, data access, "
            "and account modifications become possible with low effort."
        ),
        "remediation_hint": (
            "Require multi-factor authentication (MFA) for sensitive operations. "
            "Use OAuth2/OpenID Connect. Never hardcode credentials. Rotate API keys regularly."
        ),
    },
    
    "unauthorized_data_access": {
        "display_name": "Unauthorized Data Access",
        "what_is_happening": (
            "Accounts or processes are accessing data they should not have permission to read. "
            "Privilege escalation, access control bypass, or data leakage detected."
        ),
        "business_impact": (
            "Customer personal data, payment information, and business secrets may be exposed. "
            "GDPR, PCI DSS, and HIPAA violations trigger regulatory fines and notification obligations. "
            "Customer trust and reputation damage are inevitable."
        ),
        "remediation_hint": (
            "Audit access control policies. Implement role-based access control (RBAC). "
            "Log all data access. Monitor for unauthorized queries."
        ),
    },
}

DEFAULT_PATTERN = {
    "display_name": "Security Pattern Detected",
    "what_is_happening": "Guardian has detected a security-relevant weakness pattern in system behavior.",
    "business_impact": "The detected pattern indicates a potential security vulnerability or attack indicator.",
    "remediation_hint": "Review Guardian's detailed justification and evidence.",
}

TREND_LANGUAGE: Dict[str, str] = {
    "escalating": (
        "The threat is escalating. Detected patterns are increasing in frequency, confidence, "
        "or severity. Risk is rising. Immediate investigation and response is required."
    ),
    "stable": (
        "The threat is stable. Detected patterns are persistent but not accelerating. "
        "Risk remains elevated. Ongoing monitoring and investigation required."
    ),
    "decelerating": (
        "The threat is decelerating. Detected patterns are decreasing in frequency or confidence. "
        "Risk may be reducing. However, vigilance is warranted until patterns fully resolve."
    ),
}

DEFAULT_TREND = (
    "The threat trend is uncertain. Guardian has insufficient historical data to determine "
    "if this threat is escalating, stable, or decelerating."
)


# ======================================================================
# MAPPING FUNCTIONS
# ======================================================================

def _confidence_to_severity(confidence: float) -> ThreatSeverity:
    if confidence >= 0.75:
        return ThreatSeverity.CRITICAL
    elif confidence >= 0.60:
        return ThreatSeverity.HIGH
    elif confidence >= 0.40:
        return ThreatSeverity.MEDIUM
    else:
        return ThreatSeverity.LOW


def _alert_level_to_category(alert_level: str) -> AlertLevelCategory:
    level_map = {
        "RED": AlertLevelCategory.RED,
        "ORANGE": AlertLevelCategory.ORANGE,
        "YELLOW": AlertLevelCategory.YELLOW,
        "GREEN": AlertLevelCategory.GREEN,
    }
    return level_map.get(alert_level, AlertLevelCategory.GREEN)


def _trend_to_urgency(trend: str) -> ExecutiveUrgency:
    if trend == "escalating":
        return ExecutiveUrgency.IMMEDIATE
    elif trend == "stable":
        return ExecutiveUrgency.URGENT
    else:
        return ExecutiveUrgency.ELEVATED
    



def _build_actor_narrative(
    actors: Optional[list[ActorContext]],
    pattern_labels: list[str],
) -> Optional[str]:
    if not actors:
        return None

    lines = []
    lines.append("Observable actor surfaces (external vantage point):")

    for actor in actors:
        identifier = actor.identifier
        if actor.actor_type == "SESSION":
            identifier = identifier[:8] + "…" if len(identifier) > 8 else identifier

        lines.append(
            f"• {actor.actor_type}: {identifier} "
            f"({actor.confidence:.0%} confidence)"
        )

    # Limitations
    limitations = {a.limitations for a in actors if a.limitations}
    if limitations:
        lines.append("\nImportant limitations:")
        for l in limitations:
            lines.append(f"• {l}")

    # Correlations
    correlations = {a.recommended_correlation for a in actors if a.recommended_correlation}
    if correlations:
        lines.append("\nRecommended correlations:")
        for c in correlations:
            lines.append(f"• {c}")


    actions = recommend_actions(actors, pattern_labels)
    if actions:
        lines.append("\nRecommended immediate actions:")
        for action in actions:
            lines.append(f"• {action}")

    return "\n".join(lines)



def recommend_actions(
    actors: list[ActorContext],
    pattern_labels: list[str],
) -> list[str]:
    actions = []

    for actor in actors:
        if actor.actor_type == "SESSION" and "session_replay" in pattern_labels:
            actions.append("KILL_SESSION")

        if actor.actor_type == "IP_ADDRESS" and "protocol_downgrade" in pattern_labels:
            actions.append("BLOCK_IP")

    return sorted(set(actions))





# ======================================================================
# PROVENANCE
# ======================================================================

@dataclass
class Provenance:
    """Audit trail for narrative fields"""
    source_component: str
    source_field: str
    derivation_rule: str
    confidence: float


# ======================================================================
# NARRATIVE OBJECTS
# ======================================================================

@dataclass
class ThreatNarrative:
    pattern_label: str
    pattern_name: str
    what_is_happening: str
    business_impact: str
    remediation_hint: str
    severity: ThreatSeverity
    provenance: Provenance


@dataclass
class PolicyViolationNarrative:
    """Policy violation details for narratives"""
    policy_id: str
    policy_name: str
    framework: str
    status: str
    violation_risk: str
    required_action: str
    remediation_deadline_days: Optional[int]
    regulator: Optional[str]


@dataclass
class CampaignContextNarrative:
    """Campaign context for narratives"""
    campaign_name: str
    campaign_description: str
    severity: str
    current_phase: str
    attacker_capability: str
    attacker_sophistication: str
    time_to_exploitation_days: Optional[int]
    affected_asset_count: int


@dataclass
class AdvisoryNarrative:
    trend: str
    priority_patterns: List[str]
    business_interpretation: Optional[str]
    trend_explanation: str
    urgency: ExecutiveUrgency
    provenance: Provenance


@dataclass
class ImpactNarrative:
    estimated_scope: Optional[int]
    impacted_assets: List[str]
    scope_summary: str
    provenance: Provenance


@dataclass
class OperationalNarrative:
    """TIER 2: Engineering view"""
    alert_level: str
    confidence: float
    entity_id: str
    primary_threat: Optional[ThreatNarrative]
    secondary_threats: List[ThreatNarrative]
    advisory: AdvisoryNarrative
    impact: Optional[ImpactNarrative]
    
    # NEW: Policy & Campaign
    policy_violations: List[PolicyViolationNarrative]
    policy_risk_level: str
    campaign_context: Optional[CampaignContextNarrative]
    attacker_capability: str
    time_to_exploitation_days: Optional[int]
    
    investigation_focus: List[str]
    evidence_ids: List[str]
    justification: str
    contributing_predictors: List[str]
    actor_context_summary: Optional[str] = None
    observable_actors: List[ActorContext] = field(default_factory=list)


@dataclass
class ExecutiveNarrative:
    """TIER 1: C-level view"""
    headline: str
    summary: str
    alert_level: AlertLevelCategory
    severity: ThreatSeverity
    urgency: ExecutiveUrgency
    affected_scope: Optional[int]
    affected_system_names: List[str]
    threat_trend: str
    threat_trend_explanation: str
    business_context: Optional[str]
    recommended_action: str
    
    # NEW: Regulatory & Campaign Context
    regulatory_risk_summary: Optional[str]
    regulatory_deadline_days: Optional[int]
    regulatory_escalation_required: bool
    campaign_summary: Optional[str]
    campaign_objective: Optional[str]
    decision_window_hours: Optional[int]


@dataclass
class AuditNarrative:
    """TIER 3: Regulator view"""
    alert_level: str
    confidence_observed: float
    confidence_ceiling: float
    confidence_rationale: str
    entity_id: str
    evidence_ids: List[str]
    explanation: str
    contributing_predictors: List[str]
    policy_version: str
    schema_version: str
    generated_at_utc: int
    
    # NEW: Policy & Campaign trails
    policy_trail: List[Dict[str, Any]]
    campaign_trail: Optional[Dict[str, Any]]
    all_provenances: List[Provenance]


@dataclass
class GuardianNarrative:
    """COMPLETE SEMANTIC NARRATIVE with Policy & Campaign"""
    alert_id: str
    generated_at_utc: datetime
    source_guardian_version: str
    
    executive: ExecutiveNarrative
    operational: OperationalNarrative
    audit: AuditNarrative


# ======================================================================
# BUILDER FUNCTIONS
# ======================================================================

def _build_threat_narratives(
    patterns: List[PatternResponse],
    alert: AlertResponse,
    policy: Optional[PolicyResponse],
    campaign: Optional[CampaignResponse],
) -> List[ThreatNarrative]:
    """
    Convert patterns into threat narratives.

    IMPORTANT:
    - Patterns do NOT carry confidence
    - Severity is derived from alert level + policy + campaign
    """

    threats: List[ThreatNarrative] = []

    # 1️⃣ Base severity from alert level
    alert_severity_map = {
        "RED": ThreatSeverity.CRITICAL,
        "ORANGE": ThreatSeverity.HIGH,
        "YELLOW": ThreatSeverity.MEDIUM,
        "GREEN": ThreatSeverity.LOW,
    }


        # Resolve alert level robustly (supports AlertResponse, Alert, and test MockAlert)
    raw_level = getattr(alert, "alert_level", None)

    if raw_level is None:
        raw_level = getattr(alert, "level", None)

        # Normalize enums / strings into stable uppercase names
    if hasattr(raw_level, "name"):
        level_key = str(raw_level.name).upper()
    else:
        level_key = str(raw_level).strip().upper()

    base_severity = alert_severity_map.get(level_key, ThreatSeverity.MEDIUM)






    # 2️⃣ Escalate if policy violations exist
    if policy and policy.overall_risk_level in ("CRITICAL", "HIGH"):
        base_severity = ThreatSeverity.CRITICAL

    # 3️⃣ Escalate if campaign detected
    if campaign and campaign.campaign_detected:
        base_severity = ThreatSeverity.CRITICAL

    for pattern in patterns:
        language = PATTERN_LANGUAGE.get(pattern.label, DEFAULT_PATTERN)

        threats.append(
            ThreatNarrative(
                pattern_label=pattern.label,
                pattern_name=language["display_name"],
                what_is_happening=language["what_is_happening"],
                business_impact=language["business_impact"],
                remediation_hint=language["remediation_hint"],
                severity=base_severity,
                provenance=Provenance(
                    source_component="guardian_nlp",
                    source_field=f"PatternResponse(label={pattern.label})",
                    derivation_rule=(
                        f"Severity derived from alert level ({level_key}), "
                        f"policy risk ({policy.overall_risk_level.name if policy and hasattr(policy.overall_risk_level,'name') else (policy.overall_risk_level if policy else 'N/A')}), "
                        f"campaign detected ({bool(getattr(campaign, 'campaign_detected', False))})"
                    ),
                    confidence= float(getattr(getattr(alert, "confidence", None), "observed", getattr(alert, "confidence", 0.0)))
                                      or 0.0
                                ),
            )
        )

    return threats


def _build_impact_narrative(impact: Optional[ImpactResponse]) -> Optional[ImpactNarrative]:
    """Convert impact to narrative"""
    if impact is None:
        return None
    
    scope_text = f"{impact.estimated_scope} systems at risk" if impact.estimated_scope else "Scope being analyzed"
    asset_text = f"Affected: {', '.join(impact.impacted_assets)}" if impact.impacted_assets else "No specific assets"
    
    return ImpactNarrative(
        estimated_scope=impact.estimated_scope,
        impacted_assets=impact.impacted_assets,
        scope_summary=f"{scope_text}. {asset_text}.",
        provenance=Provenance(
            source_component="impact",
            source_field="ImpactResponse",
            derivation_rule="Direct mapping",
            confidence=1.0,
        ),
    )


def _build_policy_violations(policy: Optional[PolicyResponse]) -> tuple[List[PolicyViolationNarrative], str]:
    """Convert policy response to violation narratives"""
    violations: List[PolicyViolationNarrative] = []
    risk_level = "LOW"
    
    if not policy:
        return violations, risk_level
    
    risk_level = policy.overall_risk_level
    
    for finding in policy.findings:
        if finding.status in ("VIOLATED", "AT_RISK"):
            violation = PolicyViolationNarrative(
                policy_id=finding.policy_id,
                policy_name=finding.policy_name,
                framework=finding.framework,
                status=finding.status,
                violation_risk=finding.violation_risk,
                required_action=finding.required_action,
                remediation_deadline_days=finding.remediation_deadline_days,
                regulator=finding.regulator,
            )
            violations.append(violation)
    
    return violations, risk_level


def _build_campaign_context(campaign: Optional[CampaignResponse]) -> Optional[CampaignContextNarrative]:
    """Convert campaign response to context narrative"""
    if not campaign or not campaign.campaign_detected:
        return None
    
    if not campaign.most_urgent_campaign:
        return None
    
    camp = campaign.most_urgent_campaign
    
    return CampaignContextNarrative(
        campaign_name=camp.campaign_name,
        campaign_description=camp.campaign_description,
        severity=camp.severity,
        current_phase=camp.current_phase,
        attacker_capability=camp.attacker_capability,
        attacker_sophistication=camp.attacker_sophistication,
        time_to_exploitation_days=camp.time_to_exploitation_days,
        affected_asset_count=len(camp.affected_assets),
    )


def _build_advisory_narrative(advisory: AdvisoryResponse) -> AdvisoryNarrative:
    """Convert advisory response into advisory narrative"""

    trend_explanation = TREND_LANGUAGE.get(advisory.trend, DEFAULT_TREND)
    urgency = _trend_to_urgency(advisory.trend)

    return AdvisoryNarrative(
        trend=advisory.trend,
        priority_patterns=advisory.dominant_patterns,
        business_interpretation=advisory.business_interpretation,
        trend_explanation=trend_explanation,
        urgency=urgency,
        provenance=Provenance(
            source_component="advisory",
            source_field="AdvisoryResponse",
            derivation_rule=f"Trend '{advisory.trend}' → Urgency {urgency.value}",
            confidence=1.0,
        ),
    )


def build_guardian_narrative(response: GuardianQueryResponse) -> GuardianNarrative:
    """
    MAIN ENTRY POINT
    
    Compile GuardianQueryResponse into GuardianNarrative.
    Now wires in Policy and Campaign data.
    """

    if isinstance(response, dict):
        typed = response.get("_typed_response", None)
        if typed is None:
            raise ValueError("Dict response missing _typed_response required for narrative build")
        response = typed
    
    # Extract components
    alert: AlertResponse = response.alert
    patterns: List[PatternResponse] = response.patterns
    advisory: AdvisoryResponse = response.advisory
    impact: Optional[ImpactResponse] = response.impact
    justification: JustificationResponse = response.justification
    policy: Optional[PolicyResponse] = response.policy
    campaign: Optional[CampaignResponse] = response.campaign
    
    # Build narratives
    threat_narratives = _build_threat_narratives(patterns, alert=alert, policy=policy, campaign=campaign,)
    primary_threat = threat_narratives[0] if threat_narratives else None
    secondary_threats = threat_narratives[1:] if len(threat_narratives) > 1 else []
    
    advisory_narrative = _build_advisory_narrative(advisory)
    impact_narrative = _build_impact_narrative(impact)
    
    # NEW: Build policy narratives
    policy_violations, policy_risk_level = _build_policy_violations(policy)
    
    # NEW: Build campaign context
    campaign_context = _build_campaign_context(campaign)
    
    # =====================================================================
    # BUILD OPERATIONAL TIER
    # =====================================================================
    
    attacker_capability = (
        campaign_context.attacker_capability
        if campaign_context
        else "UNKNOWN"
    )
    
    time_to_exploitation = (
        campaign_context.time_to_exploitation_days
        if campaign_context
        else None
    )




    actor_context_summary = _build_actor_narrative(
        response.actors,
        [p.label for p in patterns],
    )
    


    raw_level = getattr(alert, "alert_level", None)
    if raw_level is None:
        raw_level = getattr(alert, "level", None)

    if hasattr(raw_level, "name"):
        resolved_alert_level = str(raw_level.name).upper()
    else:
        resolved_alert_level = str(raw_level).strip().upper()


    
    operational = OperationalNarrative(
        alert_level=resolved_alert_level,
        confidence= float(getattr(getattr(alert, "confidence", None), "observed", getattr(alert, "confidence", 0.0))
                           or 0.0),
        entity_id=alert.entity_id,
        primary_threat=primary_threat,
        secondary_threats=secondary_threats,
        advisory=advisory_narrative,
        impact=impact_narrative,
        policy_violations=policy_violations,
        policy_risk_level=policy_risk_level,
        campaign_context=campaign_context,
        attacker_capability=attacker_capability,
        time_to_exploitation_days=time_to_exploitation,
        investigation_focus=advisory.dominant_patterns or[],
        evidence_ids=alert.evidence_ids,
        justification=justification.summary,
        contributing_predictors=justification.contributing_predictors,
        actor_context_summary=actor_context_summary,
        observable_actors=response.actors or [],
    )
    
    # =====================================================================
    # BUILD EXECUTIVE TIER
    # =====================================================================
    
    all_severities = [t.severity for t in threat_narratives]
    severity_order = {
        ThreatSeverity.CRITICAL: 0,
        ThreatSeverity.HIGH: 1,
        ThreatSeverity.MEDIUM: 2,
        ThreatSeverity.LOW: 3,
    }
    highest_severity = (
        min(all_severities, key=lambda s: severity_order[s])
        if all_severities
        else ThreatSeverity.LOW
    )
    


    _raw_level = getattr(alert, "alert_level", None)
    if _raw_level is None:
        _raw_level = getattr(alert, "level", None)

    if hasattr(_raw_level, "name"):
        _level_key = str(_raw_level.name).upper()
    else:
        _level_key = str(_raw_level).strip().upper()

    alert_category = _alert_level_to_category(_level_key)
    primary_threat_name = primary_threat.pattern_name if primary_threat else "Security"
    scope_phrase = f"; {impact.estimated_scope} systems at risk" if impact and impact.estimated_scope else ""
    
    headline = f"{alert_category.value} alert: {primary_threat_name} detected{scope_phrase}"
    
    threat_count = len(threat_narratives)
    threat_phrase = f"{threat_count} threat pattern(s)" if threat_count > 0 else "anomaly"
    primary_what = primary_threat.what_is_happening if primary_threat else "Anomaly detected."
    
    summary = (
        f"Guardian detected {threat_phrase} in {alert.entity_id}. "
        f"{primary_what} "
        f"Trend is {advisory_narrative.trend}. "
        f"{advisory_narrative.business_interpretation or 'Investigation required.'}"
    )
    
    # NEW: Regulatory risk summary
    regulatory_risk_summary = None
    regulatory_deadline = None
    regulatory_escalation = False
    
    if policy_violations:
        violated = [v for v in policy_violations if v.status == "VIOLATED"]
        if violated:
            regulatory_escalation = True
            frameworks = set(v.framework for v in violated)
            regulatory_risk_summary = (
                f"REGULATORY VIOLATION: {', '.join(frameworks)} requirements not met. "
                f"{len(violated)} policy violation(s) detected."
            )
            deadlines = [v.remediation_deadline_days for v in violated if v.remediation_deadline_days]
            if deadlines:
                regulatory_deadline = min(deadlines)
    
    # NEW: Campaign summary
    campaign_summary = None
    campaign_objective = None
    decision_window = None
    
    if campaign_context:
        campaign_summary = campaign_context.campaign_name
        campaign_objective = campaign_context.campaign_description[:200] + "..."  # Truncate
        if campaign_context.time_to_exploitation_days:
            decision_window = campaign_context.time_to_exploitation_days * 24  # Convert to hours
    
    # Recommended action
    if advisory_narrative.urgency == ExecutiveUrgency.IMMEDIATE:
        recommended = (
            f"IMMEDIATE ACTION REQUIRED. "
            f"Escalate to Security & Compliance teams. "
            f"Activate incident response. "
            f"Focus investigation on: {', '.join(advisory.dominant_patterns)}"
        )
    elif advisory_narrative.urgency == ExecutiveUrgency.URGENT:
        recommended = (
            f"URGENT ATTENTION REQUIRED. "
            f"Notify security team. "
            f"Begin investigation of: {', '.join(advisory.dominant_patterns)}"
        )
    else:
        recommended = (
            f"MONITOR CLOSELY. "
            f"Assign to security team for analysis. "
            f"Review: {', '.join(advisory.dominant_patterns)}"
        )
    
    executive = ExecutiveNarrative(
        headline=headline,
        summary=summary,
        alert_level=alert_category,
        severity=highest_severity,
        urgency=advisory_narrative.urgency,
        affected_scope=impact.estimated_scope if impact else None,
        affected_system_names=impact.impacted_assets if impact else [],
        threat_trend=advisory_narrative.trend,
        threat_trend_explanation=advisory_narrative.trend_explanation,
        business_context=advisory.business_interpretation,
        recommended_action=recommended,
        regulatory_risk_summary=regulatory_risk_summary,
        regulatory_deadline_days=regulatory_deadline,
        regulatory_escalation_required=regulatory_escalation,
        campaign_summary=campaign_summary,
        campaign_objective=campaign_objective,
        decision_window_hours=decision_window,
    )
    
    # =====================================================================
    # BUILD AUDIT TIER
    # =====================================================================
    
    all_provenances: List[Provenance] = [
        threat.provenance for threat in threat_narratives
    ] + [advisory_narrative.provenance]
    
    if impact_narrative:
        all_provenances.append(impact_narrative.provenance)
    
    # NEW: Policy trail
    policy_trail = []
    if policy and policy.findings:
        for finding in policy.findings:
            policy_trail.append({
                "policy_id": finding.policy_id,
                "framework": finding.framework,
                "status": finding.status,
                "triggers": finding.trigger_patterns,
            })
    
    # NEW: Campaign trail
    campaign_trail = None
    if campaign_context:
        campaign_trail = {
            "campaign_name": campaign_context.campaign_name,
            "severity": campaign_context.severity,
            "current_phase": campaign_context.current_phase,
            "time_to_exploitation": campaign_context.time_to_exploitation_days,
        }
    
    audit = AuditNarrative(
        alert_level=resolved_alert_level,
        confidence_observed=alert.confidence.observed,
        confidence_ceiling=alert.confidence.ceiling,
        confidence_rationale=alert.confidence.rationale,
        entity_id=alert.entity_id,
        evidence_ids=alert.evidence_ids,
        explanation=justification.summary,
        contributing_predictors=justification.contributing_predictors,
        policy_version=alert.policy_version,
        schema_version=alert.schema_version,
        generated_at_utc=alert.generated_at_utc,
        policy_trail=policy_trail,
        campaign_trail=campaign_trail,
        all_provenances=all_provenances,
    )
    
    # =====================================================================
    # ASSEMBLE COMPLETE NARRATIVE
    # =====================================================================
    
    return GuardianNarrative(
        alert_id=alert.entity_id,
        generated_at_utc=datetime.utcnow(),
        source_guardian_version=alert.policy_version,
        executive=executive,
        operational=operational,
        audit=audit,
    )


# ======================================================================
# VALIDATION
# ======================================================================

def validate_narrative(narrative: GuardianNarrative) -> tuple[bool, str]:
    """Validate complete narrative"""
    
    if not narrative.executive.headline:
        return False, "Executive headline is empty"
    
    if not narrative.operational.alert_level:
        return False, "Operational alert_level is empty"
    
    if not narrative.audit.alert_level:
        return False, "Audit alert_level is empty"
    
    if narrative.audit.confidence_observed < 0 or narrative.audit.confidence_observed > 1.0:
        return False, "Confidence out of range"
    
    if narrative.executive.alert_level.value != narrative.audit.alert_level:
        return False, "Alert level mismatch"
    
    return True, "Valid"
