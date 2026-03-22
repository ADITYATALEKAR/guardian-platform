"""
Layer 5 – Campaign Detection Response Contract

CampaignResponse.py

PURPOSE
-------
This module defines the canonical response model for Guardian's Campaign Detection Engine (Layer 4).

It is the CONTRACT between:
- Guardian's Campaign Detection Engine (Layer 4) — detects coordinated attacks
- Layer 4.5 NLP — translates campaigns into threat narratives
- UI/API (Layer 5-6) — renders campaigns to security teams and executives

WHAT IS A CAMPAIGN?
-------------------
A campaign is a coordinated, multi-stage attack where:

1. MULTIPLE PATTERNS co-occur (not isolated incidents)
2. TEMPORAL PROXIMITY: patterns cluster in time (same day/week)
3. LOGICAL SEQUENCE: patterns follow attack phases
   - Reconnaissance (information gathering)
   - Preparation (setting up for exploitation)
   - Exploitation (active attack)
   - Exfiltration (stealing data)
   - Persistence (maintaining access)
4. TARGET COHERENCE: same assets or asset class
5. INTENT CLARITY: obvious attacker objective

Example Campaign:
-----------------
Days 1-7:   Entropy exhaustion (PREPARATION: setting up for decryption)
Days 1-14:  Protocol downgrade probes (PREPARATION: testing weaker protocols)
Days 7-14:  Session harvesting (PREPARATION: collecting authentication tokens)
Day 15:     Unauthorized access attempt (EXPLOITATION: trying to use harvested sessions)

This is a "Long-Term Decryption Preparation" campaign.
Not three separate incidents — one coordinated attack in phases.

DETERMINISM
-----------
Campaign detection is DETERMINISTIC:
- Same patterns + same timeline → same campaign always
- No ML, no guessing, no probabilistic reasoning
- Rules are explicit and auditable
- Detection is repeatable and testable
"""

from dataclasses import dataclass
from typing import List, Literal, Optional
from datetime import datetime


# ======================================================================
# CAMPAIGN PHASE
# ======================================================================

@dataclass(frozen=True)
class CampaignPhase:
    """
    One phase of a campaign (reconnaissance, preparation, exploitation, etc.)
    """
    
    phase_type: Literal[
        "RECONNAISSANCE",
        "PREPARATION",
        "EXPLOITATION",
        "EXFILTRATION",
        "PERSISTENCE",
    ]
    """
    Attack phase based on attack lifecycle.
    
    RECONNAISSANCE: Information gathering about target
                    (port scanning, service enumeration, credential testing)
    
    PREPARATION:   Setting up for attack without being detected
                    (entropy degradation, protocol downgrade, key harvesting)
    
    EXPLOITATION:  Active attack execution
                    (authentication bypass, privilege escalation, injection attacks)
    
    EXFILTRATION:  Stealing data
                    (unauthorized queries, data copying, credential harvesting)
    
    PERSISTENCE:   Maintaining access for future use
                    (backdoor installation, persistence mechanism setup)
    """
    
    detected_patterns: List[str]
    """Which patterns indicate this phase?"""
    
    duration_days: int
    """How long has this phase been active?"""
    
    confidence: float
    """Confidence in this phase detection (0.0-1.0)"""


# ======================================================================
# CAMPAIGN FINDING – SINGLE COORDINATED ATTACK
# ======================================================================

@dataclass(frozen=True)
class CampaignFinding:
    """
    One detected coordinated attack campaign.
    
    This represents multiple security patterns that:
    - Occur together in time
    - Follow a logical attack sequence
    - Target common assets
    - Indicate clear attacker intent
    
    Example:
    --------
    CampaignFinding(
        campaign_id="CAMPAIGN-2026-01-10-ENTROPY-DOWNGRADE-PREP",
        campaign_name="Long-Term Decryption Preparation",
        campaign_description="Attackers are executing a 14-90 day reconnaissance campaign...",
        
        severity="CRITICAL",
        confidence=0.76,
        
        phases=[
            CampaignPhase(
                phase_type="PREPARATION",
                detected_patterns=["entropy_exhaustion", "protocol_downgrade", "session_replay"],
                duration_days=14,
                confidence=0.82
            ),
        ],
        
        duration_days=14,
        escalation_trend="escalating",
        escalation_velocity=0.13,  # +13% per week
        
        affected_assets=["payment-gateway-3", "auth-service-prod", "vault-secrets-01"],
        blast_radius_estimate=47,
        
        attacker_objective="Prepare for large-scale decryption of payment transaction data",
        attacker_capability="PREPARATION",
        
        immediate_action_required=True,
    )
    """
    
    # ====================================================================
    # IDENTIFICATION
    # ====================================================================
    
    campaign_id: str
    """
    Unique identifier for this campaign.
    
    Format: CAMPAIGN-{DATE}-{ATTACK_TYPE}-{PHASE}
    Example: CAMPAIGN-2026-01-10-ENTROPY-DOWNGRADE-PREP
    """
    
    campaign_name: str
    """
    Human-readable name for the campaign.
    
    Examples:
    - "Long-Term Decryption Preparation"
    - "Session Hijacking Campaign"
    - "Credential Harvesting and Reuse"
    - "Payment System Reconnaissance"
    """
    
    campaign_description: str
    """
    Narrative description of the campaign.
    
    Should answer:
    - What is the attacker doing?
    - Why is it coordinated (not isolated)?
    - What is the sequence of phases?
    - What is the probable objective?
    
    Example:
    "Attackers are executing a 14-90 day reconnaissance campaign targeting your
    payment infrastructure. They are using entropy degradation and protocol
    downgrade attacks to prepare for large-scale decryption of transaction data
    and authentication tokens. This indicates sophisticated long-term planning."
    """
    
    # ====================================================================
    # SEVERITY & CONFIDENCE
    # ====================================================================
    
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    """
    Campaign severity (not just pattern severity).
    
    CRITICAL: Active exploitation or immediate threat to critical systems
    HIGH:     Multi-stage attack with clear intent and significant impact
    MEDIUM:   Coordinated attack but defensive measures available
    LOW:      Campaign detected but low impact or containable
    """
    
    confidence: float
    """
    Confidence that this is a real campaign (not coincidence).
    
    0.0-1.0 scale.
    High confidence means: patterns co-occur, sequence is logical, timing is tight.
    Low confidence means: patterns scattered, timing unclear, alternative explanations.
    """
    
    # ====================================================================
    # ATTACK PHASES
    # ====================================================================
    
    phases: List[CampaignPhase]
    """
    Detected phases of the campaign.
    
    Each phase represents one stage of the attack lifecycle.
    Should be in order: reconnaissance → preparation → exploitation → exfiltration.
    """
    
    current_phase: Literal[
        "RECONNAISSANCE",
        "PREPARATION",
        "EXPLOITATION",
        "EXFILTRATION",
        "PERSISTENCE",
        "UNKNOWN",
    ]
    """Which phase is the attacker in RIGHT NOW?"""
    
    # ====================================================================
    # TEMPORAL ANALYSIS
    # ====================================================================
    
    duration_days: int
    """
    How long has this campaign been active?
    
    Calculated as: (latest_pattern_timestamp - earliest_pattern_timestamp).days
    """
    
    escalation_trend: Literal["escalating", "stable", "decelerating"]
    """
    Is the campaign speeding up, staying same pace, or slowing?
    
    escalating:     Patterns increasing in frequency/confidence (URGENT)
    stable:         Patterns sustained at consistent level (ELEVATED)
    decelerating:   Patterns decreasing (MONITOR)
    """
    
    escalation_velocity: float
    """
    Rate of change per week (0.0-1.0 scale).
    
    +0.13 = confidence increasing 13% per week
    -0.05 = confidence decreasing 5% per week
    
    Used to estimate time to exploitation.
    """
    
    # ====================================================================
    # SCOPE & IMPACT
    # ====================================================================
    
    affected_assets: List[str]
    """
    Systems targeted or affected by this campaign.
    
    Examples: ["payment-gateway-3", "auth-service-prod", "vault-secrets-01"]
    """
    
    blast_radius_estimate: Optional[int]
    """
    Estimated number of systems that would be at risk if campaign succeeds.
    
    From impact_analysis.py if available.
    """
    
    # ====================================================================
    # ATTACKER ANALYSIS
    # ====================================================================
    
    attacker_objective: str
    """
    What is the attacker trying to achieve?
    
    Examples:
    - "Prepare for large-scale decryption of payment transaction data"
    - "Establish persistent backdoor access to customer database"
    - "Harvest authentication credentials for account takeover"
    - "Exfiltrate personal financial records"
    """
    
    attacker_capability: Literal[
        "RECONNAISSANCE",
        "PREPARATION",
        "EXPLOITATION",
        "EXFILTRATION",
        "PERSISTENCE",
    ]
    """
    What can the attacker currently do?
    
    Based on current phase and detected capabilities.
    If in PREPARATION, attacker can gather info and set up.
    If in EXPLOITATION, attacker can execute attacks.
    """
    
    attacker_sophistication: Literal["COMMODITY", "ADVANCED", "NATION_STATE"]
    """
    Estimated skill level of attacker.
    
    COMMODITY:    Basic tools, common attack patterns
    ADVANCED:     Custom tools, multi-stage coordination
    NATION_STATE: Highly coordinated, long-term planning, sophisticated techniques
    """
    
    # ====================================================================
    # URGENCY
    # ====================================================================
    
    time_to_exploitation_days: Optional[int]
    """
    Estimated days until attacker moves to exploitation phase.
    
    Calculated from: escalation_velocity + current_phase + historical_patterns
    
    If in EXPLOITATION phase, this is 0.
    If in PREPARATION and escalating fast, this might be 3-7 days.
    """
    
    immediate_action_required: bool
    """
    True if campaign is in EXPLOITATION or seconds away from it.
    
    Triggers C-level escalation and incident response.
    """
    
    # ====================================================================
    # PROVENANCE
    # ====================================================================
    
    detection_timestamp: datetime
    """When was this campaign detected?"""
    
    first_pattern_timestamp: datetime
    """When did earliest pattern first appear?"""
    
    last_pattern_timestamp: datetime
    """When did latest pattern last appear?"""


# ======================================================================
# CAMPAIGN RESPONSE – COMPLETE CAMPAIGN ASSESSMENT
# ======================================================================

@dataclass(frozen=True)
class CampaignResponse:
    """
    Complete campaign detection assessment from Guardian.
    
    This is what GuardianQueryResponse.campaign contains.
    
    It answers:
    1. Are multiple patterns coordinated (a campaign)?
    2. What is the attack sequence?
    3. What is the attacker's objective?
    4. What is the current phase?
    5. How much time before exploitation?
    
    Example:
    --------
    CampaignResponse(
        campaigns=[
            CampaignFinding(
                campaign_name="Long-Term Decryption Preparation",
                severity="CRITICAL",
                confidence=0.76,
                current_phase="PREPARATION",
                escalation_trend="escalating",
                time_to_exploitation_days=9,
                immediate_action_required=True,
                ...
            ),
        ],
        campaign_detected=True,
        campaign_count=1,
        overall_risk_level="CRITICAL",
    )
    """
    
    # ====================================================================
    # FINDINGS
    # ====================================================================
    
    campaigns: List[CampaignFinding]
    """
    All detected campaigns.
    
    Sorted by severity and urgency (most threatening first).
    """
    
    # ====================================================================
    # SUMMARY
    # ====================================================================
    
    campaign_detected: bool
    """True if any campaign found (patterns are coordinated)"""
    
    campaign_count: int
    """Number of detected campaigns"""
    
    overall_campaign_risk: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    """
    Highest risk level across all campaigns.
    
    CRITICAL: Any campaign is in EXPLOITATION or immediate exploitation imminent
    HIGH:     Campaign is in PREPARATION with escalating trend
    MEDIUM:   Campaign is in PREPARATION with stable trend
    LOW:      No campaigns or only RECONNAISSANCE phase
    """
    
    # ====================================================================
    # URGENCY
    # ====================================================================
    
    most_urgent_campaign: Optional[CampaignFinding]
    """The campaign requiring most immediate attention"""
    
    time_to_most_critical_event_days: Optional[int]
    """
    Shortest time until any campaign reaches exploitation.
    
    This is the true deadline for defenders.
    """
    
    immediate_escalation_required: bool
    """
    True if any campaign requires immediate C-level escalation.
    
    Triggers incident response, law enforcement notification, regulator contact.
    """
    
    # ====================================================================
    # METADATA
    # ====================================================================
    
    generated_at_utc: datetime
    """When was this assessment computed?"""
    
    campaign_detection_version: str
    """
    Which version of campaign detection rules was used?
    
    Allows audit trail: "This campaign was detected using detection_v1.2"
    """


# ======================================================================
# HELPER FUNCTIONS
# ======================================================================

def critical_campaigns(response: CampaignResponse) -> List[CampaignFinding]:
    """Get only CRITICAL severity campaigns."""
    return [c for c in response.campaigns if c.severity == "CRITICAL"]


def campaigns_in_exploitation(response: CampaignResponse) -> List[CampaignFinding]:
    """Get campaigns currently in exploitation phase."""
    return [c for c in response.campaigns if c.current_phase == "EXPLOITATION"]


def campaigns_by_urgency(response: CampaignResponse) -> List[CampaignFinding]:
    """Get campaigns sorted by time_to_exploitation_days (ascending)."""
    return sorted(
        response.campaigns,
        key=lambda c: c.time_to_exploitation_days or 999
    )


def requires_incident_response(response: CampaignResponse) -> bool:
    """
    True if any campaign requires immediate incident response activation.
    
    Usually: campaign in EXPLOITATION or EXPLOITATION within 24 hours.
    """
    if not response.campaign_detected:
        return False
    
    for campaign in response.campaigns:
        if campaign.immediate_action_required:
            return True
        if campaign.time_to_exploitation_days and campaign.time_to_exploitation_days <= 1:
            return True
    
    return False


def requires_law_enforcement(response: CampaignResponse) -> bool:
    """
    True if campaign indicates criminal activity.
    
    Heuristic: ADVANCED or NATION_STATE sophistication + EXFILTRATION phase.
    """
    for campaign in response.campaigns:
        if campaign.attacker_sophistication in ("ADVANCED", "NATION_STATE"):
            if campaign.current_phase in ("EXFILTRATION", "PERSISTENCE"):
                return True
    
    return False