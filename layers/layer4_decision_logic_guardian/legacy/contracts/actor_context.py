"""
Layer 4 – Actor Context Contract

ActorContext.py

PURPOSE
-------
This module defines the contract for observable actor context.

It answers: "Which observable actor surfaces can Guardian detect from its external vantage point?"

CRITICAL PRINCIPLE
------------------
Guardian NEVER claims identity.
Guardian SURFACES OBSERVABLE ACTORS for intervention.

VANTAGE POINT HONESTY
---------------------
Your current Guardian is EXTERNAL-ONLY:
- Observes: IP, ASN, Domain, TLS fingerprint, HTTP patterns, Session tokens
- Cannot observe: User accounts, service names, internal processes (need internal logs/agents)

This contract reflects what you CAN actually see.
"""

from dataclasses import dataclass, field
from typing import Literal, Optional, Dict, List
from datetime import datetime


# ======================================================================
# ACTOR TYPE ENUMERATION
# ======================================================================

ActorType = Literal[
    "IP_ADDRESS", "IP_RANGE", "ASN", "DOMAIN", "ENDPOINT", "SESSION",
    "DEVICE_FINGERPRINT", "PROTOCOL_SIGNATURE", "USER_ACCOUNT", "SERVICE_ACCOUNT",
    "PROCESS", "NETWORK_SEGMENT", "CONTAINER", "UNKNOWN",
]


# ======================================================================
# VANTAGE POINT CLASSIFICATION
# ======================================================================

VantagePoint = Literal[
    "EXTERNAL", "INTERNAL_LOGS", "INTERNAL_AGENT", "CORRELATION", "UNKNOWN",
]


# ======================================================================
# ACTOR CONTEXT – OBSERVABLE ACTOR SURFACE (FIXED FIELD ORDER)
# ======================================================================

@dataclass(frozen=True)
class ActorContext:
    """
    One observable actor surface associated with a threat pattern.
    
    CRITICAL: All fields without defaults MUST come before any field with defaults.
    """
    
    # ====================================================================
    # REQUIRED FIELDS (NO DEFAULTS) — MUST COME FIRST
    # ====================================================================
    
    actor_type: ActorType
    """What type of observable actor is this? (IP_ADDRESS, SESSION, ENDPOINT, etc.)"""
    
    identifier: str
    """The actual value observed (e.g., '185.199.108.42', 'sess_a91f7d2e')"""
    
    confidence: float
    """How confident is Guardian in this observation? (0.0–1.0)"""
    
    vantage_point: VantagePoint
    """From where is this actor observed? (EXTERNAL, INTERNAL_LOGS, etc.)"""
    
    first_observed_utc: int
    """When was this actor first observed? (epoch seconds)"""
    
    # ====================================================================
    # OPTIONAL FIELDS (WITH DEFAULTS) — COME AFTER ALL REQUIRED FIELDS
    # ====================================================================
    
    last_observed_utc: Optional[int] = None
    """When was this actor last observed? (epoch seconds)"""
    
    observation_count: int = 0
    """How many times has this actor been observed?"""
    
    confidence_factors: Dict[str, float] = field(default_factory=dict)
    """Breakdown of how confidence was computed"""
    
    source_evidence: List[str] = field(default_factory=list)
    """What specific evidence supports this actor observation?"""
    
    source_pattern_labels: List[str] = field(default_factory=list)
    """Which Guardian patterns detected this actor?"""
    
    is_internal: bool = False
    """Is this actor originating from inside your network?"""
    
    limitations: str = ""
    """What CANNOT Guardian determine from here? (HONESTY FIELD)"""
    
    requires_internal_data: bool = False
    """Does full context require internal instrumentation?"""
    
    recommended_correlation: Optional[str] = None
    """What internal data would complete this picture?"""
    
    generated_at_utc: datetime = field(default_factory=datetime.utcnow)
    """When was this ActorContext generated?"""
    
    priority: int = 0
    """Priority rank (0-10) for UI rendering"""


# ======================================================================
# HELPER: ACTOR CONTEXT COLLECTION
# ======================================================================

@dataclass(frozen=True)
class ActorContextCollection:
    """Collection of all observed actors for a single pattern or alert."""
    
    contexts: List[ActorContext]
    """All observed actor contexts"""
    
    primary_threat_actor: Optional[ActorContext] = None
    """The most significant actor"""
    
    requires_escalation: bool = False
    """True if any actor requires immediate escalation"""
    
    def external_only(self) -> List[ActorContext]:
        """Get only externally-observable actors"""
        return [c for c in self.contexts if c.vantage_point == "EXTERNAL"]
    
    def internal_only(self) -> List[ActorContext]:
        """Get only internally-observable actors"""
        return [
            c for c in self.contexts
            if c.vantage_point in ("INTERNAL_LOGS", "INTERNAL_AGENT")
        ]
    
    def actionable_immediately(self) -> List[ActorContext]:
        """Get actors that can be acted on without internal data"""
        return [c for c in self.contexts if not c.requires_internal_data]
    
    def requires_internal_correlation(self) -> List[ActorContext]:
        """Get actors that need internal data for full context"""
        return [c for c in self.contexts if c.requires_internal_data]
    
    def summary_text(self) -> str:
        """Generate human-readable summary"""
        if not self.contexts:
            return "No observable actors detected"
        
        lines = []
        external = self.external_only()
        if external:
            lines.append(f"Observable from external vantage point:")
            for ctx in external:
                lines.append(
                    f"  • {ctx.actor_type}: {ctx.identifier} "
                    f"({ctx.confidence:.0%} confidence)"
                )
        
        return "\n".join(lines)


# ======================================================================
# VALIDATOR
# ======================================================================

def validate_actor_context(context: ActorContext) -> tuple[bool, str]:
    """Validate that ActorContext is complete and honest."""
    
    if not context.identifier:
        return False, "identifier cannot be empty"
    
    if context.confidence < 0 or context.confidence > 1.0:
        return False, f"confidence out of range: {context.confidence}"
    
    return True, "Valid"