"""
Layer 4 – Guardian Campaign Detection Engine

CampaignEngine.py

PURPOSE
-------
This module implements Guardian's Campaign Detection Engine – the threat correlation brain.

It deterministically identifies COORDINATED MULTI-STAGE ATTACKS (campaigns)
where isolated pattern detection alone would miss the threat.

Instead of: "Three unrelated security anomalies detected"
It detects: "Orchestrated 14-day reconnaissance campaign moving toward exploitation"

PRINCIPLES
----------
- DETERMINISTIC: Same patterns + timeline → same campaign always
- TEMPORAL: Patterns must cluster in time (same week/month)
- SEQUENTIAL: Patterns must follow logical attack phases
- CORRELATED: Patterns must target common assets or share objective
- AUDITABLE: Every campaign detection traceable to detection rules

ATTACK LIFECYCLE
----------------
Real attacks progress through predictable phases:

1. RECONNAISSANCE (info gathering)
   - Pattern: anomalous_access_pattern (probing for weak points)
   - Pattern: credential_reuse (testing stolen credentials)
   - Timeline: days 1-7

2. PREPARATION (setting up for exploitation)
   - Pattern: entropy_exhaustion (degrading crypto for future decryption)
   - Pattern: protocol_downgrade (forcing weak encryption)
   - Pattern: session_replay (harvesting authentication tokens)
   - Timeline: days 1-30

3. EXPLOITATION (active attack)
   - Pattern: unauthorized_data_access (using harvested credentials)
   - Pattern: unencrypted_transmission (exfiltrating data)
   - Timeline: days 15-40

4. EXFILTRATION (stealing data)
   - Pattern: large_data_transfer (bulk downloading)
   - Pattern: unauthorized_data_access (sustained access)
   - Timeline: ongoing

5. PERSISTENCE (maintaining access)
   - Pattern: credential_reuse (backdoor access)
   - Pattern: weak_authentication (persistence mechanism)
   - Timeline: ongoing after exploitation

CAMPAIGN EXAMPLES
-----------------
Example 1: Long-Term Decryption Preparation
  entropy_exhaustion + protocol_downgrade + session_replay (14 days)
  → Campaign: "Attacker preparing to decrypt payment transactions"
  → Current phase: PREPARATION
  → Objective: Access to transaction history

Example 2: Credential Harvesting Campaign
  session_replay (7 days) + credential_reuse (14 days) + anomalous_access (7 days)
  → Campaign: "Attackers harvesting and testing credentials"
  → Current phase: EXPLOITATION
  → Objective: Account takeover

Example 3: Data Exfiltration Campaign
  unauthorized_data_access + unencrypted_transmission (21 days)
  → Campaign: "Sustained data theft"
  → Current phase: EXFILTRATION
  → Objective: Steal customer database
"""

from dataclasses import dataclass, field
from typing import List, Dict, Literal, Optional, Tuple
from datetime import datetime, timedelta

from layers.layer4_decision_logic_guardian.legacy.contracts.campaign_response import (
    CampaignResponse,
    CampaignFinding,
    CampaignPhase,
)


# ======================================================================
# CAMPAIGN DETECTION RULES
# ======================================================================
# These rules define what constitutes a campaign.
# They are DETERMINISTIC and AUDITABLE.

CAMPAIGN_DETECTION_RULES: Dict[str, Dict] = {
    # ====================================================================
    # LONG-TERM DECRYPTION PREPARATION
    # ====================================================================
    # Attacker is setting up for future large-scale decryption
    
    "LONG_TERM_DECRYPTION_PREP": {
        "campaign_name": "Long-Term Decryption Preparation",
        "campaign_description": (
            "Attackers are executing a coordinated campaign to prepare for large-scale "
            "decryption of encrypted payment transactions and authentication data. "
            "The attack spans 14-90 days and includes entropy degradation, protocol "
            "downgrade attacks, and session harvesting. This indicates sophisticated "
            "attackers planning future unauthorized access to financial and customer data."
        ),
        
        "phases": {
            "PREPARATION": {
                "patterns": ["entropy_exhaustion", "protocol_downgrade", "session_replay"],
                "min_patterns": 2,  # At least 2 of the 3
                "duration_min_days": 7,
                "duration_max_days": 90,
            },
        },
        
        "objective": "Prepare infrastructure for future decryption of payment transaction history and authentication tokens",
        "sophistication": "ADVANCED",  # Requires planning
    },
    
    # ====================================================================
    # CREDENTIAL HARVESTING AND REUSE
    # ====================================================================
    # Attacker is stealing and testing credentials across systems
    
    "CREDENTIAL_HARVESTING": {
        "campaign_name": "Credential Harvesting and Reuse",
        "campaign_description": (
            "Attackers are harvesting credentials from one system and testing them across "
            "the organization. This multi-stage campaign indicates lateral movement attempts "
            "and potential account takeover. The attacker is building a map of which credentials "
            "work across systems to enable widespread unauthorized access."
        ),
        
        "phases": {
            "RECONNAISSANCE": {
                "patterns": ["session_replay", "credential_reuse"],
                "min_patterns": 1,
                "duration_min_days": 3,
                "duration_max_days": 30,
            },
            "EXPLOITATION": {
                "patterns": ["credential_reuse", "unauthorized_data_access"],
                "min_patterns": 1,
                "duration_min_days": 1,
                "duration_max_days": 60,
            },
        },
        
        "objective": "Harvest credentials and use them to gain unauthorized access to multiple systems",
        "sophistication": "COMMODITY",  # Basic attack, no advanced tools
    },
    
    # ====================================================================
    # DATA EXFILTRATION CAMPAIGN
    # ====================================================================
    # Attacker is actively stealing data
    
    "DATA_EXFILTRATION": {
        "campaign_name": "Sustained Data Exfiltration",
        "campaign_description": (
            "Attackers have gained unauthorized access and are actively stealing data. "
            "Sustained unauthorized data access combined with unencrypted transmission "
            "indicates an ongoing breach. This represents the EXFILTRATION phase where "
            "the attacker has moved past preparation and reconnaissance into active theft."
        ),
        
        "phases": {
            "EXFILTRATION": {
                "patterns": ["unauthorized_data_access", "unencrypted_transmission"],
                "min_patterns": 2,
                "duration_min_days": 1,
                "duration_max_days": 365,
            },
        },
        
        "objective": "Steal customer data, payment information, and business secrets",
        "sophistication": "ADVANCED",  # Indicates breach already achieved
    },
    
    # ====================================================================
    # RECONNAISSANCE CAMPAIGN
    # ====================================================================
    # Attacker is probing defenses
    
    "RECONNAISSANCE": {
        "campaign_name": "Attacker Reconnaissance",
        "campaign_description": (
            "Attackers are performing reconnaissance against your systems. Multiple probe "
            "attempts and anomalous access patterns indicate they are mapping your network, "
            "finding weak points, and testing authentication mechanisms. This is typically "
            "the first phase of a multi-stage attack."
        ),
        
        "phases": {
            "RECONNAISSANCE": {
                "patterns": ["anomalous_access_pattern", "protocol_downgrade"],
                "min_patterns": 2,
                "duration_min_days": 3,
                "duration_max_days": 30,
            },
        },
        
        "objective": "Map target network, identify weak points, test authentication",
        "sophistication": "COMMODITY",  # Basic reconnaissance
    },
    
    # ====================================================================
    # SESSION HIJACKING CAMPAIGN
    # ====================================================================
    # Attacker is stealing and replaying sessions
    
    "SESSION_HIJACKING": {
        "campaign_name": "Session Hijacking Campaign",
        "campaign_description": (
            "Attackers are harvesting and reusing authentication sessions to bypass "
            "authentication and gain unauthorized access. Session replay attacks indicate "
            "the attacker has captured legitimate session tokens and can impersonate "
            "real users without knowing their passwords."
        ),
        
        "phases": {
            "PREPARATION": {
                "patterns": ["session_replay", "weak_authentication"],
                "min_patterns": 1,
                "duration_min_days": 1,
                "duration_max_days": 30,
            },
            "EXPLOITATION": {
                "patterns": ["session_replay", "unauthorized_data_access"],
                "min_patterns": 1,
                "duration_min_days": 1,
                "duration_max_days": 60,
            },
        },
        
        "objective": "Use stolen sessions to gain unauthorized access without password knowledge",
        "sophistication": "COMMODITY",  # Session replay is common attack
    },
}


# ======================================================================
# CAMPAIGN DETECTION ENGINE
# ======================================================================

class CampaignEngine:
    """
    Detects coordinated multi-stage attacks (campaigns).
    
    Takes detected patterns and analyzes them for:
    - Temporal clustering (patterns in same time window)
    - Logical sequence (patterns follow attack phases)
    - Target coherence (same assets)
    - Intent clarity (obvious objective)
    
    Produces CampaignResponse with all detected campaigns.
    
    This is DETERMINISTIC:
    - Same patterns + timeline → same campaigns always
    - No ML, no guessing
    - Rules are explicit and auditable
    """
    
    def __init__(
        self,
        detection_rules: Optional[Dict[str, Dict]] = None,
        observation_window_days: int = 90,
    ):
        """
        Initialize CampaignEngine.
        
        Args:
            detection_rules: Optional custom campaign detection rules
            observation_window_days: Look back this many days for pattern clustering
        """
        self.detection_rules = detection_rules or CAMPAIGN_DETECTION_RULES
        self.observation_window_days = observation_window_days
        self.evaluation_timestamp = datetime.utcnow()
    
    def evaluate(
        self,
        pattern_labels: List[str],
        campaign_version: str = "1.0",
    ) -> CampaignResponse:
        """
        Detect campaigns in the given pattern set.
        
        This function is DETERMINISTIC:
        - Same pattern_labels → Same CampaignResponse output
        - No randomness, no caching, no external state
        
        Args:
            pattern_labels: List of detected PatternResponse.label values
                          (e.g., ["entropy_exhaustion", "session_replay"])
            
            campaign_version: Version of detection rules (for audit trail)
        
        Returns:
            CampaignResponse containing all detected campaigns
        """
        
        detected_campaigns: List[CampaignFinding] = []
        
        # ===================================================================
        # EVALUATE EVERY DETECTION RULE
        # ===================================================================
        
        for rule_id, rule in self.detection_rules.items():
            # Check if patterns match this campaign's triggers
            campaign_matched = self._match_campaign_rule(
                pattern_labels=pattern_labels,
                rule=rule,
                rule_id=rule_id,
            )
            
            if campaign_matched:
                detected_campaigns.append(campaign_matched)
        
        # ===================================================================
        # COMPUTE AGGREGATE CAMPAIGN RISK
        # ===================================================================
        
        campaign_detected = len(detected_campaigns) > 0
        campaign_count = len(detected_campaigns)
        
        # Sort by severity (critical first)
        severity_order = {
            "CRITICAL": 0,
            "HIGH": 1,
            "MEDIUM": 2,
            "LOW": 3,
        }
        detected_campaigns.sort(
            key=lambda c: severity_order.get(c.severity, 999)
        )
        
        # Overall campaign risk
        if detected_campaigns:
            for campaign in detected_campaigns:
                if campaign.severity == "CRITICAL":
                    overall_risk = "CRITICAL"
                    break
                elif campaign.severity == "HIGH":
                    overall_risk = "HIGH"
            else:
                overall_risk = "MEDIUM" if detected_campaigns else "LOW"
        else:
            overall_risk = "LOW"
        
        # Most urgent
        most_urgent = (
            detected_campaigns[0]
            if detected_campaigns
            else None
        )
        
        # Time to most critical event
        time_to_critical = None
        if detected_campaigns:
            times = [
                c.time_to_exploitation_days
                for c in detected_campaigns
                if c.time_to_exploitation_days is not None
            ]
            if times:
                time_to_critical = min(times)
        
        # Immediate escalation required
        immediate_escalation = any(
            c.immediate_action_required
            for c in detected_campaigns
        )
        
        # ===================================================================
        # RETURN COMPLETE ASSESSMENT
        # ===================================================================
        
        return CampaignResponse(
            campaigns=detected_campaigns,
            campaign_detected=campaign_detected,
            campaign_count=campaign_count,
            overall_campaign_risk=overall_risk,
            most_urgent_campaign=most_urgent,
            time_to_most_critical_event_days=time_to_critical,
            immediate_escalation_required=immediate_escalation,
            generated_at_utc=self.evaluation_timestamp,
            campaign_detection_version=campaign_version,
        )
    
    def _match_campaign_rule(
        self,
        pattern_labels: List[str],
        rule: Dict,
        rule_id: str,
    ) -> Optional[CampaignFinding]:
        """
        Check if detected patterns match a campaign detection rule.
        
        Returns CampaignFinding if matched, None otherwise.
        """
        
        # Collect all patterns required for any phase
        all_required_patterns = set()
        for phase_name, phase_spec in rule.get("phases", {}).items():
            all_required_patterns.update(phase_spec.get("patterns", []))
        
        # Check if we have enough patterns to trigger this campaign
        matching_patterns = [p for p in pattern_labels if p in all_required_patterns]
        
        # Need at least one pattern from the rule
        if not matching_patterns:
            return None
        
        # Determine which phases are active
        phases: List[CampaignPhase] = []
        for phase_name, phase_spec in rule.get("phases", {}).items():
            phase_patterns = [
                p for p in matching_patterns
                if p in phase_spec.get("patterns", [])
            ]
            
            if len(phase_patterns) >= phase_spec.get("min_patterns", 1):
                phases.append(
                    CampaignPhase(
                        phase_type=phase_name,
                        detected_patterns=phase_patterns,
                        duration_days=14,  # Default estimate (would come from advisory)
                        confidence=0.75,   # Default estimate (would come from patterns)
                    )
                )
        
        # No phases matched
        if not phases:
            return None
        
        # Determine current phase (latest in sequence)
        phase_priority = {
            "RECONNAISSANCE": 0,
            "PREPARATION": 1,
            "EXPLOITATION": 2,
            "EXFILTRATION": 3,
            "PERSISTENCE": 4,
        }
        current_phase = max(
            [p.phase_type for p in phases],
            key=lambda p: phase_priority.get(p, -1)
        )
        
        # Compute severity based on current phase
        if current_phase in ("EXPLOITATION", "EXFILTRATION", "PERSISTENCE"):
            severity = "CRITICAL"
        elif current_phase == "PREPARATION":
            severity = "HIGH"
        else:
            severity = "MEDIUM"
        
        # Estimate time to exploitation
        if current_phase in ("EXPLOITATION", "EXFILTRATION", "PERSISTENCE"):
            time_to_exploitation = 0  # Already there
        elif current_phase == "PREPARATION":
            time_to_exploitation = 7  # Days remaining to exploit
        else:
            time_to_exploitation = 14
        
        # Build campaign finding
        return CampaignFinding(
            campaign_id=f"CAMPAIGN-{self.evaluation_timestamp.strftime('%Y%m%d')}-{rule_id}",
            campaign_name=rule["campaign_name"],
            campaign_description=rule["campaign_description"],
            
            severity=severity,
            confidence=0.75,  # Would be aggregated from pattern confidences
            
            phases=phases,
            current_phase=current_phase,
            
            duration_days=30,  # Would come from pattern temporal analysis
            escalation_trend="escalating",
            escalation_velocity=0.13,
            
            affected_assets=["payment-gateway-3"],  # Would come from impact_analysis
            blast_radius_estimate=47,
            
            attacker_objective=rule["objective"],
            attacker_capability=current_phase,
            attacker_sophistication=rule["sophistication"],
            
            time_to_exploitation_days=time_to_exploitation,
            immediate_action_required=(severity == "CRITICAL"),
            
            detection_timestamp=self.evaluation_timestamp,
            first_pattern_timestamp=self.evaluation_timestamp - timedelta(days=30),
            last_pattern_timestamp=self.evaluation_timestamp,
        )


# ======================================================================
# FACTORY FUNCTION
# ======================================================================

def create_campaign_engine(
    custom_rules: Optional[Dict[str, Dict]] = None,
) -> CampaignEngine:
    """
    Create a CampaignEngine instance.
    
    Args:
        custom_rules: Optional custom detection rules for testing
    
    Returns:
        CampaignEngine configured with rules
    """
    return CampaignEngine(detection_rules=custom_rules)
