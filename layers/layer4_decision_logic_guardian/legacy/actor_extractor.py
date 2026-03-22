"""
Layer 4 – Actor Context Extraction Engine v1

actor_extractor_v1.py

PURPOSE
-------
Deterministically extract observable actor contexts from detected security patterns.

Transforms:
  GuardianPattern + Evidence → ActorContext[]

SCOPE (v1 - Intentionally Limited)
-----------------------------------
This version does ONE thing:
  Map pattern_label + evidence → observable actors

What v1 does NOT do:
  ✗ Aggregate actors across patterns
  ✗ Score coherence or attribution
  ✗ Build timelines
  ✗ Infer campaign theory
  ✗ Generate narrative

Those are Layer 4.5 (NLP) or Layer 5+ (UI) responsibilities.

PRINCIPLES (Non-Negotiable)
----------------------------
1. DETERMINISTIC: Same evidence → Same actors always
2. EVIDENCE-BACKED: Only extract actors from observed evidence
3. HONEST: Include limitations for every actor type
4. EXTERNAL-ONLY: Never claim internal-observable actors without instrumentation
5. IMMUTABLE: ActorContext is frozen; no modification after creation

PATTERN MAPPINGS (v1 Complete)
------------------------------
All 8 patterns mapped to external-observable actor types:

1. entropy_exhaustion
   Evidence keys: endpoint, source_ip, service_name
   Actors: ENDPOINT (0.85), IP_ADDRESS (0.95)
   Intervention: ISOLATE_ENDPOINT
   Threat: HIGH

2. protocol_downgrade
   Evidence keys: source_ip, tls_ja3, endpoint, destination_host
   Actors: IP_ADDRESS (0.95), DEVICE_FINGERPRINT (0.75), ENDPOINT (0.85)
   Intervention: BLOCK_IP
   Threat: HIGH

3. session_replay
   Evidence keys: session_id, session_token, bearer_token, source_ip, tls_ja3
   Actors: SESSION (0.92), IP_ADDRESS (0.95), DEVICE_FINGERPRINT (0.75)
   Intervention: KILL_SESSION
   Threat: CRITICAL

4. credential_reuse
   Evidence keys: source_ip, targeted_endpoint, target_systems, domain
   Actors: IP_ADDRESS (0.95), ENDPOINT (0.85), DOMAIN (0.80)
   Intervention: BLOCK_IP
   Threat: HIGH

5. anomalous_access_pattern
   Evidence keys: anomalous_source_ip, unusual_target, device_fingerprint
   Actors: IP_ADDRESS (0.90), ENDPOINT (0.85), DEVICE_FINGERPRINT (0.75)
   Intervention: INVESTIGATE
   Threat: MEDIUM

6. unencrypted_transmission
   Evidence keys: source_endpoint, destination_ip, dest_domain
   Actors: ENDPOINT (0.90), IP_ADDRESS (0.95), DOMAIN (0.80)
   Intervention: ISOLATE_ENDPOINT
   Threat: CRITICAL

7. weak_authentication
   Evidence keys: vulnerable_endpoint, source_ip, auth_pattern
   Actors: ENDPOINT (0.85), IP_ADDRESS (0.90), PROTOCOL_SIGNATURE (0.70)
   Intervention: ISOLATE_ENDPOINT
   Threat: HIGH

8. unauthorized_data_access
   Evidence keys: source_ip, data_endpoint, accessing_session
   Actors: IP_ADDRESS (0.95), ENDPOINT (0.85), SESSION (0.88)
   Intervention: KILL_SESSION
   Threat: CRITICAL

CONFIDENCE SCORING (Fixed, No Adjustment)
------------------------------------------
Confidence values are FIXED per actor type.
No dynamic adjustment, no ML, no heuristics.

Reasons:
  • Simplicity: Easy to audit and understand
  • Stability: No hidden inference in scoring
  • Repeatability: Same evidence = same confidence
  • Transparency: Can explain to auditors and regulators

Fixed confidence by actor type (external-observable):
  IP_ADDRESS:         0.95 (observed in packets)
  SESSION:            0.92 (observed in HTTP)
  ENDPOINT:           0.85 (TLS cert CN/SAN or Host header)
  DEVICE_FINGERPRINT: 0.75 (TLS JA3, User-Agent)
  DOMAIN:             0.80 (reverse DNS, TLS SNI)
  PROTOCOL_SIGNATURE: 0.70 (HTTP behavior, heuristic)

EVIDENCE HANDLING
-----------------
Evidence is a dict passed from pattern detection.

For each actor type extraction, check evidence_keys in order:
  for key in evidence_keys:
    if key in evidence:
      identifier = evidence[key]
      break

If no evidence_key found → actor not extracted (empty list for that type).

No fabrication. No defaults. No assumptions.

LIMITATIONS (Honesty Field)
---------------------------
Every actor type has a fixed limitations string.

These are shown in UI and audit logs.
They explain what this actor type CANNOT reveal.

Example limitations:
  IP_ADDRESS:
    "Cannot determine attacker identity from IP alone.
     IP may be proxy, VPN, cloud provider, or spoofed.
     Recommend: Correlate with threat intelligence and firewall logs."

  SESSION:
    "Cannot determine user account without authentication logs.
     Session token alone does not identify the user.
     Recommend: Correlate with authentication system to find compromised user."

  ENDPOINT:
    "Cannot determine service name or business purpose without internal logs.
     Endpoint name may be visible but service details are hidden.
     Recommend: Correlate with asset inventory and service registry."

INTERVENTION TYPES (Deterministic by Pattern + Actor Type)
-----------------------------------------------------------
Fixed mapping: Pattern + Actor Type → Intervention

Examples:
  session_replay + SESSION    → KILL_SESSION
  protocol_downgrade + IP     → BLOCK_IP
  unauthorized_access + IP    → KILL_SESSION (or BLOCK_IP if external)
  unencrypted_transmission + ENDPOINT → ISOLATE_ENDPOINT

These are the immediate actions banks can take.

THREAT LEVELS (Fixed by Pattern)
--------------------------------
CRITICAL: unauthorized_data_access, session_replay, unencrypted_transmission
HIGH:     entropy_exhaustion, protocol_downgrade, credential_reuse, weak_authentication
MEDIUM:   anomalous_access_pattern

These are the threat levels used in UI/alerts.

EXAMPLE EXTRACTION
------------------
Input:
  pattern_label = "session_replay"
  evidence = {
    "session_id": "sess_a91f7d2e",
    "source_ip": "185.199.108.42",
    "tls_ja3": "TLS_v1.3_AEAD_AES256_SHA384",
    "first_seen": 1705221600,
    "last_seen": 1705228800,
  }
  evidence_ids = ["ev_001", "ev_002", "ev_003"]
  alert_timestamp = 1705228800

Processing:
  1. Get pattern mapping: session_replay → [SESSION, IP_ADDRESS, DEVICE_FINGERPRINT]
  2. For SESSION:
     - Check evidence keys: session_id ✓ found
     - identifier = "sess_a91f7d2e"
     - confidence = 0.92 (fixed)
     - intervention = "KILL_SESSION"
     - threat = "CRITICAL"
  3. For IP_ADDRESS:
     - Check evidence keys: source_ip ✓ found
     - identifier = "185.199.108.42"
     - confidence = 0.95 (fixed)
     - intervention = "BLOCK_IP"
     - threat = "CRITICAL"
  4. For DEVICE_FINGERPRINT:
     - Check evidence keys: tls_ja3 ✓ found
     - identifier = "TLS_v1.3_AEAD_AES256_SHA384"
     - confidence = 0.75 (fixed)
     - intervention = "INVESTIGATE"
     - threat = "CRITICAL"

Output: List[ActorContext] with 3 actors

TESTING IMPLICATIONS
--------------------
All extractions are deterministic → easy to test.

For each pattern, create test cases:
  1. Evidence with all keys → all actors extracted
  2. Evidence with partial keys → only available actors extracted
  3. Evidence with no keys → empty actor list
  4. Confidence values fixed → always the same
  5. Limitations always present → never empty

Example test:
  ```python
  extractor = ActorExtractorV1()
  actors = extractor.extract(
      pattern_label="session_replay",
      evidence={"session_id": "sess_abc", "source_ip": "1.2.3.4"},
      evidence_ids=["ev_001"],
      alert_timestamp_utc=1705228800,
  )
  assert len(actors) == 2
  assert actors[0].actor_type == "SESSION"
  assert actors[0].confidence == 0.92
  assert "Cannot determine user account" in actors[0].limitations
  ```

VERSIONING STRATEGY
-------------------
This is v1 (November 2025).

Future versions will:
  v2: Add evidence confidence factors (boost/reduce based on evidence quality)
  v3: Add evidence schema validation
  v4: Add evidence normalization
  v5: Add actor aggregation (Phase 2)

Each version is backwards-compatible.
New fields are optional and default to sensible values.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional
from datetime import datetime
import time



from layers.layer4_decision_logic_guardian.legacy.contracts.actor_context import (
    ActorContext,
    ActorType,
    VantagePoint,
)


# ======================================================================
# PATTERN MAPPING RULES (THE TRUTH TABLE)
# ======================================================================

PATTERN_MAPPINGS = {
    # ====================================================================
    # Pattern 1: ENTROPY_EXHAUSTION
    # ====================================================================
    "entropy_exhaustion": {
        "description": "Cryptographic entropy degradation",
        "actors": [
            {
                "type": "ENDPOINT",
                "confidence": 0.85,
                "evidence_keys": ["endpoint", "service_name", "destination_host"],
                "evidence_description": "System experiencing entropy exhaustion",
                "intervention": "ISOLATE_ENDPOINT",
                "threat_level": "HIGH",
            },
            {
                "type": "IP_ADDRESS",
                "confidence": 0.90,
                "evidence_keys": ["source_ip", "requesting_ip"],
                "evidence_description": "Source of entropy requests",
                "intervention": "INVESTIGATE",
                "threat_level": "HIGH",
            },
        ],
    },
    
    # ====================================================================
    # Pattern 2: PROTOCOL_DOWNGRADE
    # ====================================================================
    "protocol_downgrade": {
        "description": "Cryptographic protocol downgrade",
        "actors": [
            {
                "type": "IP_ADDRESS",
                "confidence": 0.95,
                "evidence_keys": ["source_ip", "initiator_ip"],
                "evidence_description": "Client attempting protocol downgrade",
                "intervention": "BLOCK_IP",
                "threat_level": "HIGH",
            },
            {
                "type": "DEVICE_FINGERPRINT",
                "confidence": 0.75,
                "evidence_keys": ["tls_ja3", "tls_fingerprint", "client_fingerprint"],
                "evidence_description": "TLS fingerprint of downgrading client",
                "intervention": "INVESTIGATE",
                "threat_level": "HIGH",
            },
            {
                "type": "ENDPOINT",
                "confidence": 0.85,
                "evidence_keys": ["endpoint", "destination_host", "target_service"],
                "evidence_description": "Endpoint accepting downgrade negotiation",
                "intervention": "ISOLATE_ENDPOINT",
                "threat_level": "HIGH",
            },
        ],
    },
    
    # ====================================================================
    # Pattern 3: SESSION_REPLAY
    # ====================================================================
    "session_replay": {
        "description": "Session token replay attack",
        "actors": [
            {
                "type": "SESSION",
                "confidence": 0.92,
                "evidence_keys": ["session_id", "session_token", "cookie_value", "bearer_token"],
                "evidence_description": "Session token being replayed",
                "intervention": "KILL_SESSION",
                "threat_level": "CRITICAL",
            },
            {
                "type": "IP_ADDRESS",
                "confidence": 0.95,
                "evidence_keys": ["replay_source_ip", "source_ip"],
                "evidence_description": "IP replaying the session",
                "intervention": "BLOCK_IP",
                "threat_level": "CRITICAL",
            },
            {
                "type": "DEVICE_FINGERPRINT",
                "confidence": 0.75,
                "evidence_keys": ["tls_ja3", "device_fingerprint"],
                "evidence_description": "Device fingerprint of session replayer",
                "intervention": "INVESTIGATE",
                "threat_level": "CRITICAL",
            },
        ],
    },
    
    # ====================================================================
    # Pattern 4: CREDENTIAL_REUSE
    # ====================================================================
    "credential_reuse": {
        "description": "Credentials tested across systems",
        "actors": [
            {
                "type": "IP_ADDRESS",
                "confidence": 0.95,
                "evidence_keys": ["source_ip", "attacking_ip", "origin_ip"],
                "evidence_description": "IP testing credentials across systems",
                "intervention": "BLOCK_IP",
                "threat_level": "HIGH",
            },
            {
                "type": "ENDPOINT",
                "confidence": 0.85,
                "evidence_keys": ["targeted_endpoint", "target_systems"],
                "evidence_description": "Endpoints targeted by credential reuse attack",
                "intervention": "ISOLATE_ENDPOINT",
                "threat_level": "HIGH",
            },
            {
                "type": "DOMAIN",
                "confidence": 0.80,
                "evidence_keys": ["domain", "hostname"],
                "evidence_description": "Domains being targeted",
                "intervention": "BLOCK_DOMAIN",
                "threat_level": "HIGH",
            },
        ],
    },
    
    # ====================================================================
    # Pattern 5: ANOMALOUS_ACCESS_PATTERN
    # ====================================================================
    "anomalous_access_pattern": {
        "description": "Access patterns deviate from baseline",
        "actors": [
            {
                "type": "IP_ADDRESS",
                "confidence": 0.90,
                "evidence_keys": ["anomalous_source_ip", "unusual_ip", "source_ip"],
                "evidence_description": "Source IP with unusual characteristics",
                "intervention": "INVESTIGATE",
                "threat_level": "MEDIUM",
            },
            {
                "type": "ENDPOINT",
                "confidence": 0.85,
                "evidence_keys": ["unusual_target", "target_endpoint"],
                "evidence_description": "Unusual target endpoint for this access pattern",
                "intervention": "INVESTIGATE",
                "threat_level": "MEDIUM",
            },
            {
                "type": "DEVICE_FINGERPRINT",
                "confidence": 0.75,
                "evidence_keys": ["device_fingerprint", "tls_ja3"],
                "evidence_description": "Device fingerprint differs from baseline",
                "intervention": "INVESTIGATE",
                "threat_level": "MEDIUM",
            },
        ],
    },
    
    # ====================================================================
    # Pattern 6: UNENCRYPTED_TRANSMISSION
    # ====================================================================
    "unencrypted_transmission": {
        "description": "Sensitive data transmitted without encryption",
        "actors": [
            {
                "type": "ENDPOINT",
                "confidence": 0.90,
                "evidence_keys": ["source_endpoint", "transmitting_service"],
                "evidence_description": "Endpoint transmitting unencrypted data",
                "intervention": "ISOLATE_ENDPOINT",
                "threat_level": "CRITICAL",
            },
            {
                "type": "IP_ADDRESS",
                "confidence": 0.95,
                "evidence_keys": ["destination_ip", "dest_ip"],
                "evidence_description": "Destination IP receiving unencrypted data",
                "intervention": "BLOCK_IP",
                "threat_level": "CRITICAL",
            },
            {
                "type": "DOMAIN",
                "confidence": 0.80,
                "evidence_keys": ["destination_domain", "dest_domain"],
                "evidence_description": "Destination domain receiving unencrypted data",
                "intervention": "BLOCK_DOMAIN",
                "threat_level": "CRITICAL",
            },
        ],
    },
    
    # ====================================================================
    # Pattern 7: WEAK_AUTHENTICATION
    # ====================================================================
    "weak_authentication": {
        "description": "Weak or deprecated authentication methods",
        "actors": [
            {
                "type": "ENDPOINT",
                "confidence": 0.85,
                "evidence_keys": ["vulnerable_endpoint", "auth_endpoint"],
                "evidence_description": "Endpoint with weak authentication",
                "intervention": "ISOLATE_ENDPOINT",
                "threat_level": "HIGH",
            },
            {
                "type": "IP_ADDRESS",
                "confidence": 0.90,
                "evidence_keys": ["source_ip", "requesting_ip"],
                "evidence_description": "IP using weak authentication method",
                "intervention": "BLOCK_IP",
                "threat_level": "HIGH",
            },
            {
                "type": "PROTOCOL_SIGNATURE",
                "confidence": 0.70,
                "evidence_keys": ["auth_pattern", "http_signature"],
                "evidence_description": "HTTP signature indicating weak auth",
                "intervention": "INVESTIGATE",
                "threat_level": "HIGH",
            },
        ],
    },
    
    # ====================================================================
    # Pattern 8: UNAUTHORIZED_DATA_ACCESS
    # ====================================================================
    "unauthorized_data_access": {
        "description": "Unauthorized data access or privilege escalation",
        "actors": [
            {
                "type": "IP_ADDRESS",
                "confidence": 0.95,
                "evidence_keys": ["source_ip", "accessing_ip"],
                "evidence_description": "IP accessing unauthorized data",
                "intervention": "BLOCK_IP",
                "threat_level": "CRITICAL",
            },
            {
                "type": "ENDPOINT",
                "confidence": 0.85,
                "evidence_keys": ["data_endpoint", "target_endpoint"],
                "evidence_description": "Endpoint with unauthorized data access",
                "intervention": "ISOLATE_ENDPOINT",
                "threat_level": "CRITICAL",
            },
            {
                "type": "SESSION",
                "confidence": 0.88,
                "evidence_keys": ["session_id", "accessing_session"],
                "evidence_description": "Session performing unauthorized access",
                "intervention": "KILL_SESSION",
                "threat_level": "CRITICAL",
            },
        ],
    },
}


# ======================================================================
# FIXED LIMITATIONS (HONESTY BY ACTOR TYPE)
# ======================================================================

ACTOR_LIMITATIONS: Dict[ActorType, str] = {
    "IP_ADDRESS": (
        "Cannot determine attacker identity from IP address alone. "
        "IP may be proxy, VPN, cloud provider, VPS, or spoofed. "
        "Recommend: Correlate with threat intelligence feeds, firewall logs, and "
        "BGP reputation databases to validate IP reputation and ownership."
    ),
    
    "SESSION": (
        "Cannot determine which user account owns this session without authentication logs. "
        "Session token alone does not reveal the user's identity or legitimacy. "
        "Recommend: Correlate session token with authentication system logs to identify "
        "compromised or at-risk user accounts."
    ),
    
    "ENDPOINT": (
        "Cannot determine service name, purpose, or internal identity without internal logs. "
        "Endpoint hostname may be visible externally but internal details are hidden. "
        "Recommend: Correlate with asset inventory, service registry, and CMDB to "
        "identify service owner and business criticality."
    ),
    
    "DEVICE_FINGERPRINT": (
        "TLS fingerprint matching is probabilistic, not deterministic. "
        "Same fingerprint may occur on different devices or systems. "
        "Fingerprints can be spoofed with custom TLS implementations. "
        "Recommend: Use as supporting evidence only, not as primary identification. "
        "Correlate with IP reputation and behavioral patterns for stronger confidence."
    ),
    
    "DOMAIN": (
        "Domain ownership requires external threat intelligence. "
        "Cannot determine if domain is attacker-controlled or compromised from external vantage. "
        "DNS resolution patterns may indicate attacker infrastructure but are not definitive. "
        "Recommend: Correlate with passive DNS, WHOIS records, and threat feeds. "
        "Check domain registration history and certificate transparency logs."
    ),
    
    "PROTOCOL_SIGNATURE": (
        "HTTP signatures are heuristic-based patterns, not definitive indicators. "
        "False positives are possible; legitimate traffic may match attack signatures. "
        "Signature matching confidence varies by specificity and historical accuracy. "
        "Recommend: Use as supporting evidence. Require additional patterns or evidence "
        "before taking action based on signatures alone."
    ),
    
    "IP_RANGE": (
        "CIDR block aggregation reduces specificity and increases false positive risk. "
        "Not all IPs in range may be malicious; innocent traffic may be blocked. "
        "Recommend: Validate against threat intelligence before blocking entire ranges. "
        "Consider rate-limiting instead of outright blocking if uncertainty exists."
    ),
    
    "ASN": (
        "ASN lookup uses GeoIP database which is ~95% accurate, not 100%. "
        "Hosting provider may not equal attacker location or identity. "
        "ASN databases may be stale or inaccurate for newer infrastructure. "
        "Recommend: Validate with current BGP routing data and threat intelligence. "
        "Consider that legitimate services may be hosted on same ASN as attacker infrastructure."
    ),
}


# ======================================================================
# CORRELATION SUGGESTIONS (WHAT INTERNAL DATA WOULD HELP)
# ======================================================================

ACTOR_CORRELATIONS: Dict[ActorType, str] = {
    "IP_ADDRESS": (
        "Correlate with firewall logs (source IP tracking), VPC flow logs (traffic analysis), "
        "and threat intelligence (IP reputation) to determine if internal or external origin"
    ),
    
    "SESSION": (
        "Correlate with authentication logs to find which user account owns this session, "
        "when it was created, and what systems it accessed"
    ),
    
    "ENDPOINT": (
        "Correlate with asset inventory (CMDB), service registry, and ownership records "
        "to identify service purpose, business unit, and owner"
    ),
    
    "DEVICE_FINGERPRINT": (
        "Correlate with endpoint management system and device inventory to identify device type, "
        "OS, installed applications, and owner"
    ),
    
    "DOMAIN": (
        "Correlate with DNS logs (who resolved this domain), WHOIS records (registration details), "
        "and passive DNS to understand domain history and control"
    ),
    
    "PROTOCOL_SIGNATURE": (
        "Correlate with application logs and WAF logs to understand the intent and impact "
        "of the requests matching this signature"
    ),
    
    "IP_RANGE": (
        "Correlate with network topology, routing tables, and threat intelligence "
        "to understand legitimate vs. malicious use of this CIDR block"
    ),
    
    "ASN": (
        "Correlate with current BGP routing data, hosting provider reputation, "
        "and threat intelligence to assess ASN trustworthiness"
    ),
}


# ======================================================================
# ACTOR EXTRACTOR V1
# ======================================================================

class ActorExtractor:
    """
    Extract observable actor contexts from Guardian patterns.
    
    v1 scope:
      ✓ Deterministic pattern → actor mapping
      ✓ Fixed confidence values
      ✓ Fixed limitations and correlations
      ✓ Evidence-backed extraction only
      ✗ No aggregation across patterns
      ✗ No scoring or inference
      ✗ No timelines or campaigns
    """
    
    def __init__(self):
        self.mappings = PATTERN_MAPPINGS
        self.limitations = ACTOR_LIMITATIONS
        self.correlations = ACTOR_CORRELATIONS
    
    def extract(
        self,
        pattern_label: str,
        evidence: Dict,
        evidence_ids: List[str],
        alert_timestamp_utc: int,
    ) -> List[ActorContext]:
        """
        Extract observable actors from a single pattern.
        
        Args:
            pattern_label: Name of detected pattern (entropy_exhaustion, etc.)
            evidence: Dict of evidence from pattern detection
            evidence_ids: List of evidence IDs supporting this detection
            alert_timestamp_utc: Timestamp when alert was generated (epoch seconds)
        
        Returns:
            List of ActorContext objects (may be empty if no evidence)
        
        Raises:
            ValueError: If pattern_label not recognized
        """
        
        if pattern_label not in self.mappings:
            raise ValueError(
                f"Unknown pattern: {pattern_label}. "
                f"Known patterns: {', '.join(self.mappings.keys())}"
            )
        
        actors: List[ActorContext] = []
        pattern_spec = self.mappings[pattern_label]
        
        # Extract each actor type defined for this pattern
        for actor_spec in pattern_spec["actors"]:
            actor_type: ActorType = actor_spec["type"]
            evidence_keys = actor_spec["evidence_keys"]
            
            # Try to find evidence for this actor type
            identifier = None
            for key in evidence_keys:
                if key in evidence:
                    identifier = evidence[key]
                    break
            
            if not identifier:
                # No evidence for this actor type; skip it
                continue
            
            # Build source evidence list
            source_evidence = [
                actor_spec["evidence_description"],
                f"From pattern: {pattern_label}",
            ]
            if evidence_ids:
                source_evidence.append(f"Evidence IDs: {', '.join(evidence_ids[:3])}")
            
            # Create ActorContext
            context = ActorContext(
                actor_type=actor_type,
                identifier=identifier,
                confidence=actor_spec["confidence"],  # Fixed, no adjustment
                vantage_point="EXTERNAL",
                confidence_factors={
                    "base_confidence": actor_spec["confidence"],
                    "evidence_present": 1.0,
                },
                source_evidence=source_evidence,
                source_pattern_labels=[pattern_label],
                first_observed_utc=evidence.get("first_seen_utc", alert_timestamp_utc),
                last_observed_utc=evidence.get("last_seen_utc", alert_timestamp_utc),
                observation_count=evidence.get("observation_count", 1),
                is_internal=False,
                limitations=self.limitations.get(actor_type),
                requires_internal_data=False,  # v1: all external actors
                recommended_correlation=self.correlations.get(actor_type),
            )
            
            actors.append(context)
        
        return actors
    
    def extract_from_patterns(
        self,
        patterns: List[tuple[str, Dict]],
        evidence_ids: List[str],
        alert_timestamp_utc: int,
    ) -> List[ActorContext]:
        """
        Extract actors from multiple patterns.
        
        Args:
            patterns: List of (pattern_label, evidence_dict) tuples
            evidence_ids: Evidence IDs supporting these detections
            alert_timestamp_utc: Alert timestamp
        
        Returns:
            Flattened list of all actors from all patterns
        """
        
        all_actors: List[ActorContext] = []
        
        for pattern_label, evidence in patterns:
            actors = self.extract(
                pattern_label=pattern_label,
                evidence=evidence,
                evidence_ids=evidence_ids,
                alert_timestamp_utc=alert_timestamp_utc,
            )
            all_actors.extend(actors)
        
        return all_actors


# ======================================================================
# CONVENIENCE FUNCTION
# ======================================================================

def extract_actors(
    pattern_label: str,
    evidence: Dict,
    evidence_ids: List[str],
    alert_timestamp_utc: int,
) -> List[ActorContext]:
    """
    Convenience function: extract actors from a single pattern.
    
    Args:
        pattern_label: Pattern name
        evidence: Evidence dict
        evidence_ids: Evidence IDs
        alert_timestamp_utc: Alert timestamp
    
    Returns:
        List[ActorContext]
    """
    
    extractor = ActorExtractor()
    return extractor.extract(
        pattern_label=pattern_label,
        evidence=evidence,
        evidence_ids=evidence_ids,
        alert_timestamp_utc=alert_timestamp_utc,
    )


def extract_actors_from_patterns(
    patterns: List[tuple[str, Dict]],
    evidence_ids: List[str],
    alert_timestamp_utc: int,
) -> List[ActorContext]:
    """
    Convenience function: extract actors from multiple patterns.
    
    Args:
        patterns: [(pattern_label, evidence_dict), ...]
        evidence_ids: Evidence IDs
        alert_timestamp_utc: Alert timestamp
    
    Returns:
        List[ActorContext]
    """
    
    extractor = ActorExtractor()
    return extractor.extract_from_patterns(
        patterns=patterns,
        evidence_ids=evidence_ids,
        alert_timestamp_utc=alert_timestamp_utc,
    )
