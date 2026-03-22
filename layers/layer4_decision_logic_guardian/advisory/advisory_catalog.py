"""
Deterministic advisory catalog (rule-based response posture).
"""

ADVISORY_BY_PHASE = {
    "stable": "Maintain standard monitoring.",
    "recon": "Increase monitoring sensitivity and observe short-term changes.",
    "probe": "Increase monitoring and validate protocol hardening.",
    "escalation": "Prepare incident response playbooks and tighten controls.",
    "structural_stress": "Activate cross-surface validation and containment checks.",
    "persistent_pressure": "Sustain heightened monitoring and review access policies.",
    "recovery": "Maintain observation to confirm stabilization.",
    "transitional": "Maintain observation; phase remains ambiguous.",
}


ADVISORY_BY_RISK_CLASS = {
    "low": "No immediate action required beyond standard monitoring.",
    "medium": "Review controls and increase targeted monitoring.",
    "high": "Initiate response review and validate critical dependencies.",
}
