"""
Deterministic narrative templates for Guardian Layer 4.

No randomness, no LLMs. Template selection is rule-driven.
"""

PHASE_DESCRIPTIONS = {
    "stable": "System signals are stable with no sustained stress indicators.",
    "recon": "Observed short-horizon volatility suggests reconnaissance or probing behavior.",
    "probe": "Persistent anomalies indicate probing with increasing coordination.",
    "escalation": "Signals show coordinated escalation with short-horizon risk.",
    "structural_stress": "Multi-axis structural stress is present with strong synchronization.",
    "persistent_pressure": "Sustained pressure indicates prolonged stress conditions.",
    "recovery": "Signals indicate recovery with declining stress markers.",
    "transitional": "Signals are mixed and do not map to a stable phase.",
}


RISK_CLASS_DESCRIPTIONS = {
    "low": "Overall risk is low with limited propagation potential.",
    "medium": "Overall risk is moderate with signs of structural coupling.",
    "high": "Overall risk is high with strong propagation potential.",
}


SECTION_HEADERS = {
    "summary": "System State Summary",
    "drivers": "Dominant Stress Drivers",
    "structure": "Structural Coupling",
    "phase": "Campaign Phase",
    "outlook": "Stability Outlook",
}
