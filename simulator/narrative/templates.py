"""
Narrative Templates
===================

Deterministic narrative templates used by the simulator.
"""

TEMPLATES = {
    "summary": "Simulation indicates {risk_level} systemic stress across {impacted_nodes} impacted nodes.",
    "blast": "Structural convergence depth={depth}, spread={spread_pct:.2f}, amplification={amplification:.2f}.",
    "delta": "Severity delta={severity_delta:+.2f}, confidence delta={confidence_delta:+.2f}.",
    "paths": "Structural chain: {top_path} (weight={top_weight:.2f}). This reflects shared identity cluster expansion, not direct endpoint reachability.",
}
