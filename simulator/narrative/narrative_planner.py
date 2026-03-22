"""
Narrative Planner
=================

Deterministic narrative construction (template-based).
"""

from typing import Dict, Any, List

from simulator.narrative.templates import TEMPLATES


def build_narrative(
    *,
    blast_radius: Dict[str, Any],
    top_paths: List[Dict[str, Any]],
    deltas: Dict[str, Dict[str, float]],
) -> Dict[str, Any]:
    """
    Build a deterministic narrative from simulation outputs.
    """

    impacted_nodes = int(blast_radius.get("impacted_nodes", 0))
    depth = int(blast_radius.get("depth", 0))
    spread_pct = float(blast_radius.get("spread_pct", 0.0))
    amplification = float(blast_radius.get("amplification", 0.0))

    risk_level = "LOW"
    if impacted_nodes >= 20 or amplification >= 0.9:
        risk_level = "HIGH"
    elif impacted_nodes >= 10 or amplification >= 0.7:
        risk_level = "MODERATE"

    # Aggregate deltas deterministically (mean over entities)
    severity_delta = _mean_delta(deltas, "severity_delta")
    confidence_delta = _mean_delta(deltas, "confidence_delta")

    # Top path
    top_path = "none"
    top_weight = 0.0
    if top_paths:
        top_path = " -> ".join(top_paths[0].get("nodes", []))
        top_weight = float(top_paths[0].get("weight", 0.0))

    summary = TEMPLATES["summary"].format(
        risk_level=risk_level,
        impacted_nodes=impacted_nodes,
    )

    blast = TEMPLATES["blast"].format(
        depth=depth,
        spread_pct=spread_pct,
        amplification=amplification,
    )

    delta = TEMPLATES["delta"].format(
        severity_delta=severity_delta,
        confidence_delta=confidence_delta,
    )

    path = TEMPLATES["paths"].format(
        top_path=top_path,
        top_weight=top_weight,
    )

    return {
        "summary": summary,
        "blast": blast,
        "delta": delta,
        "path": path,
    }


def _mean_delta(deltas: Dict[str, Dict[str, float]], key: str) -> float:
    values = []
    for v in deltas.values():
        if key in v:
            values.append(float(v[key]))
    if not values:
        return 0.0
    return sum(values) / float(len(values))
