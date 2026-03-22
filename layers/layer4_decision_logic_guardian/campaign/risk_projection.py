"""
Layer 4 — Structural risk projection (deterministic).

Uses only:
- structural_reinforcement_score
- sync_index
- persistence_norm
- propagation_persistence_norm (if present)

No additive stacking of Layer 3 physics.
"""

from dataclasses import dataclass
from typing import Any, Iterable, Dict

MAX_PERSISTENCE = 20


def _safe_float(x: Any, default: float = 0.0) -> float:
    try:
        v = float(x)
        if v != v or v in (float("inf"), float("-inf")):
            return default
        return v
    except Exception:
        return default


def _clamp01(x: Any) -> float:
    v = _safe_float(x, 0.0)
    if v < 0.0:
        return 0.0
    if v > 1.0:
        return 1.0
    return v


@dataclass(frozen=True, slots=True)
class RiskProjection:
    structural_risk_potential: float
    propagation_potential: float
    risk_class: str


def project_risk(
    signals: Iterable[Dict[str, Any]],
    *,
    sync_index: float,
) -> RiskProjection:
    """
    structural_risk_potential = reinforcement_mean * sync_index * persistence_mean
    propagation_potential = propagation_persistence_norm_mean * reinforcement_mean
    """
    total = 0
    sum_p = 0.0
    sum_r = 0.0
    sum_prop = 0.0

    for s in signals or []:
        if not isinstance(s, dict):
            continue
        total += 1
        metrics = s.get("metrics", {})
        if not isinstance(metrics, dict):
            metrics = {}

        persistence = _safe_float(metrics.get("persistence", 0.0), 0.0)
        persistence_norm = _clamp01(persistence / float(MAX_PERSISTENCE))
        reinforcement = _clamp01(
            metrics.get("structural_reinforcement_score", metrics.get("structural_reinforcement", 0.0))
        )
        prop_persistence = _safe_float(metrics.get("propagation_persistence", 0.0), 0.0)
        prop_norm = _clamp01(prop_persistence / float(MAX_PERSISTENCE))

        sum_p += persistence_norm
        sum_r += reinforcement
        sum_prop += prop_norm

    if total <= 0:
        return RiskProjection(0.0, 0.0, "low")

    p_mean = _clamp01(sum_p / float(total))
    r_mean = _clamp01(sum_r / float(total))
    prop_mean = _clamp01(sum_prop / float(total))
    s_idx = _clamp01(sync_index)

    structural = _clamp01(r_mean * s_idx * p_mean)
    propagation = _clamp01(prop_mean * r_mean)

    if structural >= 0.70 or propagation >= 0.70:
        risk_class = "high"
    elif structural >= 0.35 or propagation >= 0.35:
        risk_class = "medium"
    else:
        risk_class = "low"

    return RiskProjection(structural, propagation, risk_class)
