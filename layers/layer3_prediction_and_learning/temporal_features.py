from __future__ import annotations

from typing import Any


def _safe_float(x: Any, default: float = 0.0) -> float:
    try:
        v = float(x)
        if v != v or v in (float("inf"), float("-inf")):
            return default
        return v
    except Exception:
        return default


def clamp01(x: Any) -> float:
    v = _safe_float(x, 0.0)
    if v < 0.0:
        return 0.0
    if v > 1.0:
        return 1.0
    return float(v)


def compute_prediction_severity(
    ewma_severity: float,
    peak_severity_recent: float,
    velocity: float,
    persistence_norm: float,
    reinforcement: float,
    metric_intensity: float,
) -> float:
    v_pos = clamp01(max(0.0, float(velocity)))
    sev = (
        0.45 * clamp01(ewma_severity)
        + 0.05 * clamp01(peak_severity_recent)
        + 0.20 * v_pos
        + 0.15 * clamp01(persistence_norm)
        + 0.10 * clamp01(reinforcement)
        + 0.05 * clamp01(metric_intensity)
    )
    return clamp01(sev)


def compute_prediction_confidence(
    ewma_confidence: float,
    velocity: float,
    volatility_ewma: float,
    persistence_norm: float,
    reinforcement: float,
    reliability_score: float,
) -> float:
    v_abs = abs(float(velocity))
    vol = clamp01(volatility_ewma)
    stability = 1.0 - max(min(1.0, v_abs), vol)
    conf = (
        0.55 * clamp01(ewma_confidence)
        + 0.20 * clamp01(stability)
        + 0.15 * clamp01(persistence_norm)
        + 0.05 * clamp01(reinforcement)
        + 0.05 * clamp01(reliability_score)
    )
    return clamp01(conf)


def compute_horizon_days(
    velocity: float,
    persistence_norm: float,
    reinforcement: float,
    volatility_ewma: float,
    propagation_persistence_norm: float,
    max_horizon_days: int,
) -> int:
    v_pos = clamp01(max(0.0, float(velocity)))
    p = clamp01(persistence_norm)
    r = clamp01(reinforcement)

    if v_pos >= 0.35 and p < 0.30:
        horizon = 3
    elif 0.30 <= p < 0.70:
        horizon = 7
    elif p >= 0.70 and r >= 0.60:
        horizon = 14
    else:
        horizon = 7

    if clamp01(volatility_ewma) >= 0.70 and horizon > 3:
        horizon = max(3, horizon - 2)

    if clamp01(propagation_persistence_norm) >= 0.60:
        horizon = min(int(max_horizon_days), horizon + 2)
    return horizon
