"""
Layer 4 — Deterministic campaign phase machine (stateless).

Design:
- No persistent state, no cross-entity logic.
- Hysteresis via low/high bands to prevent flicker.
- O(N_signals) per entity.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Iterable

MAX_PERSISTENCE = 20


class CampaignPhase(str, Enum):
    STABLE = "stable"
    RECON = "recon"
    PROBE = "probe"
    ESCALATION = "escalation"
    STRUCTURAL_STRESS = "structural_stress"
    PERSISTENT_PRESSURE = "persistent_pressure"
    RECOVERY = "recovery"
    TRANSITIONAL = "transitional"


@dataclass(frozen=True, slots=True)
class PhaseResult:
    phase: CampaignPhase
    confidence: float
    summary: Dict[str, float]


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


def _urgency_from_horizon(horizon_days: int) -> float:
    try:
        h = int(horizon_days)
    except Exception:
        h = 0
    if h <= 3:
        return 1.0
    if h <= 7:
        return 0.7
    if h <= 14:
        return 0.4
    return 0.2


def _band(value: float, *, low: float, high: float) -> str:
    if value >= high:
        return "high"
    if value <= low:
        return "low"
    return "mid"


def infer_phase(
    signals: Iterable[Dict[str, Any]],
    *,
    sync_index: float,
) -> PhaseResult:
    """
    Stateless phase inference with hysteresis bands.
    Returns (phase, confidence, summary metrics).
    """
    total = 0
    sum_p = 0.0
    sum_r = 0.0
    sum_v = 0.0
    sum_u = 0.0

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
        volatility = _clamp01(metrics.get("volatility_ewma", 0.0))

        horizon_days = s.get("horizon_days", 0)
        urgency = _urgency_from_horizon(horizon_days)

        sum_p += persistence_norm
        sum_r += reinforcement
        sum_v += volatility
        sum_u += urgency

    if total <= 0:
        return PhaseResult(
            phase=CampaignPhase.STABLE,
            confidence=1.0,
            summary={"persistence": 0.0, "reinforcement": 0.0, "volatility": 0.0, "urgency": 0.0, "sync_index": _clamp01(sync_index)},
        )

    p_mean = _clamp01(sum_p / float(total))
    r_mean = _clamp01(sum_r / float(total))
    v_mean = _clamp01(sum_v / float(total))
    u_mean = _clamp01(sum_u / float(total))
    s_idx = _clamp01(sync_index)

    # hysteresis bands
    p_band = _band(p_mean, low=0.45, high=0.70)
    r_band = _band(r_mean, low=0.40, high=0.60)
    v_band = _band(v_mean, low=0.40, high=0.70)
    u_band = _band(u_mean, low=0.30, high=0.70)
    s_band = _band(s_idx, low=0.30, high=0.60)

    # deterministic transition table (ordered)
    if p_band == "high" and r_band == "high" and s_band == "high":
        phase = CampaignPhase.STRUCTURAL_STRESS
        conf = 0.85
    elif p_band == "high" and v_band == "low" and r_band in ("high", "mid"):
        phase = CampaignPhase.PERSISTENT_PRESSURE
        conf = 0.80
    elif v_band == "high" and p_band == "low":
        phase = CampaignPhase.RECON if r_band == "low" else CampaignPhase.PROBE
        conf = 0.70
    elif u_band == "high" and r_band in ("high", "mid") and p_band in ("high", "mid"):
        phase = CampaignPhase.ESCALATION
        conf = 0.75
    elif p_band == "mid" and v_band in ("mid", "low"):
        phase = CampaignPhase.PROBE
        conf = 0.60
    elif p_band == "low" and r_band == "low" and v_band == "low":
        phase = CampaignPhase.RECOVERY
        conf = 0.55
    else:
        phase = CampaignPhase.TRANSITIONAL
        conf = 0.40

    return PhaseResult(
        phase=phase,
        confidence=_clamp01(conf),
        summary={
            "persistence": p_mean,
            "reinforcement": r_mean,
            "volatility": v_mean,
            "urgency": u_mean,
            "sync_index": s_idx,
        },
    )
