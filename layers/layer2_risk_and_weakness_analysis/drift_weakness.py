"""
drift_weakness.py

Layer 2 — Drift Weakness Detection (bank-grade, contract-preserving)

Changes applied:
- weakness_id uses BaseWeakness.stable_kind_id(...)
- stable rounding for severity/confidence and public numeric fields

Everything else preserved.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .base_weakness import BaseWeakness


def _require_entity(entity_id: str) -> Optional[str]:
    eid = str(entity_id or "").strip()
    return eid if eid else None


def _safe_float(x: object, default: float = 0.0) -> float:
    try:
        v = float(x)
        if v != v or v in (float("inf"), float("-inf")):
            return default
        return v
    except Exception:
        return default


def _clamp01(x: object) -> float:
    v = _safe_float(x, 0.0)
    if v < 0.0:
        return 0.0
    if v > 1.0:
        return 1.0
    return v


def _round_stable(x: object, ndigits: int = 6) -> float:
    return float(round(_safe_float(x, 0.0), ndigits))


@dataclass(frozen=True, kw_only=True)
class DriftWeakness(BaseWeakness):
    drift_zscore: float = 0.0
    momentum_anomaly: bool = False
    coherence_drop: float = 0.0


class DriftWeaknessDetector:
    WEAKNESS_ID = BaseWeakness.stable_kind_id("drift", 1)

    ZSCORE_MIN = 2.5
    MOMENTUM_MIN = 0.25
    COHERENCE_DROP_MIN = 0.20

    def evaluate(
        self,
        entity_id: str,
        drift_rate: float,
        momentum: float,
        coherence_score: float,
        baseline_drift_mean: float,
        baseline_drift_std: float,
        *,
        baseline_coherence: Optional[float] = None,
    ) -> Optional[DriftWeakness]:
        eid = _require_entity(entity_id)
        if not eid:
            return None

        dr = _safe_float(drift_rate, 0.0)
        mom = _safe_float(momentum, 0.0)
        coh = _clamp01(coherence_score)

        mu = _safe_float(baseline_drift_mean, dr)
        sd = abs(_safe_float(baseline_drift_std, 0.0))

        if baseline_coherence is not None:
            bcoh = _clamp01(baseline_coherence)
            coh_drop = max(0.0, bcoh - coh)
        else:
            coh_drop = max(0.0, 1.0 - coh)

        if sd > 1e-12:
            z = (dr - mu) / sd
        else:
            z = 0.0

        momentum_anomaly = bool(mom >= self.MOMENTUM_MIN)

        drift_gate = z >= self.ZSCORE_MIN
        coherence_gate = coh_drop >= self.COHERENCE_DROP_MIN
        momentum_gate = momentum_anomaly

        if not (drift_gate or coherence_gate or momentum_gate):
            return None

        z_component = max(0.0, min(1.0, z / 6.0))
        m_component = max(0.0, min(1.0, mom / 1.0))
        c_component = max(0.0, min(1.0, coh_drop / 0.6))

        severity = min(1.0, 0.50 * z_component + 0.25 * m_component + 0.25 * c_component)
        confidence = min(1.0, severity + 0.10)

        return DriftWeakness(
            weakness_id=self.WEAKNESS_ID,
            entity_id=eid,
            severity=_round_stable(severity),
            confidence=_round_stable(confidence),
            first_seen_ms=0,
            drift_zscore=_round_stable(z),
            momentum_anomaly=bool(momentum_anomaly),
            coherence_drop=_round_stable(coh_drop),
        )
