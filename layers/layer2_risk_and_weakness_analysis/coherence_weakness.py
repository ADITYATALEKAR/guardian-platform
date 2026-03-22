"""
coherence_weakness.py

Layer 2 — Coherence Weakness Detection (bank-grade, contract-preserving)

Changes applied (per your approved concerns):
- weakness_id now uses BaseWeakness.stable_kind_id(...)
- stable rounding applied to public numeric fields
- optional baseline_std enables variance-aware persistence (non-breaking)

Everything else remains consistent with your current file:
- same thresholds
- same fields
- replay-safe first_seen_ms=0
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
class CoherenceWeakness(BaseWeakness):
    coherence_drop: float = 0.0
    persistent: bool = False


class CoherenceWeaknessDetector:
    """
    Conservative, baseline-aware coherence degradation detector.

    Persistence logic:
    - Always triggers persistence if drop >= DROP_PERSISTENT (legacy behavior)
    - Additionally (optional): if baseline_std is provided, can mark persistent
      when drop is large relative to baseline variance (z-drop gate).
    """
    WEAKNESS_ID = BaseWeakness.stable_kind_id("coherence", 1)

    DROP_MIN = 0.10
    DROP_PERSISTENT = 0.35

    # optional variance gate (only used if baseline_std is provided)
    ZDROP_PERSISTENT = 2.0

    def evaluate(
        self,
        entity_id: str,
        coherence_score: float,
        baseline_coherence: float,
        *,
        baseline_std: Optional[float] = None,
    ) -> Optional[CoherenceWeakness]:
        eid = _require_entity(entity_id)
        if not eid:
            return None

        score = _clamp01(coherence_score)
        base = _clamp01(baseline_coherence)

        drop = max(0.0, base - score)

        if drop < self.DROP_MIN:
            return None

        # Legacy severity shaping preserved
        severity = min(1.0, drop / 0.60)

        # Legacy persistent rule preserved
        persistent = bool(drop >= self.DROP_PERSISTENT)

        # Optional variance-aware persistence (non-breaking, only adds sensitivity)
        if not persistent and baseline_std is not None:
            sd = abs(_safe_float(baseline_std, 0.0))
            if sd > 1e-12:
                z_drop = drop / sd
                if z_drop >= self.ZDROP_PERSISTENT:
                    persistent = True

        confidence = min(1.0, severity + 0.10)

        return CoherenceWeakness(
            weakness_id=self.WEAKNESS_ID,
            entity_id=eid,
            severity=_round_stable(severity),
            confidence=_round_stable(confidence),
            first_seen_ms=0,
            coherence_drop=_round_stable(drop),
            persistent=bool(persistent),
        )
