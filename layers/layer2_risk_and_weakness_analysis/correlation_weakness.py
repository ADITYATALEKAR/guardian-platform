"""
correlation_weakness.py

Layer 2 — Correlation Weakness Detection (bank-grade, contract-preserving)

IMPORTANT POLARITY DISCIPLINE (your approved fix):
This detector only accepts "badness strength" inputs:

    signal_values[name] in [0..1]
    where HIGHER = WORSE

If upstream wants to pass "goodness metrics" (higher=better),
they MUST invert them before calling this detector.

This prevents semantic corruption in production.

Changes applied:
- weakness_id uses BaseWeakness.stable_kind_id(...)
- stable rounding everywhere
- polarity-safe evaluation: "weak" means value >= threshold
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

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


def _round_stable(x: object, ndigits: int = 6) -> float:
    return float(round(_safe_float(x, 0.0), ndigits))


def _clamp01(x: object) -> float:
    v = _safe_float(x, 0.0)
    if v < 0.0:
        return 0.0
    if v > 1.0:
        return 1.0
    return v


@dataclass(frozen=True, kw_only=True)
class CorrelationWeakness(BaseWeakness):
    correlation_strength: float = 0.0
    persistent: bool = False
    weak_signals: List[str] = field(default_factory=list)


class CorrelationWeaknessDetector:
    WEAKNESS_ID = BaseWeakness.stable_kind_id("correlation", 1)

    MIN_WEAK_SIGNALS = 2
    MAX_WEAK_SIGNAL_NAMES = 12

    def evaluate(
        self,
        entity_id: str,
        signal_values: Dict[str, float],
        thresholds: Dict[str, float],
    ) -> Optional[CorrelationWeakness]:
        eid = _require_entity(entity_id)
        if not eid:
            return None

        if not signal_values or not thresholds:
            return None

        weak: List[str] = []

        # deterministic order
        for name in sorted(signal_values.keys()):
            if name not in thresholds:
                continue

            # both must be numeric and clamped to [0..1] (bank-grade invariant)
            v = _clamp01(signal_values.get(name))
            t = _clamp01(thresholds.get(name))

            # POLARITY FIX:
            # weak means "badness strength >= threshold"
            if v >= t:
                weak.append(name)

        if len(weak) < self.MIN_WEAK_SIGNALS:
            return None

        n = len(weak)
        if n == 2:
            corr_strength = 0.70
        elif n == 3:
            corr_strength = 0.85
        else:
            corr_strength = 1.00

        severity = corr_strength
        confidence = min(1.0, severity + 0.10)

        persistent = bool(n >= 3)

        return CorrelationWeakness(
            weakness_id=self.WEAKNESS_ID,
            entity_id=eid,
            severity=_round_stable(severity),
            confidence=_round_stable(confidence),
            first_seen_ms=0,
            correlation_strength=_round_stable(corr_strength),
            persistent=bool(persistent),
            weak_signals=list(weak[: self.MAX_WEAK_SIGNAL_NAMES]),
        )
