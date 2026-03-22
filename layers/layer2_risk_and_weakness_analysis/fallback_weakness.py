"""
fallback_weakness.py

Layer 2 — Fallback Weakness Detection (bank-grade, contract-preserving)

Changes applied:
- weakness_id uses BaseWeakness.stable_kind_id(...)
- stable rounding everywhere
- correlation polarity not relevant here (unchanged logic)
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


def _round_stable(x: object, ndigits: int = 6) -> float:
    return float(round(_safe_float(x, 0.0), ndigits))


@dataclass(frozen=True, kw_only=True)
class FallbackWeakness(BaseWeakness):
    fallback_frequency: float = 0.0
    recent_spike: bool = False


class FallbackWeaknessDetector:
    WEAKNESS_ID = BaseWeakness.stable_kind_id("fallback", 1)

    MIN_SPIKE_RATIO = 1.5
    SPIKE_RATIO_STRONG = 3.0
    MAX_SPIKE_RATIO = 50.0

    ABS_TRIGGER = 0.35
    ABS_STRONG = 0.60

    def evaluate(
        self,
        entity_id: str,
        fallback_rate: float,
        baseline_fallback_rate: float,
    ) -> Optional[FallbackWeakness]:
        eid = _require_entity(entity_id)
        if not eid:
            return None

        fr = _safe_float(fallback_rate, -1.0)
        br = _safe_float(baseline_fallback_rate, 0.0)

        if fr < 0.0:
            return None

        # Cold start baseline missing
        if br <= 0.0:
            if fr < self.ABS_TRIGGER:
                return None

            severity = min(1.0, max(0.0, (fr - self.ABS_TRIGGER) / (1.0 - self.ABS_TRIGGER)))
            recent_spike = bool(fr >= self.ABS_STRONG)

            confidence = min(1.0, 0.45 + 0.35 * severity + (0.10 if recent_spike else 0.0))

            return FallbackWeakness(
                weakness_id=self.WEAKNESS_ID,
                entity_id=eid,
                severity=_round_stable(severity),
                confidence=_round_stable(confidence),
                first_seen_ms=0,
                fallback_frequency=_round_stable(fr),
                recent_spike=bool(recent_spike),
            )

        # Baseline ratio logic
        ratio = fr / br if br > 0.0 else self.MAX_SPIKE_RATIO
        if ratio != ratio:
            return None
        if ratio == float("inf"):
            ratio = self.MAX_SPIKE_RATIO
        ratio = min(self.MAX_SPIKE_RATIO, max(0.0, ratio))

        if ratio < self.MIN_SPIKE_RATIO:
            return None

        normalized = (ratio - self.MIN_SPIKE_RATIO) / (10.0 - self.MIN_SPIKE_RATIO)
        severity = max(0.0, min(1.0, normalized))

        recent_spike = bool(ratio >= self.SPIKE_RATIO_STRONG)

        confidence = min(1.0, 0.60 + 0.40 * severity)
        if recent_spike:
            confidence = min(1.0, confidence + 0.05)

        return FallbackWeakness(
            weakness_id=self.WEAKNESS_ID,
            entity_id=eid,
            severity=_round_stable(severity),
            confidence=_round_stable(confidence),
            first_seen_ms=0,
            fallback_frequency=_round_stable(fr),
            recent_spike=bool(recent_spike),
        )
