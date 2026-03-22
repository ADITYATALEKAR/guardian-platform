"""
transition_weakness.py

Layer 2 — Transition Weakness Detection (bank-grade, contract-preserving)

Changes applied:
- weakness_id uses BaseWeakness.stable_kind_id(...)
- stable rounding everywhere (public numeric fields + severity/confidence)

Everything else preserved.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .base_weakness import BaseWeakness


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
class TransitionWeakness(BaseWeakness):
    signal_name: str = ""
    previous_value: float = 0.0
    current_value: float = 0.0
    delta: float = 0.0
    transition_score: float = 0.0
    transition_detected: bool = False


class TransitionWeaknessDetector:
    WEAKNESS_ID = BaseWeakness.stable_kind_id("transition", 1)

    def __init__(self, threshold: float = 0.5):
        self.threshold = max(0.0, min(1.0, _safe_float(threshold, 0.5)))

    def detect(
        self,
        signal_name: str,
        previous_value: float,
        current_value: float,
        *,
        entity_id: Optional[str] = None,
    ) -> TransitionWeakness:
        eid = str(entity_id or "").strip() or "unknown"

        prev = _safe_float(previous_value, 0.0)
        curr = _safe_float(current_value, 0.0)

        # deterministic delta
        delta = round(curr - prev, 10)
        score = abs(delta)

        detected = bool(score >= self.threshold)

        if self.threshold > 0.0:
            severity = min(1.0, score / (self.threshold * 2.0))
        else:
            severity = 1.0 if detected else 0.0

        confidence = min(1.0, severity + 0.10)

        return TransitionWeakness(
            weakness_id=self.WEAKNESS_ID,
            entity_id=eid,
            severity=_round_stable(severity),
            confidence=_round_stable(confidence),
            first_seen_ms=0,
            signal_name=str(signal_name),
            previous_value=_round_stable(prev),
            current_value=_round_stable(curr),
            delta=_round_stable(delta),
            transition_score=_round_stable(score),
            transition_detected=bool(detected),
        )
