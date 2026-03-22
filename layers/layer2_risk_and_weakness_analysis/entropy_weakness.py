"""
entropy_weakness.py

Layer 2 — Entropy Weakness Detection (minimal hardening, contract-preserving)

Changes applied (only approved):
- weakness_id uses BaseWeakness.stable_kind_id(...)
- stable rounding everywhere

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


def _round_stable(x: object, ndigits: int = 6) -> float:
    return float(round(_safe_float(x, 0.0), ndigits))


@dataclass(frozen=True, kw_only=True)
class EntropyWeakness(BaseWeakness):
    entropy_zscore: float = 0.0
    entropy_decay_rate: float = 0.0

    entropy_drop: float = 0.0
    decay_rate: float = 0.0

    entropy_level: float = 0.0
    entropy_decay: float = 0.0

    def __post_init__(self) -> None:
        canonical = _round_stable(self.entropy_decay_rate)
        object.__setattr__(self, "entropy_decay_rate", canonical)
        object.__setattr__(self, "decay_rate", canonical)
        object.__setattr__(self, "entropy_decay", canonical)


class EntropyWeaknessDetector:
    WEAKNESS_ID = BaseWeakness.stable_kind_id("entropy", 1)

    ZSCORE_TRIGGER = 3.0
    DECAY_TRIGGER = 0.05

    def evaluate(
        self,
        entity_id: str,
        entropy_value: float,
        entropy_decay_rate: float,
        baseline_entropy_mean: float,
        baseline_entropy_std: float,
        entropy_floor: float,
    ) -> Optional[EntropyWeakness]:
        eid = _require_entity(entity_id)
        if not eid:
            return None

        val = _safe_float(entropy_value, 0.0)
        decay = _safe_float(entropy_decay_rate, 0.0)
        mu = _safe_float(baseline_entropy_mean, val)
        sd = abs(_safe_float(baseline_entropy_std, 0.0))
        floor = _safe_float(entropy_floor, 0.0)

        if sd > 1e-12:
            z = (mu - val) / sd
        else:
            z = 0.0

        drop = max(0.0, mu - val)

        degraded_floor = val < floor
        degraded_zscore = z >= self.ZSCORE_TRIGGER
        degraded_decay = decay >= self.DECAY_TRIGGER

        if not (degraded_floor or degraded_zscore or degraded_decay):
            return None

        z_component = min(1.0, max(0.0, z / 6.0))
        d_component = min(1.0, max(0.0, decay / 0.2))
        f_component = 1.0 if degraded_floor else 0.0

        severity = min(1.0, 0.45 * z_component + 0.35 * d_component + 0.20 * f_component)
        confidence = min(1.0, severity + 0.10)

        return EntropyWeakness(
            weakness_id=self.WEAKNESS_ID,
            entity_id=eid,
            severity=_round_stable(severity),
            confidence=_round_stable(confidence),
            first_seen_ms=0,
            entropy_zscore=_round_stable(z),
            entropy_decay_rate=_round_stable(decay),
            entropy_drop=_round_stable(drop),
            entropy_level=_round_stable(val),
        )
