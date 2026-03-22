"""
schemas/timing_schema.py

Layer 0 compatibility shim.

Purpose:
- Preserve stable imports for older Layer-0 modules:
  baselines/calibrator.py, normalization/timing_normalizer.py,
  validation/timing_validation.py, tests, etc.

Policy:
- Keep names stable even if the canonical schema expands.
- Numeric-only, bounded, no semantics.
- Do NOT add business meaning.


Importance:  Input contracts

What they do

Define what “valid observation” means

Prevent garbage from entering physics

What’s special

Schemas are pre-physics

This avoids downstream defensive code

Metaphor

Airport security screening before boarding.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Sequence, Tuple

# Canonical expanded observation schema lives here
from layers.layer0_observation.normalization.timing_schema import (
    TimingSchemaError,
    TimingObservation,
    NormalizedTiming,
    timing_observation_from_dict,
)


@dataclass(frozen=True)
class TimingWindow:
    """
    Minimal numeric timing window container.

    Used by calibrator/normalizer code paths that expect a "window object"
    rather than raw lists.

    Keep this tiny: just numbers + optional window metadata.
    """
    values: Tuple[float, ...] = ()
    window_ms: Optional[int] = None

    @classmethod
    def from_values(
        cls,
        values: Optional[Sequence[float]],
        *,
        window_ms: Optional[int] = None,
    ) -> "TimingWindow":
        if not values:
            return cls(values=(), window_ms=window_ms)
        out = []
        for v in values:
            try:
                f = float(v)
                if f != f or f in (float("inf"), float("-inf")):
                    continue
                out.append(f)
            except Exception:
                continue
        return cls(values=tuple(out), window_ms=window_ms)


@dataclass(frozen=True)
class TimingBaseline:
    """
    Minimal baseline contract used by TimingCalibrator.

    This exists primarily for backward compatibility.
    As baseline learning improves, this can be extended without breaking imports.
    """
    entity_id: str

    # RTT baseline
    rtt_ms_mean: Optional[float] = None
    rtt_ms_mad: Optional[float] = None

    # Jitter baseline
    jitter_ms_mean: Optional[float] = None
    jitter_ms_mad: Optional[float] = None

    # Optional metadata
    window_ms: Optional[int] = None


@dataclass(frozen=True)
class TimingCalibrationResult:
    """
    Output of calibration step.

    Numeric-only transformation metadata so downstream normalization/fingerprints
    can remain deterministic and reproducible.
    """
    entity_id: str

    # Calibrated shift/scale factors (optional)
    rtt_shift: float = 0.0
    rtt_scale: float = 1.0

    jitter_shift: float = 0.0
    jitter_scale: float = 1.0

    # Quality of calibration (0..1)
    quality: float = 0.0

    # Optional info
    window_ms: Optional[int] = None
    baseline_used: bool = False


__all__ = [
    "TimingObservation",
    "NormalizedTiming",
    "TimingWindow",
    "TimingBaseline",
    "TimingCalibrationResult",
    "TimingSchemaError",
    "timing_observation_from_dict",
]
