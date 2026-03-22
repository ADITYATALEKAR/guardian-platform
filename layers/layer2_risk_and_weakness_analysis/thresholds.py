"""
thresholds.py

Layer 2 — stable parameter governance.

Fixes:
- Explicitly align evidence cap = 8 (matches WeaknessSignal MAX_EVIDENCE_REFS).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict


@dataclass(frozen=True)
class Layer2Thresholds:
    # Fusion gating
    fusion_min_axes: int = 2
    fusion_axis_severity_min: float = 0.45
    fusion_bundle_severity_min: float = 0.55

    # Correlation governance
    correlation_min_weak_signals: int = 2

    # Hard caps
    max_signals_per_bundle: int = 32
    max_evidence_refs_per_signal: int = 8


def default_thresholds() -> Layer2Thresholds:
    return Layer2Thresholds()


def correlation_badness_thresholds() -> Dict[str, float]:
    """
    Thresholds over BADNESS strengths in [0..1], higher=worse.

    IMPORTANT:
    Correlation must only consume:
      - weakness severities
      - or pre-normalized "badness strengths"
    NEVER feed "goodness metrics" (like raw coherence_score) here.
    """
    return {
        "drift": 0.55,
        "jitter": 0.55,
        "entropy": 0.55,
        "fallback": 0.45,
        "transition": 0.60,
        "coherence_drop": 0.50,
    }
