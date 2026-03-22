"""
calibrator.py (Layer 0)

Calibration + baselines generator for timing observations.

This is one of the most important Layer 0 “production hardening” modules:
it converts raw noisy timing into stable baseline references that downstream layers can use.

Design goals:
- Deterministic
- No filesystem writes
- Robust to outliers
- Stable with low sample counts
- EWMA updates supported
- Produces TimingCalibrationResult

This is NOT a detection module.
It only builds/updates baselines.


Importance:  Reality alignment

What it does

Adjusts raw metrics against baselines

Removes scale bias

Converts “raw numbers” → “meaningful deviation”

What’s special

No thresholds

No labels

Pure normalization math

Metaphor

Taring a scale before weighing evidence.
"""

# calibrator.py
# -------------------------------------------------------------------
# Layer 0 Baseline Updater (Pure Logic)
#
# Responsibility:
#   - Compute new EntityBaseline from:
#       - previous baseline (optional)
#       - live metric samples
#
# This file does NOT:
#   - Store state
#   - Access filesystem
#   - Know about tenants
#   - Know about EngineRuntime
#
# It is pure baseline evolution logic.
# -------------------------------------------------------------------

import time
from typing import Dict, List, Optional
from statistics import mean

from layers.layer0_observation.baselines.baseline_types import (
    BaselineStats,
    EntityBaseline,
)


class TimingCalibrator:
    """
    Stateless updater for EntityBaseline.
    """

    def update(
        self,
        entity_id: str,
        metric_samples: Dict[str, List[float]],
        previous: Optional[EntityBaseline],
    ) -> EntityBaseline:
        """
        Compute updated baseline from live metrics.

        metric_samples:
            {
                "rtt_ms": [...],
                "entropy": [...],
                ...
            }
        """

        new_metrics: Dict[str, BaselineStats] = {}

        for metric_name, samples in metric_samples.items():
            if not samples:
                continue

            prev_stats = None
            if previous and metric_name in previous.metrics:
                prev_stats = previous.metrics[metric_name]

            new_stats = self._compute_stats(samples, prev_stats)

            new_metrics[metric_name] = new_stats

        return EntityBaseline(
            entity_id=entity_id,
            updated_at_ms=int(time.time() * 1000),
            metrics=new_metrics,
        )

    # ------------------------------------------------------------
    # Internal Computation
    # ------------------------------------------------------------

    def _compute_stats(
        self,
        samples: List[float],
        prev: Optional[BaselineStats],
    ) -> BaselineStats:
        """
        Compute robust baseline stats.
        """

        m = mean(samples)
        abs_devs = [abs(x - m) for x in samples]
        mad = mean(abs_devs) if abs_devs else 0.0

        # EWMA update
        alpha = 0.2
        if prev:
            ewma = alpha * m + (1 - alpha) * prev.ewma
            maturity = min(1.0, prev.maturity + 0.05)
            n_bucket = min(1000, prev.n_bucket + len(samples))
        else:
            ewma = m
            maturity = 0.05
            n_bucket = len(samples)

        return BaselineStats(
            mean=m,
            mad=mad,
            ewma=ewma,
            min_v=min(samples),
            max_v=max(samples),
            maturity=maturity,
            n_bucket=n_bucket,
        )