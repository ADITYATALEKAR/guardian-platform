"""
baseline_types.py

Layer 0 baseline model types.

Goal:
- Provide a stable, bounded baseline state object for each entity_id.
- No semantics: just numeric ranges/statistics used by calibrator/normalizer.

These are plain dataclasses used internally by Layer 0 baselines.


Importance:  Defines what “normal” means

What it does:

Defines baseline state shapes

Separates learned norms from live signals

What’s special:

Baselines are data, not assumptions

No heuristic “expected values”

Metaphor:

The medical chart format, not the diagnosis.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass(frozen=True)
class BaselineStats:
    """
    Minimal robust baseline statistics container.
    All values must be numeric-only.

    You can store:
    - location (mean/median)
    - scale (mad/std proxy)
    - ewma (rolling)
    - bounds (min/max)
    """
    mean: float = 0.0
    mad: float = 0.0
    ewma: float = 0.0
    min_v: float = 0.0
    max_v: float = 0.0

    # quality of baseline maturity (0..1)
    maturity: float = 0.0

    # sample count bucket (bounded)
    n_bucket: int = 0


@dataclass(frozen=True)
class EntityBaseline:
    """
    Baseline object per entity_id.

    metrics is a dict keyed by signal_name or metric_name, for example:
      metrics["jitter_ms"] = BaselineStats(...)
      metrics["entropy_level"] = BaselineStats(...)

    It stays numeric-only, stable and bounded.
    """
    entity_id: str
    updated_at_ms: Optional[int] = None
    metrics: Dict[str, BaselineStats] = field(default_factory=dict)
