"""
Layer 4 — Multi-axis synchronization index (deterministic).

Uses ONLY:
- persistence_norm (from metrics.persistence / MAX_PERSISTENCE)
- structural_reinforcement_score (from metrics)

No new state, O(N_signals).
"""

from typing import Any, Iterable, Dict

MAX_PERSISTENCE = 20


def _safe_float(x: Any, default: float = 0.0) -> float:
    try:
        v = float(x)
        if v != v or v in (float("inf"), float("-inf")):
            return default
        return v
    except Exception:
        return default


def _clamp01(x: Any) -> float:
    v = _safe_float(x, 0.0)
    if v < 0.0:
        return 0.0
    if v > 1.0:
        return 1.0
    return v


def compute_sync_index(
    signals: Iterable[Dict[str, Any]],
    *,
    min_axes: int = 3,
    persistence_threshold: float = 0.6,
    reinforcement_threshold: float = 0.5,
) -> float:
    """
    sync_index =
      (# axes where persistence_norm >= threshold AND reinforcement >= threshold)
      / total_active_axes

    If total_active_axes < min_axes, returns 0.0.
    """
    total = 0
    aligned = 0

    for s in signals or []:
        if not isinstance(s, dict):
            continue
        total += 1
        metrics = s.get("metrics", {})
        if not isinstance(metrics, dict):
            metrics = {}
        persistence = _safe_float(metrics.get("persistence", 0.0), 0.0)
        persistence_norm = _clamp01(persistence / float(MAX_PERSISTENCE))
        reinforcement = _clamp01(
            metrics.get("structural_reinforcement_score", metrics.get("structural_reinforcement", 0.0))
        )
        if persistence_norm >= persistence_threshold and reinforcement >= reinforcement_threshold:
            aligned += 1

    if total < int(min_axes):
        return 0.0
    return _clamp01(aligned / float(total))
