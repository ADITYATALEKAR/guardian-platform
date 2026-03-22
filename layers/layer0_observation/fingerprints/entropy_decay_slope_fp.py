"""
entropy_decay_slope_fp.py

Layer 0 high-resolution temporal fingerprint:
Generic slope+monotonicity+persistence fingerprint for "entropy-like" signals.

Even though the name includes "decay", Layer 0 stays semantics-free:
- We measure slope magnitude (direction-independent strength)
- Monotonicity is computed CONSISTENT with the observed slope direction
- Persistence is late-vs-early magnitude ratio

Rules:
- Canonical Fingerprint only
- Stable identity uses bucketized payload only
- window_bucket stored as INT everywhere
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, Optional, Sequence, Tuple

from .fingerprint_types import Fingerprint


def _safe_float(x: Any) -> float:
    try:
        f = float(x)
        if f != f or f in (float("inf"), float("-inf")):
            return 0.0
        return f
    except Exception:
        return 0.0


def _clamp01(x: float) -> float:
    return 0.0 if x < 0.0 else 1.0 if x > 1.0 else x


def _compress_pos01(x: float) -> float:
    v = abs(_safe_float(x))
    return v / (1.0 + v)


def _bucketize01(x01: float, edges: Sequence[float]) -> int:
    x = _clamp01(_safe_float(x01))
    for i, e in enumerate(edges):
        if x <= e:
            return i
    return len(edges)


def _finite_series(values: Optional[Iterable[Any]]) -> Tuple[float, ...]:
    if not values:
        return ()
    out = []
    for v in values:
        out.append(_safe_float(v))
    return tuple(out)


def _mean(xs: Sequence[float]) -> float:
    return sum(xs) / float(len(xs)) if xs else 0.0


def _window_bucket(window_ms: Optional[int]) -> int:
    if not window_ms or window_ms <= 0:
        return 0
    w = int(window_ms)
    if w <= 250:
        return 1
    if w <= 1000:
        return 2
    if w <= 5000:
        return 3
    if w <= 30000:
        return 4
    return 5


def _bucket_n(n: int) -> int:
    if n <= 0:
        return 0
    if n < 5:
        return 1
    if n < 10:
        return 2
    if n < 20:
        return 3
    if n < 50:
        return 4
    return 5


def _compute_monotonicity(values: Sequence[float]) -> float:
    """
    Compute monotonicity consistent with the observed direction of change.

    - If overall trend is upward, count deltas > 0.
    - If overall trend is downward, count deltas < 0.
    - If flat, return 0.

    Output: 0..1
    """
    x = list(values)
    if len(x) < 3:
        return 0.0

    net = x[-1] - x[0]
    if abs(net) < 1e-12:
        return 0.0

    want_positive = net > 0

    deltas = [x[i] - x[i - 1] for i in range(1, len(x))]
    valid = 0
    aligned = 0

    for d in deltas:
        if abs(d) < 1e-12:
            continue
        valid += 1
        if want_positive:
            if d > 0:
                aligned += 1
        else:
            if d < 0:
                aligned += 1

    return aligned / max(1, valid)


def _compute_from_series(values: Sequence[float]) -> Dict[str, float]:
    x = list(values)
    if len(x) < 6:
        return {
            "slope_strength": 0.0,
            "monotonicity": 0.0,
            "persistence": 0.0,
        }

    mean_abs = _mean([abs(v) for v in x])

    # slope magnitude (direction-independent)
    # normalized slope magnitude, bounded later
    raw_slope = (x[-1] - x[0]) / (mean_abs + 1e-9)
    slope_strength = abs(raw_slope)

    monotonicity = _compute_monotonicity(x)

    mid = len(x) // 2
    early_mag = _mean([abs(v) for v in x[:mid]])
    late_mag = _mean([abs(v) for v in x[mid:]])
    ratio = late_mag / (early_mag + 1e-9)
    persistence = ratio / (1.0 + ratio)

    return {
        "slope_strength": float(slope_strength),
        "monotonicity": float(monotonicity),
        "persistence": float(persistence),
    }


def compute_entropy_decay_slope_fingerprint(
    *,
    entity_id: str,
    entropy_values: Optional[Iterable[Any]] = None,
    physics_signals: Optional[Dict[str, Any]] = None,
    window_ms: Optional[int] = None,
) -> Fingerprint:
    entity_id_s = str(entity_id or "").strip()
    if not entity_id_s:
        raise ValueError("entity_id must be non-empty")

    physics_signals = dict(physics_signals or {})
    used_physics = False

    # Keep aliases compatible but semantics-free
    s = physics_signals.get("entropy_decay_slope_strength", physics_signals.get("slope_strength"))
    m = physics_signals.get("entropy_decay_monotonicity", physics_signals.get("monotonicity"))
    p = physics_signals.get("entropy_decay_persistence", physics_signals.get("persistence"))

    if s is not None or m is not None or p is not None:
        used_physics = True
        slope_strength = _safe_float(s)
        monotonicity = _safe_float(m)
        persistence = _safe_float(p)
    else:
        series = _finite_series(entropy_values)
        metrics = _compute_from_series(series)
        slope_strength = metrics["slope_strength"]
        monotonicity = metrics["monotonicity"]
        persistence = metrics["persistence"]

    # strength is unbounded -> compress
    strength01 = _compress_pos01(slope_strength)

    # monotonicity/persistence are [0..1] -> clamp
    mono01 = _clamp01(monotonicity)
    pers01 = _clamp01(persistence)

    n = len(_finite_series(entropy_values))
    n_bucket = _bucket_n(n)
    w_bucket = _window_bucket(window_ms)

    strength_b = _bucketize01(strength01, edges=[0.02, 0.05, 0.10, 0.20, 0.35, 0.55, 0.75])
    mono_b = _bucketize01(mono01, edges=[0.10, 0.25, 0.40, 0.55, 0.70, 0.85, 0.95])
    pers_b = _bucketize01(pers01, edges=[0.10, 0.25, 0.40, 0.55, 0.70, 0.85, 0.95])

    hash_payload = {
        "entity_id": entity_id_s,
        "window_bucket": int(w_bucket),
        "n_bucket": int(n_bucket),
        "strength_b": int(strength_b),
        "mono_b": int(mono_b),
        "pers_b": int(pers_b),
    }

    fp_hash = Fingerprint.stable_hash_from_payload(hash_payload)

    vector = Fingerprint.make_vector(
        [
            strength01,
            mono01,
            pers01,
            float(strength_b) / 7.0,
            float(w_bucket) / 5.0,
            float(n_bucket) / 5.0,
        ],
        quantize_decimals=4,
    )

    base_q = 0.9 if used_physics else 0.65
    size_q = 0.35 + 0.65 * (float(n_bucket) / 5.0) if n > 0 else 0.25
    quality = Fingerprint.safe_quality(base_q * size_q)

    source_fields = {
        "used_physics_signals": used_physics,
        "slope_strength": float(slope_strength),
        "monotonicity": float(monotonicity),
        "persistence": float(persistence),
        "strength01": float(strength01),
        "mono01": float(mono01),
        "persistence01": float(pers01),
        "strength_bucket": int(strength_b),
        "mono_bucket": int(mono_b),
        "persistence_bucket": int(pers_b),
        "n_bucket": int(n_bucket),
        "window_bucket": int(w_bucket),
    }

    return Fingerprint(
        entity_id=entity_id_s,
        kind="entropy_decay_slope_fp_v1",
        version=1,
        hash=fp_hash,
        vector=vector,
        quality=quality,
        source_fields=source_fields,
    )
