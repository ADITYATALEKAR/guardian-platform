"""
fallback_periodicity_fp.py

Layer 0 high-resolution temporal fingerprint:
Fallback periodicity fingerprint (attempt-path recurrence rhythm).

This is purely structural:
- detects periodicity in "fallback-like" events or attempt transitions
- no semantics, no risk

Inputs:
- event_times_ms: timestamps of fallback/transition events (epoch ms or relative ms)
OR physics_signals providing periodicity metrics.

Rules:
- Canonical Fingerprint only
- Stable identity hash uses bucketized payload only
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


def _safe_int(x: Any) -> int:
    try:
        return int(x)
    except Exception:
        return 0


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
    if n < 3:
        return 1
    if n < 6:
        return 2
    if n < 12:
        return 3
    if n < 24:
        return 4
    return 5


def _mean(xs: Sequence[float]) -> float:
    return sum(xs) / float(len(xs)) if xs else 0.0


def _median(xs: Sequence[float]) -> float:
    if not xs:
        return 0.0
    s = sorted(xs)
    m = len(s) // 2
    return s[m] if len(s) % 2 else 0.5 * (s[m - 1] + s[m])


def _mad(xs: Sequence[float], med: float) -> float:
    if not xs:
        return 0.0
    dev = [abs(x - med) for x in xs]
    return _median(dev) or 1e-9


def _compute_from_times(times_ms: Sequence[float]) -> Dict[str, float]:
    t = sorted(times_ms)
    if len(t) < 4:
        return {
            "periodicity_strength": 0.0,
            "periodicity_mad_ratio": 0.0,
            "periodicity_density": 0.0,
        }

    gaps = [max(0.0, t[i] - t[i - 1]) for i in range(1, len(t))]
    mean_gap = _mean(gaps)
    med_gap = _median(gaps)
    mad_gap = _mad(gaps, med_gap)

    # periodicity strength: inverse dispersion ratio
    mad_ratio = mad_gap / (mean_gap + 1e-9)
    periodicity_strength = 1.0 / (1.0 + mad_ratio)  # 0..1

    # density proxy: more events packed -> higher density
    span = max(1.0, t[-1] - t[0])
    density = len(t) / span  # events per ms (tiny)
    density01 = _compress_pos01(density * 1000.0)  # scale anchor

    return {
        "periodicity_strength": float(_clamp01(periodicity_strength)),
        "periodicity_mad_ratio": float(mad_ratio),
        "periodicity_density": float(density01),
    }


def compute_fallback_periodicity_fingerprint(
    *,
    entity_id: str,
    event_times_ms: Optional[Iterable[Any]] = None,
    physics_signals: Optional[Dict[str, Any]] = None,
    window_ms: Optional[int] = None,
) -> Fingerprint:
    entity_id_s = str(entity_id or "").strip()
    if not entity_id_s:
        raise ValueError("entity_id must be non-empty")

    physics_signals = dict(physics_signals or {})
    used_physics = False

    s = physics_signals.get("fallback_periodicity_strength", None)
    r = physics_signals.get("fallback_periodicity_mad_ratio", None)
    d = physics_signals.get("fallback_periodicity_density01", None)

    if s is not None or r is not None or d is not None:
        used_physics = True
        strength01 = _clamp01(_safe_float(s))
        mad_ratio01 = _compress_pos01(_safe_float(r))
        density01 = _clamp01(_safe_float(d))
    else:
        t = _finite_series(event_times_ms)
        metrics = _compute_from_times(t)
        strength01 = _clamp01(metrics["periodicity_strength"])
        mad_ratio01 = _compress_pos01(metrics["periodicity_mad_ratio"])
        density01 = _clamp01(metrics["periodicity_density"])

    n = len(_finite_series(event_times_ms))
    n_bucket = _bucket_n(n)
    w_bucket = _window_bucket(window_ms)

    strength_b = _bucketize01(strength01, edges=[0.10, 0.25, 0.40, 0.55, 0.70, 0.85, 0.95])
    mad_b = _bucketize01(mad_ratio01, edges=[0.02, 0.05, 0.10, 0.20, 0.35, 0.55, 0.75])
    density_b = _bucketize01(density01, edges=[0.02, 0.05, 0.10, 0.20, 0.35, 0.55, 0.75])

    hash_payload = {
        "entity_id": entity_id_s,
        "window_bucket": int(w_bucket),
        "n_bucket": int(n_bucket),
        "strength_b": int(strength_b),
        "mad_b": int(mad_b),
        "density_b": int(density_b),
    }

    fp_hash = Fingerprint.stable_hash_from_payload(hash_payload)

    vector = Fingerprint.make_vector(
        [
            strength01,
            mad_ratio01,
            density01,
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
        "periodicity_strength01": float(strength01),
        "periodicity_mad_ratio01": float(mad_ratio01),
        "periodicity_density01": float(density01),
        "strength_bucket": int(strength_b),
        "mad_bucket": int(mad_b),
        "density_bucket": int(density_b),
        "n_bucket": int(n_bucket),
        "window_bucket": int(w_bucket),  # ✅ INT (fixed)
    }

    return Fingerprint(
        entity_id=entity_id_s,
        kind="fallback_periodicity_fp_v1",
        version=1,
        hash=fp_hash,
        vector=vector,
        quality=quality,
        source_fields=source_fields,
    )
