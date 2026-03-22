"""
meta.py

Layer 0 third-order meta-physics.
Physics of physics. Numeric-only, bounded, deterministic.

What it does

Governs how physics interact

Prevents double-counting

Metaphor

The laws of physics themselves.
"""

from __future__ import annotations

from typing import Dict, Iterable, Sequence


def _safe_float(x) -> float:
    try:
        f = float(x)
        if f != f or f in (float("inf"), float("-inf")):
            return 0.0
        return f
    except Exception:
        return 0.0


def _clamp01(x: float) -> float:
    return 0.0 if x < 0.0 else 1.0 if x > 1.0 else x


def _median(xs: Sequence[float]) -> float:
    if not xs:
        return 0.0
    s = sorted(xs)
    m = len(s) // 2
    return s[m] if len(s) % 2 else 0.5 * (s[m - 1] + s[m])


def _mad(xs: Sequence[float], med: float) -> float:
    dev = [abs(x - med) for x in xs]
    return _median(dev) or 1e-9


def _standardize(xs: Sequence[float]):
    if not xs:
        return []
    med = _median(xs)
    mad = _mad(xs, med)
    # meta physics does not require strict Gaussian scaling,
    # but keeping MAD unscaled is fine because we only use bounded outputs.
    scale = mad or 1e-9
    return [(x - med) / scale for x in xs]


def _diff(xs: Sequence[float]):
    return [xs[i] - xs[i - 1] for i in range(1, len(xs))]


def _mean(xs: Sequence[float]) -> float:
    return sum(xs) / len(xs) if xs else 0.0


def _compress01(x: float) -> float:
    ax = abs(x)
    return ax / (1.0 + ax)


def _corr(xs: Sequence[float], ys: Sequence[float]) -> float:
    n = min(len(xs), len(ys))
    if n < 3:
        return 0.0
    mx = sum(xs[:n]) / n
    my = sum(ys[:n]) / n
    num = dx2 = dy2 = 0.0
    for i in range(n):
        dx = xs[i] - mx
        dy = ys[i] - my
        num += dx * dy
        dx2 += dx * dx
        dy2 += dy * dy
    den = (dx2 * dy2) ** 0.5
    return 0.0 if den <= 1e-12 else num / den


def _window_bucket(window_ms: int | None) -> float:
    """
    Bucket window duration to 0..5 for stability.
    This is metadata only (not interpretation).
    """
    if not window_ms or window_ms <= 0:
        return 0.0
    w = int(window_ms)
    if w <= 5_000:
        return 1.0
    if w <= 15_000:
        return 2.0
    if w <= 60_000:
        return 3.0
    if w <= 300_000:
        return 4.0
    return 5.0


def compute_meta_physics(
    *,
    values: Iterable[float],
    window_ms: int | None = None,
) -> Dict[str, float]:
    xs = [_safe_float(v) for v in values or []]
    n = len(xs)

    if n < 6:
        return {
            "persistence_index": 0.0,
            "divergence_index": 0.0,
            "jerk_index": 0.0,
            "stability_index": 0.0,
            "sample_count_norm": _clamp01(n / 64.0),
            "window_bucket": _window_bucket(window_ms),
        }

    z = _standardize(xs)
    d1 = _diff(z)
    d2 = _diff(d1)

    # Persistence: late magnitude vs early magnitude (stable + symmetric)
    mid = n // 2
    early_mag = _mean([abs(x) for x in z[:mid]])
    late_mag = _mean([abs(x) for x in z[mid:]])

    ratio = late_mag / (early_mag + 1e-9)
    persistence_index = _clamp01(ratio / (1.0 + ratio))

    # Divergence: trend magnitude of abs(z) over time
    absz = [abs(x) for x in z]
    t = list(range(len(absz)))
    divergence_index = _clamp01(abs(_corr(absz, t)))

    # Jerk: second difference energy (standardized)
    jerk_raw = _mean([abs(x) for x in d2]) if d2 else 0.0
    jerk_index = _clamp01(_compress01(jerk_raw))

    # Stability: inverse of first-diff energy (standardized)
    d1_energy = _mean([abs(x) for x in d1]) if d1 else 0.0
    stability_index = _clamp01(1.0 / (1.0 + d1_energy))

    return {
        "persistence_index": persistence_index,
        "divergence_index": divergence_index,
        "jerk_index": jerk_index,
        "stability_index": stability_index,
        "sample_count_norm": _clamp01(n / 64.0),
        "window_bucket": _window_bucket(window_ms),
    }
